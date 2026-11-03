package target

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// git runs git plumbing for a scan, under ADR-001 section 5's rules: the
// global switches before every command, a fixed environment with nothing
// inherited, and standard error discarded (HSH-11/T19).
type git struct {
	ctx   context.Context // ends every call once done, or nil
	dir   string          // GIT_DIR, absolute, or "" before a repository is named
	cwd   string          // the directory git runs in: the work tree's top or the git dir
	index string          // GIT_INDEX_FILE, or "" for the repository's own index
	max   int             // the most output one call may give, or 0 for no limit
}

// globalFlags go before every command: replace refs off, nothing fetched
// from a promisor remote (an older git refuses the flag, which fails closed),
// and no fsmonitor program run.
var globalFlags = []string{"--no-replace-objects", "--no-lazy-fetch", "-c", "core.fsmonitor=false"}

// fixedEnv is the whole environment of every git command a scan runs. os/exec
// finds git through hush's own PATH; git gets none, nor HOME, nor any GIT_
// variable but those derived from the scan's explicit inputs, so global and
// system configuration, trace output, prompts and another repository or
// index named by the caller's environment never apply.
var fixedEnv = []string{"LC_ALL=C", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0"}

func (g git) cmd(args ...string) *exec.Cmd {
	args = slices.Concat(globalFlags, args)
	var c *exec.Cmd
	if g.ctx != nil {
		c = exec.CommandContext(g.ctx, "git", args...)
	} else {
		c = exec.Command("git", args...)
	}
	c.Env = slices.Clone(fixedEnv)
	if g.dir != "" {
		c.Env = append(c.Env, "GIT_DIR="+g.dir)
	}
	if g.index != "" {
		c.Env = append(c.Env, "GIT_INDEX_FILE="+g.index)
	}
	c.Dir = g.cwd
	return c // Stderr nil: git's standard error goes to the null device
}

// errTooLarge is the error for git output or an object over its limit.
var errTooLarge = errors.New("over the size limit")

// out runs git and returns its whole standard output, or errTooLarge when
// it gives more than g.max bytes.
func (g git) out(args ...string) ([]byte, error) {
	return g.run(nil, args...)
}

// run is out with stdin as git's standard input.
func (g git) run(stdin io.Reader, args ...string) ([]byte, error) {
	c := g.cmd(args...)
	c.Stdin = stdin
	if g.max <= 0 {
		return c.Output()
	}
	pipe, err := c.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := c.Start(); err != nil {
		return nil, err
	}
	data, rerr := io.ReadAll(io.LimitReader(pipe, int64(g.max)+1))
	if len(data) > g.max {
		c.Process.Kill()
		c.Wait()
		return nil, errTooLarge
	}
	if werr := c.Wait(); werr != nil {
		return nil, werr
	}
	return data, rerr
}

// minGit is the oldest git a scan runs, the first with --no-lazy-fetch
// (HSH-11/D6).
var minGit = [2]int{2, 44}

// checkVersion runs "git version" with the global switches and the fixed
// environment, and refuses a git that is missing, fails or is older than
// minGit.
func (g git) checkVersion() error {
	tooOld := fail(GitTooOld, "git is missing or older than 2.44")
	out, err := git{ctx: g.ctx, max: 4096}.out("version")
	rest, ok := strings.CutPrefix(string(out), "git version ")
	if err != nil || !ok {
		return tooOld
	}
	f := strings.SplitN(strings.TrimSpace(rest), ".", 3)
	var v [2]int
	for i := range v {
		n, err := -1, error(nil)
		if i < len(f) {
			n, err = strconv.Atoi(f[i])
		}
		if err != nil || n < 0 {
			return tooOld
		}
		v[i] = n
	}
	if v[0] < minGit[0] || v[0] == minGit[0] && v[1] < minGit[1] {
		return tooOld
	}
	return nil
}

// repository is a repository a scan has located: its git directory and
// common directory, and its work tree's top, all absolute with symlinks
// resolved; top is "" for a bare repository or when hush cannot tell.
type repository struct {
	gitDir, common, top string
}

// open checks git and locates the repository at dir ("" for the current
// directory), as ADR-001 section 5 asks, and returns a runner for it. dir is
// a work tree, or a directory below one, or a git directory. hush names the
// repository to git through GIT_DIR rather than letting git search for it, so
// no inherited variable chooses it, and the work tree's top is where git runs.
// A repository that holds info/grafts is refused.
func (s *Scan) open(dir string) (git, repository, error) {
	g := git{ctx: s.Ctx, max: s.MaxGit}
	if err := g.checkVersion(); err != nil {
		return g, repository{}, err
	}
	notRepo := fail(NotRepository, "not a git repository")
	if dir == "" {
		dir = "."
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return g, repository{}, notRepo
	}
	var repo repository
	found := false
	for d, first := abs, true; ; d, first = filepath.Dir(d), false {
		if _, err := os.Lstat(filepath.Join(d, ".git")); err == nil {
			g.dir, g.cwd = filepath.Join(d, ".git"), d
			if repo, err = g.locate(); err == nil {
				repo.top, found = resolved(d), true
				break
			}
		}
		if first {
			g.dir, g.cwd = d, d
			if repo, err = g.locate(); err == nil {
				repo.top, found = worktreeOf(repo), true
				break
			}
		}
		if filepath.Dir(d) == d {
			break
		}
	}
	if !found {
		return g, repository{}, notRepo
	}
	g.dir, g.cwd = repo.gitDir, repo.gitDir
	if repo.top != "" {
		g.cwd = repo.top
	}
	if _, err := os.Lstat(filepath.Join(repo.common, "info", "grafts")); err == nil {
		return g, repository{}, fail(Grafts, "the repository has grafts")
	}
	if err := s.termFileApart(g, repo); err != nil {
		return g, repository{}, err
	}
	return g, repo, nil
}

// termFileApart refuses a repository that holds the term file: in its work
// tree, its git directory, its common directory or, when that is named .git,
// the main work tree around it, by path with symlinks resolved, or as an
// object with the id the file's bytes have as a blob, whether or not a commit
// or the index reaches it (ADR-001 section 5). git's rev-parse
// --show-toplevel also names the work tree, reading core.worktree, as a
// submodule's git directory sets it, once for the repository and once with
// the common directory as GIT_DIR, for the main work tree of a linked
// worktree; it fails for a bare repository, adding nothing.
func (s *Scan) termFileApart(g git, repo repository) error {
	if s.Terms == "" {
		return nil
	}
	terms, err := filepath.EvalSymlinks(s.Terms)
	if err != nil {
		return fail(TermFileGone, "the term file is gone")
	}
	dirs := []string{repo.top, repo.gitDir, repo.common}
	main := g
	main.dir, main.cwd = repo.common, repo.common
	for _, at := range []git{g, main} {
		if out, err := at.out("rev-parse", "--show-toplevel"); err == nil {
			if top := strings.TrimSuffix(string(out), "\n"); filepath.IsAbs(top) {
				dirs = append(dirs, resolved(top))
			}
		}
	}
	if filepath.Base(repo.common) == ".git" {
		dirs = append(dirs, filepath.Dir(repo.common))
	}
	for _, dir := range dirs {
		if dir != "" && within(terms, dir) {
			return fail(TermFileInRepo, "the term file is inside the scanned repository")
		}
	}
	format, err := g.out("rev-parse", "--show-object-format")
	id := s.TermIDs[strings.TrimSuffix(string(format), "\n")]
	if err != nil || id == "" {
		return fail(GitOutput, "git failed")
	}
	if g.cmd("cat-file", "-e", id).Run() == nil {
		return fail(TermFileCommitted, "the term file is committed to the scanned repository")
	}
	return nil
}

// locate asks git for the repository at g.dir.
func (g git) locate() (repository, error) {
	out, err := g.out("rev-parse", "--absolute-git-dir", "--path-format=absolute", "--git-common-dir", "--is-bare-repository")
	f := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	if err != nil || len(f) != 3 {
		return repository{}, errors.New("not a repository")
	}
	repo := repository{gitDir: resolved(f[0]), common: resolved(f[1])}
	if f[2] == "true" {
		repo.top = "-" // bare
	}
	return repo, nil
}

// worktreeOf returns the work tree's top for a repository named by its git
// directory: none for a bare one; the directory a linked worktree's gitdir
// file names; or the parent of a directory named .git. Otherwise "", and
// hush cannot tell where the work tree is.
func worktreeOf(repo repository) string {
	if repo.top == "-" {
		return ""
	}
	if data, err := os.ReadFile(filepath.Join(repo.gitDir, "gitdir")); err == nil {
		if p := strings.TrimSpace(string(data)); filepath.IsAbs(p) {
			return resolved(filepath.Dir(p))
		}
	}
	if filepath.Base(repo.gitDir) == ".git" {
		return resolved(filepath.Dir(repo.gitDir))
	}
	return ""
}

// resolved returns path with symlinks resolved, or path itself when that fails.
func resolved(path string) string {
	if r, err := filepath.EvalSymlinks(path); err == nil {
		return r
	}
	return path
}

// hunkStart returns the new file's first line from "@@ -a,b +c,d @@", or 0.
func hunkStart(line string) int {
	rest := line
	if r, ok := strings.CutPrefix(line, "@@ -"); ok {
		j := 0
		for j < len(r) && (r[j] == ',' || '0' <= r[j] && r[j] <= '9') {
			j++
		}
		if t, ok := strings.CutPrefix(r[j:], " +"); ok && j > 0 {
			rest = t
		}
	}
	j := 0
	for j < len(rest) && '0' <= rest[j] && rest[j] <= '9' {
		j++
	}
	n, _ := strconv.Atoi(rest[:j])
	return n
}

// Index scans the git index: every entry's path, and the staged blob each
// entry names, read by object id through git plumbing and never from the
// work tree. Paths are relative to the top of the work tree, and findings
// read like a tree scan's: rules match and redact the raw path, which then
// prints with git's escapes. The interim has no index target, so no flag
// reaches this yet (HSH-5/D6). Every git call gets s.IndexFile, when set, as
// GIT_INDEX_FILE (HSH-9/D5). With Sink set, that is the only index git is
// given (HSH-11/D31).
func (s *Scan) Index(repo string) error {
	g, _, err := s.open(repo)
	if err != nil {
		return err
	}
	g.index = s.IndexFile
	bad := fail(IndexUnreadable, "cannot read the index")
	// git runs at the top of the work tree, or in the git directory, so
	// ls-files lists the whole index with paths from the top. The global
	// switches keep the repository's fsmonitor program from running, and
	// nothing is fetched from a promisor remote, so a blob that is not local
	// reads as "missing" and fails the scan (HSH-5/D6).
	ls, err := g.out("ls-files", "-z", "--stage")
	if err != nil {
		return bad
	}
	type entry struct{ mode, path string }
	var entries []entry
	var ids bytes.Buffer
	for _, rec := range strings.Split(string(ls), "\x00") {
		if rec == "" {
			continue // after the last record
		}
		meta, path, ok := strings.Cut(rec, "\t")
		f := strings.Fields(meta)
		if !ok || len(f) != 3 {
			return bad
		}
		if f[2] != "0" {
			// A path with conflict stages has no stage 0, and git commits
			// none of them (HSH-11/D19).
			continue
		}
		entries = append(entries, entry{f[0], path})
		if f[0] != "160000" { // a gitlink names a commit, not a blob
			ids.WriteString(f[1] + "\n")
		}
	}
	c := g.cmd("cat-file", "--batch")
	c.Stdin = &ids
	pipe, err := c.StdoutPipe()
	if err != nil || c.Start() != nil {
		return bad
	}
	r := bufio.NewReader(pipe)
	for _, e := range entries {
		if s.stopped() {
			c.Process.Kill()
			c.Wait()
			return fail(Interrupted, "interrupted")
		}
		at := Finding{Loc: InIndex, Path: e.path}
		s.path(at)
		if e.mode == "160000" {
			continue
		}
		s.Counts.Files++
		_, data, err := readObject(r, s.MaxFile)
		if err != nil {
			c.Process.Kill() // cat-file would block on the output left unread
			c.Wait()
			if err == errTooLarge {
				return fail(TooLarge, "input over the size limit")
			}
			return bad
		}
		if bytes.IndexByte(data, 0) >= 0 {
			s.unscanned(at, "binary-unscanned")
		} else {
			s.text(at, data, fileContext(e.path)) // a symlink's blob is its target text
		}
		if s.failed != nil {
			c.Process.Kill()
			c.Wait()
			return s.failed
		}
	}
	if c.Wait() != nil {
		return bad
	}
	return nil
}

// escape returns p as git quotes a path under core.quotePath=false, without
// the surrounding quotes.
func escape(p string) string {
	var b strings.Builder
	for _, c := range []byte(p) {
		if i := strings.IndexByte("\a\b\t\n\v\f\r\"\\", c); i >= 0 {
			b.WriteString(`\` + `abtnvfr"\`[i:i+1])
		} else if c < ' ' || c == 0x7f {
			fmt.Fprintf(&b, `\%03o`, c) // other control bytes
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// readObject reads one "ID TYPE SIZE" record of git cat-file --batch, or of
// --batch-command's "contents", and returns the object's type and data. An
// object over max bytes (max 0: no limit) is errTooLarge, and is not read; a
// missing object is errMissing.
func readObject(r *bufio.Reader, max int) (string, []byte, error) {
	head, err := r.ReadString('\n')
	f := strings.Fields(head)
	if err == nil && len(f) == 2 && f[1] == "missing" {
		return "", nil, errMissing
	}
	if err != nil || len(f) != 3 {
		return "", nil, errBadObject
	}
	size, err := strconv.Atoi(f[2])
	if err != nil || size < 0 {
		return "", nil, errBadObject
	}
	if max > 0 && size > max {
		return "", nil, errTooLarge
	}
	data := make([]byte, size+1)
	if _, err := io.ReadFull(r, data); err != nil || data[size] != '\n' {
		return "", nil, errBadObject
	}
	return f[1], data[:size], nil
}

// The errors of readObject and batch, besides errTooLarge.
var (
	errMissing   = errors.New("missing object")
	errBadObject = errors.New("bad object")
)
