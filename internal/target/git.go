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
	"slices"
	"strconv"
	"strings"

	"github.com/nonhumanhq/hush/internal/rule"
)

// git runs git plumbing in a repository, with the interim's environment, or,
// for a scan through package hush's API, without the GIT_ variables.
type git struct {
	dir    string          // for -C, or "" for the current directory
	stderr io.Writer       // where relayed calls send git's standard error
	index  string          // GIT_INDEX_FILE for every call, or "" for none set here
	ctx    context.Context // ends every call once done, or nil
	// noGit drops every inherited GIT_ variable, so that GIT_DIR,
	// GIT_WORK_TREE, GIT_INDEX_FILE and the rest, as a git hook sets them,
	// cannot point the scan at another repository or index (HSH-11/D31). The
	// command line keeps the interim's environment until part d's fixed one.
	noGit bool
}

func (g git) cmd(args ...string) *exec.Cmd {
	if g.dir != "" {
		args = append([]string{"-C", g.dir}, args...)
	}
	var c *exec.Cmd
	if g.ctx != nil {
		c = exec.CommandContext(g.ctx, "git", args...)
	} else {
		c = exec.Command("git", args...)
	}
	env := os.Environ()
	if g.noGit {
		env = slices.DeleteFunc(env, func(kv string) bool { return strings.HasPrefix(kv, "GIT_") })
	}
	c.Env = append(env, "LC_ALL=C", "GIT_NO_REPLACE_OBJECTS=1")
	if g.index != "" {
		c.Env = append(c.Env, "GIT_INDEX_FILE="+g.index) // the last value of a name wins
	}
	return c
}

// out runs git and returns its whole standard output. Git's standard error
// is relayed if relay is set, and discarded otherwise.
func (g git) out(relay bool, args ...string) ([]byte, error) {
	c := g.cmd(args...)
	if relay && g.stderr != nil {
		c.Stderr = g.stderr
	}
	return c.Output()
}

func (g git) check() error {
	if _, err := g.out(false, "rev-parse", "--git-dir"); err != nil {
		return fail(NotRepository, "not a git repository")
	}
	return nil
}

var diffFlags = []string{"-c", "core.quotePath=false", "diff-tree", "-r", "-p", "-U0",
	"--no-commit-id", "--no-color", "--no-ext-diff", "--no-textconv", "--no-renames",
	"--src-prefix=a/", "--dst-prefix=b/"}

// Range scans the commits "git rev-list --reverse REVS" lists, oldest first.
// For each it scans the commit object's author, committer and message, then
// the paths the commit adds or changes and the lines it adds, against its
// first parent or, for a root commit, the empty tree. revs is split on
// spaces, tabs and newlines, as the shell splits it.
func (s *Scan) Range(repo, revs string) error {
	return s.RevList(repo, strings.FieldsFunc(revs, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n'
	}))
}

// RevList scans the commits "git rev-list --reverse ARGS" lists, as Range
// does. The caller has checked args: each is handed to rev-list as given.
func (s *Scan) RevList(repo string, args []string) error {
	g := git{dir: repo, stderr: s.GitStderr, ctx: s.Ctx, noGit: s.Sink != nil}
	if err := g.check(); err != nil {
		return err
	}
	c := g.cmd(append([]string{"rev-list", "--reverse"}, args...)...)
	c.Stdin = s.GitStdin // for rev-list's own --stdin; the other calls never read it
	list, err := c.Output()
	if s.stopped() {
		return fail(Interrupted, "interrupted")
	}
	if err != nil {
		return fail(BadRange, "bad --range")
	}
	for _, sha := range lines(list) {
		if s.stopped() {
			return fail(Interrupted, "interrupted")
		}
		short := short(sha)
		obj, err := g.out(true, "cat-file", "commit", sha)
		if err != nil {
			return &Error{Kind: CommitUnreadable, Commit: sha, text: "cannot read commit " + short}
		}
		s.Counts.Commits++
		s.commit(sha, obj)
		if s.failed != nil {
			return s.failed
		}
		if err := s.flush(); err != nil {
			return err
		}
		against := []string{"--root", sha}
		if p, err := g.out(false, "rev-parse", "-q", "--verify", sha+"^1"); err == nil {
			against = []string{strings.TrimRight(string(p), "\n"), sha}
		}
		diff, err := g.out(true, slices.Concat(diffFlags, against)...)
		if err != nil {
			return &Error{Kind: DiffFailed, Commit: sha, text: "cannot diff commit " + short}
		}
		s.diff(sha, diff)
		if s.failed != nil {
			return s.failed
		}
		if err := s.flush(); err != nil {
			return err
		}
	}
	return nil
}

// commit scans a raw commit object. Only the author and committer header
// lines are text; the rest of the header is hashes and signatures. Each line
// carries its part (ADR-002 section 5.1).
func (s *Scan) commit(sha string, obj []byte) {
	at := Finding{Loc: InCommit, Commit: sha}
	body := false
	for i, line := range lines(obj) {
		ctx := rule.Context{Source: rule.Object}
		switch {
		case body:
			ctx.Part = rule.Message
		case strings.HasPrefix(line, "author "):
			ctx.Part = rule.Author
		case strings.HasPrefix(line, "committer "):
			ctx.Part = rule.Committer
		case line == "":
			body = true
			continue
		default:
			continue
		}
		at.Part = ctx.Part
		s.emit(at, i+1, line, ctx)
	}
}

// diff scans diff-tree output: each path not deleted, and each added line,
// numbered in the new file. Deleted lines are not findings.
func (s *Scan) diff(sha string, data []byte) {
	var at Finding
	var pending, inHunk bool
	ln := 0
	flush := func() {
		if pending {
			s.Counts.Files++
			s.path(at)
		}
		pending = false
	}
	for _, line := range lines(data) {
		switch {
		case strings.HasPrefix(line, "diff --git "):
			flush()
			// "a/P b/P", or quoted as "\"a/P\" \"b/P\"": both halves are equal.
			rest := line[len("diff --git "):]
			path := substr(rest, 3, (len(rest)-5)/2)
			if strings.HasPrefix(rest, `"`) {
				path = substr(rest, 4, (len(rest)-9)/2)
			}
			at = Finding{Loc: InDiff, Commit: sha, Path: path}
			pending, inHunk = true, false
		case strings.HasPrefix(line, "@@ "):
			flush()
			inHunk, ln = true, hunkStart(line)
		case inHunk:
			if strings.HasPrefix(line, "+") {
				s.emit(at, ln, line[1:], fileContext(at.Path))
				ln++
			}
		case strings.HasPrefix(line, "deleted file mode "):
			pending = false
		case len(line) >= 20 && strings.HasPrefix(line, "Binary files ") && strings.HasSuffix(line, " differ") &&
			!strings.HasSuffix(line, " and /dev/null differ"):
			flush()
			s.unscanned(at, "binary-unscanned")
		}
	}
	flush()
}

// substr is awk's substr(s, m, n): n bytes from 1-based position m, clamped.
func substr(s string, m, n int) string {
	start, end := max(m, 1), min(m+n, len(s)+1)
	if end <= start {
		return ""
	}
	return s[start-1 : end-1]
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
	g := git{dir: repo, stderr: s.GitStderr, index: s.IndexFile, ctx: s.Ctx, noGit: s.Sink != nil}
	if err := g.check(); err != nil {
		return err
	}
	bad := fail(IndexUnreadable, "cannot read the index")
	// The repository's configuration runs no fsmonitor program, and nothing
	// is fetched from a promisor remote, so a blob that is not local reads
	// as "missing" and fails the scan (HSH-5/D6).
	safe := []string{"-c", "core.fsmonitor=false", "--no-lazy-fetch"}
	ls, err := g.out(false, slices.Concat(safe, []string{"--no-literal-pathspecs",
		"ls-files", "-z", "--stage", "--full-name", "--", ":/"})...)
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
		entries = append(entries, entry{f[0], path})
		if f[0] != "160000" { // a gitlink names a commit, not a blob
			ids.WriteString(f[1] + "\n")
		}
	}
	c := g.cmd(slices.Concat(safe, []string{"cat-file", "--batch"})...)
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
		data, err := readObject(r, s.MaxFile)
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

// errTooLarge is readObject's error for an object over its limit.
var errTooLarge = errors.New("object over the size limit")

// readObject reads one "ID TYPE SIZE" record of git cat-file --batch. An
// object over max bytes (max 0: no limit) is errTooLarge, and is not read.
func readObject(r *bufio.Reader, max int) ([]byte, error) {
	head, err := r.ReadString('\n')
	f := strings.Fields(head)
	if err != nil || len(f) != 3 {
		return nil, errors.New("bad object")
	}
	size, err := strconv.Atoi(f[2])
	if err != nil || size < 0 {
		return nil, errors.New("bad object")
	}
	if max > 0 && size > max {
		return nil, errTooLarge
	}
	data := make([]byte, size+1)
	if _, err := io.ReadFull(r, data); err != nil || data[size] != '\n' {
		return nil, errors.New("bad object")
	}
	return data[:size], nil
}
