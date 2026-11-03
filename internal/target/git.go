package target

import (
	"bufio"
	"bytes"
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

// git runs git plumbing in a repository, with the interim's environment.
type git struct {
	dir    string    // for -C, or "" for the current directory
	stderr io.Writer // where relayed calls send git's standard error
	index  string    // GIT_INDEX_FILE for every call, or "" for the inherited one
}

func (g git) cmd(args ...string) *exec.Cmd {
	if g.dir != "" {
		args = append([]string{"-C", g.dir}, args...)
	}
	c := exec.Command("git", args...)
	c.Env = append(os.Environ(), "LC_ALL=C", "GIT_NO_REPLACE_OBJECTS=1")
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
		return errors.New("not a git repository")
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
	g := git{dir: repo, stderr: s.GitStderr}
	if err := g.check(); err != nil {
		return err
	}
	args := append([]string{"rev-list", "--reverse"}, strings.FieldsFunc(revs, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n'
	})...)
	c := g.cmd(args...)
	c.Stdin = s.GitStdin // for rev-list's own --stdin; the other calls never read it
	list, err := c.Output()
	if err != nil {
		return errors.New("bad --range")
	}
	for _, sha := range lines(list) {
		short := sha
		if len(short) > 12 {
			short = short[:12]
		}
		obj, err := g.out(true, "cat-file", "commit", sha)
		if err != nil {
			return errors.New("cannot read commit " + short)
		}
		s.commit(short+":(commit)", obj)
		if err := s.flush(); err != nil {
			return err
		}
		against := []string{"--root", sha}
		if p, err := g.out(false, "rev-parse", "-q", "--verify", sha+"^1"); err == nil {
			against = []string{strings.TrimRight(string(p), "\n"), sha}
		}
		diff, err := g.out(true, slices.Concat(diffFlags, against)...)
		if err != nil {
			return errors.New("cannot diff commit " + short)
		}
		s.diff(short, diff)
		if err := s.flush(); err != nil {
			return err
		}
	}
	return nil
}

// commit scans a raw commit object. Only the author and committer header
// lines are text; the rest of the header is hashes and signatures. Each line
// carries its part (ADR-002 section 5.1).
func (s *Scan) commit(where string, obj []byte) {
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
		s.emit(where, i+1, line, ctx)
	}
}

// diff scans diff-tree output: each path not deleted, and each added line,
// numbered in the new file. Deleted lines are not findings.
func (s *Scan) diff(short string, data []byte) {
	var file, path string
	var pending, inHunk bool
	ln := 0
	flush := func() {
		if pending {
			s.path(file, path)
		}
		pending = false
	}
	for _, line := range lines(data) {
		switch {
		case strings.HasPrefix(line, "diff --git "):
			flush()
			// "a/P b/P", or quoted as "\"a/P\" \"b/P\"": both halves are equal.
			rest := line[len("diff --git "):]
			if strings.HasPrefix(rest, `"`) {
				path = substr(rest, 4, (len(rest)-9)/2)
			} else {
				path = substr(rest, 3, (len(rest)-5)/2)
			}
			file = short + ":" + s.redact(path)
			pending, inHunk = true, false
		case strings.HasPrefix(line, "@@ "):
			flush()
			inHunk, ln = true, hunkStart(line)
		case inHunk:
			if strings.HasPrefix(line, "+") {
				s.emit(file, ln, line[1:], fileContext(path))
				ln++
			}
		case strings.HasPrefix(line, "deleted file mode "):
			pending = false
		case len(line) >= 20 && strings.HasPrefix(line, "Binary files ") && strings.HasSuffix(line, " differ") &&
			!strings.HasSuffix(line, " and /dev/null differ"):
			flush()
			s.Out.Finding(file, 0, "binary-unscanned")
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
// GIT_INDEX_FILE (HSH-9/D5).
func (s *Scan) Index(repo string) error {
	g := git{dir: repo, stderr: s.GitStderr, index: s.IndexFile}
	if err := g.check(); err != nil {
		return err
	}
	bad := errors.New("cannot read the index")
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
		where := escape(s.redact(e.path))
		s.path(where, e.path)
		if e.mode == "160000" {
			continue
		}
		data, err := readObject(r)
		if err != nil {
			c.Process.Kill() // cat-file would block on the output left unread
			c.Wait()
			return bad
		}
		if bytes.IndexByte(data, 0) >= 0 {
			s.Out.Finding(where, 0, "binary-unscanned")
		} else {
			s.text(where, data, fileContext(e.path)) // a symlink's blob is its target text
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

// readObject reads one "ID TYPE SIZE" record of git cat-file --batch.
func readObject(r *bufio.Reader) ([]byte, error) {
	head, err := r.ReadString('\n')
	f := strings.Fields(head)
	if err != nil || len(f) != 3 {
		return nil, errors.New("bad object")
	}
	size, err := strconv.Atoi(f[2])
	if err != nil || size < 0 {
		return nil, errors.New("bad object")
	}
	data := make([]byte, size+1)
	if _, err := io.ReadFull(r, data); err != nil || data[size] != '\n' {
		return nil, errors.New("bad object")
	}
	return data[:size], nil
}
