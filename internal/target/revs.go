package target

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// Rev is one revision of a range scan: text that git rev-parse --verify
// resolves, its 1-based number among the range's revisions, which errors
// give, and whether it is subtracted.
type Rev struct {
	Text string
	N    int
	Not  bool
}

// Selector names a namespace of refs that hush lists itself (ADR-001 section
// 5).
type Selector uint8

// The selectors.
const (
	AllRefs  Selector = iota + 1 // HEAD, every worktree's HEAD and every ref but refs/stash and refs/replace/
	Branches                     // refs/heads/
	Tags                         // refs/tags/
	Remotes                      // refs/remotes/
)

// Ref is a selector of a range scan, and whether its refs are subtracted.
type Ref struct {
	Sel Selector
	Not bool
}

// Revs is what a range scan walks: the commits reachable from the revisions
// and refs not subtracted, and from none of those subtracted. The caller has
// checked each revision's text (package hush's ParseRange).
type Revs struct {
	Revs []Rev
	Refs []Ref
}

// Range scans the commits revs selects in the repository at repo ("" for the
// current directory), oldest first: each commit's object, then the paths it
// adds or changes and the lines it adds, against its first parent or, for a
// root commit, the empty tree. Every revision and every ref a selector lists
// is resolved to an object id before rev-list runs, and peeled through its
// annotated tags to a commit, so no rev-list option and no pathspec can
// narrow the walk (ADR-001 section 5). A named revision that does not resolve
// to a commit, or a listed ref that is to be walked and does not, stops the
// scan; so does a walk that reaches a shallow boundary.
func (s *Scan) Range(repo string, revs Revs) error {
	g, _, err := s.open(repo)
	if err != nil {
		return err
	}
	b, err := g.batch()
	if err != nil {
		return fail(GitOutput, "git failed")
	}
	defer b.close()
	var include, exclude []string
	var tags tagList
	for _, r := range revs.Revs {
		id, err := g.verify(r.Text)
		if err != nil {
			return s.stopOr(revisionError(r.N))
		}
		commit, chain, err := s.peel(b, id)
		switch {
		case err == errMissing:
			return s.stopOr(revisionError(r.N))
		case err != nil:
			return s.stopOr(s.objectError(err))
		case commit == "":
			return revisionError(r.N)
		case r.Not:
			exclude = append(exclude, commit)
		default:
			include = append(include, commit)
			tags.add(chain, commit)
		}
	}
	for _, ref := range revs.Refs {
		ids, err := s.listRefs(g, ref.Sel)
		if err != nil {
			return s.stopOr(err)
		}
		for _, id := range ids {
			commit, chain, err := s.peel(b, id)
			switch {
			case err != nil:
				return s.stopOr(s.objectError(err))
			case commit == "" && ref.Not:
				// Subtracting a ref that names no commit subtracts nothing.
			case commit == "":
				return fail(RefNotCommit, "a ref does not point to a commit")
			case ref.Not:
				exclude = append(exclude, commit)
			default:
				include = append(include, commit)
				tags.add(chain, commit)
			}
		}
	}
	list, err := s.revList(g, include, exclude)
	if err != nil {
		var e *Error
		if errors.As(err, &e) && e.Kind == BadRange {
			// Every revision peeled to a commit, so rev-list failed on an
			// ancestor it could not read.
			return s.stopOr(s.unreadable(b, include, exclude))
		}
		return err
	}
	return s.walk(g, b, list, tags)
}

// unreadable finds, once rev-list has failed, the first commit reachable
// from include or exclude that cannot be read as a commit, walking parents
// as idHeaders reads them, and returns "cannot read commit" for it, or "git
// failed" when every commit reads.
func (s *Scan) unreadable(b *batch, include, exclude []string) error {
	queue := slices.Concat(include, exclude)
	seen := map[string]bool{}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if seen[id] {
			continue
		}
		seen[id] = true
		typ, obj, err := b.contents(id, s.MaxFile)
		if err == errTooLarge {
			return fail(TooLarge, "input over the size limit")
		}
		if err != nil || typ != "commit" {
			return &Error{Kind: CommitUnreadable, Commit: id, text: "cannot read commit " + short(id)}
		}
		_, parents := idHeaders(lines(obj))
		queue = append(queue, parents...)
	}
	return fail(GitOutput, "git failed")
}

// tagList is the annotated tags a range scan scans as objects: every tag in
// the peel chain of an included revision or ref, each once, in the order
// they were met, with the commit its chain ends at.
type tagList struct {
	ids, commits []string
	seen         map[string]bool
}

func (l *tagList) add(chain []string, commit string) {
	if l.seen == nil {
		l.seen = map[string]bool{}
	}
	for _, id := range chain {
		if !l.seen[id] {
			l.seen[id] = true
			l.ids, l.commits = append(l.ids, id), append(l.commits, commit)
		}
	}
}

// revisionError is the error for the n-th revision of a range, which does not
// resolve to a commit or an annotated tag, or whose tags peel to something
// else.
func revisionError(n int) *Error {
	return &Error{Kind: RevisionBad, Arg: n, text: "range: revision " + strconv.Itoa(n) + " does not resolve to a commit"}
}

// stopOr returns the interrupted error once Ctx is done, since a git command
// killed by the context fails like any other, and err otherwise.
func (s *Scan) stopOr(err error) error {
	if s.stopped() {
		return fail(Interrupted, "interrupted")
	}
	return err
}

// verify resolves one revision to an object id. --end-of-options keeps a
// text that starts with "-" from being read as an option, although the caller
// refuses those already.
func (g git) verify(text string) (string, error) {
	out, err := g.out("rev-parse", "-q", "--verify", "--end-of-options", text)
	id := strings.TrimSuffix(string(out), "\n")
	if err != nil || !isID(id) {
		return "", errBadObject
	}
	return id, nil
}

// isID reports whether id is a full object id: 40 or 64 lowercase hex digits.
func isID(id string) bool {
	if len(id) != 40 && len(id) != 64 {
		return false
	}
	for i := 0; i < len(id); i++ {
		if !('0' <= id[i] && id[i] <= '9' || 'a' <= id[i] && id[i] <= 'f') {
			return false
		}
	}
	return true
}

// peel follows id through its annotated tags and returns the commit it
// finally names, or "" when that is a tree or a blob, or a chain too long to
// be real, with the tags it went through. Its error is batch's.
func (s *Scan) peel(b *batch, id string) (commit string, chain []string, err error) {
	for range 64 {
		typ, err := b.info(id)
		if err != nil {
			return "", nil, err
		}
		switch typ {
		case "commit":
			return id, chain, nil
		case "tag":
			_, data, err := b.contents(id, s.MaxFile)
			if err != nil {
				return "", nil, err
			}
			chain = append(chain, id)
			if id = tagTarget(data); id == "" {
				return "", nil, errBadObject
			}
		default:
			return "", nil, nil
		}
	}
	return "", nil, nil
}

// objectError is the error for an object batch could not give.
func (s *Scan) objectError(err error) error {
	if err == errTooLarge {
		return fail(TooLarge, "input over the size limit")
	}
	return fail(GitOutput, "git failed")
}

// tagTarget returns the id a tag object's "object" header names, or "".
func tagTarget(data []byte) string {
	for _, line := range lines(data) {
		if line == "" {
			break
		}
		if id, ok := strings.CutPrefix(line, "object "); ok && isID(id) {
			return id
		}
	}
	return ""
}

// listRefs returns the object ids sel lists, in ref order: for AllRefs,
// HEAD and every linked worktree's HEAD first, then every ref under refs/
// except refs/stash and refs/replace/, which is git's own --all without those
// two, so refs such as refs/original/ and refs/notes/ are walked.
func (s *Scan) listRefs(g git, sel Selector) ([]string, error) {
	pattern := map[Selector]string{Branches: "refs/heads", Tags: "refs/tags", Remotes: "refs/remotes"}[sel]
	var ids []string
	if sel == AllRefs {
		if id, err := g.verify("HEAD"); err == nil {
			ids = append(ids, id)
		}
		out, err := g.out("worktree", "list", "--porcelain", "-z")
		if err != nil {
			return nil, fail(GitOutput, "git failed")
		}
		for _, field := range strings.Split(string(out), "\x00") {
			if id, ok := strings.CutPrefix(field, "HEAD "); ok && isID(id) && strings.Trim(id, "0") != "" {
				ids = append(ids, id)
			}
		}
	}
	args := []string{"for-each-ref", "--format=%(objectname) %(refname)"}
	if pattern != "" {
		args = append(args, "--", pattern)
	}
	out, err := g.out(args...)
	if err != nil {
		return nil, fail(GitOutput, "git failed")
	}
	for _, line := range lines(out) {
		id, name, ok := strings.Cut(line, " ")
		if !ok || !isID(id) {
			return nil, fail(GitOutput, "git failed")
		}
		if sel == AllRefs && (name == "refs/stash" || strings.HasPrefix(name, "refs/replace/")) {
			continue
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// revList returns the commits reachable from include and from none of
// exclude, oldest first. rev-list gets object ids only, on its standard
// input, so the list's length is not bound by the command line's. A commit
// in the repository's shallow file is a boundary the walk cannot see past,
// which stops the scan.
func (s *Scan) revList(g git, include, exclude []string) ([]string, error) {
	if len(include) == 0 {
		return nil, nil
	}
	var in bytes.Buffer
	for _, id := range include {
		in.WriteString(id + "\n")
	}
	for _, id := range exclude {
		in.WriteString("^" + id + "\n")
	}
	out, err := g.run(&in, "rev-list", "--reverse", "--stdin")
	switch {
	case err == errTooLarge:
		return nil, fail(TooLarge, "input over the size limit")
	case err != nil:
		return nil, s.stopOr(fail(BadRange, "bad --range"))
	}
	list := lines(out)
	shallow, err := g.shallow()
	if err != nil {
		return nil, err
	}
	for _, id := range list {
		if !isID(id) {
			return nil, fail(GitOutput, "git failed")
		}
		if shallow[id] {
			return nil, fail(Shallow, "range: reaches a shallow boundary")
		}
	}
	return list, nil
}

// shallow returns the commits the repository's shallow file lists.
func (g git) shallow() (map[string]bool, error) {
	out, err := g.out("rev-parse", "--path-format=absolute", "--git-path", "shallow")
	if err != nil {
		return nil, fail(GitOutput, "git failed")
	}
	data, err := os.ReadFile(filepath.Clean(strings.TrimSuffix(string(out), "\n")))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fail(GitOutput, "git failed")
	}
	set := map[string]bool{}
	for _, id := range lines(data) {
		set[id] = true
	}
	return set, nil
}

// walk scans each commit of list in turn, and the tags of tags: each right
// after the commit it points to, and those whose commit is not in list after
// every commit, in the order they were met (ADR-001 section 6.2).
func (s *Scan) walk(g git, b *batch, list []string, tags tagList) error {
	done := make([]bool, len(tags.ids))
	scanTags := func(commit string) error {
		for i, id := range tags.ids {
			if done[i] || commit != "" && tags.commits[i] != commit {
				continue
			}
			done[i] = true
			if err := s.tag(b, id); err != nil {
				return err
			}
		}
		return nil
	}
	for _, sha := range list {
		if s.stopped() {
			return fail(Interrupted, "interrupted")
		}
		short := short(sha)
		typ, obj, err := b.contents(sha, s.MaxFile)
		if err == errTooLarge {
			return fail(TooLarge, "input over the size limit")
		}
		if err != nil || typ != "commit" || !utf8Commit(obj) {
			return s.stopOr(&Error{Kind: CommitUnreadable, Commit: sha, text: "cannot read commit " + short})
		}
		s.Counts.Commits++
		s.object(Finding{Loc: InCommit, Commit: sha}, obj, false)
		if s.failed != nil {
			return s.failed
		}
		if err := s.flush(); err != nil {
			return err
		}
		against := []string{"--root", sha}
		if p := firstParent(obj); p != "" {
			against = []string{p, sha}
		}
		diff, err := g.out(slices.Concat(diffFlags, against)...)
		if err == errTooLarge {
			return fail(TooLarge, "input over the size limit")
		}
		if err != nil {
			return s.stopOr(&Error{Kind: DiffFailed, Commit: sha, text: "cannot diff commit " + short})
		}
		if err := s.diff(b, sha, diff); err != nil {
			return err
		}
		if err := s.flush(); err != nil {
			return err
		}
		if err := scanTags(sha); err != nil {
			return err
		}
	}
	return scanTags("")
}

// tag scans the annotated tag object id. Its lines count, but it is neither
// a file nor a commit (HSH-11/D18).
func (s *Scan) tag(b *batch, id string) error {
	if s.stopped() {
		return fail(Interrupted, "interrupted")
	}
	typ, obj, err := b.contents(id, s.MaxFile)
	if err == errTooLarge {
		return fail(TooLarge, "input over the size limit")
	}
	if err != nil || typ != "tag" {
		return s.stopOr(fail(TagUnreadable, "cannot read a tag object"))
	}
	s.object(Finding{Loc: InTag, Tag: id}, obj, true)
	if s.failed != nil {
		return s.failed
	}
	return s.flush()
}

// utf8Commit reports whether a commit object's text is UTF8 as its headers
// declare it: every encoding header, if any, is one line naming UTF8, as
// "utf-8" or "utf8" in any case. hush does not re-encode a message; a commit
// in another encoding cannot be read (HSH-11/D55).
func utf8Commit(obj []byte) bool {
	ls := lines(obj)
	for i := 0; i < len(ls) && ls[i] != ""; i++ {
		enc, ok := strings.CutPrefix(ls[i], "encoding ")
		if !ok && ls[i] != "encoding" {
			continue
		}
		next := i+1 < len(ls) && strings.HasPrefix(ls[i+1], " ")
		if e := strings.ToLower(enc); next || e != "utf-8" && e != "utf8" {
			return false
		}
	}
	return true
}

// firstParent returns the id of a commit object's first parent, as
// idHeaders reads the parents, or "" for a root commit.
func firstParent(obj []byte) string {
	if _, parents := idHeaders(lines(obj)); len(parents) > 0 {
		return parents[0]
	}
	return ""
}

// batch is one git cat-file --batch-command, which gives objects one at a
// time for the whole of a range scan.
type batch struct {
	c  *exec.Cmd
	in io.WriteCloser
	r  *bufio.Reader
}

// batch starts git cat-file --batch-command. Without --buffer it answers
// each command at once.
func (g git) batch() (*batch, error) {
	c := g.cmd("cat-file", "--batch-command")
	in, err := c.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := c.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := c.Start(); err != nil {
		return nil, err
	}
	return &batch{c: c, in: in, r: bufio.NewReader(out)}, nil
}

// info returns the type of the object id, or errMissing.
func (b *batch) info(id string) (string, error) {
	if _, err := io.WriteString(b.in, "info "+id+"\n"); err != nil {
		return "", errBadObject
	}
	line, err := b.r.ReadString('\n')
	f := strings.Fields(line)
	switch {
	case err == nil && len(f) == 2 && f[1] == "missing":
		return "", errMissing
	case err != nil || len(f) != 3 || f[0] != id:
		return "", errBadObject
	}
	return f[1], nil
}

// contents returns the type and the data of the object id, or errMissing, or
// errTooLarge for an object over max bytes. After errTooLarge or
// errBadObject the batch can give nothing more.
func (b *batch) contents(id string, max int) (string, []byte, error) {
	if _, err := io.WriteString(b.in, "contents "+id+"\n"); err != nil {
		return "", nil, errBadObject
	}
	return readObject(b.r, max)
}

// close ends the batch. It kills the process, which may be blocked writing
// an object the scan stopped reading.
func (b *batch) close() {
	b.in.Close()
	b.c.Process.Kill()
	b.c.Wait()
}
