package hush

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/nonhumanhq/hush/internal/target"
)

// Repo names a git repository for ScanIndex and ScanRange. The git commands
// a scan runs inherit no GIT_ variable from the environment, so GIT_DIR,
// GIT_WORK_TREE and GIT_INDEX_FILE, as a git hook sets them, never change
// which repository or index is scanned: Dir and IndexFile alone say.
type Repo struct {
	// Dir is a work tree or a git directory, bare mirrors included. It is
	// required.
	Dir string
	// IndexFile is the index ScanIndex reads: "" for the repository's own,
	// or a file that must exist and be a regular file. hush never reads
	// GIT_INDEX_FILE itself; a caller in a git hook passes it here.
	IndexFile string
}

// recoverError turns a panic into the fixed internal error and calls reset,
// when not nil, so the function returns no value with it. It never formats
// the recovered value (ADR-001 section 6.6).
func recoverError(err *error, reset func()) {
	if recover() != nil {
		*err = errInternal()
		if reset != nil {
			reset()
		}
	}
}

// run is one scan in progress: the target scan, with its sink, and the
// findings built so far.
type run struct {
	s        *Scanner
	ctx      context.Context
	target   Target
	t        *target.Scan
	findings []Finding
	bad      bool // the output check refused a finding
}

// start checks s and ctx and returns a run of target t whose target scan
// reports to it.
func (s *Scanner) start(ctx context.Context, t Target) (*run, error) {
	switch {
	case !s.ready():
		return nil, newError(CodeUsage, msgNoScanner, 0)
	case ctx == nil:
		return nil, newError(CodeUsage, msgNoContext, 0)
	case ctx.Err() != nil:
		return nil, newError(CodeInterrupted, msgInterrupted, 0)
	}
	r := &run{s: s, ctx: ctx, target: t}
	r.t = &target.Scan{Rules: *s.rules.get(), Sets: s.sets.get(), Apply: s.apply, Ctx: ctx, Sink: r.add,
		MaxFile: MaxInputSize, MaxLine: MaxLineSize, Unsafe: func(p string) bool { return unsafeAt(p) >= 0 }}
	if s.terms != nil {
		r.t.Terms = *s.terms.path.get()
	}
	return r, nil
}

// add is the target scan's sink: it builds each finding through the one
// constructor, and records a finding the output check refuses.
func (r *run) add(raw target.Finding) {
	f, ok := r.s.finding(raw)
	if !ok {
		r.bad = true
		return
	}
	r.findings = append(r.findings, f)
}

// finish returns the scan's result under ADR-001 section 7's contract: a
// clean report and nil, the report and a *FindingsError, or nil and an
// *Error. A done context, a refused finding or err, in that order, make it an
// error.
func (r *run) finish(err error) (*Report, error) {
	switch {
	case r.ctx.Err() != nil:
		return nil, newError(CodeInterrupted, msgInterrupted, 0)
	case r.bad:
		return nil, errInternal()
	case err != nil:
		return nil, targetError(err)
	}
	rep := &Report{done: true, findings: r.findings, dest: r.s.dest, coverage: r.s.coverage,
		sets: r.s.applied, target: r.target, counts: Counts(r.t.Counts)}
	if len(rep.findings) > 0 {
		return rep, &FindingsError{report: rep}
	}
	return rep, nil
}

// targetError converts a target's error to the message table. Any other error
// becomes the internal error, never formatted.
func targetError(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	var te *target.Error
	if !errors.As(err, &te) {
		return errInternal()
	}
	switch te.Kind {
	case target.PathMissing:
		return argError(CodePath, msgPathMissing, te.Arg)
	case target.PathUnresolved:
		return argError(CodePath, msgPathUnresolved, te.Arg)
	case target.TermFileInside:
		return newError(CodeTermFile, msgTermInside, 0)
	case target.NotRepository:
		return newError(CodeGit, msgNotRepository, 0)
	case target.BadRange:
		return newError(CodeRange, msgRangeResolve, 0)
	case target.CommitUnreadable:
		return commitError(CodeGit, msgCommitUnreadable, te.Commit)
	case target.DiffFailed:
		return commitError(CodeGit, msgDiffFailed, te.Commit)
	case target.IndexUnreadable:
		return newError(CodeGit, msgIndexUnreadable, 0)
	case target.StdinUnreadable:
		return newError(CodeRead, msgStdinUnreadable, 0)
	case target.Interrupted:
		return newError(CodeInterrupted, msgInterrupted, 0)
	case target.TooLarge:
		return newError(CodeRead, msgTooLarge, 0)
	case target.TermFileGone:
		return newError(CodeTermFile, msgTermMissing, 0)
	}
	return errInternal()
}

// checkLabel returns the label findings in a buffer carry: "<stdin>" for "",
// and otherwise label itself once it matches [A-Za-z0-9][A-Za-z0-9._-]{0,63},
// contains no term of any loaded set (ignoring ASCII case), is not a client
// label any set declares (ignoring ASCII case) and breaks no generic rule as
// a bare string. A refused label is ErrLabel, never echoed.
func (s *Scanner) checkLabel(label string) (string, error) {
	if label == "" {
		return "<stdin>", nil
	}
	refused := !goodStdinLabel(label) || s.breaksText(label) ||
		s.sets != nil && (s.sets.get().RefusesName([]byte(label)) || s.declaredLabel(label))
	if refused {
		return "", newError(CodeLabel, msgLabelRefused, 0)
	}
	return label, nil
}

// declaredLabel reports whether label equals, ignoring ASCII case, a client
// label that any loaded set declares.
func (s *Scanner) declaredLabel(label string) bool {
	sets, lower := s.sets.get(), lowerASCII(label)
	for i := 0; i < sets.Len(); i++ {
		for _, l := range sets.Labels(i) {
			if lowerASCII(l) == lower {
				return true
			}
		}
	}
	return false
}

func goodStdinLabel(label string) bool {
	if len(label) < 1 || len(label) > 64 {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case (c == '.' || c == '_' || c == '-') && i > 0:
		default:
			return false
		}
	}
	return true
}

// ScanBytes scans b as text under label, which findings carry as their
// location: "" gives "<stdin>", and any other label must match
// [A-Za-z0-9][A-Za-z0-9._-]{0,63} and hold no term and nothing a generic rule
// flags (ErrLabel otherwise). Lines are split on "\n". Input that holds a NUL
// byte is not scanned: it gives one binary-unscanned finding. Input over
// MaxInputSize, or a line over MaxLineSize, is ErrRead.
func (s *Scanner) ScanBytes(ctx context.Context, label string, b []byte) (rep *Report, err error) {
	defer recoverError(&err, func() { rep = nil })
	r, err := s.start(ctx, TargetStdin)
	if err != nil {
		return nil, err
	}
	if label, err = s.checkLabel(label); err != nil {
		return nil, err
	}
	if len(b) > MaxInputSize {
		return nil, newError(CodeRead, msgTooLarge, 0)
	}
	r.t.Buffer(b, label)
	return r.finish(r.t.Err())
}

// ScanReader reads rd to its end and scans what it read as ScanBytes does. A
// read error is ErrRead, and so is a stream over MaxInputSize.
func (s *Scanner) ScanReader(ctx context.Context, label string, rd io.Reader) (rep *Report, err error) {
	defer recoverError(&err, func() { rep = nil })
	if _, err := s.start(ctx, TargetStdin); err != nil {
		return nil, err
	}
	if _, err := s.checkLabel(label); err != nil {
		return nil, err
	}
	if rd == nil {
		return nil, newError(CodeRead, msgStdinUnreadable, 0)
	}
	b, rerr := io.ReadAll(io.LimitReader(rd, MaxInputSize+1))
	switch {
	case rerr != nil:
		return nil, newError(CodeRead, msgStdinUnreadable, 0)
	case len(b) > MaxInputSize:
		return nil, newError(CodeRead, msgTooLarge, 0)
	}
	return s.ScanBytes(ctx, label, b)
}

// ScanTree scans files and directory trees. A directory is walked in byte
// order, an entry named .git is pruned, and a symlink is scanned as its link
// text without being followed. With no paths it scans the whole of root, and
// findings' paths are relative to root. Otherwise each path is opened below
// root (or as given, when absolute), and findings' paths start with the path
// as given. A file that cannot be read, a FIFO, socket or device, and a
// directory that cannot be walked each give an unreadable finding, and the
// rest is scanned; a path that cannot print safely gives unreadable in path,
// and its content is still scanned. A path argument that does not exist is
// ErrPath; a path argument that holds the term file, by any name or hard
// link, is ErrTermFile, before any file is read; a file over MaxInputSize or
// a line over MaxLineSize is ErrRead.
func (s *Scanner) ScanTree(ctx context.Context, root string, paths ...string) (rep *Report, err error) {
	defer recoverError(&err, func() { rep = nil })
	r, err := s.start(ctx, TargetTree)
	if err != nil {
		return nil, err
	}
	if root == "" {
		root = "."
	}
	if len(paths) == 0 {
		if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
			return nil, newError(CodePath, msgRootNotDir, 0)
		}
		paths = []string{"."}
	}
	return r.finish(r.t.Tree(root, paths))
}

// ScanIndex scans the git index of repo: each stage's entry path and the blob
// it names, read by object id through git plumbing, never from the work tree.
// Paths are relative to the top of the work tree. A missing repository is
// ErrGit, and so is a set IndexFile that is not a regular file. A blob over
// MaxInputSize or a line over MaxLineSize is ErrRead.
func (s *Scanner) ScanIndex(ctx context.Context, repo Repo) (rep *Report, err error) {
	defer recoverError(&err, func() { rep = nil })
	r, err := s.start(ctx, TargetIndex)
	if err != nil {
		return nil, err
	}
	if repo.Dir == "" {
		return nil, newError(CodeUsage, msgRepoDir, 0)
	}
	if repo.IndexFile != "" {
		abs, aerr := filepath.Abs(repo.IndexFile)
		fi, serr := os.Stat(abs)
		if aerr != nil || serr != nil || !fi.Mode().IsRegular() {
			return nil, newError(CodeGit, msgIndexFile, 0)
		}
		r.t.IndexFile = abs
	}
	return r.finish(r.t.Index(repo.Dir))
}

// ScanRange scans the commits rg selects in repo, oldest first: each commit's
// author, committer and message, the paths it adds or changes and the lines
// it adds, against its first parent. rg must pass the checks ParseRange makes
// (ErrRange otherwise), and a range with no commits is ErrEmptyRange unless
// rg.AllowEmpty is set. A line over MaxLineSize is ErrRead.
func (s *Scanner) ScanRange(ctx context.Context, repo Repo, rg Range) (rep *Report, err error) {
	defer recoverError(&err, func() { rep = nil })
	r, err := s.start(ctx, TargetRange)
	if err != nil {
		return nil, err
	}
	if repo.Dir == "" {
		return nil, newError(CodeUsage, msgRepoDir, 0)
	}
	args, err := rg.revListArgs()
	if err != nil {
		return nil, err
	}
	if err := r.t.RevList(repo.Dir, args); err != nil {
		return r.finish(err)
	}
	if r.t.Counts.Commits == 0 && !rg.AllowEmpty {
		return r.finish(newError(CodeEmptyRange, msgEmptyRange, 0))
	}
	return r.finish(nil)
}
