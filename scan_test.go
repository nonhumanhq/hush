package hush

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	lc "github.com/nonhumanhq/hush/internal/leakcheck"
	"github.com/nonhumanhq/hush/internal/target"
)

var bg = context.Background()

// ScanBytes and ScanReader: stdin labels (ADR-001 section 5), NUL bytes,
// empty input, the size limit and the counts.
func TestScanBuffers(t *testing.T) {
	s := scanner(t, Config{Destination: Public(), Terms: load(t, adrTerms())})
	rep, err := s.ScanBytes(bg, "", []byte("a\n"+lc.Zantoph+"\nc "+lc.Bad))
	if ExitCode(err) != 1 || plain(t, rep) != "<stdin>:2: set:people\n<stdin>:3: id-prefix\n" ||
		rep.Scanned() != (Counts{Lines: 3}) {
		t.Errorf("got %v, %+v", err, rep.Scanned())
	}
	f := rep.Findings()[0]
	if f.Kind != Match || f.Tier != TierPrivate || f.Label != "<stdin>" || f.Path != "" || f.Commit != "" {
		t.Errorf("finding: %+v", f)
	}
	rep, err = s.ScanBytes(bg, "issue-body", nil)
	if err != nil || !rep.Clean() || rep.Scanned() != (Counts{}) {
		t.Errorf("empty input: %v", err)
	}
	rep, err = s.ScanBytes(bg, "issue-body", []byte("x\x00y\n"+lc.Bad+"\n"))
	if ExitCode(err) != 1 || plain(t, rep) != "issue-body:0: binary-unscanned\n" || rep.Findings()[0].Kind != Unscanned {
		t.Errorf("NUL: %v", err)
	}
	for _, label := range []string{"-x", ".x", "a b", "a/b", "a:b", "<stdin>", strings.Repeat("a", 65),
		"x" + lc.Quorvel, "notes-" + strings.ToUpper(lc.Zantoph), lc.Bad, "203.0.114" + ".7"} {
		rep, err := s.ScanBytes(bg, label, []byte("clean\n"))
		wantError(t, err, CodeLabel)
		if rep != nil || err.Error() != "stdin label refused" {
			t.Errorf("label refused: %v", err)
		}
		_, err = s.ScanReader(bg, label, strings.NewReader("clean\n"))
		wantError(t, err, CodeLabel)
	}
	for _, label := range []string{"a", "A.b_c-9", strings.Repeat("a", 64), "commit-message"} {
		if _, err := s.ScanBytes(bg, label, []byte("clean\n")); err != nil {
			t.Errorf("label %q: %v", label, err)
		}
	}
	rep, err = s.ScanReader(bg, "body", strings.NewReader(lc.Quorvel+"\n"))
	if ExitCode(err) != 1 || plain(t, rep) != "body:1: set:clients\n" {
		t.Errorf("reader: %v", err)
	}
	_, err = s.ScanReader(bg, "body", failingReader{})
	wantError(t, err, CodeRead)
	_, err = s.ScanReader(bg, "body", nil)
	wantError(t, err, CodeRead)
	leak(t, rep, err)
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("read failed: " + lc.Quorvel) }

// HSH-11/D4: buffers and streams over MaxInputSize are refused, never cut.
func TestScanBuffersTooLarge(t *testing.T) {
	s := scanner(t, Config{Destination: Public(), GenericOnly: true})
	big := make([]byte, MaxInputSize+1)
	for i := range big {
		big[i] = 'a'
	}
	_, err := s.ScanBytes(bg, "", big)
	wantError(t, err, CodeRead)
	_, err = s.ScanReader(bg, "", strings.NewReader(string(big)))
	wantError(t, err, CodeRead)
	if err == nil || err.Error() != "input over the size limit" {
		t.Errorf("got %v", err)
	}
	if _, err := s.ScanBytes(bg, "", big[:MaxInputSize]); err != nil {
		t.Errorf("at the limit: %v", err)
	}
}

// ADR-001 section 7: every exported entry point recovers a panic into the
// fixed internal error and returns no report.
func TestPanicRecovered(t *testing.T) {
	s := scanner(t, Config{Destination: Public(), GenericOnly: true})
	rep, err := s.ScanReader(bg, "", panickingReader{})
	wantError(t, err, CodeInternal)
	if rep != nil || err.Error() != "internal error; output withheld" {
		t.Errorf("got %v", err)
	}
	wantError(t, (&Report{done: true, findings: []Finding{{Rule: "id-prefix", Label: "x", Line: 1}}}).WritePlain(panickingWriter{}), CodeInternal)
}

type panickingReader struct{}

func (panickingReader) Read([]byte) (int, error) { panic("a panic holding " + lc.Quorvel) }

type panickingWriter struct{}

func (panickingWriter) Write([]byte) (int, error) { panic("a panic holding " + lc.Quorvel) }

// ADR-001 section 7: cancellation returns ErrInterrupted and no report.
func TestContextCancelled(t *testing.T) {
	s := scanner(t, Config{Destination: Public(), GenericOnly: true})
	ctx, cancel := context.WithCancel(bg)
	cancel()
	dir, git := gitRepo(t)
	write(t, dir, "a.md", "clean\n")
	git("add", "-A")
	git("commit", "-q", "-m", "one")
	scans := []func() (*Report, error){
		func() (*Report, error) { return s.ScanBytes(ctx, "", []byte("x\n")) },
		func() (*Report, error) { return s.ScanReader(ctx, "", strings.NewReader("x\n")) },
		func() (*Report, error) { return s.ScanTree(ctx, dir) },
		func() (*Report, error) { return s.ScanIndex(ctx, Repo{Dir: dir}) },
		func() (*Report, error) { return s.ScanRange(ctx, Repo{Dir: dir}, Range{Include: []string{"HEAD"}}) },
	}
	for i, scan := range scans {
		rep, err := scan()
		wantError(t, err, CodeInterrupted)
		if rep != nil {
			t.Errorf("scan %d returned a report", i)
		}
	}
	// A context done during the scan: the run stops at the next file.
	ctx, cancel = context.WithCancel(bg)
	r, err := s.start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	rep, err := r.finish(r.t.Tree(dir, []string{"."}))
	wantError(t, err, CodeInterrupted)
	if rep != nil {
		t.Error("got a report")
	}
}

// A context done during the scan, after the target's last check, still gives
// ErrInterrupted and no report (HSH-11/D41): the sink cancels it on the first
// finding, in a buffer, which the target never checks, and in a range's last
// commit.
func TestContextCancelledAtEnd(t *testing.T) {
	s := scanner(t, Config{Destination: Public(), GenericOnly: true})
	dir, git := gitRepo(t)
	write(t, dir, "a.md", "see "+lc.Bad+"\n")
	git("add", "-A")
	git("commit", "-q", "-m", "one")
	scans := map[string]func(r *run) error{
		"buffer": func(r *run) error { r.t.Buffer([]byte("see "+lc.Bad+"\n"), "<stdin>"); return nil },
		"range":  func(r *run) error { return r.t.RevList(dir, []string{"HEAD", "--"}) },
	}
	for name, scan := range scans {
		ctx, cancel := context.WithCancel(bg)
		r, err := s.start(ctx)
		if err != nil {
			t.Fatal(err)
		}
		r.t.Sink = func(f target.Finding) { r.add(f); cancel() }
		rep, err := r.finish(scan(r))
		wantError(t, err, CodeInterrupted)
		if rep != nil || len(r.findings) == 0 {
			t.Errorf("%s: got a report, or the sink saw no finding", name)
		}
		leak(t, rep, err)
	}
}

// ScanTree: the root, path arguments below it or absolute, the walk's order,
// .git pruned, symlinks as link text, the counts, and the path conditions.
func TestScanTree(t *testing.T) {
	s := scanner(t, Config{Destination: Public(), Terms: load(t, adrTerms())})
	dir := t.TempDir()
	write(t, dir, "docs/b.md", "see "+lc.Bad+"\n")
	write(t, dir, "docs/a.md", "clean\n"+lc.Quorvel+"\n")
	write(t, dir, ".git/config", lc.Bad+"\n")
	write(t, dir, "bin/x.bin", "a\x00b\n")
	if err := os.Symlink("../"+lc.Zantoph, filepath.Join(dir, "docs/link")); err != nil {
		t.Fatal(err)
	}
	rep, err := s.ScanTree(bg, dir)
	want := "bin/x.bin:0: binary-unscanned\ndocs/a.md:2: set:clients\ndocs/b.md:1: id-prefix\ndocs/link:1: set:people\n"
	if ExitCode(err) != 1 || plain(t, rep) != want || rep.Scanned() != (Counts{Files: 4, Lines: 4}) {
		t.Errorf("whole root: %v, %q, %+v", err, plain(t, rep), rep.Scanned())
	}
	rep, err = s.ScanTree(bg, dir, "docs/b.md", "./docs//a.md")
	if ExitCode(err) != 1 || plain(t, rep) != "docs/b.md:1: id-prefix\ndocs/a.md:2: set:clients\n" {
		t.Errorf("paths below root: %v, %q", err, plain(t, rep))
	}
	rep, err = s.ScanTree(bg, t.TempDir(), dir+"/docs/b.md")
	if ExitCode(err) != 1 || plain(t, rep) != dir+"/docs/b.md:1: id-prefix\n" {
		t.Errorf("absolute path: %v", err)
	}
	rep, err = s.ScanTree(bg, t.TempDir())
	if err != nil || !rep.Clean() || rep.Scanned() != (Counts{}) {
		t.Errorf("empty tree: %v", err)
	}

	rep, err = s.ScanTree(bg, dir, "docs", "nothing-here")
	wantError(t, err, CodePath)
	var e *Error
	if rep != nil || !errorsAs(err, &e) || e.Argument() != 2 || err.Error() != "path argument 2 does not exist" {
		t.Errorf("missing path: %v", err)
	}
	for _, root := range []string{filepath.Join(dir, "missing"), filepath.Join(dir, "docs/a.md")} {
		_, err = s.ScanTree(bg, root)
		wantError(t, err, CodePath)
	}

	// A path argument that holds the term file is refused.
	inside := filepath.Join(dir, "terms")
	if err := os.WriteFile(inside, []byte(adrTerms()), 0o600); err != nil {
		t.Fatal(err)
	}
	ts, err := LoadTermSets(inside)
	if err != nil {
		t.Fatal(err)
	}
	s2 := scanner(t, Config{Destination: Public(), Terms: ts})
	for _, args := range [][]string{nil, {"."}, {"terms"}} {
		rep, err := s2.ScanTree(bg, dir, args...)
		wantError(t, err, CodeTermFile)
		if rep != nil || err.Error() != "the term file is inside a scanned path" {
			t.Errorf("term file inside: %v", err)
		}
	}
	if _, err := s2.ScanTree(bg, dir, "docs"); ExitCode(err) != 1 {
		t.Errorf("a path beside the term file: %v", err)
	}
	leak(t, rep, err)
}

// ADR-001 negative test 2, in the API: a public destination fails on any
// private-set match, in a tree and in a range, even though the set declares a
// client; a client destination applies every set it is not declared in.
func TestNegative2PublicMatch(t *testing.T) {
	ts := load(t, adrTerms())
	dir, git := gitRepo(t)
	write(t, dir, "docs/a.md", "QuorVel\n")
	git("add", "-A")
	git("commit", "-q", "-m", "one\n\nline three\nline four\nmention QuorVel")
	head := git("rev-parse", "HEAD")
	for _, c := range []struct {
		dest       Destination
		tree, rnge string
	}{
		{Public(), "docs/a.md:1: set:clients\n", head[:12] + ":(commit):9: set:clients\n" + head[:12] + ":docs/a.md:1: set:clients\n"},
		{client(t, lc.LabelB), "docs/a.md:1: set:clients\n", head[:12] + ":(commit):9: set:clients\n" + head[:12] + ":docs/a.md:1: set:clients\n"},
		{client(t, lc.LabelA), "", ""},
	} {
		s := scanner(t, Config{Destination: c.dest, Terms: ts})
		rep, err := s.ScanTree(bg, dir)
		if ExitCode(err) != min(1, len(c.tree)) || rep == nil || plain(t, rep) != c.tree {
			t.Errorf("%v tree: %v", c.dest, err)
		}
		rep, err = s.ScanRange(bg, Repo{Dir: dir}, Range{Include: []string{"HEAD"}})
		if ExitCode(err) != min(1, len(c.rnge)) || rep == nil || plain(t, rep) != c.rnge {
			t.Errorf("%v range: %v, %q", c.dest, err, plain(t, rep))
		}
		leak(t, rep, err)
	}
}

// ScanRange: commits oldest first with their full ids and parts, redaction in
// a range (ADR-001 negative test 7's range case), the counts, and an empty
// range.
func TestScanRange(t *testing.T) {
	s := scanner(t, Config{Destination: Public(), Terms: load(t, adrTerms())})
	dir, git := gitRepo(t)
	write(t, dir, "a.md", "clean\n")
	git("add", "-A")
	git("commit", "-q", "-m", "first")
	first := git("rev-parse", "HEAD")
	write(t, dir, "docs/"+lc.Quorvel+"/plan.md", "clean\nsee "+lc.Bad+"\n")
	git("add", "-A")
	git("commit", "-q", "-m", "second "+lc.Zantoph)
	second := git("rev-parse", "HEAD")

	rep, err := s.ScanRange(bg, Repo{Dir: dir}, Range{Include: []string{first + "..HEAD"}})
	want := second[:12] + ":(commit):6: set:people\n" +
		second[:12] + ":docs/<redacted>:0: set:clients in path\n" +
		second[:12] + ":docs/<redacted>:2: id-prefix\n"
	if ExitCode(err) != 1 || plain(t, rep) != want || rep.Scanned() != (Counts{Files: 1, Commits: 1, Lines: 5}) {
		t.Errorf("got %v, %q, %+v", err, plain(t, rep), rep.Scanned())
	}
	fs := rep.Findings()
	if fs[0].Commit != second || fs[0].Part != Message || fs[0].Path != "" ||
		fs[1].Commit != second || fs[1].Part != 0 || fs[1].Path != "docs/<redacted>" || !fs[1].PathRedacted || !fs[1].InPath {
		t.Errorf("findings: %+v", fs)
	}

	rep, err = s.ScanRange(bg, Repo{Dir: dir}, Range{Include: []string{"HEAD"}, Exclude: []string{"HEAD"}})
	wantError(t, err, CodeEmptyRange)
	if rep != nil || err.Error() != "the range holds no commits" {
		t.Errorf("empty range: %v", err)
	}
	rep, err = s.ScanRange(bg, Repo{Dir: dir}, Range{Include: []string{"HEAD"}, ExcludeRefs: []RefSelector{AllRefs}, AllowEmpty: true})
	if err != nil || !rep.Clean() || rep.Scanned().Commits != 0 {
		t.Errorf("allowed empty range: %v", err)
	}
	rep, err = s.ScanRange(bg, Repo{Dir: dir}, Range{IncludeRefs: []RefSelector{Branches}, Exclude: []string{second}})
	wantError(t, err, CodeEmptyRange)

	_, err = s.ScanRange(bg, Repo{Dir: dir}, Range{Include: []string{"no-such-branch"}})
	wantError(t, err, CodeRange)
	_, err = s.ScanRange(bg, Repo{Dir: t.TempDir()}, Range{Include: []string{"HEAD"}})
	wantError(t, err, CodeGit)
	for i, rg := range []Range{
		{},
		{Include: []string{"--max-count=1"}},
		{Include: []string{"HEAD", "-n1"}},
		{Include: []string{"HEAD"}, Exclude: []string{"^HEAD~1"}},
		{Include: []string{"HEAD...HEAD~1"}},
		{Include: []string{"HEAD -- a.md"}},
		{Include: []string{"A\u00a0B"}},
		{IncludeRefs: []RefSelector{0}},
		{Include: []string{"HEAD"}, ExcludeRefs: []RefSelector{9}},
	} {
		rep, err := s.ScanRange(bg, Repo{Dir: dir}, rg)
		wantError(t, err, CodeRange)
		if rep != nil {
			t.Errorf("case %d: got a report", i)
		}
	}
	leak(t, rep, err)
}

// A range word that names a file, or is a pathspec, is a bad revision and
// never narrows the walk (HSH-11/D36): rev-list gets "--" after the
// revisions.
func TestRangePathspecRefused(t *testing.T) {
	s := scanner(t, Config{Destination: Public(), GenericOnly: true})
	dir, git := gitRepo(t)
	write(t, dir, "leak.txt", "see "+lc.Bad+"\n")
	git("add", "-A")
	git("commit", "-q", "-m", "first")
	write(t, dir, "a.md", "clean\n")
	git("add", "-A")
	git("commit", "-q", "-m", "second")
	rep, err := s.ScanRange(bg, Repo{Dir: dir}, Range{Include: []string{"HEAD"}})
	if ExitCode(err) != 1 || !strings.HasSuffix(plain(t, rep), ":leak.txt:1: id-prefix\n") {
		t.Errorf("HEAD: %v", err)
	}
	for _, text := range []string{"HEAD a.md", "HEAD *.md", "HEAD :(exclude)leak.txt", "HEAD :!leak.txt"} {
		rg, err := ParseRange(text)
		if err != nil {
			t.Fatalf("ParseRange(%q): %v", text, err)
		}
		rep, err := s.ScanRange(bg, Repo{Dir: dir}, rg)
		wantError(t, err, CodeRange)
		if rep != nil || err == nil || err.Error() != "range: the revisions do not resolve" {
			t.Errorf("%q: got %v", text, err)
		}
	}
	leak(t, rep, err)
}

// A revision with the suffix "^!", "^@" or "^-" is refused, from the text
// and in a Range built by hand: each slips a subtraction into what reads as
// one revision, and "HEAD^!", "HEAD^-" and "HEAD^-1" walk only HEAD's own
// commit, missing an ID its parent added (HSH-11/D36, review round 2).
func TestRangeSuffixRefused(t *testing.T) {
	s := scanner(t, Config{Destination: Public(), GenericOnly: true})
	dir, git := gitRepo(t)
	write(t, dir, "leak.txt", "see "+lc.Bad+"\n")
	git("add", "-A")
	git("commit", "-q", "-m", "first")
	write(t, dir, "a.md", "clean\n")
	git("add", "-A")
	git("commit", "-q", "-m", "second")
	rep, err := s.ScanRange(bg, Repo{Dir: dir}, Range{Include: []string{"HEAD"}})
	if ExitCode(err) != 1 || !strings.HasSuffix(plain(t, rep), ":leak.txt:1: id-prefix\n") {
		t.Errorf("HEAD: %v", err)
	}
	for _, text := range []string{"HEAD^!", "HEAD^@", "HEAD^-", "HEAD^-1", "HEAD --not HEAD^!", "HEAD ^HEAD^@"} {
		if rg, err := ParseRange(text); err == nil {
			t.Errorf("ParseRange(%q) = %+v", text, rg)
		}
	}
	for i, rg := range []Range{
		{Include: []string{"HEAD^-"}},
		{Include: []string{"HEAD^-1"}},
		{Include: []string{"HEAD^!"}},
		{Include: []string{"HEAD^@"}},
		{Include: []string{"HEAD~1..HEAD^-"}},
		{Include: []string{"HEAD"}, Exclude: []string{"HEAD^!"}},
		{Include: []string{"HEAD"}, Exclude: []string{"HEAD^-"}},
	} {
		rg.AllowEmpty = true
		rep, err := s.ScanRange(bg, Repo{Dir: dir}, rg)
		wantError(t, err, CodeRange)
		if rep != nil || err == nil || !strings.HasSuffix(err.Error(), " is refused") {
			t.Errorf("case %d: got %v", i, err)
		}
	}
	leak(t, rep, err)
}

// ScanIndex reads staged blobs, never the work tree; a named index file must
// be a regular file.
func TestScanIndex(t *testing.T) {
	s := scanner(t, Config{Destination: Public(), Terms: load(t, adrTerms())})
	dir, git := gitRepo(t)
	write(t, dir, "docs/a.md", "clean\n"+lc.Quorvel+"\n")
	write(t, dir, lc.Zantoph+"/b.md", "clean\n")
	git("add", "-A")
	write(t, dir, "docs/a.md", "clean\n") // the work tree no longer holds the term
	rep, err := s.ScanIndex(bg, Repo{Dir: dir})
	want := "docs/a.md:2: set:clients\n<redacted>:0: set:people in path\n"
	if ExitCode(err) != 1 || plain(t, rep) != want || rep.Scanned() != (Counts{Files: 2, Lines: 3}) {
		t.Errorf("got %v, %q, %+v", err, plain(t, rep), rep.Scanned())
	}
	index := filepath.Join(dir, ".git", "index")
	other := filepath.Join(t.TempDir(), "index")
	data, err := os.ReadFile(index)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other, data, 0o600); err != nil {
		t.Fatal(err)
	}
	git("update-index", "--force-remove", "docs/a.md") // only the copy still holds it
	rep, err = s.ScanIndex(bg, Repo{Dir: dir, IndexFile: other})
	if ExitCode(err) != 1 || plain(t, rep) != want {
		t.Errorf("named index: %v, %q", err, plain(t, rep))
	}
	for _, f := range []string{filepath.Join(dir, "missing-index"), dir} {
		rep, err = s.ScanIndex(bg, Repo{Dir: dir, IndexFile: f})
		wantError(t, err, CodeGit)
		if rep != nil || err.Error() != "the index file is missing or not a regular file" {
			t.Errorf("index file %v", err)
		}
	}
	_, err = s.ScanIndex(bg, Repo{Dir: t.TempDir()})
	wantError(t, err, CodeGit)
	leak(t, rep, err)
}

// The API's git commands inherit no GIT_ variable (HSH-11/D31): GIT_DIR at a
// clean repository and GIT_INDEX_FILE at an empty index, as a git hook sets
// them, change neither the repository nor the index scanned.
func TestScanIgnoresGitEnvironment(t *testing.T) {
	s := scanner(t, Config{Destination: Public(), GenericOnly: true})
	clean, cleanGit := gitRepo(t)
	write(t, clean, "a.md", "clean\n")
	cleanGit("add", "-A")
	cleanGit("commit", "-q", "-m", "clean")
	dirty, dirtyGit := gitRepo(t)
	write(t, dirty, "leak.txt", "see "+lc.Bad+"\n")
	dirtyGit("add", "-A")
	dirtyGit("commit", "-q", "-m", "dirty")
	empty := filepath.Join(t.TempDir(), "index")
	c := exec.Command("git", "-C", clean, "read-tree", "--empty")
	c.Env = append(os.Environ(), "GIT_INDEX_FILE="+empty)
	if c.Run() != nil {
		t.Fatal("cannot write an empty index")
	}
	scans := map[string]func() (*Report, error){
		"range": func() (*Report, error) { return s.ScanRange(bg, Repo{Dir: dirty}, Range{Include: []string{"HEAD"}}) },
		"index": func() (*Report, error) { return s.ScanIndex(bg, Repo{Dir: dirty}) },
	}
	for name, env := range map[string]map[string]string{
		"GIT_DIR":        {"GIT_DIR": filepath.Join(clean, ".git")},
		"GIT_WORK_TREE":  {"GIT_DIR": filepath.Join(clean, ".git"), "GIT_WORK_TREE": clean},
		"GIT_INDEX_FILE": {"GIT_INDEX_FILE": empty},
	} {
		t.Run(name, func(t *testing.T) {
			for k, v := range env {
				t.Setenv(k, v)
			}
			for target, scan := range scans {
				rep, err := scan()
				if ExitCode(err) != 1 || !strings.HasSuffix(plain(t, rep), "leak.txt:1: id-prefix\n") {
					t.Errorf("%s: got %v", target, err)
				}
				leak(t, rep, err)
			}
		})
	}
}

// ParseRange: ADR-001 section 5's accepted syntax, and the refusals that keep
// rev-list options out (negative test 11's second point, in the API).
func TestParseRange(t *testing.T) {
	good := map[string]Range{
		"HEAD":                        {Include: []string{"HEAD"}},
		"main..HEAD":                  {Include: []string{"main..HEAD"}},
		" a\tb\nc ":                   {Include: []string{"a", "b", "c"}},
		"HEAD ^v0.1 ^HEAD~3":          {Include: []string{"HEAD"}, Exclude: []string{"v0.1", "HEAD~3"}},
		"--all":                       {IncludeRefs: []RefSelector{AllRefs}},
		"HEAD --not --remotes":        {Include: []string{"HEAD"}, ExcludeRefs: []RefSelector{Remotes}},
		"--branches --tags --not a b": {IncludeRefs: []RefSelector{Branches, Tags}, Exclude: []string{"a", "b"}},
		"0123abc --not 4567def":       {Include: []string{"0123abc"}, Exclude: []string{"4567def"}},
	}
	for text, want := range good {
		got, err := ParseRange(text)
		if err != nil || !slices.Equal(got.Include, want.Include) || !slices.Equal(got.Exclude, want.Exclude) ||
			!slices.Equal(got.IncludeRefs, want.IncludeRefs) || !slices.Equal(got.ExcludeRefs, want.ExcludeRefs) || got.AllowEmpty {
			t.Errorf("ParseRange(%q) = %+v, %v", text, got, err)
		}
		if _, err := got.revListArgs(); err != nil {
			t.Errorf("%q: revListArgs: %v", text, err)
		}
	}
	bad := map[string]string{
		"":                            "range: nothing to include",
		"--not HEAD":                  "range: nothing to include",
		"^HEAD":                       "range: nothing to include",
		"HEAD --max-count=1":          "range: word 2 is refused",
		"HEAD -n 1":                   "range: word 2 is refused",
		"HEAD --since=2020":           "range: word 2 is refused",
		"HEAD -- a.md":                "range: word 2 is refused",
		"--stdin":                     "range: word 1 is refused",
		"HEAD --not --not x":          "range: word 3 is refused",
		"HEAD --not ^x":               "range: word 3 is refused",
		"HEAD --not a..b":             "range: word 3 is refused",
		"a...b":                       "range: word 1 is refused",
		"a..":                         "range: word 1 is refused",
		"..b":                         "range: word 1 is refused",
		"a..b..c":                     "range: word 1 is refused",
		"^^a":                         "range: word 1 is refused",
		"^-a":                         "range: word 1 is refused",
		"a\x00b":                      "range: word 1 is refused",
		"A\u00a0B":                    "range: word 1 is refused", // any whitespace, not only ASCII
		"HEAD --not A\u2003B":         "range: word 3 is refused",
		"HEAD " + lc.Quorvel + "\x00": "range: word 2 is refused",
		"HEAD^!":                      "range: word 1 is refused",
		"HEAD^@":                      "range: word 1 is refused",
		"HEAD^-":                      "range: word 1 is refused",
		"HEAD^-1":                     "range: word 1 is refused",
		"HEAD~2^-2":                   "range: word 1 is refused",
		"^HEAD^!":                     "range: word 1 is refused",
		"HEAD ^HEAD^@":                "range: word 2 is refused",
		"HEAD --not HEAD^-":           "range: word 3 is refused",
		"a..HEAD^!":                   "range: word 1 is refused",
	}
	for text, msg := range bad {
		_, err := ParseRange(text)
		wantError(t, err, CodeRange)
		if err == nil || err.Error() != msg {
			t.Errorf("ParseRange(%q): got %v, want %q", text, err, msg)
		}
	}
}

// The counts follow HSH-11/D18 for a range: each commit walked, each path a
// commit adds or changes, and every line scanned, object lines included.
func TestRangeCounts(t *testing.T) {
	s := scanner(t, Config{Destination: Public(), GenericOnly: true})
	dir, git := gitRepo(t)
	write(t, dir, "a.md", "one\ntwo\n")
	write(t, dir, "b.md", "three\n")
	git("add", "-A")
	git("commit", "-q", "-m", "first")
	git("rm", "-q", "b.md")
	write(t, dir, "a.md", "one\ntwo\nfour\n")
	git("add", "-A")
	git("commit", "-q", "-m", "second\n\nbody")
	rep, err := s.ScanRange(bg, Repo{Dir: dir}, Range{IncludeRefs: []RefSelector{AllRefs}})
	// Objects: author, committer and one or three message lines; diffs: three
	// added lines in the first commit and one in the second.
	if err != nil || rep.Scanned() != (Counts{Files: 3, Commits: 2, Lines: 3 + 5 + 3 + 1}) {
		t.Errorf("got %v, %+v", err, rep.Scanned())
	}
}

// A Scanner is safe for concurrent use: scans share it and get the same
// reports. Run with -race to check for data races.
func TestScannerConcurrent(t *testing.T) {
	s := scanner(t, Config{Destination: client(t, lc.LabelB), Terms: load(t, adrTerms())})
	dir := t.TempDir()
	write(t, dir, "docs/"+lc.Quorvel+"/a.md", lc.Zantoph+"\n"+lc.Bad+"\n")
	want := "docs/<redacted>:0: set:clients in path\ndocs/<redacted>:2: id-prefix\n"
	errs := make(chan string, 16)
	for range 16 {
		go func() {
			rep, err := s.ScanTree(bg, dir)
			if ExitCode(err) != 1 || rep == nil {
				errs <- "a scan failed"
				return
			}
			var b strings.Builder
			rep.WritePlain(&b)
			if b.String() != want {
				errs <- "a scan gave other findings"
				return
			}
			errs <- ""
		}()
	}
	for range 16 {
		if e := <-errs; e != "" {
			t.Error(e)
		}
	}
}
