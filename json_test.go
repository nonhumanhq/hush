package hush

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	lc "github.com/nonhumanhq/hush/internal/leakcheck"
	"github.com/nonhumanhq/hush/internal/schema"
)

// jsonOf returns rep.WriteJSON's output, which must pass the closed schema.
func jsonOf(t *testing.T, rep *Report) string {
	t.Helper()
	var b countingWriter
	if err := rep.WriteJSON(&b); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if b.writes != 1 {
		t.Errorf("WriteJSON wrote %d times, want once", b.writes)
	}
	if err := schema.CheckLine(b.b.String()); err != nil {
		t.Errorf("%v: %s", err, b.b.String())
	}
	leak(t, b.b.String())
	return b.b.String()
}

// ADR-001 section 6.3: the document for each result and target, one line in
// the schema's key order, without HTML escaping, the destination's class and
// never a client label.
func TestWriteJSON(t *testing.T) {
	v := Version()
	dir := t.TempDir()
	write(t, dir, "docs/"+lc.Quorvel+"/plan.md", "clean\nsee "+lc.Bad+"\n")
	write(t, dir, "a.md", "clean\n")
	s := scanner(t, Config{Destination: Public(), Terms: load(t, adrTerms())})
	_, err := s.ScanTree(bg, dir)
	var fe *FindingsError
	if !errors.As(err, &fe) {
		t.Fatalf("got %v", err)
	}
	want := `{"schema":"hush.scan/1","hush":"` + v + `","result":"findings","exit":1,"destination":"public",` +
		`"coverage":"complete","tiers":["generic","private"],"sets":["clients","people"],"target":"tree",` +
		`"scanned":{"files":2,"commits":0,"lines":3},"findings":[` +
		`{"kind":"match","tier":"private","rule":"set:clients","in_path":true,"path":"docs/<redacted>","path_redacted":true,"line":0,"where":"docs/<redacted>"},` +
		`{"kind":"match","tier":"generic","rule":"id-prefix","path":"docs/<redacted>","path_redacted":true,"line":2,"where":"docs/<redacted>"}]}` + "\n"
	if got := jsonOf(t, fe.Report()); got != want {
		t.Errorf("tree with findings:\n got %s\nwant %s", got, want)
	}

	// Clean, generic-only, from standard input: no sets, an empty list.
	g := scanner(t, Config{Destination: Public(), GenericOnly: true})
	rep, err := g.ScanBytes(bg, "issue-body", []byte("one\ntwo\nthree\nfour\n"))
	if err != nil {
		t.Fatal(err)
	}
	want = `{"schema":"hush.scan/1","hush":"` + v + `","result":"clean","exit":0,"destination":"public",` +
		`"coverage":"generic-only","tiers":["generic"],"target":"stdin","scanned":{"files":0,"commits":0,"lines":4},"findings":[]}` + "\n"
	if got := jsonOf(t, rep); got != want {
		t.Errorf("clean stdin:\n got %s\nwant %s", got, want)
	}
	// Empty input: "lines": 0 (ADR-001 section 5).
	rep, err = g.ScanBytes(bg, "", nil)
	if err != nil || !strings.Contains(jsonOf(t, rep), `"scanned":{"files":0,"commits":0,"lines":0},"findings":[]}`) {
		t.Errorf("empty input: %v", err)
	}
	// A finding in a buffer carries its label; a binary one is unscanned
	// and has no tier.
	_, err = g.ScanBytes(bg, "", []byte("a\x00b"))
	if !errors.As(err, &fe) || !strings.Contains(jsonOf(t, fe.Report()),
		`"findings":[{"kind":"unscanned","rule":"binary-unscanned","label":"<stdin>","line":0,"where":"<stdin>"}]}`) {
		t.Errorf("binary stdin: %v", err)
	}

	// A client destination prints its class only; the private destination
	// runs the generic tier alone.
	k8 := scanner(t, Config{Destination: client(t, lc.LabelB), Terms: load(t, adrTerms())})
	rep, err = k8.ScanBytes(bg, "", []byte("clean\n"))
	if err != nil || !strings.Contains(jsonOf(t, rep), `"destination":"client","coverage":"complete","tiers":["generic","private"],"sets":["clients"],`) {
		t.Errorf("client: %v", err)
	}
	p := scanner(t, Config{Destination: Private()})
	rep, err = p.ScanBytes(bg, "", []byte("clean\n"))
	if err != nil || !strings.Contains(jsonOf(t, rep), `"destination":"private","coverage":"complete","tiers":["generic"],"target":"stdin",`) {
		t.Errorf("private: %v", err)
	}

	// A range: the commit's full id, its part, and paths in changed files.
	repo, git := gitRepo(t)
	write(t, repo, "a.md", "see "+lc.Bad+"\n")
	git("add", "a.md")
	git("commit", "-q", "-m", "add a")
	id := git("rev-parse", "HEAD")
	_, err = g.ScanRange(bg, Repo{Dir: repo}, Range{Include: []string{"HEAD"}})
	if !errors.As(err, &fe) {
		t.Fatalf("range: %v", err)
	}
	if got := jsonOf(t, fe.Report()); !strings.Contains(got, `"target":"range","scanned":{"files":1,"commits":1,"lines":`+
		`4},"findings":[{"kind":"match","tier":"generic","rule":"id-prefix","commit":"`+id+`","path":"a.md","path_redacted":false,"line":1,"where":"`+id[:12]+`:a.md"}]}`) {
		t.Errorf("range: %s", got)
	}
	_, err = g.ScanIndex(bg, Repo{Dir: repo})
	if !errors.As(err, &fe) || !strings.Contains(jsonOf(t, fe.Report()), `"target":"index",`) {
		t.Errorf("index: %v", err)
	}

	// A report no scan made is refused, and nothing is written.
	for _, r := range []*Report{nil, {}} {
		var b strings.Builder
		err := r.WriteJSON(&b)
		wantError(t, err, CodeUsage)
		if b.Len() != 0 {
			t.Error("a report no scan made wrote a document")
		}
	}
	// A failing writer is ErrOutput.
	err = rep.WriteJSON(failingWriter{})
	wantError(t, err, CodeOutput)
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed: " + lc.Quorvel) }

// ADR-001 sections 6.3 and 7: WriteErrorJSON writes an *Error's code,
// message, argument, term-file line and commit, and anything else as the
// internal error, never formatted.
func TestWriteErrorJSON(t *testing.T) {
	v := Version()
	id := strings.Repeat("4d7f0a2c9e1b", 3) + "abcd"
	k7 := client(t, lc.LabelA)
	for i, c := range []struct {
		d    Destination
		cov  Coverage
		tgt  Target
		err  error
		want string
	}{
		{Public(), Complete, TargetTree, newError(CodeCoverage, msgPublicCoverage, 0),
			`"destination":"public","coverage":"complete","tiers":[],"target":"tree","error":{"code":"coverage","message":"the public destination needs --terms FILE or --generic-only"}}`},
		{Public(), Complete, TargetTree, &Error{code: CodeTermFile, msg: "term file: line 7: bad set name", line: 7},
			`"error":{"code":"term-file","message":"term file: line 7: bad set name","line":7}}`},
		{k7, Complete, TargetStdin, newError(CodeLabel, msgLabelRefused, 0).WithArgument(4),
			`"destination":"client","coverage":"complete","tiers":[],"target":"stdin","error":{"code":"label","message":"argument 4: stdin label refused","argument":4}}`},
		{Public(), GenericOnly, TargetRange, commitError(CodeGit, msgDiffFailed, id),
			`"coverage":"generic-only","tiers":[],"target":"range","error":{"code":"git","message":"cannot diff commit 4d7f0a2c9e1b","commit":"` + id + `"}}`},
		{Private(), Complete, TargetIndex, ErrInterrupted,
			`"destination":"private","coverage":"complete","tiers":[],"target":"index","error":{"code":"interrupted","message":"interrupted"}}`},
		// Not an *Error: the internal error, whatever the text.
		{Public(), Complete, TargetTree, errors.New("cannot open " + lc.Quorvel), `"error":{"code":"internal","message":"internal error; output withheld"}}`},
		{Public(), Complete, TargetTree, fmt.Errorf("wrapped: %w", ErrUsage), `"error":{"code":"internal","message":"internal error; output withheld"}}`},
		{Public(), Complete, TargetTree, nil, `"error":{"code":"internal","message":"internal error; output withheld"}}`},
		{Public(), Complete, TargetTree, &FindingsError{}, `"error":{"code":"internal","message":"internal error; output withheld"}}`},
		{Public(), Complete, TargetTree, (*Error)(nil), `"error":{"code":"internal","message":"internal error; output withheld"}}`},
	} {
		var b countingWriter
		if err := WriteErrorJSON(&b, c.d, c.cov, c.tgt, c.err); err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		got := b.b.String()
		if !strings.HasPrefix(got, `{"schema":"hush.scan/1","hush":"`+v+`","result":"error","exit":2,`) ||
			!strings.HasSuffix(got, c.want+"\n") || b.writes != 1 {
			t.Errorf("case %d: %s", i, got)
		}
		if err := schema.CheckLine(got); err != nil {
			t.Errorf("case %d: %v", i, err)
		}
		leak(t, got)
	}
	// Nothing is written for a zero destination, coverage or target.
	for i, c := range []struct {
		d    Destination
		cov  Coverage
		tgt  Target
		code Code
	}{
		{Destination{}, Complete, TargetTree, CodeDestination},
		{Public(), 0, TargetTree, CodeUsage},
		{Public(), Complete, 0, CodeUsage},
		{Public(), Complete, Target(9), CodeUsage},
	} {
		var b strings.Builder
		err := WriteErrorJSON(&b, c.d, c.cov, c.tgt, ErrUsage)
		wantError(t, err, c.code)
		if b.Len() != 0 {
			t.Errorf("case %d wrote a document", i)
		}
	}
	wantError(t, WriteErrorJSON(failingWriter{}, Public(), Complete, TargetTree, ErrUsage), CodeOutput)
	wantError(t, WriteErrorJSON(nil, Public(), Complete, TargetTree, ErrUsage), CodeUsage)
}

// Error.WithArgument adds a position, never a value, and leaves the original
// and a nil error alone.
func TestWithArgument(t *testing.T) {
	e := newError(CodeDestination, msgUnknownDest, 0)
	w := e.WithArgument(2)
	if w.Error() != "argument 2: unknown destination" || w.Argument() != 2 || w.Code() != CodeDestination ||
		e.Error() != "unknown destination" || e.Argument() != 0 || !errors.Is(w, ErrDestination) {
		t.Errorf("got %q %d, original %q %d", w.Error(), w.Argument(), e.Error(), e.Argument())
	}
	if e.WithArgument(0) != e || (*Error)(nil).WithArgument(3) != nil {
		t.Error("WithArgument changed an error it should leave alone")
	}
	wantError(t, w, CodeDestination)
}

// HSH-11/D4 and ADR-001 section 5: a tree file over MaxInputSize or a line
// over MaxLineSize stops the scan with ErrRead; nothing is skipped.
func TestTreeSizeLimits(t *testing.T) {
	g := scanner(t, Config{Destination: Public(), GenericOnly: true})
	dir := t.TempDir()
	line := strings.Repeat("a", MaxLineSize)
	write(t, dir, "ok.md", line+"\n")
	if _, err := g.ScanTree(bg, dir); err != nil {
		t.Errorf("a line at the limit: %v", err)
	}
	write(t, dir, "long.md", line+"a\n")
	rep, err := g.ScanTree(bg, dir)
	wantError(t, err, CodeRead)
	if rep != nil || err.Error() != "input over the size limit" {
		t.Errorf("a line over the limit: %v", err)
	}
	_, err = g.ScanBytes(bg, "", []byte(line+"a"))
	wantError(t, err, CodeRead)

	dir = t.TempDir()
	f, err := os.Create(filepath.Join(dir, "big.md"))
	if err == nil {
		err = f.Truncate(MaxInputSize + 1) // sparse: no disk is used
	}
	if err != nil || f.Close() != nil {
		t.Fatal("cannot make a large file")
	}
	_, err = g.ScanTree(bg, dir)
	wantError(t, err, CodeRead)
}
