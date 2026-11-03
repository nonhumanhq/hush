package hush

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	lc "github.com/nonhumanhq/hush/internal/leakcheck"
	"github.com/nonhumanhq/hush/internal/rule"
	"github.com/nonhumanhq/hush/internal/target"
)

// ADR-001 section 6.2: Where and String give the plain format's location and
// line for every kind of place, ADR-001's own examples among them.
func TestFindingWhereAndString(t *testing.T) {
	id := "9c1e5b7a2f04d3b6a8e1c0f9d2b7a4e6c3f1a0b9"
	cases := []struct {
		f    Finding
		want string
	}{
		{Finding{Rule: "id-prefix", Path: "docs/a.md", Line: 3}, "docs/a.md:3: id-prefix"},
		{Finding{Rule: "set:clients", Path: "docs/<redacted>", PathRedacted: true, InPath: true}, "docs/<redacted>:0: set:clients in path"},
		{Finding{Rule: "binary-unscanned", Path: "assets/logo.bin"}, "assets/logo.bin:0: binary-unscanned"},
		{Finding{Rule: "id-prefix", Commit: id, Path: "docs/a.md", Line: 2}, "9c1e5b7a2f04:docs/a.md:2: id-prefix"},
		{Finding{Rule: "set:people", Commit: id, Part: Author, Line: 3}, "9c1e5b7a2f04:(commit):3: set:people"},
		{Finding{Rule: "set:clients", Tag: id, Part: Message, Line: 4}, "9c1e5b7a2f04:(tag):4: set:clients"},
		{Finding{Rule: "id-prefix", Label: "issue-body", Line: 1}, "issue-body:1: id-prefix"},
	}
	for _, c := range cases {
		if got := c.f.String(); got != c.want {
			t.Errorf("got %q, want %q", got, c.want)
		}
		if !strings.HasPrefix(c.want, c.f.Where()+":") {
			t.Errorf("Where() = %q", c.f.Where())
		}
	}
}

// The one constructor runs ADR-001 section 5's output check: a finding's rule
// is in the registry, a loaded set, or one of the two unscanned names; its
// place is one a target reports. Anything else stops the scan with the fixed
// internal error.
func TestOutputCheck(t *testing.T) {
	s := scanner(t, Config{Destination: Public(), Terms: load(t, adrTerms())})
	id := strings.Repeat("ab", 20)
	good := []target.Finding{
		{Loc: target.InTree, Path: "a", Rule: "id-prefix"},
		{Loc: target.InTree, Path: "a", Rule: "email-address", InPath: true},
		{Loc: target.InIndex, Path: "a", Rule: "set:people"},
		{Loc: target.InStdin, Label: "<stdin>", Rule: "binary-unscanned"},
		{Loc: target.InDiff, Commit: id, Path: "a", Rule: "unreadable"},
		{Loc: target.InCommit, Commit: id, Part: rule.Message, Rule: "ip-address", Line: 5},
	}
	for i, raw := range good {
		if _, ok := s.finding(raw); !ok {
			t.Errorf("good case %d refused", i)
		}
	}
	bad := []target.Finding{
		{Loc: target.InTree, Path: "a", Rule: "no-such-rule"},
		{Loc: target.InTree, Path: "a", Rule: "set:nosuchset"},
		{Loc: target.InTree, Path: "a", Rule: "set:"},
		{Loc: target.InTree, Path: "a", Rule: ""},
		{Loc: target.InTree, Path: "a", Rule: "unreadable", InPath: true},
		{Loc: target.InTree, Path: "", Rule: "id-prefix"},
		{Loc: target.InCommit, Commit: id, Rule: "id-prefix"}, // no part
		{Loc: 0, Path: "a", Rule: "id-prefix"},
	}
	for i, raw := range bad {
		if _, ok := s.finding(raw); ok {
			t.Errorf("bad case %d accepted", i)
		}
	}
	generic := scanner(t, Config{Destination: Public(), GenericOnly: true})
	if _, ok := generic.finding(target.Finding{Loc: target.InTree, Path: "a", Rule: "set:people"}); ok {
		t.Error("a set finding passed a scan without sets")
	}

	// A refused finding stops the scan with the internal error.
	r, err := s.start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r.add(bad[0])
	rep, err := r.finish(nil)
	wantError(t, err, CodeInternal)
	if rep != nil || err.Error() != "internal error; output withheld" {
		t.Errorf("got %v", err)
	}
}

// ADR-001 section 6.4 and negative test 7, in the API: a path component that
// holds a term is redacted from the component where the earliest match
// begins, a term that spans "/" from where it starts, and exempt sets still
// redact.
func TestNegative7Redaction(t *testing.T) {
	ctx := context.Background()
	terms := adrTerms()
	spanning := strings.Replace(terms, lc.Quorvel+"\n", lc.Quorvel+"\nquor/vel\n", 1)
	spanningToo := strings.Replace(spanning, "quor/vel\n", "quor/vel\nvel\n", 1)
	cases := []struct {
		name, terms, file string
		dest              Destination
		want              string
		redacted          bool
	}{
		{"basic", terms, "docs/" + lc.Quorvel + "/plan.md", Public(),
			"docs/<redacted>:0: set:clients in path\ndocs/<redacted>:2: id-prefix\n", true},
		{"first component", terms, lc.Quorvel + "/plan.md", Public(),
			"<redacted>:0: set:clients in path\n<redacted>:2: id-prefix\n", true},
		{"spans a slash", spanning, "docs/quor/vel/plan.md", Public(),
			"docs/<redacted>:0: set:clients in path\ndocs/<redacted>:2: id-prefix\n", true},
		{"spans a slash, second term", spanningToo, "docs/quor/vel/plan.md", Public(),
			"docs/<redacted>:0: set:clients in path\ndocs/<redacted>:2: id-prefix\n", true},
		{"exempt sets still redact", terms, "docs/" + lc.Quorvel + "/plan.md", client(t, lc.LabelA),
			"docs/<redacted>:2: id-prefix\n", true},
		{"a rule redacts", terms, "docs/" + lc.Bad + "/plan.md", Public(),
			"docs/<redacted>:0: id-prefix in path\ndocs/<redacted>:2: id-prefix\n", true},
		{"nothing to redact", terms, "docs/plan.md", Public(), "docs/plan.md:2: id-prefix\n", false},
	}
	for _, c := range cases {
		dir := t.TempDir()
		write(t, dir, c.file, "clean\nsee "+lc.Bad+"\n")
		s := scanner(t, Config{Destination: c.dest, Terms: load(t, c.terms)})
		rep, err := s.ScanTree(ctx, dir)
		if ExitCode(err) != 1 || plain(t, rep) != c.want {
			t.Errorf("%s: got %v and %q", c.name, err, plain(t, rep))
			continue
		}
		for _, f := range rep.Findings() {
			if f.PathRedacted != c.redacted || f.Kind != Match {
				t.Errorf("%s: %+v", c.name, f)
			}
		}
		leak(t, rep, rep.Findings(), err)
	}
}

// ADR-001 section 6.4: a component that cannot print safely is redacted from
// where it starts, whether or not a rule matches there.
func TestRedactUnsafe(t *testing.T) {
	s := scanner(t, Config{Destination: Public(), GenericOnly: true})
	cases := map[string]string{
		"docs/a.md":                              "docs/a.md",
		"docs/a\nb/c.md":                         "docs/<redacted>",
		"docs/a\tb.md":                           "docs/<redacted>",
		"x\x1b[31m/c.md":                         "<redacted>",
		"docs/\xff.md":                           "docs/<redacted>",
		"docs/a‮b/c":                             "docs/<redacted>",
		"docs/a​b/c":                             "docs/<redacted>",
		"docs/a b":                               "docs/<redacted>",
		"docs/a\u0085b":                          "docs/<redacted>",
		"docs/été/�.md":                          "docs/été/�.md",
		"docs/ok/" + lc.Bad + "/\x01/f":          "docs/ok/<redacted>",
		"docs/\x01/" + lc.Bad + "/f":             "docs/<redacted>",
		"docs/a‍b/c":                             "docs/<redacted>", // the joiner is a format character too
		"docs/؀x/c":                              "docs/<redacted>",
		"docs/plain/" + strings.Repeat("x", 300): "docs/plain/" + strings.Repeat("x", 300),
	}
	for in, want := range cases {
		got, redacted := s.redact(in)
		if got != want || redacted != (got != in) {
			t.Errorf("redact(%q) = %q, %v", in, got, redacted)
		}
	}
}

// WritePlain writes every finding in one write, and a failed or short write is
// ErrOutput.
func TestWritePlain(t *testing.T) {
	s := scanner(t, Config{Destination: Public(), GenericOnly: true})
	rep, err := s.ScanBytes(context.Background(), "body", []byte(lc.Bad+"\nclean\n"+lc.Bad+"\n"))
	if ExitCode(err) != 1 {
		t.Fatal(err)
	}
	w := &countingWriter{}
	if err := rep.WritePlain(w); err != nil || w.writes != 1 || w.b.String() != "body:1: id-prefix\nbody:3: id-prefix\n" {
		t.Errorf("got %v, %d writes, %q", err, w.writes, w.b.String())
	}
	for _, fw := range []*countingWriter{{fail: true}, {short: true}} {
		wantError(t, rep.WritePlain(fw), CodeOutput)
	}
	wantError(t, rep.WritePlain(nil), CodeUsage)
	clean, err := s.ScanBytes(context.Background(), "body", []byte("clean\n"))
	w = &countingWriter{}
	if err != nil || clean.WritePlain(w) != nil || w.writes != 0 {
		t.Error("a clean report wrote something")
	}
	leak(t, rep, w.b.String())
}

type countingWriter struct {
	b           strings.Builder
	writes      int
	fail, short bool
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.writes++
	switch {
	case w.fail:
		return 0, errors.New("disk full, " + lc.Quorvel)
	case w.short:
		return len(p) / 2, nil
	}
	return w.b.Write(p)
}

// ADR-001 section 6.6: a Report prints a fixed summary with the destination's
// class, never its label, and cannot be encoded as a value; its findings hold
// only redacted paths.
func TestReportGuards(t *testing.T) {
	ts := load(t, adrTerms())
	dir := t.TempDir()
	write(t, dir, lc.Quorvel+"/a.md", lc.Zantoph+"\n")
	s := scanner(t, Config{Destination: client(t, lc.LabelA), Terms: ts})
	rep, err := s.ScanTree(context.Background(), dir)
	if ExitCode(err) != 1 {
		t.Fatal(err)
	}
	var log strings.Builder
	slog.New(slog.NewTextHandler(&log, nil)).Info("scan", "report", rep, "error", err)
	got := fmt.Sprintf("%v|%+v|%#v|%s", rep, *rep, rep, []*Report{rep})
	if !strings.Contains(got, "hush.Report(client, 1 findings)") {
		t.Errorf("summary: %q", got)
	}
	if _, jerr := json.Marshal(rep); jerr == nil {
		t.Error("json.Marshal(*Report) succeeded")
	}
	var fe *FindingsError
	if !errorsAs(err, &fe) || fe.Report() != rep {
		t.Fatal("the FindingsError does not hold the report")
	}
	if _, jerr := json.Marshal(*fe); jerr == nil {
		t.Error("json.Marshal(FindingsError) succeeded")
	}
	leak(t, got, log.String(), rep, rep.Findings(), err, fe, *fe)
}
