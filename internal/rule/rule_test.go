package rule

import (
	"strings"
	"testing"

	lc "github.com/nonhumanhq/hush/internal/leakcheck"
)

// idPasses is the "Passes" table of ADR-002 section 4.1, every input the ADR
// writes, except the row that passes only under reference/
// (idPassesUnderReference). Each passes in every context.
var idPasses = []string{
	"HSH-1", "CHS-22", "FLT-3", "SWE-404", "ADR-001", "chassis ADR-002",
	"xHSH-7",
	"HSH-12-34",
	"abc-123", "Abc-123",
	"ABC 123", "ABC_123", "ABC123", "UTF8", "SHA256",
}

// idPassesUnderReference is the table's row that passes in a file or path
// under reference/ only.
var idPassesUnderReference = []string{"FLEET" + "-12"}

// Every context a line can come from, with a path outside reference/.
var outsideReference = []Context{
	{}, {Source: File, Path: "docs/a.md"}, {Source: Path, Path: "docs/a.md"},
	{Source: Object, Part: Message}, {Source: Object, Part: Author}, {Source: Stdin},
}

// ADR-002 section 4.1's two tables, and negative test 9 as far as the rule
// sees it: the exception is taken from the context's path.
func TestIDPrefixTables(t *testing.T) {
	r := newReport(t)
	defer r.done()
	for i, line := range idPasses {
		for _, ctx := range outsideReference {
			if start, b := (IDPrefix{}).Check([]byte(line), ctx); b || start != -1 {
				r.errorf("passing row %d is flagged in source %d", i, ctx.Source)
			}
		}
	}
	for i, line := range lc.IDFlagged {
		for _, ctx := range outsideReference {
			if _, b := (IDPrefix{}).Check([]byte(line), ctx); !b {
				r.errorf("flagged row %d passes in source %d", i, ctx.Source)
			}
		}
	}
	fleet := idPassesUnderReference[0]
	for i, c := range []struct {
		ctx  Context
		want bool // flagged
	}{
		{Context{Source: File, Path: "reference/notes.md"}, false},
		{Context{Source: Path, Path: "reference/" + fleet + ".md"}, false},
		{Context{Source: Path, Path: "reference/notes.md"}, false},
		// Never for object text, standard input or a bare string.
		{Context{Source: Object, Part: Message, Path: "reference/notes.md"}, true},
		{Context{Source: Stdin, Path: "reference/notes.md"}, true},
		{Context{Path: "reference/notes.md"}, true},
		// Never for a path that only looks like one under reference/.
		{Context{Source: File, Path: "docs/reference/a.md"}, true},
		{Context{Source: File, Path: "Reference/a.md"}, true},
		{Context{Source: File, Path: "reference"}, true},
		{Context{Source: Path, Path: "./reference/a.md"}, true},
		{Context{Source: File, Path: "docs/a.md"}, true},
	} {
		for _, line := range []string{fleet, "VMWS" + "-3", "see " + fleet + " and " + "VMWS" + "-3"} {
			if _, b := (IDPrefix{}).Check([]byte(line), c.ctx); b != c.want {
				r.errorf("reference case %d: flagged %t, want %t", i, b, c.want)
			}
		}
	}
	// Another prefix is flagged under reference/ too.
	if _, b := (IDPrefix{}).Check([]byte(lc.Bad), Context{Source: File, Path: "reference/a.md"}); !b {
		r.errorf("the exception covers a prefix other than the pack's own")
	}
}

// Where the match begins: the token boundaries of section 4.1.
func TestIDPrefixStart(t *testing.T) {
	r := newReport(t)
	defer r.done()
	for i, c := range []struct {
		line string
		want int
	}{
		{"see HSH-1, CHS-22, FLT-3, SWE-404 and ADR-001", -1},
		{"HSH-1 then " + lc.Bad, 11},
		{"a" + lc.Near, 1},
		{"x " + lc.Fleet, 2},
		{"HSH-1" + lc.Bad, 5},        // scanning resumes after an allowed token
		{"xx" + "ACMEHSH" + "-1", 2}, // the prefix is the whole run
		{"9" + "AB1" + "-23", 1},     // a run starts at its first uppercase letter
		{"_" + "A_B" + "-12", 1},
		{"[A-Z0" + "-9]", 3},
		{"HSH-12" + "QPV" + "-3", 6},
		{"HSH-x ADR- lower-case-1 ABC-", -1},
		{"ADR-001-" + "HSH-2", -1},
	} {
		start, b := (IDPrefix{}).Check([]byte(c.line), Context{})
		if start != c.want || b != (c.want >= 0) {
			r.errorf("case %d: start %d, want %d", i, start, c.want)
		}
	}
	if (IDPrefix{}).Name() != "id-prefix" {
		r.errorf("the rule's name changed")
	}
}

// A line that breaks several rules gives their names in list order, and Start
// is the earliest match of any of them.
func TestListCheckAndStart(t *testing.T) {
	r := newReport(t)
	defer r.done()
	l := Registry(nil)
	line := []byte("bob@" + "acme.local" + " " + lc.Bad)
	if got := strings.Join(l.Check(line, Context{}), ","); got != "id-prefix,email-address" {
		r.errorf("Check gives %q", got)
	}
	if got := l.Start(line, Context{}); got != 0 {
		r.errorf("Start is %d, want 0", got)
	}
	if got := l.Start([]byte("clean"), Context{}); got != -1 {
		r.errorf("Start on a clean line is %d", got)
	}
	if got := l.Check([]byte("clean"), Context{}); got != nil {
		r.errorf("Check on a clean line gives %d names", len(got))
	}
}

// Redact cuts from the component where the match begins.
func TestRedact(t *testing.T) {
	r := newReport(t)
	defer r.done()
	l := Registry(nil)
	for i, c := range []struct{ path, want string }{
		{"docs/a.md", "docs/a.md"},
		{"docs/notes-" + lc.Bad + ".md", "docs/<redacted>"},
		{lc.Bad + "-notes/x.md", "<redacted>"},
		{"/srv/" + lc.Bad, "/srv/<redacted>"},
		{"a/" + lc.Near + "/" + lc.Bad + "/b", "a/<redacted>"},
		{"reference/" + lc.Fleet + ".md", "reference/" + lc.Fleet + ".md"},
		{"docs/" + lc.Fleet + ".md", "docs/<redacted>"},
	} {
		got := Redact(c.path, l.Start([]byte(c.path), Context{Source: Path, Path: c.path}))
		if got != c.want {
			r.errorf("path %d redacts to %d bytes, want %d", i, len(got), len(c.want))
		}
		if c.path != c.want {
			lc.Check(t, got)
		}
	}
	if got := Redact("a/b", -1); got != "a/b" {
		r.errorf("a negative start changes the path")
	}
	if got := Redact("a/b", 2); got != "a/<redacted>" {
		r.errorf("a start at a component's first byte gives %d bytes", len(got))
	}
	if got := Redact("a/b", 1); got != "<redacted>" {
		r.errorf("a start at a slash gives %d bytes", len(got))
	}
}
