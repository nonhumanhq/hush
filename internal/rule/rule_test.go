package rule

import (
	"strings"
	"testing"

	"github.com/nonhumanhq/hush/internal/leakcheck"
	"github.com/nonhumanhq/hush/internal/termset"
)

func rules(t *testing.T, file string) List {
	t.Helper()
	sets, err := termset.Parse([]byte(file))
	if err != nil {
		t.Fatal("parse failed")
	}
	l := List{IDPrefix{}}
	for _, s := range sets {
		l = append(l, s)
	}
	return l
}

func TestIDPrefix(t *testing.T) {
	lc := leakcheck.Client
	for _, c := range []struct {
		s     string
		inRef bool
		want  int
	}{
		{"see HSH-1, CHS-22, FLT-3, SWE-404 and ADR-001", false, -1},
		{"HSH-1 then " + leakcheck.Bad, false, 11},
		{"a" + leakcheck.Near, false, 1},
		{leakcheck.Fleet + " " + leakcheck.Vmws, true, -1},
		{"x " + leakcheck.Fleet, false, 2},
		{"HSH-1" + leakcheck.Bad, false, 5},      // scanning resumes after an allowed token
		{"ABC-DEF" + "-1 utf-8 " + lc, false, 4}, // the token starts at the last capital run
		{"HSH-x ADR- lower-case-1", false, -1},   // not shaped [A-Z]+-[0-9]+
	} {
		if got := (IDPrefix{}).Index(c.s, c.inRef); got != c.want {
			t.Errorf("Index(case %d) = %d, want %d", len(c.s), got, c.want)
		}
	}
	leakcheck.Check(t, IDPrefix{}.Name())
}

func TestCheckOrdersFindings(t *testing.T) {
	l := rules(t, leakcheck.TermFile())
	line := leakcheck.Person + " and " + strings.ToUpper(leakcheck.Client) + " on " + leakcheck.Bad
	got := strings.Join(l.Check(line, false), ",")
	if got != "id-prefix,set:clients,set:people" {
		t.Errorf("Check: %s", got)
	}
	leakcheck.Check(t, got)
}

func TestRedact(t *testing.T) {
	l := rules(t, leakcheck.TermFile()+"[places]\n"+leakcheck.Span+"\n")
	for _, c := range []struct{ path, want string }{
		{"docs/a.md", "docs/a.md"},
		{"docs/notes-" + leakcheck.Bad + ".md", "docs/<redacted>"},
		{"docs/" + leakcheck.Client + "/plan.md", "docs/<redacted>"},
		{leakcheck.Client + "-notes/x.md", "<redacted>"},
		{"/srv/" + leakcheck.Person, "/srv/<redacted>"},
		{"a/" + leakcheck.Person + "/" + leakcheck.Bad + "/b", "a/<redacted>"},
		{"reference/" + leakcheck.Fleet + ".md", "reference/" + leakcheck.Fleet + ".md"},
		{"docs/" + leakcheck.Fleet + ".md", "docs/<redacted>"},
		// A term that spans "/": the interim printed its first part.
		{"docs/" + leakcheck.Span + "/a.md", "docs/<redacted>"},
		{"docs/x" + strings.ToUpper(leakcheck.Span) + "y", "docs/<redacted>"},
		{leakcheck.Span, "<redacted>"},
	} {
		got := l.Redact(c.path, InRef(c.path))
		if c.path != c.want {
			leakcheck.Check(t, got)
		}
		if got != c.want {
			t.Errorf("Redact(case %d): got %d bytes, want %d", len(c.path), len(got), len(c.want))
		}
	}
}
