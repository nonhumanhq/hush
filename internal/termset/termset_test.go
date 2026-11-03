package termset

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nonhumanhq/hush/internal/leakcheck"
)

func TestParseAndMatch(t *testing.T) {
	sets, err := Parse([]byte(leakcheck.TermFile() + "[clients]\n" + leakcheck.SpanA + "\n"))
	if err != nil {
		leakcheck.Check(t, err.Error())
		t.Fatal("parse failed")
	}
	var names []string
	for _, s := range sets {
		names = append(names, s.Name(), fmt.Sprintf("%v|%+v|%#v|%s", s, s, s, s))
	}
	if got := strings.Join(names, " "); got != "set:clients set:clients|set:clients|set:clients|set:clients set:people set:people|set:people|set:people|set:people" {
		t.Errorf("sets: %s", got)
	}
	clients := sets[0]
	for _, c := range []struct {
		text string
		want int
	}{
		{"a note on " + strings.ToUpper(leakcheck.Client), 10},
		{"the " + strings.ToUpper(leakcheck.Client2[:1]) + leakcheck.Client2[1:] + " crew", 4},
		{"x " + leakcheck.SpanA + " " + leakcheck.Client, 2},   // the earliest of two terms
		{strings.Replace(leakcheck.Client2, " ", "  ", 1), -1}, // inner spaces must match exactly
		{"clean", -1},
		{"", -1},
	} {
		if got := clients.Index(c.text, false); got != c.want {
			t.Errorf("Index(case %d) = %d, want %d", len(c.text), got, c.want)
		}
	}
	leakcheck.Check(t, strings.Join(names, " "))
}

func TestParseErrors(t *testing.T) {
	for _, c := range []struct{ file, want string }{
		{"# comments only\n\n[people]\n", "term file holds no terms"},
		{"", "term file holds no terms"},
		{leakcheck.Person + "\n[people]\n" + leakcheck.Client + "\n", "term file: term outside a [set] section at line 1"},
		{"# x\n\n[two words]\n" + leakcheck.Client + "\n", "term file: bad set name at line 3"},
		{"[people]\n" + leakcheck.Person + "\n[]\n", "term file: bad set name at line 3"},
	} {
		_, err := Parse([]byte(c.file))
		if err == nil || err.Error() != c.want {
			t.Errorf("Parse: got %v, want %q", err, c.want)
		}
		if err != nil {
			leakcheck.Check(t, err.Error())
		}
	}
}

func TestLowerIsASCIIOnly(t *testing.T) {
	if got := Lower("AbC-\xc3\x89\xff"); got != "abc-\xc3\x89\xff" {
		t.Errorf("Lower: %q", got)
	}
	leakcheck.Check(t, Lower("AbC"))
}
