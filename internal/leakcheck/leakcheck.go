// Package leakcheck holds the synthetic terms and rejected tokens that tests
// use, and the check that none of them is ever printed. The strings are
// assembled at run time, so the test sources scan clean.
package leakcheck

import (
	"slices"
	"strings"
	"testing"
)

// Rejected ID-prefix tokens.
var (
	Bad   = "QPV" + "-" + "17"      // a prefix outside the allowlist
	Near  = "HSH" + "Q" + "-" + "9" // an allowed prefix with a letter added
	Fleet = "FLEET" + "-" + "5"     // allowed under reference/ only
	Vmws  = "VMWS" + "-" + "8"      // allowed under reference/ only
)

// Synthetic terms.
var (
	Client  = "Vant" + "orell"         // in set clients
	Client2 = "brindle" + "wick works" // in set clients, with an inner space
	Person  = "Osw" + "ynne"           // in set people
	SpanA   = "quor" + "vex"           // with SpanB, a term that spans "/"
	SpanB   = "lind" + "haven"
	Span    = SpanA + "/" + SpanB
	words   = []string{Client, "brindle" + "wick", Person, SpanA, SpanB, EscA, EscB}
	tokens  = []string{Bad, Near, Fleet, Vmws}
	allText = slices.Concat(words, tokens, addresses, termWords)
)

// Terms holding characters git quotes in a path.
var (
	EscA        = "drav" + "olin"
	EscB        = "mer" + "quist"
	Quoted      = EscA + "\"" + EscB // a double quote
	Backslashed = EscA + "\\" + EscB // a backslash
)

// TermFile returns a term file with the sets clients and people.
func TermFile() string {
	return "# synthetic terms, for tests only\n[clients]\n" + Client + "\n" +
		"  " + Client2 + "\t\r\n\n[people]\n" + Person + "\n"
}

// Find returns the strings from this package that appear in any of texts,
// ignoring ASCII case.
func Find(texts ...string) []string {
	var found []string
	for _, w := range allText {
		for _, s := range texts {
			if strings.Contains(lower(s), lower(w)) {
				found = append(found, w)
				break
			}
		}
	}
	return found
}

// Check fails t if any of texts holds a synthetic term or a rejected token.
// It never prints the text it found, only how many strings leaked.
func Check(t testing.TB, texts ...string) {
	t.Helper()
	if n := len(Find(texts...)); n > 0 {
		t.Errorf("leak check: %d synthetic strings printed", n)
	}
}

func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
