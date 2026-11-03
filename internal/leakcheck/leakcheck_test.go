package leakcheck

import (
	"slices"
	"testing"
)

func TestFindReportsPlantedLeaks(t *testing.T) {
	clean := "docs/<redacted>:0: set:clients in path\nHSH-1, ADR-001\n"
	Check(t, clean)
	planted := []string{
		"see " + Bad + "\n",
		"a/" + lower(Client) + "/b",
		"BRINDLEWICK",
		"x " + SpanB,
		Near, Fleet, Vmws, Person,
	}
	for i, p := range planted {
		if len(Find(clean, p)) != 1 {
			t.Errorf("planted leak %d not found", i)
		}
	}
}

// The terms, labels, refused names and ID-prefix rows of ADR-002's tests are
// found in any ASCII case (upper raises ASCII letters only, as Find
// compares them), wherever they stand.
func TestFindReportsPlantedTermSetWords(t *testing.T) {
	clean := "docs/<redacted>:0: set:abbreviations in path\nhush-interim: term file: line 3: set name refused\n"
	Check(t, clean)
	for i, w := range termWords {
		for _, text := range []string{w, "see " + w + "\n", upper(w), "a/" + w + "/b"} {
			if len(Find(clean, text)) == 0 {
				t.Errorf("planted word %d not found", i)
			}
		}
	}
	for _, w := range []string{Quorvel, Zantoph, Mirelda, Brindlemoor, QVL, MOP, Kelvo, Accented, LabelA, LabelB} {
		if !slices.Contains(termWords, w) {
			t.Error("a term of the negative tests is not checked")
		}
	}
}
