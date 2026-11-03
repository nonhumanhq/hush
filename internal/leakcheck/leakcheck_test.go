package leakcheck

import "testing"

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
