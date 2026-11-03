package leakcheck

import (
	"slices"
	"strings"
	"testing"
)

// Every flagged token of the two tables and the identities are found, in any
// ASCII case, wherever they stand in printed text. So is the address the rule
// matches in a row that holds more than the address, on its own too.
func TestFindReportsPlantedAddresses(t *testing.T) {
	clean := "docs/<redacted>:0: ip-address in path\n<stdin>:3: email-address\nHSH-14: ADR-002, 192.0.2.10 and alice@example.com\n"
	Check(t, clean)
	planted := slices.Concat(IPFlagged, EmailFlagged, []string{Identity, Identity2})
	for i, tok := range planted {
		for _, text := range []string{"see " + tok + "\n", upper(tok), "a/" + tok + "/b"} {
			if !slices.Contains(Find(clean, text), tok) {
				t.Errorf("planted token %d not found in %q-shaped text", i, text[:1])
			}
		}
	}
	// Written here again, not taken from addresses, so a dropped one fails.
	matched := []string{
		"2001:db9:" + "abcd::", "2001:db9:" + ":5", "2001:db9:1:2:3:4:5:" + "6", "2001:db9:" + ":3:4:5:6:7", "2001:db9:" + ":",
		"1.2." + "3.4", "3.2." + "1.10", "fe80:" + ":1", "10.0." + "0.0",
		"bob@" + "buildhost", "git@" + "buildhost", "git@host." + "acme.internal",
	}
	for i, tok := range matched {
		for k, text := range []string{tok, "see " + tok + "\n", upper(tok), "a/" + tok + "/b"} {
			if !slices.Contains(Find(clean, text), tok) {
				t.Errorf("matched address %d not found in text shape %d", i, k)
			}
		}
	}
}

// A token short enough to occur in ordinary output would make the check fail
// for the wrong reason; every one holds a character no finding line has.
func TestAddressTokensAreSpecific(t *testing.T) {
	for i, tok := range addresses {
		if len(tok) < 6 || !strings.ContainsAny(tok, ".:@") {
			t.Errorf("token %d is too short or too plain", i)
		}
	}
	if len(IPFlagged) < 38 || len(EmailFlagged) < 21 {
		t.Errorf("tables are cut short: %d and %d rows", len(IPFlagged), len(EmailFlagged))
	}
}

// The identity is not the address of a reserved domain, so a test of the
// allowance exercises it (ADR-002 section 6, point 4).
func TestIdentityIsNotReserved(t *testing.T) {
	for _, id := range []string{Identity, Identity2} {
		_, domain, ok := strings.Cut(id, "@")
		if !ok || strings.HasSuffix(domain, ".example") || strings.HasSuffix(domain, ".test") ||
			strings.HasSuffix(domain, ".invalid") || strings.HasSuffix(domain, ".localhost") ||
			strings.HasSuffix(domain, "example.com") || strings.HasSuffix(domain, "example.net") || strings.HasSuffix(domain, "example.org") {
			t.Error("an identity is at a reserved domain")
		}
	}
}

// upper raises the ASCII letters only, as Find compares them.
func upper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'a' <= c && c <= 'z' {
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}
