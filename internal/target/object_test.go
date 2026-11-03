package target

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	lc "github.com/nonhumanhq/hush/internal/leakcheck"
	"github.com/nonhumanhq/hush/internal/rule"
)

// everyLine is a rule that breaks on every line, so each line the scan
// checks gives a finding with its number and part.
type everyLine struct{}

func (everyLine) Name() string                           { return "every" }
func (everyLine) Check([]byte, rule.Context) (int, bool) { return 0, true }

// objectLines scans obj as a commit or tag object and returns "N PART TEXT"
// for each line the scan checked, in order.
func objectLines(t *testing.T, obj string, tag bool) []string {
	t.Helper()
	r := &recorder{}
	var got []string
	at := Finding{Loc: InCommit, Commit: strings.Repeat("a", 40)}
	if tag {
		at = Finding{Loc: InTag, Tag: strings.Repeat("b", 40)}
	}
	s := &Scan{Rules: rule.List{everyLine{}, r}, Sink: func(f Finding) {
		got = append(got, fmt.Sprintf("%d %d", f.Line, f.Part))
	}}
	s.object(at, []byte(obj), tag)
	if len(got) != len(r.seen) {
		t.Fatalf("%d findings for %d lines", len(got), len(r.seen))
	}
	for i, seen := range r.seen {
		got[i] += " " + strings.SplitN(seen, "/", 4)[3]
	}
	lc.Check(t, got...)
	return got
}

// ADR-001 section 5, "What a commit scan covers", and HSH-11/D15, without
// git: which object lines are scanned, with which part and number.
func TestObjectLines(t *testing.T) {
	A, C, G, H, M := rule.Author, rule.Committer, rule.Tagger, rule.Header, rule.Message
	line := func(n int, p rule.Part, text string) string {
		return fmt.Sprintf("%d %d %s", n, p, text)
	}
	sig := []string{
		"-----BEGIN PGP SIGNATURE-----",
		"Comment: see the notes",
		"",
		"iQEzBAABCAAdFiEE0123456789abcdefABCDEF+/xyz=",
		"abcd==",
		"=Ab12",
		"=Cd34",
		"-----END PGP SIGNATURE-----",
	}
	indent := func(ls []string) string { return " " + strings.Join(ls, "\n ") }

	commit := strings.Join([]string{
		"tree " + strings.Repeat("1", 40),
		"parent " + strings.Repeat("2", 40),
		"parent " + strings.Repeat("3", 40),
		"author alice <alice@example.org> 1700000000 +0000",
		"committer bob <bob@example.org> 1700000000 +0000",
		"encoding latin1",
		"mergetag object " + strings.Repeat("4", 40),
		" type commit",
		" tag v1",
		" tagger alice <alice@example.org> 1700000000 +0000",
		" ",
		" a tag message",
		indent(sig),
		"gpgsig " + sig[0],
		indent(sig[1:]),
		"",
		"subject",
		"",
		"body",
	}, "\n") + "\n"
	got := objectLines(t, commit, false)
	want := []string{
		line(4, A, "author alice <alice@example.org> 1700000000 +0000"),
		line(5, C, "committer bob <bob@example.org> 1700000000 +0000"),
		line(6, H, "encoding latin1"),
		line(7, H, "mergetag object "+strings.Repeat("4", 40)),
		line(8, H, " type commit"),
		line(9, H, " tag v1"),
		line(10, H, " tagger alice <alice@example.org> 1700000000 +0000"),
		line(11, H, " "),
		line(12, H, " a tag message"),
		line(14, H, " Comment: see the notes"), // armor header: scanned
		line(19, H, " =Cd34"),                  // a second checksum: scanned
		line(22, H, " Comment: see the notes"),
		line(27, H, " =Cd34"),
		line(30, M, "subject"),
		line(31, M, ""),
		line(32, M, "body"),
	}
	if !slices.Equal(got, want) {
		t.Errorf("commit:\n%q\nwant\n%q", got, want)
	}

	// A tag: object and type skipped; tag and tagger scanned; a block that
	// ends the message is a signature, one in the middle is text, and so is
	// an unterminated one.
	tag := strings.Join(append([]string{
		"object " + strings.Repeat("1", 40),
		"type commit",
		"tag v1",
		"tagger alice <alice@example.org> 1700000000 +0000",
		"",
		"message",
		"-----BEGIN SSH SIGNATURE-----",
		"free text in a block",
		"-----END SSH SIGNATURE-----",
		"after",
	}, sig...), "\n") + "\n"
	got = objectLines(t, tag, true)
	want = []string{
		line(3, H, "tag v1"),
		line(4, G, "tagger alice <alice@example.org> 1700000000 +0000"),
		line(6, M, "message"),
		line(7, M, "-----BEGIN SSH SIGNATURE-----"),
		line(8, M, "free text in a block"),
		line(9, M, "-----END SSH SIGNATURE-----"),
		line(10, M, "after"),
		line(12, M, "Comment: see the notes"),
		line(17, M, "=Cd34"),
	}
	if !slices.Equal(got, want) {
		t.Errorf("tag:\n%q\nwant\n%q", got, want)
	}
	// An unterminated block, and a fake one with free text that ends the
	// message: each line that is not base64 is scanned.
	tag = "object " + strings.Repeat("1", 40) + "\ntype commit\ntag v2\n\nmessage\n" +
		"-----BEGIN PGP SIGNATURE-----\nfree text\nabcd\n"
	got = objectLines(t, tag, true)
	want = []string{line(3, H, "tag v2"), line(5, M, "message"), line(6, M, "-----BEGIN PGP SIGNATURE-----"),
		line(7, M, "free text"), line(8, M, "abcd")}
	if !slices.Equal(got, want) {
		t.Errorf("unterminated:\n%q\nwant\n%q", got, want)
	}
}
