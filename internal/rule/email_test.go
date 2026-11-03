package rule

import (
	"slices"
	"strings"
	"testing"

	lc "github.com/nonhumanhq/hush/internal/leakcheck"
)

// emailPasses is the "Passes" table of ADR-002 section 4.3, every input of
// every row as the ADR writes it, except its last two rows. Those pass only
// with the identity listed and in an identity position, and
// TestEmailAddressAllowanceRows runs them. A shape the rule must flag is
// assembled at run time, so this file scans clean under the rule.
var emailPasses = []string{
	// Reserved second-level names, and their subdomains
	"alice@example.com", "ALICE@EXAMPLE.ORG", "bob@mail.example.net",
	// Reserved top-level names
	"bob@acme.test", "bob@acme.example", "bob@acme.invalid", "bob@acme.localhost",
	// Any form
	"<alice@example.org>", "mailto:alice@example.com",
	// A bracketed domain ends at the first /, :, ? or #
	"<mailto:alice@example.com?subject=hi>", "<https://bob@example.com/>", "<git@example.com:org/repo.git>",
	// In a code span, a backtick is no local part
	"`@AGENTS.md`", "`@pytest.fixture`",
	// The domain ends at the em dash and at the quotation mark
	"alice@example.com—see www.example.org", "“alice@example.com”",
	// The final label is not a word
	"react@18.3.1", "golang.org/x/tools@v0.1.0", "pkg@latest", "pkg@v1.0.0-rc.1",
	// No address
	"@property", "HEAD@{1}", "image@sha256:0123",
	// Bare and without a dot: not a candidate, a known miss
	"bob@buildhost",
	// Not an email candidate; the IP rule checks the address
	"ssh alice@192.0.2.10",
}

// The identity allowance the tests pass, and the contexts of ADR-002 section
// 5.1 that a target will fill once HSH-11 lands.
var (
	allowance = NewEmailAddress([]string{lc.Identity})
	inMessage = Context{Source: Object, Part: Message}
	onStdin   = Context{Source: Stdin}
	inFile    = Context{Source: File, Path: "docs/a.md"}
)

func broken(e EmailAddress, line string, ctx Context) bool {
	_, b := e.Check([]byte(line), ctx)
	return b
}

// Each row of the Passes table, alone on a line, is flagged by no rule.
func TestEmailAddressPasses(t *testing.T) {
	r := newReport(t)
	defer r.done()
	for i, line := range emailPasses {
		if got := names(line); got != "" {
			r.errorf("passes row %d is flagged by %s", i, got)
		}
	}
}

// Each row of the Flagged table, alone on a line, is flagged by
// email-address and by no other rule; with no allowance, the identity rows are
// flagged too.
func TestEmailAddressFlagged(t *testing.T) {
	r := newReport(t)
	defer r.done()
	for i, line := range lc.EmailFlagged {
		if got := names(line); got != "email-address" {
			r.errorf("flagged row %d gives %q, want email-address", i, got)
		}
		start, b := (EmailAddress{}).Check([]byte(line), Context{})
		if !b || start < 0 || start >= len(line) {
			r.errorf("flagged row %d: Check gives %d, %t", i, start, b)
		}
	}
}

// Index is HSH-5's method over the same check, with the zero Context, which is
// no identity position: even a rule built with the allowance flags the identity.
func TestEmailAddressIndex(t *testing.T) {
	r := newReport(t)
	defer r.done()
	if got := (EmailAddress{}).Name(); got != "email-address" {
		r.errorf("Name is %q", got)
	}
	for i, line := range slices.Concat(emailPasses, lc.EmailFlagged, []string{lc.TrailerLine, lc.AuthorLine}) {
		start, b := (EmailAddress{}).Check([]byte(line), Context{})
		want := -1
		if b {
			want = start
		}
		for _, e := range []EmailAddress{{}, allowance} {
			for _, inRef := range []bool{false, true} {
				if got := e.Index(line, inRef); got != want {
					r.errorf("row %d: Index(inRef %t) = %d, want %d", i, inRef, got, want)
				}
			}
		}
	}
}

// ADR-002 section 4.3's identity rows: with the identity listed, a trailer
// line in a commit message or on standard input and an author header pass; the
// rows that look the same but are no identity position stay flagged.
func TestEmailAddressAllowanceRows(t *testing.T) {
	r := newReport(t)
	defer r.done()
	for i, c := range []struct {
		name string
		line string
		ctx  Context
		want bool // flagged
	}{
		// Passes
		{"trailer, message", lc.TrailerLine, inMessage, false},
		{"trailer, stdin", lc.TrailerLine, onStdin, false},
		{"author header", lc.AuthorLine, Context{Source: Object, Part: Author}, false},
		// Flagged
		{"not at a position, message", lc.WriteToLine, inMessage, true},
		{"not at a position, stdin", lc.WriteToLine, onStdin, true},
		{"subject line", lc.SubjectLine, inMessage, true},
		{"note line", lc.NoteLine, inMessage, true},
		{"trailer, line of a file", lc.TrailerLine, inFile, true},
		{"trailer, path", lc.TrailerLine, Context{Source: Path, Path: "docs/a.md"}, true},
		{"trailer, bare string", lc.TrailerLine, Context{Source: Text}, true},
	} {
		if got := broken(allowance, c.line, c.ctx); got != c.want {
			r.errorf("row %d (%s): flagged %t, want %t", i, c.name, got, c.want)
		}
	}
	// With no allowance, the same lines are all flagged.
	for i, line := range []string{lc.TrailerLine, lc.AuthorLine, lc.WriteToLine, lc.SubjectLine, lc.NoteLine} {
		for _, e := range []EmailAddress{{}, NewEmailAddress(nil), NewEmailAddress([]string{})} {
			for _, ctx := range []Context{inMessage, onStdin, {Source: Object, Part: Author}, inFile} {
				if !broken(e, line, ctx) {
					r.errorf("row %d passes with no allowance", i)
				}
			}
		}
	}
}

// Negative test 4, with the list passed to the rule in place of --identities:
// a commit whose author, committer and trailer all carry the identity.
func TestEmailAddressNegative4(t *testing.T) {
	r := newReport(t)
	defer r.done()
	lines := func(id string) (author, committer, trailer string) {
		who := "Alice <" + id + ">"
		return "author " + who + " 1700000000 +0000", "committer " + who + " 1700000000 +0000", "Signed-off-by: " + who
	}
	mixed := "Alice@" + "Acme.Internal"
	for _, id := range []string{lc.Identity, strings.ToUpper(lc.Identity), mixed} {
		author, committer, trailer := lines(id)
		// Without the list, the three lines are flagged.
		for i, c := range []struct {
			line string
			ctx  Context
		}{
			{author, Context{Source: Object, Part: Author}},
			{committer, Context{Source: Object, Part: Committer}},
			{trailer, inMessage},
			{trailer, onStdin},
		} {
			if !broken(EmailAddress{}, c.line, c.ctx) {
				r.errorf("line %d passes with no list", i)
			}
			// With the list, in any ASCII case and beside a second address, they pass.
			for _, list := range [][]string{
				{lc.Identity},
				{strings.ToUpper(lc.Identity)},
				{mixed},
				{lc.Identity2, lc.Identity},
				{lc.Identity, lc.Identity2},
			} {
				if broken(NewEmailAddress(list), c.line, c.ctx) {
					r.errorf("line %d is flagged with the list", i)
				}
			}
			// A list that holds another address changes nothing.
			if !broken(NewEmailAddress([]string{lc.Identity2}), c.line, c.ctx) {
				r.errorf("line %d passes on another address", i)
			}
		}
		// With the allowance, the address on a line of a file is flagged, even on
		// a trailer-shaped line, and so is a subject line (decided item 6).
		if !broken(allowance, trailer, inFile) || !broken(allowance, "HSH-3: write to "+id, inMessage) {
			r.errorf("the allowance reaches a file's line or a subject line")
		}
	}
}

// Every identity position passes a listed address, and only those: the
// author, committer and tagger headers, and identity trailers in a message or
// on standard input.
func TestEmailAddressIdentityPositions(t *testing.T) {
	r := newReport(t)
	defer r.done()
	who := "Alice <" + lc.Identity + ">"
	for i, c := range []struct {
		line string
		ctx  Context
		want bool // flagged
	}{
		{"author " + who + " 1700000000 +0000", Context{Source: Object, Part: Author}, false},
		{"committer " + who + " 1700000000 +0000", Context{Source: Object, Part: Committer}, false},
		{"tagger " + who + " 1700000000 +0000", Context{Source: Object, Part: Tagger}, false},
		// A merged tag's embedded text is a plain header: no identity position.
		{"tagger " + who + " 1700000000 +0000", Context{Source: Object, Part: Header}, true},
		{"tagger " + who + " 1700000000 +0000", Context{Source: Object, Part: NoPart}, true},
		{"Signed-off-by: " + who, Context{Source: Object, Part: Header}, true},
		{"Signed-off-by: " + who, Context{Source: Object, Part: Author}, false},
		// Identity trailers.
		{"Co-authored-by: " + who, inMessage, false},
		{"Reviewed-by: " + who, onStdin, false},
		{"Signed-off-by: " + lc.Identity, inMessage, false},
		{"a-by: " + who, inMessage, false},
		// Not identity trailers: the shape is a word of letters, digits and hyphens
		// that starts with a letter and ends in -by, then a colon and a space.
		{"Signed-off-by:" + who, inMessage, true},
		{" Signed-off-by: " + who, inMessage, true},
		{"Signed-off-by : " + who, inMessage, true},
		{"1-by: " + who, inMessage, true},
		{"by: " + who, inMessage, true},
		{"Acked: " + who, inMessage, true},
		{"Signed_off-by: " + who, inMessage, true},
		{"Note: " + who, inMessage, true},
		{"HSH-3: " + who, onStdin, true},
		{who, inMessage, true},
		{"Signed-off-by: " + who, inFile, true},
		{"Signed-off-by: " + who, Context{Source: Path}, true},
		{"Signed-off-by: " + who, Context{}, true},
	} {
		if got := broken(allowance, c.line, c.ctx); got != c.want {
			r.errorf("case %d: flagged %t, want %t", i, got, c.want)
		}
	}
}

// Only the listed address passes. Another one on the same line is judged on its
// domain, and the offset is where it begins.
func TestEmailAddressOnlyTheListedAddress(t *testing.T) {
	r := newReport(t)
	defer r.done()
	other := "bob@" + "acme.local"
	line := "Co-authored-by: Alice <" + lc.Identity + ">, Bob <" + other + ">"
	if start, b := allowance.Check([]byte(line), inMessage); !b || start != strings.Index(line, "<"+other) {
		r.errorf("the second address: offset %d, flagged %t", start, b)
	}
	// A reserved domain passes with or without the allowance.
	reserved := "Signed-off-by: Bob <bob@example.org>, Alice <" + lc.Identity + ">"
	for _, ctx := range []Context{inMessage, inFile, {}} {
		if broken(EmailAddress{}, "x bob@example.org y", ctx) {
			r.errorf("a reserved domain is flagged")
		}
	}
	if broken(allowance, reserved, inMessage) {
		r.errorf("a reserved domain and the identity are flagged")
	}
	// The list is lowered once and copied: changing the caller's slice later changes nothing.
	ids := []string{lc.Identity}
	e := NewEmailAddress(ids)
	ids[0] = lc.Identity2
	if broken(e, lc.TrailerLine, inMessage) || !broken(e, "Signed-off-by: Bob <"+lc.Identity2+">", inMessage) {
		r.errorf("the rule follows the caller's slice")
	}
}

// Where the earliest breaking match begins, bare or bracketed.
func TestEmailAddressStart(t *testing.T) {
	r := newReport(t)
	defer r.done()
	bare := "bob@" + "acme.local"
	br := "<bob@" + "buildhost>"
	for i, c := range []struct {
		line string
		want int
	}{
		{bare, 0},
		{"x " + bare, 2},
		{br, 0},
		{"x " + br, 2},
		{"alice@example.com " + bare, len("alice@example.com ")},
		{bare + " " + br, 0},
		{br + " " + bare, 0},
		{"<alice@example.org> " + br, len("<alice@example.org> ")},
		{"see <" + "git@" + "buildhost:org/repo.test>", 4},
		{bare + " " + "bob@" + "acme.internal", 0}, // two bare addresses: the first
	} {
		if got, _ := (EmailAddress{}).Check([]byte(c.line), Context{}); got != c.want {
			r.errorf("case %d: offset %d, want %d", i, got, c.want)
		}
	}
}

// The examples section 4.3 gives outside its tables: the false positives, and
// the remedies and shapes that pass.
func TestEmailAddressProse(t *testing.T) {
	r := newReport(t)
	defer r.done()
	for i, line := range []string{
		"*" + "@pytest.fixture*", "'" + "@AGENTS.md'", // an @ name in emphasis or single quotes
		"<https://example.com/" + "@alice>",        // an @ inside a bracketed URL's path
		"pkg@1.0.0-alpha." + "beta",                // a version that ends in a word
		"alice@example.com" + "тест",               // a reserved address followed by another script
		"\"$USER\"@" + "acme.internal",             // a quoted local part
		"bob@mail." + "acme\xff.internal",          // a domain broken by an invalid byte, with a dot before it
		"x\xffbob@" + "acme.internal",              // an invalid byte in the local part
		"bob@" + "acme.internal.",                  // a full stop after it
		"mailto:bob@" + "acme.internal?subject=hi", // any form
		"bob@" + "ä.example.com",                   // no internationalized subdomain of a reserved name
		"bob@acme." + "ä.test",                     // nor a non-ASCII label before a reserved last label
	} {
		if got := names(line); got != "email-address" {
			r.errorf("flagged prose example %d gives %q", i, got)
		}
	}
	for i, line := range []string{
		"`@pytest.fixture`", "`@AGENTS.md`", // in a code span
		"[home](https://example.com/@alice)", // a Markdown link
		"icon-2x.png",                        // named without the @
		"pkg 1.0.0-alpha.beta",               // a space instead of the @
		"alice@example.com тест",             // a space after the address
		"\"$USER\"@example.com",              // a quoted local part at a reserved domain
	} {
		if got := names(line); got != "" {
			r.errorf("remedy %d is flagged by %s", i, got)
		}
	}
}

// Section 4.3's "Known misses": each holds an address and passes.
func TestEmailAddressKnownMisses(t *testing.T) {
	r := newReport(t)
	defer r.done()
	for i, line := range []string{
		"bob at acme dot internal",                     // obfuscated
		"bob%40acme.internal", "bob&#64;acme.internal", // percent- and entity-encoded
		"bob@acme",                         // a domain with no dot
		"\"bob smith\"@" + "acme.internal", // a quoted local part with a space
		"bob@acme\xff.internal",            // a domain with no dot before a broken byte
		"bob@",                             // an @ with nothing after it
		"@" + "acme.internal",              // an @ with nothing before it
	} {
		if got := names(line); got != "" {
			r.errorf("known miss %d is flagged by %s", i, got)
		}
	}
}

// Redaction cuts a path at the component where the earliest match begins
// (ADR-002 negative test 11).
func TestEmailAddressRedactsPaths(t *testing.T) {
	r := newReport(t)
	defer r.done()
	for i, c := range []struct{ path, want string }{
		{"docs/" + "bob@" + "acme.internal" + "/a.md", "docs/<redacted>"},
		{"docs/ok/" + "bob@" + "acme.internal" + ".md", "docs/ok/<redacted>"},
		{"bob@" + "acme.internal" + "/a.md", "<redacted>"},
		{"docs/bob@example.com/a.md", "docs/bob@example.com/a.md"},
		{"docs/<bob@" + "buildhost>/a.md", "docs/<redacted>"},
		{"docs/" + "bob@" + "acme.internal" + "/x-" + "bob@" + "acme.internal" + ".md", "docs/<redacted>"}, // two: from the first
	} {
		got := registry.Redact(c.path, false)
		if got != c.want {
			r.errorf("path %d redacts to %d bytes, want %d", i, len(got), len(c.want))
		}
		if got != c.path { // an unchanged path may hold a reserved address that starts like a flagged token
			lc.Check(t, got)
		}
	}
}
