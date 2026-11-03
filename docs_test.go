package hush

import (
	"os"
	"strings"
	"testing"

	lc "github.com/nonhumanhq/hush/internal/leakcheck"
)

// readDoc returns a document of the repository, which the tests read from the
// module root.
func readDoc(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read %s", path)
	}
	return string(b)
}

// The release notes say what the issue's criterion 9 asks for (HSH-11/T28):
// the term-file format v0.1 reads, what v0.2 adds, HSH-5/D17 with both of its
// cases, the address rules' limits from the review of PR #11, and the other
// limits the earlier reviews recorded.
func TestReleaseNotes(t *testing.T) {
	notes := readDoc(t, "docs/release-notes/v0.1.md")
	for _, want := range []string{
		"term-file format 1", "#hush-terms 1", "ADR-002 section 1.6",
		"Hostname and secret-format rules", "Normalization", "Scanner mode",
		"HSH-5/D17", "standard input closed, hush scans nothing and exits 0", "fails open",
		"standard output closed, the findings are lost, but the exit status still reports them",
		"a domain after a reserved address", "a quoted local part that holds an `@`",
		"a bracketed candidate whose domain is read after its last `@`", "an all-letter IPv6 address",
		"a hex word joined to an address by a dot", "two backslashes before its `@`",
		"base64", "GraphQL", "percent-escapes", "mergetag", "submodule",
		"reflection into unexported fields", "git 2.44", "MaxInputSize", "comment lines",
		"`+` read as a space in its query", "`GIT_CEILING_DIRECTORIES` is not honoured",
		"A term file in a sibling linked worktree of the scanned repository",
	} {
		if !strings.Contains(notes, want) {
			t.Errorf("the release notes do not say %q", want)
		}
	}
	lc.Check(t, notes)
}

// Each address the release notes list as let through exits 0 with the
// generic tier, so the notes claim no limit that is not one, and each is
// written in the notes as here, apart, so the notes scan clean.
func TestReleaseNotesLimits(t *testing.T) {
	notes := readDoc(t, "docs/release-notes/v0.1.md")
	s := scanner(t, Config{Destination: Public(), GenericOnly: true})
	for _, c := range []struct{ written, value string }{
		{`"x@example.com@" + "buildhost"`, "x@example.com@" + "buildhost"},
		{`"\"bob@" + "acme.internal\"@example.com"`, "\"bob@" + "acme.internal\"@example.com"},
		{`"<bob@" + "buildhost@example.com>"`, "<bob@" + "buildhost@example.com>"},
		{`"fdab:" + ":cafe"`, "fdab:" + ":cafe"},
		{`"cafe.fd00:" + ":1"`, "cafe.fd00:" + ":1"},
		{`"bob\\\\" + "@acme.internal"`, "bob\\\\" + "@acme.internal"},
	} {
		if !strings.Contains(notes, c.written) {
			t.Errorf("the release notes do not write %s", c.written)
		}
		for _, line := range []string{c.value, "see " + c.value + " here"} {
			rep, err := s.ScanBytes(bg, "", []byte(line+"\n"))
			if err != nil || !rep.Clean() {
				t.Errorf("%s is flagged, or the scan failed: %v", c.written, err)
			}
		}
	}
	// One backslash is flagged, as the notes say.
	one := "bob\\" + "@" + "acme.internal"
	if _, err := s.ScanBytes(bg, "", []byte(one+"\n")); ExitCode(err) != 1 {
		t.Errorf("one backslash: %v", err)
	}
}

// The migration guide carries ADR-002 section 1.7's table row for row, and
// its checklist holds every item the issue's criterion 10 names
// (HSH-11/T29).
func TestMigrationGuide(t *testing.T) {
	guide := readDoc(t, "docs/migration.md")
	adr := readDoc(t, "docs/adr/002-what-hush-matches.md")
	rows := func(doc, from, to string) []string {
		start := strings.Index(doc, from)
		if start < 0 || !strings.Contains(doc[start:], to) {
			t.Fatalf("no section %q", from)
		}
		end := strings.Index(doc[start:], to)
		var out []string
		for _, l := range strings.Split(doc[start:start+end], "\n") {
			if strings.HasPrefix(l, "| ") && !strings.HasPrefix(l, "| ---") {
				out = append(out, l)
			}
		}
		return out
	}
	want := rows(adr, "#### 1.7 Migration from the interim format", "ADR-001 adds two more changes")
	got := rows(guide, "## 2. Check the term file", "ADR-001 adds two more changes")
	// The guide words the bad character row more plainly than the ADR (it
	// must not read as if U+2028 and U+2029 were allowed); pin that wording,
	// then compare the row as the ADR has it.
	const plain = "a control character (tab excepted), U+2028, U+2029, or bytes that are not valid UTF8"
	const asADR = "a control character other than tab, U+2028, U+2029 or bytes that are not valid UTF8"
	if !strings.Contains(guide, plain) || strings.Contains(guide, asADR) {
		t.Errorf("the guide's bad character row does not use the plain wording")
	}
	for i := range got {
		got[i] = strings.Replace(got[i], plain, asADR, 1)
	}
	if len(want) != 9 || strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("the guide's table has %d lines, ADR-002 section 1.7's %d, or they differ", len(got), len(want))
	}
	checklist := guide[strings.Index(guide, "## Checklist"):]
	for _, item := range []string{
		"mapped to its `hush` command", "ADR-002 section 1.7's table",
		"the review machine's addresses", "each agent machine's agent address", "staging CI",
		"`--identities` in every hook", "none installed before v0.1",
		"`commit-msg` also scans git's comment lines", "`--identities` passed in both publish scans",
		"`v0.1.0` tagged", "The interim scanner retired",
		"full-history scan run with both tiers and the publish scans' `--identities` value",
	} {
		if !strings.Contains(checklist, item) {
			t.Errorf("the checklist does not hold %q", item)
		}
	}
	for _, phrase := range []string{
		"each agent address", "kept at a stable path", "reinstall the hooks",
	} {
		if !strings.Contains(guide, phrase) {
			t.Errorf("the guide does not say %q", phrase)
		}
	}
	lc.Check(t, guide)
}
