package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	lc "github.com/nonhumanhq/hush/internal/leakcheck"
)

// hush scan builds the list ADR-002 section 5.2 gives: id-prefix, ip-address,
// email-address, then the term sets. The comparison test cannot show it, since
// the interim scanner has neither address rule and its fixtures hold none.
func TestScanRunsTheAddressRulesBeforeTheSets(t *testing.T) {
	dir := t.TempDir()
	terms := filepath.Join(dir, "terms.txt")
	if err := os.WriteFile(terms, []byte(lc.TermFile()), 0o600); err != nil {
		t.Fatal(err)
	}
	ip, mail := "10.1."+"2.3", "bob@"+"acme.local"
	line := lc.Client + " " + mail + " " + ip + " " + lc.Bad + "\n"
	for _, c := range []struct {
		name  string
		args  []string
		in    string
		code  int
		stdin string
	}{
		{"clean", []string{"scan", "--stdin"}, "see 192.0.2.10 and alice@example.com, HSH-14\n", 0, ""},
		{"ip", []string{"scan", "--stdin"}, "at " + ip + "\n", 1, "<stdin>:1: ip-address\n"},
		{"email", []string{"scan", "--stdin", "--label", "body"}, "mail " + mail + "\n", 1, "body:1: email-address\n"},
		{"order", []string{"scan", "--stdin"}, line, 1, "<stdin>:1: id-prefix\n<stdin>:1: ip-address\n<stdin>:1: email-address\n"},
		{"order with sets", []string{"scan", "--terms", terms, "--stdin"}, line, 1,
			"<stdin>:1: id-prefix\n<stdin>:1: ip-address\n<stdin>:1: email-address\n<stdin>:1: set:clients\n"},
		{"a line each", []string{"scan", "--stdin"}, "ok\n" + ip + "\n" + mail + "\nok\n", 1, "<stdin>:2: ip-address\n<stdin>:3: email-address\n"},
	} {
		var out, errs strings.Builder
		code := run(c.args, strings.NewReader(c.in), &out, &errs)
		if code != c.code || out.String() != c.stdin || errs.Len() != 0 {
			t.Errorf("%s: exit %d, stdout %q, stderr %d bytes", c.name, code, out.String(), errs.Len())
		}
		lc.Check(t, out.String(), errs.String())
	}
}

// A tree scan redacts a path the address rules flag, and its lines are flagged.
func TestScanTreeRedactsAnAddressInAPath(t *testing.T) {
	t.Chdir(t.TempDir())
	ip := "203.0." + "114.7"
	if err := os.MkdirAll("docs/"+ip, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("docs/"+ip+"/a.md", []byte("see bob@"+"acme.internal\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errs strings.Builder
	code := run([]string{"scan", "docs"}, strings.NewReader(""), &out, &errs)
	want := "docs/<redacted>:0: ip-address in path\ndocs/<redacted>:1: email-address\n"
	if code != 1 || out.String() != want || errs.Len() != 0 {
		t.Errorf("exit %d, stdout %q, stderr %d bytes", code, out.String(), errs.Len())
	}
	lc.Check(t, out.String(), errs.String())
}
