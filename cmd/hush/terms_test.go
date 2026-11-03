package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	lc "github.com/nonhumanhq/hush/internal/leakcheck"
)

// scanWithTerms runs "hush scan --terms FILE DIR" over a clean tree, with file
// as the term file, and returns the exit status and both outputs.
func scanWithTerms(t *testing.T, file string) (int, string, string) {
	t.Helper()
	tree, outside := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(tree, "a.md"), []byte("clean\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	terms := filepath.Join(outside, "terms.txt")
	if err := os.WriteFile(terms, []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errs strings.Builder
	code := run([]string{"scan", "--destination", "public", "--terms", terms, tree}, strings.NewReader(""), &out, &errs)
	lc.Check(t, out.String(), errs.String())
	return code, out.String(), errs.String()
}

// ADR-002 negative test 6: the load-time checks of section 1.4, run by the
// CLI through hush.LoadTermSets (HSH-11/D12).
func TestNegative6LoadTimeRefusals(t *testing.T) {
	q, z, a := lc.Quorvel, lc.Zantoph, lc.QVL
	for i, c := range []struct {
		file, want string
	}{
		{"[" + strings.ToUpper(q) + "-notes]\n" + q + "\n", "line 1: set name refused"},
		{"[people]\n" + lc.Mirelda + "\n[x" + q[:3] + strings.ToUpper(q[3:]) + "]\n" + q + "\n", "line 3: set name refused"},
		{"[clients]\nNT\n", "line 1: set name refused"},
		{"[clients]\nx\n[abbr case=exact match=word]\nNT\n", "line 1: set name refused"},
		{"[" + strings.ToLower(a) + "notes]\nx\n[abbr match=word]\n" + a + "\n", "line 1: set name refused"},
		{"[clients" + a + "]\nx\n[abbr match=word]\n" + a + "\n", "line 1: set name refused"},
		{"[" + lc.RefusedNames[0] + "]\nx\n", "line 1: set name refused"},
		{"[" + lc.RefusedNames[1] + "]\nx\n", "line 1: set name refused"},
		{"[clients visible-to=k7," + z + "9]\n" + z + "\n", "line 1: client label refused"},
		{"[clients]\nx\n\n[" + z + "-notes visible-to=" + z + "]\n" + z + "\n", "line 4: set name refused"},
		// A format refusal is reported before any load-time check.
		{"[" + q + "]\n" + q + "\n[b]\n", "line 3: set has no terms"},
	} {
		code, out, errs := scanWithTerms(t, c.file)
		if want := "hush: term file: " + c.want + "\n"; code != 2 || out != "" || errs != want {
			t.Errorf("case %d: exit %d, stdout %d bytes, stderr %q, want %q", i, code, len(out), errs, want)
		}
	}
	// The controls load.
	for i, file := range []string{
		"[clients]\n" + q + "\n",
		"[notes-2026]\n" + lc.ZantophWorks + "\n[" + z + "]\nx\n[clients-" + z + "]\ny\n[" + z + "clients]\nw\n",
		"[clients visible-to=k-7]\n" + q + "\n",
		lc.TermSetFile(),
	} {
		if code, out, errs := scanWithTerms(t, file); code != 0 || out != "" || errs != "" {
			t.Errorf("control %d: exit %d, stdout %q, stderr %q", i, code, out, errs)
		}
	}
}

// Format 1's refusals reach standard error as fixed text with the line, and
// nothing from the file.
func TestTermFileRefusalsThroughTheCLI(t *testing.T) {
	q := lc.Quorvel
	for i, c := range []struct{ file, want string }{
		{"[clients]\n" + q + "\x01\n", "term file: line 2: bad character"},
		{"[" + q + "\n" + q + "\n", "term file: line 1: bad header"},
		{"[" + q + " visible-to=K7]\nx\n", "term file: line 1: bad client label"},
		{"[clients]\n" + q + "   # main client\n", "term file: line 2: bad term"},
		{"#hush-terms 2\n[clients]\n" + q + "\n", "term file: line 1: unsupported format"},
		{"\n# " + q + "\n\n", "term file holds no terms"},
	} {
		code, out, errs := scanWithTerms(t, c.file)
		if code != 2 || out != "" || errs != "hush: "+c.want+"\n" {
			t.Errorf("case %d: exit %d, stdout %d bytes, stderr %q", i, code, len(out), errs)
		}
	}
}
