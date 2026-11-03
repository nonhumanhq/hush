package main

import (
	"os"
	"strings"
	"testing"

	"github.com/nonhumanhq/hush/internal/leakcheck"
)

// The module uses only the standard library.
func TestGoModHasNoRequire(t *testing.T) {
	data, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal("cannot read go.mod")
	}
	for i, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "require") { // also "require(", which Go accepts
			t.Errorf("go.mod line %d: require", i+1)
		}
	}
	if _, err := os.Stat("../../go.sum"); err == nil {
		t.Error("go.sum exists")
	}
	leakcheck.Check(t, string(data))
}

func TestCommands(t *testing.T) {
	for _, c := range []struct {
		args       []string
		code       int
		out, error string // prefixes of standard output and standard error
	}{
		{nil, 2, "", "hush-interim: no command (see hush --help)\n"},
		{[]string{"--help"}, 0, "usage: hush scan [--terms FILE] PATH...\n", ""},
		{[]string{"-h"}, 0, "usage: hush scan", ""},
		{[]string{"scan", "--help"}, 0, "usage: hush scan [--terms FILE] PATH...\n", ""},
		{[]string{"version"}, 0, "hush ", ""},
		{[]string{"version", leakcheck.Bad}, 2, "", "hush-interim: version takes no arguments\n"},
		{[]string{leakcheck.Client}, 2, "", "hush-interim: unknown command (see hush --help)\n"},
		{[]string{"scan"}, 2, "", "hush-interim: give exactly one of PATH..., --range or --stdin (see --help)\n"},
	} {
		var out, errs strings.Builder
		code := run(c.args, strings.NewReader(""), &out, &errs)
		if code != c.code || !strings.HasPrefix(out.String(), c.out) || !strings.HasPrefix(errs.String(), c.error) ||
			(c.out == "") != (out.Len() == 0) || (c.error == "") != (errs.Len() == 0) {
			t.Errorf("hush %d args: exit %d, stdout %q, stderr %q", len(c.args), code, out.String(), errs.String())
		}
		leakcheck.Check(t, out.String(), errs.String())
	}
}
