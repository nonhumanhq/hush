package main

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/nonhumanhq/hush/internal/leakcheck"
)

// TestMain keeps the in-process runs from lowering this process's core-dump
// limit: a hard limit of 0 is inherited by every child and cannot be raised,
// so TestLimitCore could not raise it for the built binary (HSH-11/D44).
func TestMain(m *testing.M) {
	setCoreLimit = func() {}
	os.Exit(m.Run())
}

// run runs one hush command in this process, as main does but with no
// signals, and returns its exit status.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	p := &process{stdin: stdin, stdout: stdout, stderr: stderr}
	return p.run(context.Background(), args)
}

func TestCommands(t *testing.T) {
	for _, c := range []struct {
		args       []string
		code       int
		out, error string // prefixes of standard output and standard error
	}{
		{nil, 2, "", "hush: no command (see hush --help)\n"},
		{[]string{"--help"}, 0, "usage: hush scan --destination DEST [--terms FILE | --generic-only]\n", ""},
		{[]string{"-h"}, 0, "usage: hush scan", ""},
		{[]string{"--help", "scan"}, 2, "", "hush: --help is accepted only alone\n"},
		{[]string{"scan", "--help"}, 0, "usage: hush scan --destination DEST [--terms FILE | --generic-only]\n", ""},
		{[]string{"version"}, 0, "hush ", ""},
		{[]string{"version", leakcheck.Bad}, 2, "", "hush: version takes no arguments\n"},
		{[]string{leakcheck.Client}, 2, "", "hush: unknown command (see hush --help)\n"},
		{[]string{"scan"}, 2, "", "hush: the scan needs --destination (see hush scan --help)\n"},
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
