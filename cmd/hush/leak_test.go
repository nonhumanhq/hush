package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	lc "github.com/nonhumanhq/hush/internal/leakcheck"
)

// ADR-001 negative test 6's failure cases on the command line (HSH-11/T26):
// an unknown option whose text is a term, for scan and gh, and a panic
// injected in a test build, whose value holds a term and a rejected token.
// Nothing printed holds either. Package hush's tests hold the other cases.
func TestNegative6CommandLine(t *testing.T) {
	isolate(t)
	for _, args := range [][]string{
		{"scan", "--" + lc.Quorvel},
		{"scan", "--destination", "public", "--generic-only", "--" + lc.Bad, "."},
		{"scan", "--format", "json", "--destination", "public", "--generic-only", "--" + lc.Zantoph, "."},
		{"gh", "--" + lc.Quorvel, "--", "issue", "create"},
		{lc.Quorvel},
		{"hooks", "install", "--" + lc.Quorvel},
	} {
		var out, errs strings.Builder
		if code := run(args, strings.NewReader(""), &out, &errs); code != 2 || errs.Len() == 0 {
			t.Errorf("%d args: exit %d", len(args), code)
		}
		lc.Check(t, out.String(), errs.String())
	}
}

func TestNegative6InjectedPanic(t *testing.T) {
	h := newHookEnv(t)
	bin := filepath.Join(t.TempDir(), "hush-panic")
	if out, err := exec.Command("go", "build", "-buildvcs=false", "-tags", "hushpanic", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	input := filepath.Join(h.root, "in.md")
	h.write(input, "see "+lc.Quorvel+" and "+lc.Bad+"\n")
	for _, format := range []string{"plain", "json"} {
		c := exec.Command(bin, "scan", "--format", format, "--destination", "public", "--generic-only", "--stdin")
		c.Env = h.env
		in, err := os.Open(input)
		if err != nil {
			t.Fatal(err)
		}
		var out, errs strings.Builder
		c.Stdin, c.Stdout, c.Stderr = in, &out, &errs
		err = c.Run()
		in.Close()
		if c.ProcessState.ExitCode() != 2 || errs.String() != "hush: internal error; output withheld\n" {
			t.Errorf("%s: exit %d, %v, stderr %q", format, c.ProcessState.ExitCode(), err, errs.String())
		}
		if format == "json" {
			if code, msg, _, _ := errorDoc(t, out.String()); code != "internal" || msg != "internal error; output withheld" {
				t.Errorf("json: document %s", out.String())
			}
		} else if out.Len() != 0 {
			t.Errorf("plain: standard output %q", out.String())
		}
		lc.Check(t, out.String(), errs.String())
	}
}
