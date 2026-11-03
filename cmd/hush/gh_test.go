package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	lc "github.com/nonhumanhq/hush/internal/leakcheck"
)

func TestGHArguments(t *testing.T) {
	isolate(t)
	for _, c := range []struct {
		args       []string
		code       int
		out, error string
	}{
		{[]string{"gh", "--help"}, 0, ghUsage, ""},
		{[]string{"gh"}, 2, "", "hush: gh takes -- GH-ARGUMENTS (see hush gh --help)\n"},
		{[]string{"gh", "issue", "create"}, 2, "", "hush: gh takes -- GH-ARGUMENTS (see hush gh --help)\n"},
		{[]string{"gh", "--terms", "t", "--", "issue"}, 2, "", "hush: gh takes -- GH-ARGUMENTS (see hush gh --help)\n"}, // HSH-9/D4
		{[]string{"gh", "--"}, 2, "", "hush: give a gh command after -- (see hush gh --help)\n"},
		{[]string{"gh", "--", "gist", "create", lc.Bad}, 2, "", "hush: gh gist create is not covered by hush gh (see hush gh --help)\n"},
	} {
		var out, errs strings.Builder
		code := run(c.args, strings.NewReader(""), &out, &errs)
		if code != c.code || out.String() != c.out || errs.String() != c.error {
			t.Errorf("hush %d args: exit %d, stdout %q, stderr %q", len(c.args), code, out.String(), errs.String())
		}
		lc.Check(t, out.String(), errs.String())
	}
}

// hush gh end to end: the built binary, and a fake gh alone on PATH that
// records its arguments.
func TestGHCommand(t *testing.T) {
	h := newHookEnv(t)
	bin := filepath.Join(h.root, "bin")
	args := filepath.Join(h.root, "gh-args")
	h.write(filepath.Join(bin, "gh"), "#!/bin/sh\nprintf '%s\\n' \"$@\" > '"+args+"'\necho posted\n")
	if err := os.Chmod(filepath.Join(bin, "gh"), 0o755); err != nil {
		t.Fatal(err)
	}
	path := []string{"PATH=" + bin}
	ghRan := func() string {
		data, err := os.ReadFile(args)
		if err != nil {
			return ""
		}
		os.Remove(args)
		return string(data) // what gh got, not what hush printed: the generic tier passes a term
	}

	code, out := h.run(h.root, path, h.hush, "gh", "--", "issue", "create", "-t", "x", "-b", "about "+lc.Client)
	h.expect("generic tier", code, out, 0, "posted\n")
	if got := ghRan(); got != "issue\ncreate\n--title=x\n--body=about "+lc.Client+"\n" {
		t.Errorf("generic tier: gh got %q", got)
	}
	code, out = h.run(h.root, path, h.hush, "gh", "--", "pr", "comment", "3", "-b", "see "+lc.Bad)
	h.expect("token", code, out, 1, "--body:1: id-prefix\n")
	code, out = h.run(h.root, path, h.hush, "gh", "--", "pr", "create", "--web")
	h.expect("browser flow", code, out, 2, "hush: gh pr create --web is not covered by hush gh (see hush gh --help)\n")
	if got := ghRan(); got != "" {
		t.Errorf("gh ran after a finding or a refusal: %q", got)
	}
}
