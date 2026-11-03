package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	lc "github.com/nonhumanhq/hush/internal/leakcheck"
)

// hush gh's options before "--", in this process: positions only, never
// values, and nothing runs (HSH-11/T24).
func TestGHArguments(t *testing.T) {
	table() // read errors.go before isolate leaves this directory
	isolate(t)
	terms := filepath.Join(t.TempDir(), "terms")
	if err := os.WriteFile(terms, []byte(lc.TermFile()), 0o600); err != nil {
		t.Fatal(err)
	}
	pub := []string{"gh", "--destination", "public", "--generic-only"}
	for _, c := range []struct {
		args       []string
		code       int
		out, error string
	}{
		{[]string{"gh", "--help"}, 0, ghUsage, ""},
		{[]string{"gh"}, 2, "", "hush: gh takes its options, then -- GH-ARGUMENTS (see hush gh --help)\n"},
		{[]string{"gh", "issue", "create"}, 2, "", "hush: gh takes its options, then -- GH-ARGUMENTS (see hush gh --help)\n"},
		{[]string{"gh", "--destination", "public", "--generic-only", "issue"}, 2, "",
			"hush: gh takes its options, then -- GH-ARGUMENTS (see hush gh --help)\n"},
		{[]string{"gh", "--", "issue", "create"}, 2, "", "hush: gh needs --destination (see hush gh --help)\n"},
		{[]string{"gh", "--generic-only", "--generic-only", "--"}, 2, "", "hush: argument 2: option given twice\n"},
		{[]string{"gh", "--destination", "public", "--destination", "public", "--"}, 2, "", "hush: argument 3: option given twice\n"},
		{[]string{"gh", "--terms"}, 2, "", "hush: argument 1: missing value (see hush gh --help)\n"},
		{[]string{"gh", "--" + lc.Client, "--"}, 2, "", "hush: argument 1: unknown option (see hush gh --help)\n"},
		{[]string{"gh", "--format", "json", "--"}, 2, "", "hush: argument 1: unknown option (see hush gh --help)\n"},
		{[]string{"gh", "--destination", "publc", "--generic-only", "--", "issue"}, 2, "", "hush: argument 2: unknown destination\n"},
		{[]string{"gh", "--destination", "public", "--", "issue"}, 2, "",
			"hush: the public destination needs --terms FILE or --generic-only\n"},
		{[]string{"gh", "--destination", "private", "--generic-only", "--", "issue"}, 2, "",
			"hush: --generic-only is accepted only with the public destination\n"},
		{[]string{"gh", "--destination", "public", "--generic-only", "--identities", lc.Bad, "--", "issue"}, 2, "",
			"hush: argument 5: identities: address 1 is malformed\n"},
		{append(pub, "--"), 2, "", "hush: give a gh command after -- (see hush gh --help)\n"},
		{append(pub, "--", "gist", "create", lc.Bad), 2, "", "hush: gh gist create is not covered by hush gh (see hush gh --help)\n"},
		// A word prints only as a stdin label would: with the term sets, a
		// term is never one (HSH-11/D60).
		{[]string{"gh", "--destination", "public", "--terms", terms, "--", lc.Client, "create"}, 2, "",
			"hush: gh <redacted> create is not covered by hush gh (see hush gh --help)\n"},
		{[]string{"gh", "--destination", "public", "--terms", terms, "--", "issue", "comment", "-b", "x", "--" + lc.Person}, 2, "",
			"hush: gh issue comment: argument 5 is a flag hush gh does not know (see hush gh --help)\n"},
	} {
		var out, errs strings.Builder
		code := run(c.args, strings.NewReader(""), &out, &errs)
		if code != c.code || out.String() != c.out || errs.String() != c.error {
			t.Errorf("hush %d args: exit %d, stdout %q, stderr %q", len(c.args), code, out.String(), errs.String())
		}
		// internal/ghwrap's own messages are not the scan's; the rest are.
		line := strings.TrimSuffix(strings.TrimPrefix(errs.String(), "hush: "), "\n")
		ghwrap := strings.HasSuffix(line, "(see hush gh --help)") && !strings.HasPrefix(line, "argument ") && !strings.HasPrefix(line, "gh takes") &&
			!strings.HasPrefix(line, "gh needs")
		if line != "" && !ghwrap && !inTable(line) {
			t.Errorf("hush %d args: the error line is not in the message table", len(c.args))
		}
		lc.Check(t, out.String(), errs.String())
	}
}

// hush gh end to end: the built binary, and a fake gh alone on PATH that
// records its arguments and its standard input. Findings print as hush scan
// prints them, with the labels of HSH-11/D8; a body file reaches gh on its
// standard input (D9); the term sets apply by destination, and the
// identities pass where they stand as an identity.
func TestGHCommand(t *testing.T) {
	h := newHookEnv(t)
	bin := filepath.Join(h.root, "bin")
	args, in := filepath.Join(h.root, "gh-args"), filepath.Join(h.root, "gh-stdin")
	h.write(filepath.Join(bin, "gh"), "#!/bin/sh\nprintf '%s\\n' \"$@\" > '"+args+"'\ncat > '"+in+"'\necho posted\n")
	if err := os.Chmod(filepath.Join(bin, "gh"), 0o755); err != nil {
		t.Fatal(err)
	}
	cat, err := exec.LookPath("cat")
	if err != nil {
		t.Fatal("the test needs cat")
	}
	if err := os.Symlink(cat, filepath.Join(bin, "cat")); err != nil {
		t.Fatal(err)
	}
	terms := filepath.Join(h.root, "terms")
	if err := os.WriteFile(terms, []byte("[clients visible-to="+lc.LabelA+"]\n"+lc.Quorvel+"\n[people]\n"+lc.Zantoph+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := []string{"PATH=" + bin}
	ghRan := func() (string, string) {
		data, err := os.ReadFile(args)
		if err != nil {
			return "", ""
		}
		stdin, _ := os.ReadFile(in)
		os.Remove(args)
		os.Remove(in)
		return string(data), string(stdin) // what gh got, which may hold what the tier passes
	}
	generic := []string{"gh", "--destination", "public", "--generic-only", "--"}
	withTerms := func(dest string) []string { return []string{"gh", "--destination", dest, "--terms", terms, "--"} }

	code, out := h.run(h.root, path, h.hush, append(generic, "issue", "create", "-t", "x", "-b", "about "+lc.Quorvel)...)
	h.expect("generic tier", code, out, 0, "posted\n")
	if got, _ := ghRan(); got != "issue\ncreate\n--title=x\n--body=about "+lc.Quorvel+"\n" {
		t.Errorf("generic tier: gh got %q", got)
	}
	code, out = h.run(h.root, path, h.hush, append(generic, "pr", "comment", "3", "-b", "see "+lc.Bad)...)
	h.expect("token", code, out, 1, "body:1: id-prefix\n")
	code, out = h.run(h.root, path, h.hush, append(withTerms("public"), "issue", "create", "-t", "x", "-b", "about "+lc.Quorvel)...)
	h.expect("term, public", code, out, 1, "body:1: set:clients\n")
	code, out = h.run(h.root, path, h.hush, append(withTerms("client:"+lc.LabelA), "issue", "create", "-t", "x", "-b", "about "+lc.Quorvel)...)
	h.expect("term, the client it is visible to", code, out, 0, "posted\n")
	ghRan()
	code, out = h.run(h.root, path, h.hush, append(generic, "pr", "create", "--web")...)
	h.expect("browser flow", code, out, 2, "hush: gh pr create --web is not covered by hush gh (see hush gh --help)\n")
	if got, _ := ghRan(); got != "" {
		t.Errorf("gh ran after a finding or a refusal: %q", got)
	}

	// A body file on gh's standard input, past one argument's limit.
	body := filepath.Join(h.root, "body.md")
	h.write(body, strings.Repeat("a", 200*1024)+"\nend\n")
	code, out = h.run(h.root, path, h.hush, append(generic, "issue", "comment", "5", "--body-file", body)...)
	h.expect("long body file", code, out, 0, "posted\n")
	if got, stdin := ghRan(); got != "issue\ncomment\n--body-file=-\n5\n" || stdin != h.read(body) {
		t.Errorf("long body file: gh got %q and %d bytes", got, len(stdin))
	}

	// The identities pass in a trailer, and stay flagged elsewhere.
	ids := []string{"gh", "--destination", "public", "--generic-only", "--identities", lc.Identity, "--"}
	code, out = h.run(h.root, path, h.hush, append(ids, "pr", "comment", "3", "-b", "x\n\n"+lc.TrailerLine)...)
	h.expect("identity in a trailer", code, out, 0, "posted\n")
	ghRan()
	code, out = h.run(h.root, path, h.hush, append(generic, "pr", "comment", "3", "-b", "x\n\n"+lc.TrailerLine)...)
	h.expect("identity without --identities", code, out, 1, "body:3: email-address\n")
}
