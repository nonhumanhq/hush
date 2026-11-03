package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	lc "github.com/nonhumanhq/hush/internal/leakcheck"
	"github.com/nonhumanhq/hush/internal/schema"
)

// scan runs "hush scan ARGS" in this process with stdin as standard input,
// leak-checks both outputs, and returns the exit status and the outputs.
func scan(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errs strings.Builder
	code := run(append([]string{"scan"}, args...), strings.NewReader(stdin), &out, &errs)
	lc.Check(t, out.String(), errs.String())
	return code, out.String(), errs.String()
}

// termsAt writes content as a term file of mode 0600 in a new directory
// outside the scanned ones, and returns its path.
func termsAt(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "terms.txt")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// adrTerms is the term file of ADR-001's negative tests 2, 7, 8 and 20: set
// clients holds quorvel and declares the first label, and set people holds
// zantoph and declares the second (leakcheck's labels stand for k7 and k8).
func adrTerms() string {
	return "[clients visible-to=" + lc.LabelA + "]\n" + lc.Quorvel + "\n" +
		"[people visible-to=" + lc.LabelB + "]\n" + lc.Zantoph + "\n"
}

func writeFile(t *testing.T, name, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

var position = regexp.MustCompile(`^argument ([0-9]+): `)

// shifted returns msg with its argument position moved by n.
func shifted(msg string, n int) string {
	m := position.FindStringSubmatch(msg)
	if m == nil {
		return msg
	}
	k, _ := strconv.Atoi(m[1])
	return "argument " + strconv.Itoa(k+n) + ": " + msg[len(m[0]):]
}

// errorDoc returns the error of a JSON document that must pass the closed
// schema.
func errorDoc(t *testing.T, out string) (code, message string, argument, line int) {
	t.Helper()
	if err := schema.CheckLine(out); err != nil {
		t.Errorf("%v: %s", err, out)
		return
	}
	var doc struct {
		Error struct {
			Code, Message  string
			Argument, Line int
		}
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Error.Code, doc.Error.Message, doc.Error.Argument, doc.Error.Line
}

// ADR-001 section 5, "Arguments", and negative tests 1, 9, 10 and 14: every
// refusal exits 2 with standard output empty and one line that cites
// positions, never values. Each case runs again with "--format json" first:
// an error found before the destination and the target are parsed leaves
// standard output empty, and every later one writes a document whose code
// and message match (section 6.3).
func TestScanArguments(t *testing.T) {
	isolate(t)
	terms := termsAt(t, adrTerms())
	writeFile(t, "a.md", "clean\n")
	pub := []string{"--destination", "public", "--generic-only"}
	with := func(args ...string) []string { return append(append([]string{}, pub...), args...) }
	k7, k8 := "client:"+lc.LabelA, "client:"+lc.LabelB
	for _, c := range []struct {
		args []string
		code string // the JSON error code, or "" for an error before the document
		msg  string
	}{
		{[]string{"--destination"}, "", "argument 1: missing value (see hush scan --help)"},
		{[]string{"--" + lc.Quorvel, "."}, "", "argument 1: unknown option (see hush scan --help)"},
		{[]string{"--destination", "public", "-" + lc.Bad}, "", "argument 3: unknown option (see hush scan --help)"},
		{[]string{"--destination", "public", "--destination", "public", "--generic-only", "."}, "", "argument 3: option given twice"},
		{with("--stdin", "-"), "", "argument 5: option given twice"},
		{with(".", "--label", "x"), "", "argument 5: option after a path"},
		{with(".", "-"), "", "argument 5: option after a path"},
		{[]string{"--terms", terms, "--help", "."}, "", "argument 3: --help is accepted only alone"}, // test 14
		{with("--range", "HEAD~1..HEAD", "--range", "HEAD"), "", "argument 6: option given twice"},
		{with("--allow-empty-range", "."), "", "--allow-empty-range needs --range"},
		{with("--format", "xml", "."), "", "argument 5: unknown format"},
		{[]string{"--generic-only", "."}, "", "the scan needs --destination (see hush scan --help)"},
		{with(), "", msgTargets},
		{with("--stdin", "."), "", msgTargets},
		{with("--index", "--range", "HEAD"), "", msgTargets},
		{with("-C", "x", "."), "", "-C needs --range or --index"},
		{with("-C", "x", "--stdin"), "", "-C needs --range or --index"},
		{with("--label", "x", "."), "", "--label needs --stdin"},
		// Destinations (tests 8 and 10): the value is never echoed.
		{[]string{"--destination", "publc", "--generic-only", "."}, "", "argument 2: unknown destination"},
		{[]string{"--destination", "client:" + strings.ToUpper(lc.LabelA), "--terms", terms, "."}, "", "argument 2: malformed client label"},
		{[]string{"--destination", "client:" + lc.Quorvel, "--terms", terms, "."}, "destination", "argument 2: client label refused"},
		{[]string{"--destination", "client:korv9", "--terms", terms, "."}, "destination", "argument 2: the client label is not declared in the term file"},
		// Identities (ADR-002 test 4): malformed values, and the flag twice.
		{with("--identities", "", "."), "", "argument 5: identities: address 1 is malformed"},
		{with("--identities", lc.Identity+",", "."), "", "argument 5: identities: address 2 is malformed"},
		{with("--identities", lc.Identity+",,"+lc.Identity2, "."), "", "argument 5: identities: address 2 is malformed"},
		{with("--identities", lc.Identity2+",alice", "."), "", "argument 5: identities: address 2 is malformed"},
		{with("--identities", "@acme", "."), "", "argument 5: identities: address 1 is malformed"},
		{with("--identities", lc.Identity+"@", "."), "", "argument 5: identities: address 1 is malformed"},
		{with("--identities", "a "+lc.Identity, "."), "", "argument 5: identities: address 1 is malformed"},
		{with("--identities", "a\t"+lc.Identity, "."), "", "argument 5: identities: address 1 is malformed"},
		{with("--identities", "<"+lc.Identity+">", "."), "", "argument 5: identities: address 1 is malformed"},
		{with("--identities", lc.Identity, "--identities", lc.Identity, "."), "", "argument 6: option given twice"},
		// Coverage (tests 1 and 9): after the document is owed.
		{[]string{"--destination", "public", "."}, "coverage", "the public destination needs --terms FILE or --generic-only"},
		{[]string{"--destination", k7, "."}, "coverage", "a client destination needs --terms FILE"},
		{[]string{"--destination", "public", "--generic-only", "--terms", terms, "."}, "coverage", "--generic-only cannot be combined with --terms"},
		{[]string{"--destination", k7, "--generic-only", "."}, "coverage", "--generic-only is accepted only with the public destination"},
		{[]string{"--destination", "private", "--generic-only", "."}, "coverage", "--generic-only is accepted only with the public destination"},
		{[]string{"--destination", "private", "--terms", terms, "."}, "coverage", "the private destination takes no term file"},
		// The combination is checked before the term file is read.
		{[]string{"--destination", "private", "--terms", "missing.txt", "."}, "coverage", "the private destination takes no term file"},
		{[]string{"--destination", k8, "--terms", "missing.txt", "."}, "term-file", "term file: missing or unreadable"},
		// A value is taken verbatim, even one that starts with "-".
		{with("--range", "--all"), "git", "not a git repository"},
		{with("--range", "--not"), "range", "argument 5: range: nothing to include"},
		{with("--range", "HEAD --max-count=1"), "range", "argument 5: range: word 2 is refused"},
		{with("--range", "HEAD -- docs"), "range", "argument 5: range: word 2 is refused"},
		{with("--label", "-", "--stdin"), "label", "argument 5: stdin label refused"},
		{with("--label", "", "--stdin"), "label", "argument 5: stdin label refused"},
		{with("--label", lc.Bad, "-"), "label", "argument 5: stdin label refused"},
		{with("--label", "body text", "-"), "label", "argument 5: stdin label refused"},
		{[]string{"--destination", "public", "--terms", terms, "--label", "x" + lc.Quorvel, "--stdin"}, "label", "argument 6: stdin label refused"},
		{[]string{"--destination", "public", "--terms", terms, "--label", strings.ToUpper(lc.LabelA), "--stdin"}, "label", "argument 6: stdin label refused"},
		{[]string{"--destination", k7, "--terms", terms, "--label", lc.LabelB, "--stdin"}, "label", "argument 6: stdin label refused"},
		// A path error cites the path's position among scan's arguments, and
		// among the paths (HSH-11/D43).
		{with("missing.md"), "path", "argument 4: path argument 1 does not exist"},
		{with("--", "-x"), "path", "argument 5: path argument 1 does not exist"},
		{with("a.md", "nope"), "path", "argument 5: path argument 2 does not exist"},
		{with("--", "a.md", "nope"), "path", "argument 6: path argument 2 does not exist"},
	} {
		for _, json := range []bool{false, true} {
			if json && strings.Contains(strings.Join(c.args, " "), "--format") {
				continue
			}
			args, shift := c.args, 0
			if json {
				args, shift = append([]string{"--format", "json"}, c.args...), 2
			}
			code, out, errs := scan(t, "", args...)
			want := shifted(c.msg, shift)
			if code != 2 || errs != "hush: "+want+"\n" {
				t.Errorf("%q: exit %d, stderr %q, want %q", args, code, errs, want)
			}
			switch {
			case !json || c.code == "":
				if out != "" {
					t.Errorf("%q: standard output %q", args, out)
				}
			default:
				code, msg, arg, _ := errorDoc(t, out)
				wantArg := 0
				if m := position.FindStringSubmatch(want); m != nil {
					wantArg, _ = strconv.Atoi(m[1])
				}
				if code != c.code || msg != want || arg != wantArg {
					t.Errorf("%q: document %s", args, out)
				}
			}
		}
	}
	// Accepted: values taken verbatim, "-" as --stdin, "--" before a path
	// that starts with "-", --identities with every destination.
	writeFile(t, "-x", "clean\n")
	for _, args := range [][]string{
		with("a.md"),
		with("--", "-x"),
		with("--format", "plain", "--label", "issue-body", "-"),
		with("--identities", lc.Identity+","+strings.ToUpper(lc.Identity2), "a.md"),
		{"--destination", "private", "--identities", lc.Identity, "a.md"},
		{"--destination", "public", "--terms", terms, "--identities", lc.Identity, "a.md"},
		{"--destination", k8, "--terms", terms, "--identities", lc.Identity, "a.md"},
	} {
		if code, out, errs := scan(t, "clean\n", args...); code != 0 || out != "" || errs != "" {
			t.Errorf("%q: exit %d, stdout %q, stderr %q", args, code, out, errs)
		}
	}
	if code, out, errs := scan(t, "", "--help"); code != 0 || !strings.HasPrefix(out, "usage: hush scan --destination") || errs != "" {
		t.Errorf("--help alone: exit %d, stderr %q", code, errs)
	}
}

// ADR-001 negative tests 2 and 9 through the command line: a public scan
// applies every set, a client scan the sets that do not declare it, and a
// private scan runs the generic tier.
func TestScanDestinations(t *testing.T) {
	isolate(t)
	terms := termsAt(t, adrTerms())
	writeFile(t, "docs/a.md", strings.ToUpper(lc.Quorvel[:1])+lc.Quorvel[1:4]+strings.ToUpper(lc.Quorvel[4:5])+lc.Quorvel[5:]+"\n")
	writeFile(t, "id/b.md", "see "+lc.Bad+"\n")
	for _, c := range []struct {
		dest string
		code int
		out  string
	}{
		{"public", 1, "docs/a.md:1: set:clients\n"},
		{"client:" + lc.LabelB, 1, "docs/a.md:1: set:clients\n"},
		{"client:" + lc.LabelA, 0, ""},
	} {
		if code, out, errs := scan(t, "", "--destination", c.dest, "--terms", terms, "docs"); code != c.code || out != c.out || errs != "" {
			t.Errorf("%s: exit %d, stdout %q, stderr %q", c.dest, code, out, errs)
		}
	}
	if code, out, _ := scan(t, "", "--destination", "private", "id"); code != 1 || out != "id/b.md:1: id-prefix\n" {
		t.Errorf("private: exit %d, stdout %q", code, out)
	}
	// Both sets declare the label: no term applies (test 8).
	both := termsAt(t, "[clients visible-to="+lc.LabelA+"]\n"+lc.Quorvel+"\n[people visible-to="+lc.LabelA+"]\n"+lc.Zantoph+"\n")
	code, out, errs := scan(t, "", "--format", "json", "--destination", "client:"+lc.LabelA, "--terms", both, "docs")
	if c, msg, _, _ := errorDoc(t, out); code != 2 || c != "coverage" || msg != "no term applies to this destination" ||
		errs != "hush: no term applies to this destination\n" || strings.Contains(strings.ToLower(out+errs), lc.LabelA) {
		t.Errorf("no term applies: exit %d, %s, %q", code, out, errs)
	}
}

// ADR-001 negative test 20 and ADR-002 negative test 2 through the command
// line: the term file's mode, and its refusals, as fixed text with a line
// number only, in both formats; neither names the file.
func TestScanTermFile(t *testing.T) {
	isolate(t)
	writeFile(t, "a.md", "clean\n")
	q := lc.Quorvel
	for _, c := range []struct {
		file string
		mode os.FileMode
		msg  string
		line int
	}{
		{adrTerms(), 0o640, "term file: readable or writable by group or others", 0},
		{adrTerms(), 0o604, "term file: readable or writable by group or others", 0},
		{adrTerms(), 0o620, "term file: readable or writable by group or others", 0},
		{adrTerms(), 0o602, "term file: readable or writable by group or others", 0},
		{"[clients]\n" + q + "\x01\n", 0o600, "term file: line 2: bad character", 2},
		{"# a note\r" + q + "\n[clients]\nx\n", 0o600, "term file: line 1: bad character", 1},
		{"[" + q + "\n" + q + "\n", 0o600, "term file: line 1: bad header", 1},
		{"[" + q + " visible-to=K7]\nx\n", 0o600, "term file: line 1: bad client label", 1},
		{"[" + q + "-notes]\n" + q + "\n", 0o600, "term file: line 1: set name refused", 1},
		{"[clients visible-to=zan9]\nzan\n", 0o600, "term file: line 1: client label refused", 1},
		{"\n# " + q + "\n\n", 0o600, "term file holds no terms", 0},
	} {
		terms := termsAt(t, c.file)
		if err := os.Chmod(terms, c.mode); err != nil {
			t.Fatal(err)
		}
		code, out, errs := scan(t, "", "--format", "json", "--destination", "public", "--terms", terms, "a.md")
		cd, msg, arg, line := errorDoc(t, out)
		if code != 2 || errs != "hush: "+c.msg+"\n" || cd != "term-file" || msg != c.msg || arg != 0 || line != c.line {
			t.Errorf("%q at %o: exit %d, %s, %q", c.msg, c.mode, code, out, errs)
		}
		if strings.Contains(out+errs, terms) || strings.Contains(out+errs, "terms.txt") {
			t.Errorf("%q: the output names the term file", c.msg)
		}
		lc.Check(t, out, errs, terms)
	}
	// At mode 0600 the file loads, and so does a symlink to it, whatever the
	// link's own mode.
	terms := termsAt(t, adrTerms())
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(terms, link); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{terms, link} {
		if code, out, errs := scan(t, "", "--destination", "public", "--terms", p, "a.md"); code != 0 || out != "" || errs != "" {
			t.Errorf("mode 0600: exit %d, %q, %q", code, out, errs)
		}
	}
}

// ADR-002 negative test 1 for trees, and ADR-001 test 5's tree point: a term
// file inside a scanned path, an ancestor's scan, the file itself or a hard
// link to it exits 2 with code term-file before anything is scanned.
func TestScanTermFileInside(t *testing.T) {
	isolate(t)
	writeFile(t, "repo/docs/a.md", "see "+lc.Bad+"\n")
	writeFile(t, "repo/.hush/terms", adrTerms())
	if err := os.Chmod("repo/.hush/terms", 0o600); err != nil {
		t.Fatal(err)
	}
	outside := termsAt(t, adrTerms())
	if err := os.Link(outside, "repo/docs/link"); err != nil {
		t.Fatal(err)
	}
	const msg = "the term file is inside a scanned path"
	for _, c := range []struct{ terms, path string }{
		{"repo/.hush/terms", "repo"},
		{"repo/.hush/terms", "repo/.hush"},
		{"repo/.hush/terms", "repo/.hush/terms"},
		{"repo/.hush/terms", "."},
		{outside, "repo"},
		{outside, "repo/docs"},
		{outside, "repo/docs/link"},
	} {
		code, out, errs := scan(t, "", "--format", "json", "--destination", "public", "--terms", c.terms, c.path)
		if cd, m, _, _ := errorDoc(t, out); code != 2 || cd != "term-file" || m != msg || errs != "hush: "+msg+"\n" {
			t.Errorf("%s in %s: exit %d, %s, %q", c.terms, c.path, code, out, errs)
		}
	}
	// A term file committed in the repository is never loaded unless named.
	if code, out, _ := scan(t, "", "--destination", "public", "--generic-only", "repo"); code != 1 || out != "repo/docs/a.md:1: id-prefix\n" {
		t.Errorf("generic-only beside a committed term file: exit %d, %q", code, out)
	}
}

// ADR-001 negative tests 7 and 15 for trees: a component that holds a term,
// or that cannot print safely, prints as <redacted>; an unsafe name also gives
// unreadable in path, and its content is still scanned; a FIFO and a
// directory that cannot be read give unreadable, and the rest is scanned.
func TestScanTreeConditions(t *testing.T) {
	isolate(t)
	terms := termsAt(t, adrTerms())
	writeFile(t, "t7/docs/"+lc.Quorvel+"/plan.md", "clean\nsee "+lc.Bad+"\n")
	writeFile(t, "t7/"+lc.Quorvel+"-notes/a.md", "clean\n")
	code, out, _ := scan(t, "", "--destination", "public", "--terms", terms, "t7")
	want := "t7/docs/<redacted>:0: set:clients in path\nt7/docs/<redacted>:2: id-prefix\n" +
		"t7/<redacted>:0: set:clients in path\n"
	if code != 1 || out != want {
		t.Errorf("test 7: exit %d, stdout %q", code, out)
	}
	code, out, _ = scan(t, "", "--format", "json", "--destination", "client:"+lc.LabelA, "--terms", terms, "t7/docs")
	if err := schema.CheckLine(out); code != 1 || err != nil || !strings.Contains(out,
		`"findings":[{"kind":"match","tier":"generic","rule":"id-prefix","path":"t7/docs/<redacted>","path_redacted":true,"line":2,"where":"t7/docs/<redacted>"}]}`) {
		t.Errorf("test 7, exempt sets still redact: exit %d, %v, %s", code, err, out)
	}
	t.Chdir("t7")
	code, out, _ = scan(t, "", "--destination", "public", "--terms", terms, lc.Quorvel+"-notes")
	if code != 1 || out != "<redacted>:0: set:clients in path\n" {
		t.Errorf("test 7, first component: exit %d, stdout %q", code, out)
	}
	t.Chdir("..")

	bidi := "a‮z.md"
	writeFile(t, "t15/"+bidi, "see "+lc.Bad+"\n")
	writeFile(t, "t15/b\nc.md", "clean\n")
	writeFile(t, "t15/d.md", "clean\n")
	if err := syscall.Mkfifo("t15/fifo", 0o644); err != nil {
		t.Fatal(err)
	}
	writeFile(t, "t15/shut/e.md", "see "+lc.Bad+"\n")
	if err := os.Chmod("t15/shut", 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod("t15/shut", 0o755)
	want = "t15/<redacted>:0: unreadable in path\nt15/<redacted>:1: id-prefix\n" +
		"t15/<redacted>:0: unreadable in path\n" +
		"t15/fifo:0: unreadable\n"
	if os.Geteuid() != 0 {
		want += "t15/shut:0: unreadable\n"
	}
	code, out, errs := scan(t, "", "--destination", "public", "--generic-only", "t15")
	if code != 1 || out != want || errs != "" {
		t.Errorf("test 15: exit %d, stdout %q, stderr %q", code, out, errs)
	}
	code, out, _ = scan(t, "", "--format", "json", "--destination", "public", "--generic-only", "t15/fifo")
	if err := schema.CheckLine(out); code != 1 || err != nil || !strings.Contains(out,
		`"findings":[{"kind":"unscanned","rule":"unreadable","path":"t15/fifo","path_redacted":false,"line":0,"where":"t15/fifo"}]}`) {
		t.Errorf("FIFO in JSON: exit %d, %v, %s", code, err, out)
	}
	code, out, _ = scan(t, "", "--format", "json", "--destination", "public", "--generic-only", "t15/b\nc.md")
	if err := schema.CheckLine(out); code != 1 || err != nil || !strings.Contains(out,
		`"findings":[{"kind":"unscanned","rule":"unreadable","in_path":true,"path":"t15/<redacted>","path_redacted":true,"line":0,"where":"t15/<redacted>"}]}`) {
		t.Errorf("unsafe name in JSON: exit %d, %v, %s", code, err, out)
	}
}

// ADR-001 section 5, "Standard input and buffers": a NUL byte is
// binary-unscanned, empty input passes with no lines, and a stdin label is
// printed as given once it is checked.
func TestScanStdin(t *testing.T) {
	isolate(t)
	pub := []string{"--destination", "public", "--generic-only"}
	for _, c := range []struct {
		in, label string
		code      int
		out       string
	}{
		{"a\x00b\n", "", 1, "<stdin>:0: binary-unscanned\n"},
		{"ok\nsee " + lc.Bad + "\n", "issue-body", 1, "issue-body:2: id-prefix\n"},
		{"", "", 0, ""},
		{"ok", "Q.1_x-y", 0, ""},
	} {
		args := pub
		if c.label != "" {
			args = append(append([]string{}, pub...), "--label", c.label)
		}
		code, out, errs := scan(t, c.in, append(args, "-")...)
		if code != c.code || out != c.out || errs != "" {
			t.Errorf("%q: exit %d, stdout %q, stderr %q", c.in, code, out, errs)
		}
	}
	code, out, _ := scan(t, "", append([]string{"--format", "json"}, append(pub, "--stdin")...)...)
	if err := schema.CheckLine(out); code != 0 || err != nil || !strings.Contains(out, `"target":"stdin","scanned":{"files":0,"commits":0,"lines":0},"findings":[]}`) {
		t.Errorf("empty input in JSON: exit %d, %v, %s", code, err, out)
	}
}

// ADR-001 negative test 18: --index with GIT_INDEX_FILE naming a missing file,
// or set but empty, exits 2 before git runs.
func TestScanIndexFile(t *testing.T) {
	isolate(t)
	for _, value := range []string{filepath.Join(t.TempDir(), "missing"), ""} {
		t.Setenv("GIT_INDEX_FILE", value)
		code, out, errs := scan(t, "", "--format", "json", "--destination", "public", "--generic-only", "--index")
		const msg = "the index file is missing or not a regular file"
		if c, m, _, _ := errorDoc(t, out); code != 2 || c != "git" || m != msg || errs != "hush: "+msg+"\n" {
			t.Errorf("GIT_INDEX_FILE=%q: exit %d, %s, %q", value, code, out, errs)
		}
	}
}

// ADR-001 section 6.6: the core-dump size limit is zero once hush starts. The
// built binary runs under a shell that raises the soft limit first, waiting
// on standard input that stays open, and /proc must then show its limit as 0.
func TestLimitCore(t *testing.T) {
	if _, err := os.Stat("/proc/self/limits"); err != nil {
		t.Skip("no /proc")
	}
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &lim); err != nil || lim.Max < 1<<20 {
		t.Skip("the hard core size limit is too low to raise the soft one")
	}
	h := newHookEnv(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	c := exec.Command("sh", "-c", `ulimit -c 1024 || exit 99; exec "$0" "$@"`,
		h.hush, "scan", "--destination", "public", "--generic-only", "--stdin")
	var errs strings.Builder
	c.Dir, c.Env, c.Stdin, c.Stderr = h.root, h.env, r, &errs
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	r.Close()
	defer c.Process.Kill()
	limits := filepath.Join("/proc", strconv.Itoa(c.Process.Pid), "limits")
	exe := filepath.Join("/proc", strconv.Itoa(c.Process.Pid), "exe")
	core := regexp.MustCompile(`(?m)^Max core file size +(\S+)`)
	var last string
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if target, err := os.Readlink(exe); err != nil || target != h.hush {
			continue // still the shell
		}
		b, err := os.ReadFile(limits)
		if err != nil {
			t.Fatalf("hush ended: %v, stderr %q", err, errs.String())
		}
		if m := core.FindSubmatch(b); m != nil {
			if last = string(m[1]); last == "0" {
				w.Close()
				if code := wait(t, c); code != 0 {
					t.Errorf("exit %d, stderr %q", code, errs.String())
				}
				return
			}
		}
	}
	if last == "" {
		w.Close()
		if wait(t, c) == 99 {
			t.Skip("the shell cannot raise the core size limit")
		}
	}
	t.Errorf("hush's core size limit is %q, want 0", last)
	lc.Check(t, errs.String())
}
