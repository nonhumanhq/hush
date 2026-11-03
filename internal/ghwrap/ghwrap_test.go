package ghwrap

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	lc "github.com/nonhumanhq/hush/internal/leakcheck"
	"github.com/nonhumanhq/hush/internal/output"
	"github.com/nonhumanhq/hush/internal/rule"
	"github.com/nonhumanhq/hush/internal/target"
	"github.com/nonhumanhq/hush/internal/termset"
)

// The test binary is also the fake gh: linked as "gh", alone on PATH, it
// records its arguments, its standard input and GH_PROMPT_DISABLED, and exits
// as told. The real gh is never found, and nothing reaches the network
// (HSH-9/D13).
func TestMain(m *testing.M) {
	if filepath.Base(os.Args[0]) == "gh" {
		fakeGH()
	}
	os.Exit(m.Run())
}

func fakeGH() {
	dir := os.Getenv("FAKE_GH_DIR")
	var args []byte
	for _, a := range os.Args[1:] {
		args = append(append(args, a...), 0)
	}
	in, err := io.ReadAll(os.Stdin)
	prompt, set := os.LookupEnv("GH_PROMPT_DISABLED")
	if !set {
		prompt = "(unset)"
	}
	if err != nil || os.WriteFile(filepath.Join(dir, "args"), args, 0o600) != nil ||
		os.WriteFile(filepath.Join(dir, "stdin"), in, 0o600) != nil ||
		os.WriteFile(filepath.Join(dir, "prompt"), []byte(prompt), 0o600) != nil {
		os.Exit(99)
	}
	io.WriteString(os.Stdout, "gh output\n")
	code, _ := strconv.Atoi(os.Getenv("FAKE_GH_EXIT"))
	if code < 0 {
		syscall.Kill(os.Getpid(), syscall.SIGKILL)
	}
	os.Exit(code)
}

// fake puts the fake gh alone on PATH and returns its directory.
func fake(t *testing.T) string {
	dir := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(exe, filepath.Join(dir, "gh")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("FAKE_GH_DIR", dir)
	t.Setenv("FAKE_GH_EXIT", "0")
	t.Setenv("GH_PROMPT_DISABLED", "") // restored when the test ends
	os.Unsetenv("GH_PROMPT_DISABLED")
	return dir
}

// called returns what the fake gh recorded, and forgets it. A gh that ran
// must have had GH_PROMPT_DISABLED=1 (HSH-9/D6).
func called(t *testing.T, dir string) (args []string, stdin string, ok bool) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "args"))
	if err != nil {
		return nil, "", false
	}
	in, _ := os.ReadFile(filepath.Join(dir, "stdin"))
	if prompt, _ := os.ReadFile(filepath.Join(dir, "prompt")); string(prompt) != "1" {
		t.Errorf("gh ran with GH_PROMPT_DISABLED %q, want 1", prompt)
	}
	os.Remove(filepath.Join(dir, "args"))
	os.Remove(filepath.Join(dir, "stdin"))
	os.Remove(filepath.Join(dir, "prompt"))
	args = strings.Split(strings.TrimSuffix(string(data), "\x00"), "\x00")
	lc.Check(t, string(data), string(in))
	return args, string(in), true
}

// scanner returns a scan with the ID-prefix rule and, if terms, the
// synthetic term sets.
func scanner(t *testing.T, out io.Writer, terms bool) *target.Scan {
	s := &target.Scan{Rules: rule.List{rule.IDPrefix{}}, Out: output.New(out)}
	if terms {
		sets, err := termset.Parse([]byte(lc.TermFile()))
		if err != nil {
			t.Fatal("parse failed")
		}
		for _, set := range sets {
			s.Rules = append(s.Rules, set)
		}
	}
	return s
}

func TestRun(t *testing.T) {
	dir := fake(t)
	files := t.TempDir()
	file := func(name, content string) string {
		p := filepath.Join(files, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	body, badBody := file("body.md", "one\ntwo\n"), file("bad.md", "one\nsee "+lc.Bad+"\n")
	req := file("req.json", `{"body":"clean"}`)
	edge := strings.Repeat("a", maxArg-1-len("--body=")) // the longest body one argument holds (HSH-9/D9)
	edgeFile := file("edge.md", edge)
	esc := strings.Replace(lc.Bad, "-", `\u002d`, 1) // the token behind a JSON escape
	for _, c := range []struct {
		name   string
		terms  bool
		args   []string
		stdin  string
		code   int
		out    string   // hush's findings, or the fake gh's own output
		ghArgs []string // nil: gh must not run
		ghIn   string
	}{
		{"clean issue create", false, []string{"issue", "create", "-t", "HSH-9: hooks", "--body", "one\ntwo"}, "",
			0, "gh output\n", []string{"issue", "create", "--title=HSH-9: hooks", "--body=one\ntwo"}, ""},
		{"token in a title", false, []string{"issue", "create", "--title=see " + lc.Bad, "-b", "x"}, "",
			1, "--title:1: id-prefix\n", nil, ""},
		{"token on a body's third line", false, []string{"pr", "edit", "4", "-b", "one\ntwo\n" + lc.Bad}, "",
			1, "--body:3: id-prefix\n", nil, ""},
		{"body file", false, []string{"pr", "create", "-F", body, "-t", "x", "-d"}, "",
			0, "gh output\n", []string{"pr", "create", "--body=one\ntwo\n", "--title=x", "--draft"}, ""},
		{"token in a body file", false, []string{"issue", "comment", "5", "--body-file=" + badBody}, "",
			1, "--body-file:2: id-prefix\n", nil, ""},
		{"body file on standard input", false, []string{"issue", "comment", "5", "-F", "-"}, "ok\n",
			0, "gh output\n", []string{"issue", "comment", "--body=ok\n", "5"}, ""},
		{"token on standard input", false, []string{"pr", "review", "7", "-c", "--body-file", "-"}, "x\n" + lc.Bad,
			1, "--body-file:2: id-prefix\n", nil, ""},
		{"grouped shorthands", false, []string{"pr", "review", "7", "-cbsee " + lc.Bad}, "",
			1, "--body:1: id-prefix\n", nil, ""},
		{"value after a shorthand group", false, []string{"pr", "review", "-cb", "fine", "7"}, "",
			0, "gh output\n", []string{"pr", "review", "--comment", "--body=fine", "7"}, ""},
		{"closing comment", false, []string{"issue", "close", "3", "-c", "see " + lc.Bad, "-r", "not planned"}, "",
			1, "--comment:1: id-prefix\n", nil, ""},
		{"alias", false, []string{"issue", "new", "-t", lc.Bad, "-b", "x"}, "",
			1, "--title:1: id-prefix\n", nil, ""},
		{"term in a body", true, []string{"pr", "comment", "-b", "about " + lc.Client}, "",
			1, "--body:1: set:clients\n", nil, ""},
		{"api fields", false, []string{"api", "repos/acme/x/issues/1/comments", "-X", "POST", "-f", "body=clean",
			"-F", "note=@" + body, "-F", "n=3", "--jq", ".id"}, "",
			0, "gh output\n", []string{"api", "--method=POST", "--raw-field=body=clean", "--raw-field=note=one\ntwo\n",
				"--field=n=3", "--jq=.id", "repos/acme/x/issues/1/comments"}, ""},
		{"token in an api field", false, []string{"api", "graphql", "-f", "query=one\n" + lc.Bad}, "",
			1, "--raw-field query:2: id-prefix\n", nil, ""},
		{"token in an api file field", false, []string{"api", "x", "-F", "body=@" + badBody}, "",
			1, "--field body:2: id-prefix\n", nil, ""},
		{"token in a field on standard input", false, []string{"api", "x", "-F", "body=@-"}, lc.Bad,
			1, "--field body:1: id-prefix\n", nil, ""},
		{"token in a key", false, []string{"api", "x", "-f", lc.Bad + "=v"}, "",
			1, "--raw-field <redacted>:1: id-prefix\n", nil, ""},
		{"term in a key", true, []string{"api", "x", "-f", strings.ToLower(lc.Person) + "=v"}, "",
			1, "--raw-field <redacted>:1: set:people\n", nil, ""},
		{"token in the endpoint", false, []string{"api", "search/issues?q=" + lc.Bad}, "",
			1, "endpoint:1: id-prefix\n", nil, ""},
		{"a GET of the contents API", false, []string{"api", "repos/acme/x/contents/notes.md"}, "",
			0, "gh output\n", []string{"api", "repos/acme/x/contents/notes.md"}, ""},
		{"a GET of the contents API with fields", false, []string{"api", "-X", "get", "repos/acme/x/contents/a.md", "-f", "ref=main"}, "",
			0, "gh output\n", []string{"api", "--method=get", "--raw-field=ref=main", "repos/acme/x/contents/a.md"}, ""},
		{"placeholders gh fills in the endpoint name the repository", false,
			[]string{"api", "repos/{owner}/{repo}/issues", "-F", "title={x}", "-f", "body=from {branch} and :repo"}, "",
			0, "gh output\n", []string{"api", "--field=title={x}", "--raw-field=body=from {branch} and :repo", "repos/{owner}/{repo}/issues"}, ""},
		{"api input from a file", false, []string{"api", "x", "--input", req}, "",
			0, "gh output\n", []string{"api", "--input=-", "x"}, `{"body":"clean"}`},
		{"token in api input on standard input", false, []string{"api", "x", "--input", "-"}, `{"body":"` + lc.Bad + `"}`,
			1, "--input:1: id-prefix\n--input (decoded):1: id-prefix\n", nil, ""},
		{"token behind a JSON escape in api input", false, []string{"api", "repos/acme/x/issues/1/comments", "--input", "-"},
			`{"body":"see ` + strings.Replace(lc.Bad, "-", `\u002d`, 1) + `"}`, 1, "--input (decoded):1: id-prefix\n", nil, ""},
		// The walk keeps numbers as text, reads every top-level value, and
		// skips a byte order mark (HSH-9/D8).
		{"a number past float64 beside a JSON escape in api input", false, []string{"api", "repos/acme/x/issues/1/comments", "--input", "-"},
			`{"n":1e999,"body":"see ` + esc + `"}`, 1, "--input (decoded):1: id-prefix\n", nil, ""},
		{"a JSON escape in the second top-level value of api input", false, []string{"api", "x", "--input", "-"},
			`{"body":"clean"} {"body":"see ` + esc + `"}`, 1, "--input (decoded):1: id-prefix\n", nil, ""},
		{"a JSON escape in api input after a byte order mark", false, []string{"api", "x", "--input", "-"},
			"\uFEFF" + `{"body":"see ` + esc + `"}`, 1, "--input (decoded):1: id-prefix\n", nil, ""},
		{"a body file as long as one argument allows", false, []string{"issue", "comment", "5", "-F", edgeFile}, "",
			0, "gh output\n", []string{"issue", "comment", "--body=" + edge, "5"}, ""},
		{"positional arguments after --", false, []string{"issue", "edit", "-t", "x", "--", "-5"}, "",
			0, "gh output\n", []string{"issue", "edit", "--title=x", "--", "-5"}, ""},
		{"read-only command, as given, never with hush's standard input", false, []string{"pr", "view", "5", "--json", "title"}, "x\n",
			0, "gh output\n", []string{"pr", "view", "5", "--json", "title"}, ""},
		{"no standard input for gh unless it posts it", false, []string{"issue", "comment", "5", "-b", "x"}, "y\n",
			0, "gh output\n", []string{"issue", "comment", "--body=x", "5"}, ""},
		{"several findings, all printed", false, []string{"issue", "create", "-t", lc.Bad, "-b", lc.Near}, "",
			1, "--title:1: id-prefix\n--body:1: id-prefix\n", nil, ""},
	} {
		var out, errs strings.Builder
		code, err := Run(scanner(t, &out, c.terms), c.args, strings.NewReader(c.stdin), &out, &errs)
		ghArgs, ghIn, ran := called(t, dir)
		if err != nil || code != c.code || out.String() != c.out || errs.Len() != 0 {
			t.Errorf("%s: exit %d, error %v, stdout %q, stderr %q", c.name, code, err, out.String(), errs.String())
		}
		if ran != (c.ghArgs != nil) || fmt.Sprintf("%q", ghArgs) != fmt.Sprintf("%q", c.ghArgs) || ghIn != c.ghIn {
			t.Errorf("%s: gh ran %t with %q and standard input %q", c.name, ran, ghArgs, ghIn)
		}
		lc.Check(t, out.String(), errs.String(), fmt.Sprint(err))
	}
}

func TestRefused(t *testing.T) {
	dir := fake(t)
	notCovered := " is not covered by hush gh (see hush gh --help)"
	over := filepath.Join(t.TempDir(), "over.md") // one byte more than an argument holds as --body=CONTENT
	if err := os.WriteFile(over, []byte(strings.Repeat("a", maxArg-len("--body="))), 0o644); err != nil {
		t.Fatal(err)
	}
	tooLong := " is too long for one argument to gh (128 KiB at most)"
	file := func(name, content string) string {
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	mutation := file("m.graphql", "mutation { createCommitOnBranch(input: $input) { commit { oid } } }")
	nul := file("nul.bin", "\x1f\x8b\x08\x00\x00\x00\x00\x00")
	fills := " holds {owner}, {repo} or {branch}, or :owner, :repo or :branch, which gh fills in after the scan; " +
		"give it with --raw-field, which fills nothing"
	branch := "gh api: the endpoint holds {branch} or :branch, which gh fills in after the scan"
	base64 := " sends file contents as base64, which hush gh cannot scan"
	contents := "gh api: a write to the contents or git blobs API" + base64
	notUTF8 := "gh api: --input is not valid UTF8, so it is not text that hush gh can scan"
	for _, c := range []struct {
		terms bool
		args  []string
		stdin string
		want  string
	}{
		{false, nil, "", "give a gh command after -- (see hush gh --help)"},
		{false, []string{"--version"}, "", "give a gh command after -- (see hush gh --help)"},
		{false, []string{"release", "create", "v1", "--notes", "x"}, "", "gh release create" + notCovered},
		{false, []string{"issue", "develop", "3"}, "", "gh issue develop" + notCovered},
		{false, []string{"pr", "merge", "3", "--body", "x"}, "", "gh pr merge" + notCovered},
		{false, []string{"issue"}, "", "gh issue" + notCovered},
		{false, []string{lc.Bad}, "", "gh <redacted>" + notCovered},
		{true, []string{"issue", strings.ToLower(lc.Client)}, "", "gh issue <redacted>" + notCovered},
		{false, []string{"issue", "-R", "acme/x", "create"}, "", "gh issue: give the command before any flag (see hush gh --help)"},
		{false, []string{"gist", "-p"}, "", "gh gist" + notCovered},
		{false, []string{"issue", "create", "--editor"}, "", "gh issue create --editor" + notCovered},
		{false, []string{"issue", "create", "-t", "x", "-dw"}, "", "gh issue create: argument 5 is a flag hush gh does not know (see hush gh --help)"},
		{false, []string{"pr", "create", "-t", "x", "-dw"}, "", "gh pr create --web" + notCovered},
		{false, []string{"pr", "create", "--fill"}, "", "gh pr create --fill" + notCovered},
		{false, []string{"pr", "create", "-T", "bug.md"}, "", "gh pr create --template" + notCovered},
		{false, []string{"issue", "comment", "5", "--attach", "a.png#see"}, "", "gh issue comment --attach" + notCovered},
		{false, []string{"issue", "create", "--titel", "x"}, "", "gh issue create: argument 3 is a flag hush gh does not know (see hush gh --help)"},
		{false, []string{"issue", "create", "--" + lc.Bad}, "", "gh issue create: argument 3 is a flag hush gh does not know (see hush gh --help)"},
		{false, []string{"issue", "create", "-t"}, "", "gh issue create: --title needs a value"},
		{false, []string{"issue", "create", "-b", "x", "-F", "-"}, "y", "gh issue create: give --body or --body-file, not both"},
		{false, []string{"api", "x", "--input", "-", "-F", "a=@-"}, "{}", "gh api: standard input is named twice"},
		{false, []string{"issue", "create", "-F", filepath.Join(dir, "missing.md")}, "", "gh issue create: cannot read --body-file"},
		{false, []string{"api", "x", "-F", lc.Bad + "=@" + filepath.Join(dir, "missing")}, "", "gh api: cannot read --field <redacted>"},
		{false, []string{"issue", "comment", "5", "-F", over}, "", "gh issue comment: --body-file" + tooLong},
		{false, []string{"api", "x", "-F", "content=@" + over}, "", "gh api: --field content" + tooLong + "; --input has no such limit"},
		// gh fills placeholders after the scan (HSH-9/D8).
		{false, []string{"api", "repos/{owner}/{repo}/issues", "-F", "title=hello", "-F", "body=from {branch}"}, "", "gh api: --field body" + fills},
		{false, []string{"api", "x", "-F", "body=see :branch"}, "", "gh api: --field body" + fills},
		{false, []string{"api", "x", "--field=o={owner}"}, "", "gh api: --field o" + fills},
		{false, []string{"api", "x", "-F", lc.Bad + "=a:repo"}, "", "gh api: --field <redacted>" + fills},
		{false, []string{"api", "-X", "PUT", "repos/{owner}/{repo}/git/refs/heads/{branch}"}, "", branch},
		{false, []string{"api", "repos/acme/x/branches/:branch"}, "", branch},
		// Payloads GitHub decodes (HSH-9/D7).
		{false, []string{"api", "-X", "PUT", "repos/acme/x/contents/notes.md", "-f", "message=m", "-f", "content=c2Vl"}, "", contents},
		{false, []string{"api", "repos/acme/x/contents/notes.md", "-f", "content=c2Vl"}, "", contents},
		{false, []string{"api", "-X", "PUT", "/repos/acme/x/Contents/a.md"}, "", contents},
		{false, []string{"api", "repos/acme/x/git/blobs", "-f", "content=c2Vl", "-f", "encoding=base64"}, "", contents},
		{false, []string{"api", "-X", "POST", "repos/acme/x/git/blobs/"}, "", contents},
		{false, []string{"api", "-XPOST", "repos/acme/x/git/blobs?a=b"}, "", contents},
		{false, []string{"api", "-X", "GET", "-X", "PUT", "repos/acme/x/contents/a.md"}, "", contents},
		{false, []string{"api", "repos/acme/x/git//blobs", "-f", "content=c2Vl", "-f", "encoding=base64"}, "", contents},
		{false, []string{"api", "-X", "PUT", "repos/acme/x/%63ontents/notes.md", "-f", "content=c2Vl"}, "", contents},
		{false, []string{"api", "repos/acme/x/issues/1%zz"}, "", "gh api: the endpoint holds a percent sign that is not an escape"},
		{false, []string{"api", "https://example.com/repos/acme/x/releases/1/assets?name=a.gz"}, "",
			"gh api: an endpoint given as a full URL is not covered by hush gh (give its path)"},
		{false, []string{"api", "graphql", "-f", "query=mutation { createCommitOnBranch(input: $i) { commit { oid } } }"}, "",
			"gh api: createCommitOnBranch" + base64},
		{false, []string{"api", "graphql", "-F", "query=@" + mutation}, "", "gh api: createCommitOnBranch" + base64},
		{false, []string{"api", "graphql", "--input", "-"}, `{"query":"mutation { createCommitOnBranch }"}`, "gh api: createCommitOnBranch" + base64},
		{false, []string{"api", "graphql", "--input", "-"}, `{"query":"mutation { create\u0043ommitOnBranch }"}`, "gh api: createCommitOnBranch" + base64},
		// An --input that is not UTF8, such as a gzip file, or an invalid byte
		// past the point where the walk stops, is refused (HSH-9/D8).
		{false, []string{"api", "x", "--input", nul}, "", notUTF8},
		{false, []string{"api", "repos/acme/x/issues/1/comments", "--input", "-"},
			`{/* c */ "body":"see ` + strings.Replace(lc.Bad, "-", "\xff-", 1) + `"}`, notUTF8},
		{false, []string{"api", "x", "--input", "-"}, `{"body":"a\u0000b"}`,
			"gh api: --input (decoded) holds a NUL byte, so it is not text that hush gh can scan"},
		// Past a comment the walk stops, and an escape after it could hide
		// text (HSH-9/D8).
		{false, []string{"api", "repos/acme/x/issues/1/comments", "--input", "-"},
			`{"body":/**/"see ` + strings.Replace(lc.Bad, "-", `\u002d`, 1) + `"}`,
			"gh api: --input holds an escape but is not JSON hush can read"},
		// A lone surrogate decodes to U+FFFD and would hide the token from the
		// decoded scan, even beside a raw U+FFFD (HSH-9/D8).
		{false, []string{"api", "repos/acme/x/issues/1/comments", "--input", "-"},
			`{"body":"see ` + strings.Replace(lc.Bad, "-", `\ud800-`, 1) + `"}`,
			"gh api: --input holds an escape or a byte that decodes to U+FFFD"},
		{false, []string{"api", "repos/acme/x/issues/1/comments", "--input", "-"},
			"{\"note\":\"\uFFFD\",\"body\":\"see " + strings.Replace(lc.Bad, "-", `\ud800-`, 1) + "\"}",
			"gh api: --input holds an escape or a byte that decodes to U+FFFD"},
		{false, []string{"issue", "comment", "5", "-F", nul}, "", "gh issue comment: --body-file holds a NUL byte, so it is not text that hush gh can scan"},
		{false, []string{"pr", "comment", "5", "-F", "-"}, "a\x00b", "gh pr comment: --body-file holds a NUL byte, so it is not text that hush gh can scan"},
	} {
		var out, errs strings.Builder
		code, err := Run(scanner(t, &out, c.terms), c.args, strings.NewReader(c.stdin), &out, &errs)
		_, _, ran := called(t, dir)
		if code != 2 || fmt.Sprint(err) != c.want || out.Len() != 0 || errs.Len() != 0 || ran {
			t.Errorf("%d args: exit %d, error %v, stdout %q, gh ran %t; want %q", len(c.args), code, err, out.String(), ran, c.want)
		}
		lc.Check(t, out.String(), errs.String(), fmt.Sprint(err))
	}
}

// gh's own exit status is hush gh's, and a gh killed by a signal never
// gives 0.
func TestGHStatus(t *testing.T) {
	dir := fake(t)
	args := []string{"issue", "comment", "5", "-b", "fine"}
	for _, c := range []struct {
		exit string
		code int
		err  string
	}{{"3", 3, "<nil>"}, {"1", 1, "<nil>"}, {"-1", 2, "gh did not exit normally"}} {
		t.Setenv("FAKE_GH_EXIT", c.exit)
		var out strings.Builder
		code, err := Run(scanner(t, &out, false), args, strings.NewReader(""), &out, &out)
		_, _, ran := called(t, dir)
		if code != c.code || fmt.Sprint(err) != c.err || (c.exit != "-1" && !ran) {
			t.Errorf("gh exit %s: exit %d, error %v, gh ran %t", c.exit, code, err, ran)
		}
		lc.Check(t, out.String(), fmt.Sprint(err))
	}
	t.Setenv("PATH", t.TempDir())
	var out strings.Builder
	code, err := Run(scanner(t, &out, false), args, strings.NewReader(""), &out, &out)
	if code != 2 || fmt.Sprint(err) != "cannot find gh on PATH" || out.Len() != 0 {
		t.Errorf("no gh on PATH: exit %d, error %v, output %q", code, err, out.String())
	}
}

// Every table entry parses, and every covered command has a scanned flag.
func TestTables(t *testing.T) {
	for cmd, spec := range tables {
		long, _ := flags(spec)
		text := false
		for _, f := range long {
			text = text || f.kind == '+' || f.kind == '<' || f.kind == '~'
		}
		if !text || len(long) != len(strings.Fields(spec)) {
			t.Errorf("%s: %d flags, a scanned one %t", cmd, len(long), text)
		}
	}
	for alias, cmd := range aliases {
		if tables[cmd] == "" || tables[alias] != "" || readOnly[alias] {
			t.Errorf("alias %s", alias)
		}
	}
}

// kinds holds, for each command, the flags whose text it scans, by kind, and
// those it refuses. It is kept apart from tables, so that a kind changed
// there, such as a title no longer scanned, fails TestKinds (HSH-9/D7, D8).
var kinds = map[string]string{
	"issue create":  "attach! body+ body-file< editor! recover! template! title+ web!",
	"issue edit":    "attach! body+ body-file< title+",
	"issue comment": "attach! body+ body-file< editor! web!",
	"issue close":   "comment+",
	"issue reopen":  "comment+",
	"pr create":     "attach! body+ body-file< editor! fill! fill-first! fill-verbose! recover! template! title+ web!",
	"pr edit":       "attach! body+ body-file< title+",
	"pr comment":    "attach! body+ body-file< editor! web!",
	"pr review":     "body+ body-file<",
	"pr close":      "comment+",
	"pr reopen":     "comment+",
	"api":           "field* input< raw-field~",
}

// Every table scans and refuses exactly the flags kinds lists, and each of
// them, given a token (in a file where the kind reads one), gives the finding
// or the refusal, with gh not run.
func TestKinds(t *testing.T) {
	dir := fake(t)
	bad := filepath.Join(t.TempDir(), "bad.md")
	if err := os.WriteFile(bad, []byte("see "+lc.Bad+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for cmd, spec := range tables {
		long, _ := flags(spec)
		var inTable []string
		for _, f := range long {
			if f.kind != 0 && f.kind != '=' {
				inTable = append(inTable, f.name+string(f.kind))
			}
		}
		slices.Sort(inTable)
		if got := strings.Join(inTable, " "); got != kinds[cmd] {
			t.Errorf("%s: the table scans or refuses %q, want %q", cmd, got, kinds[cmd])
		}
	}
	for cmd, want := range kinds {
		for _, f := range strings.Fields(want) {
			name, kind := f[:len(f)-1], f[len(f)-1]
			args := append(strings.Fields(cmd), "--"+name)
			finding, refusal := "--"+name+":1: id-prefix\n", ""
			switch kind {
			case '+':
				args = append(args, "see "+lc.Bad)
			case '<':
				args = append(args, bad)
			case '~':
				args, finding = append(args, "k=see "+lc.Bad), "--"+name+" k:1: id-prefix\n"
			case '*':
				args, finding = append(args, "k=@"+bad), "--"+name+" k:1: id-prefix\n"
			case '!':
				finding, refusal = "", "gh "+cmd+" --"+name+" is not covered by hush gh (see hush gh --help)"
			}
			if cmd == "api" {
				args = append(args, "x")
			}
			var out, errs strings.Builder
			code, err := Run(scanner(t, &out, false), args, strings.NewReader(""), &out, &errs)
			_, _, ran := called(t, dir)
			if ran || out.String() != finding || errs.Len() != 0 || refusal == "" && (code != 1 || err != nil) ||
				refusal != "" && (code != 2 || fmt.Sprint(err) != refusal) {
				t.Errorf("%s --%s: exit %d, error %v, stdout %q, gh ran %t", cmd, name, code, err, out.String(), ran)
			}
			lc.Check(t, out.String(), errs.String(), fmt.Sprint(err))
		}
	}
}
