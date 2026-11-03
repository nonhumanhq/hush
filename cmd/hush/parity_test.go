package main

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	lc "github.com/nonhumanhq/hush/internal/leakcheck"
)

// parity runs the interim scanner and hush over the same fixtures, with the
// interim's arguments mapped as ADR-001's Consequences table says, and
// requires the same exit status and standard output. Standard error is
// checked against the message table instead: empty on exit 0 and 1, and one
// "hush: " line from the table on exit 2 (HSH-5/D15, HSH-11/T18). Subtests run
// in order: later git cases build on earlier commits.
type parity struct {
	t                *testing.T
	interim, hush    string
	root, dir, terms string
	env              []string
	n                int
	stdin            string   // for the next run only
	extra            []string // environment for the next run only
	stdout           *os.File // standard output for the next run only, if set
}

type result struct {
	code           int
	stdout, stderr string
}

func newParity(t *testing.T) *parity {
	for _, tool := range []string{"sh", "awk", "find", "git", "go"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("the comparison test needs %s", tool)
		}
	}
	interim, err := filepath.Abs("../../reference/interim-hush/hush-interim")
	if err != nil {
		t.Fatal(err)
	}
	// The interim scanner lives in staging's reference pack, which the public
	// repository does not hold; there is nothing to compare with (HSH-25/D1).
	if _, err := os.Stat(interim); errors.Is(err, fs.ErrNotExist) {
		t.Skip("no interim scanner at reference/interim-hush to compare with")
	} else if err != nil {
		t.Fatal(err)
	}
	p := &parity{t: t, interim: interim, root: t.TempDir()}
	p.hush = filepath.Join(t.TempDir(), "hush")
	if out, err := exec.Command("go", "build", "-buildvcs=false", "-o", p.hush, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	for _, d := range []string{"home", "tmp"} {
		p.mkdir(filepath.Join(p.root, d))
	}
	p.env = []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + filepath.Join(p.root, "home"),
		"TMPDIR=" + filepath.Join(p.root, "tmp"), "LC_ALL=C",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_CEILING_DIRECTORIES=" + filepath.Dir(p.root),
		"GIT_AUTHOR_NAME=alice", "GIT_AUTHOR_EMAIL=alice@example.com",
		"GIT_COMMITTER_NAME=alice", "GIT_COMMITTER_EMAIL=alice@example.com",
	}
	p.terms = filepath.Join(p.root, "terms.txt")
	p.writeTerms(p.terms, lc.TermFile())
	return p
}

func (p *parity) mkdir(dir string) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		p.t.Fatal(err)
	}
}

// fresh starts a new empty fixture directory.
func (p *parity) fresh() {
	p.n++
	p.dir = filepath.Join(p.root, "t"+strconv.Itoa(p.n))
	p.mkdir(p.dir)
}

// write creates name, relative to the fixture directory unless absolute.
func (p *parity) write(name, content string) {
	if !filepath.IsAbs(name) {
		name = filepath.Join(p.dir, name)
	}
	p.mkdir(filepath.Dir(name))
	if err := os.WriteFile(name, []byte(content), 0o644); err != nil {
		p.t.Fatal(err)
	}
}

// writeTerms creates a term file at the absolute path name, at mode 0600,
// which hush requires and the interim ignores.
func (p *parity) writeTerms(name, content string) {
	p.write(name, content)
	if err := os.Chmod(name, 0o600); err != nil {
		p.t.Fatal(err)
	}
}

// git runs git in the fixture directory and returns its trimmed output.
func (p *parity) git(env []string, args ...string) string {
	c := exec.Command("git", args...)
	c.Dir, c.Env = p.dir, append(append([]string{}, p.env...), env...)
	out, err := c.CombinedOutput()
	if err != nil {
		p.t.Fatalf("git %s: %v\n%s", args[0], err, out)
	}
	return strings.TrimSpace(string(out))
}

func (p *parity) commit(msg string) string {
	p.git(nil, "add", "-A")
	p.git(nil, "commit", "-q", "-m", msg)
	return p.head()
}

func (p *parity) head() string { return p.git(nil, "rev-parse", "HEAD")[:12] }

func (p *parity) exec(name string, args ...string) result {
	c := exec.Command(name, args...)
	c.Dir, c.Env, c.Stdin = p.dir, append(append([]string{}, p.env...), p.extra...), strings.NewReader(p.stdin)
	var out, errs strings.Builder
	c.Stdout, c.Stderr = &out, &errs
	if p.stdout != nil {
		c.Stdout = p.stdout
	}
	err := c.Run()
	r := result{0, out.String(), errs.String()}
	if ee, ok := err.(*exec.ExitError); ok {
		r.code = ee.ExitCode()
	} else if err != nil {
		p.t.Fatalf("cannot run %s", filepath.Base(name))
	}
	return r
}

// hushArgs maps the interim scanner's arguments to hush's (ADR-001,
// Consequences): "scan --destination public", then "--terms FILE" as the
// interim gives it or "--generic-only" without one, then the rest.
func hushArgs(args []string) []string {
	out := []string{"scan", "--destination", "public"}
	if !slices.Contains(args, "--terms") {
		out = append(out, "--generic-only")
	}
	return append(out, args...)
}

// run is one case: both programs, the interim's arguments and their mapping,
// the expected status and standard output ("*" for any), standard error
// against the table, and the leak check.
func (p *parity) run(name string, code int, want string, args ...string) {
	p.t.Run(name, func(t *testing.T) {
		ref := p.exec("sh", append([]string{p.interim}, args...)...)
		got := p.exec(p.hush, hushArgs(args)...)
		if got.code != ref.code || got.stdout != ref.stdout {
			t.Errorf("hush differs from the interim scanner\nhush:    %+v\ninterim: %+v", got, ref)
		}
		checkStderr(t, got)
		if want != "*" && want != "" {
			want += "\n"
		}
		if got.code != code || (want != "*" && got.stdout != want) {
			t.Errorf("exit %d, want %d; stdout %q, want %q", got.code, code, got.stdout, want)
		}
		lc.Check(t, ref.stdout, ref.stderr, got.stdout, got.stderr)
	})
	p.stdin, p.extra, p.stdout = "", nil, nil
}

// differ is a case where hush differs from the interim scanner on purpose, in
// its exit status or standard output (HSH-11/D13, D45): each program must
// give exactly the result listed for it, hush with its arguments mapped.
func (p *parity) differ(name string, interim, hush result, args ...string) {
	p.t.Run(name, func(t *testing.T) {
		ref := p.exec("sh", append([]string{p.interim}, args...)...)
		got := p.exec(p.hush, hushArgs(args)...)
		if interim.stderr == "*" {
			ref.stderr = "*" // it names a path of this machine
		}
		if ref != interim {
			t.Errorf("the interim scanner gives %+v, want %+v", ref, interim)
		}
		if got != hush {
			t.Errorf("hush gives %+v, want %+v", got, hush)
		}
		checkStderr(t, got)
		lc.Check(t, ref.stdout, ref.stderr, got.stdout, got.stderr)
	})
	p.stdin = ""
}

// fails is the result of an error exit with one error line; interim is the
// interim scanner's text.
func fails(msg string) result { return result{2, "", "hush-interim: " + msg + "\n"} }

// hushFails is hush's result for an error exit with message msg.
func hushFails(msg string) result { return result{2, "", "hush: " + msg + "\n"} }

// checkStderr fails t unless r's standard error is ADR-001 section 6.2's:
// empty on exit 0 and 1, and on exit 2 exactly one line, "hush: " and a
// message of the table (ADR-001, Consequences).
func checkStderr(t *testing.T, r result) {
	t.Helper()
	msg, ok := strings.CutPrefix(r.stderr, "hush: ")
	switch {
	case r.code != 2 && r.stderr != "":
		t.Errorf("exit %d with standard error %q", r.code, r.stderr)
	case r.code == 2 && (!ok || strings.Count(r.stderr, "\n") != 1 || !strings.HasSuffix(msg, "\n")):
		t.Errorf("exit 2 with standard error %q, want one hush: line", r.stderr)
	case r.code == 2 && !inTable(strings.TrimSuffix(msg, "\n")):
		t.Errorf("standard error %q is not from the message table", r.stderr)
	}
}

func TestParity(t *testing.T) {
	p := newParity(t)

	// Generic tier: the ID-prefix rule.
	p.fresh()
	p.write("docs/notes.md", "an ordinary line\ntracked as HSH-7, CHS-3, FLT-12 and SWE-9\n")
	p.write("reference/pack.md", "cites "+lc.Fleet+" and "+lc.Vmws+"\n")
	p.write("docs/adr.md", "per ADR-003 and chassis ADR-001\n")
	p.run("clean tree passes", 0, "", ".")
	p.run("allowed prefixes pass", 0, "", "docs/notes.md")
	p.run("ADR numbers pass", 0, "", "docs/adr.md")
	p.run("FLEET and VMWS pass under reference/", 0, "", "reference")

	p.fresh()
	p.write("docs/a.md", "first\nsecond\nthen "+lc.Bad+" here\n")
	p.run("disallowed prefix fails", 1, "docs/a.md:3: id-prefix", ".")

	// An intended difference: the widened prefix (ADR-002 section 4.1).
	p.fresh()
	p.write("a.md", "clean\nrefers to "+"AB1"+"-23"+"\n")
	p.differ("prefix with a digit fails", result{}, result{1, "a.md:2: id-prefix\n", ""}, ".")

	p.fresh()
	p.write("a.md", "refers to "+lc.Near+"\n")
	p.run("allowed prefix with an added letter fails", 1, "a.md:1: id-prefix", ".")

	p.fresh()
	p.write("docs/a.md", lc.Fleet+" quoted\nand "+lc.Vmws+"\n")
	p.run("FLEET and VMWS fail outside reference/", 1, "docs/a.md:1: id-prefix\ndocs/a.md:2: id-prefix", ".")

	p.fresh()
	p.write("docs/notes-"+lc.Bad+".md", "clean\n")
	p.run("disallowed prefix in a file name is redacted", 1, "docs/<redacted>:0: id-prefix in path", ".")

	p.fresh()
	p.write("blob.bin", "x\x00y\n")
	p.run("binary file is reported", 1, "blob.bin:0: binary-unscanned", ".")

	p.fresh()
	if err := os.Symlink("docs/"+lc.Bad+".md", filepath.Join(p.dir, "link")); err != nil {
		t.Fatal(err)
	}
	p.run("symlink target is scanned", 1, "link:1: id-prefix", ".")

	p.fresh()
	p.run("missing path argument fails", 2, "", "nothing-here")
	p.run("no mode fails", 2, "")
	p.run("two modes fail", 2, "", "--stdin", ".")
	p.run("unknown option fails", 2, "", "--frobnicate", ".")
	p.run("label without stdin fails", 2, "", "--label", "x", ".")

	p.stdin = "ok\nsee " + lc.Bad + "\n"
	p.run("stdin is scanned", 1, "<stdin>:2: id-prefix", "--stdin")
	p.stdin = lc.Bad + "\n"
	p.run("stdin label names the source", 1, "issue-body:1: id-prefix", "--label", "issue-body", "-")
	p.stdin = "HSH-1 is next\n"
	p.run("clean stdin passes", 0, "", "--stdin")

	// Private tier: term sets.
	p.fresh()
	p.write("a.md", "clean\n")
	p.run("missing term file fails", 2, "", "--terms", filepath.Join(p.root, "no-such-file"), ".")
	p.run("empty term file name fails", 2, "", "--terms", "", ".")
	p.run("term file that is a directory fails", 2, "", "--terms", p.root, ".")
	locked := filepath.Join(p.root, "locked.txt")
	p.writeTerms(locked, lc.TermFile())
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		t.Run("unreadable term file fails", func(t *testing.T) { t.Skip("running as root") })
	} else {
		p.run("unreadable term file fails", 2, "", "--terms", locked, ".")
	}
	empty, nosection, badset := filepath.Join(p.root, "empty.txt"), filepath.Join(p.root, "nosection.txt"), filepath.Join(p.root, "badset.txt")
	p.writeTerms(empty, "# nothing but comments\n\n[people]\n")
	p.writeTerms(nosection, lc.Person+"\n[clients]\n"+lc.Client+"\n")
	p.writeTerms(badset, "[two words]\n"+lc.Client+"\n")
	// Format 1 words these refusals as ADR-002 section 1.5 does, and refuses a
	// set with no terms on its own line; the status and output are the same.
	p.run("term file without terms fails", 2, "", "--terms", empty, ".")
	p.run("term outside a section fails", 2, "", "--terms", nosection, ".")
	p.run("bad set name fails", 2, "", "--terms", badset, ".")
	// Intended differences: format 1's header attributes, which the interim
	// refuses, and section 1.4's load-time checks, which it does not run.
	options, refused := filepath.Join(p.root, "options.txt"), filepath.Join(p.root, "refused.txt")
	p.writeTerms(options, "[clients match=word]\n"+lc.Client+"\n")
	p.writeTerms(refused, "["+lc.Client+"-notes]\n"+lc.Client+"\n")
	p.differ("header attributes load", fails("term file: bad set name at line 1"), result{}, "--terms", options, ".")
	p.differ("a set name holding a term is refused", result{}, hushFails("term file: line 1: set name refused"), "--terms", refused, ".")
	// Intended difference: hush refuses a term file others can read, which the
	// interim loads (ADR-001 section 5).
	open := filepath.Join(p.root, "open.txt")
	p.write(open, lc.TermFile())
	p.differ("a term file others can read is refused", result{}, hushFails("term file: readable or writable by group or others"),
		"--terms", open, ".")
	p.run("term file given twice fails", 2, "", "--terms", p.terms, "--terms", p.terms, ".")

	p.fresh()
	p.write("a.md", "a note on "+strings.ToUpper(lc.Client)+"\n"+strings.ToLower(lc.Person)+" waved\nthe "+
		strings.ToUpper(lc.Client2)+" crew\nclean\n")
	p.run("terms match case-insensitively and name the set", 1, "a.md:1: set:clients\na.md:2: set:people\na.md:3: set:clients",
		"--terms", p.terms, ".")
	p.run("terms are not used without --terms", 0, "", ".")
	p.extra = []string{"HUSH_TERMS=" + p.terms}
	p.run("terms are never read from the environment", 0, "", ".")

	p.fresh()
	p.write("docs/"+strings.ToLower(lc.Client)+"/plan.md", "see "+lc.Bad+"\n")
	p.run("term in a path is redacted everywhere", 1, "docs/<redacted>:0: set:clients in path\ndocs/<redacted>:1: id-prefix",
		"--terms", p.terms, ".")

	p.fresh()
	p.writeTerms(filepath.Join(p.dir, "terms.txt"), lc.TermFile())
	p.run("term file inside a scanned path fails", 2, "", "--terms", "./terms.txt", ".")

	p.stdin = "ask " + lc.Person + "\n"
	p.run("stdin is matched against terms", 1, "<stdin>:1: set:people", "--terms", p.terms, "--stdin")

	// Git ranges, including commit messages.
	p.fresh()
	p.git(nil, "init", "-q", ".")
	p.write("docs/a.md", "clean\n")
	p.commit("HSH-1: start the notes")
	p.write("docs/a.md", "clean\nsee "+lc.Bad+"\n")
	c2 := p.commit("HSH-1: cite a ticket")
	p.write("docs/a.md", "clean\nsee "+lc.Bad+"\nmore\n")
	c3 := p.commit("HSH-1: mention " + lc.Client)
	p.write("docs/a.md", "clean\nmore\n")
	p.commit("HSH-1: drop the ticket")
	p.run("range finds added lines and messages", 1, c2+":docs/a.md:2: id-prefix\n"+c3+":(commit):6: set:clients",
		"--terms", p.terms, "--range", "HEAD~3..HEAD")
	p.run("range from the root commit", 1, c2+":docs/a.md:2: id-prefix", "--range", "HEAD")
	p.run("deleted lines are not findings", 0, "", "--terms", p.terms, "--range", "HEAD~1..HEAD")
	p.run("-C names the repository", 0, "", "-C", p.dir, "--range", "HEAD~1..HEAD")

	p.git(nil, "commit", "-q", "--allow-empty", "-m", "fix "+lc.Bad)
	p.run("disallowed prefix in a message fails", 1, p.head()+":(commit):6: id-prefix", "--range", "HEAD~1..HEAD")

	p.git([]string{"GIT_AUTHOR_NAME=" + lc.Person}, "commit", "-q", "--allow-empty", "-m", "HSH-2: empty")
	p.run("author is matched against terms", 1, p.head()+":(commit):3: set:people", "--terms", p.terms, "--range", "HEAD~1..HEAD")

	p.write("reference/x.md", lc.Fleet+"\n")
	p.write("docs/y.md", "two\n"+lc.Fleet+"\n")
	h := p.commit("HSH-3: quote the pack")
	p.run("range keeps the reference/ exception", 1, h+":docs/y.md:2: id-prefix", "--range", "HEAD~1..HEAD")

	p.write("blob.bin", "x\x00y\n")
	p.write("docs/"+strings.ToLower(lc.Client)+"-notes/x.md", "clean\n")
	h = p.commit("HSH-4: add files")
	p.run("range reports binaries and redacts paths", 1, h+":blob.bin:0: binary-unscanned\n"+h+":docs/<redacted>:0: set:clients in path",
		"--terms", p.terms, "--range", "HEAD~1..HEAD")

	p.run("bad range fails", 2, "", "--range", "no-such-rev..HEAD")
	repo := p.dir
	p.dir = p.root
	p.run("range outside a repository fails", 2, "", "-C", p.root, "--range", "HEAD")

	// Beyond the interim's 42 cases: revisions on standard input, merges, bare
	// mirrors, the committer, a closed reader, .git, unreadable files and the
	// help text.
	// Intended difference: "--stdin" is a rev-list option, which hush's
	// range text refuses (ADR-001 section 5).
	p.dir = repo
	p.stdin = c2 + "^.." + c2 + "\n"
	p.differ("range reads revisions from standard input", result{1, c2 + ":docs/a.md:2: id-prefix\n", ""},
		hushFails("argument 5: range: word 1 is refused"), "--range", "--stdin")
	p.git(nil, "checkout", "-q", "-b", "side")
	p.write("docs/side.md", "from the side: "+lc.Bad+"\n")
	side := p.commit("HSH-5: add a side note")
	p.git(nil, "checkout", "-q", "-")
	p.git(nil, "merge", "-q", "--no-ff", "-m", "HSH-5: merge the side note", "side")
	p.run("merge is scanned against its first parent", 1, side+":docs/side.md:1: id-prefix\n"+p.head()+":docs/side.md:1: id-prefix",
		"--range", "HEAD^1..HEAD")
	mirror := filepath.Join(p.root, "mirror.git")
	p.git(nil, "clone", "-q", "--mirror", ".", mirror)
	p.run("range works on a bare mirror", 1, "*", "--terms", p.terms, "-C", mirror, "--range", "HEAD")
	p.git([]string{"GIT_COMMITTER_NAME=" + lc.Person}, "commit", "-q", "--allow-empty", "-m", "HSH-5: empty")
	p.run("committer is matched against terms", 1, p.head()+":(commit):4: set:people", "--terms", p.terms, "--range", "HEAD~1..HEAD")
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	p.stdout = w
	p.run("a closed reader on standard output exits 2", 2, "", ".")
	p.stdout = w
	p.run("a closed reader stops the scan at the first finding", 2, "", "docs/y.md", "nope")
	w.Close()

	p.fresh()
	p.write(".git/a.md", lc.Bad+"\n")
	p.write("sub/.git", lc.Bad+"\n")
	p.write("sub/a.md", "clean\n")
	p.run("tree scan skips .git", 0, "", ".")
	p.run(".git as a path argument is skipped", 0, "", ".git")
	p.write("locked.md", "clean\n")
	p.write("shut/a.md", "clean\n")
	chmod := func(name string, mode os.FileMode) {
		if err := os.Chmod(filepath.Join(p.dir, name), mode); err != nil {
			t.Fatal(err)
		}
	}
	if os.Geteuid() == 0 {
		t.Run("unreadable file is reported", func(t *testing.T) { t.Skip("running as root") })
		t.Run("unsearchable directory with --terms fails", func(t *testing.T) { t.Skip("running as root") })
	} else {
		chmod("locked.md", 0)
		p.run("unreadable file is reported", 1, "locked.md:0: unreadable", ".")
		// With --terms, neither can show that the term file is not inside.
		chmod("shut", 0o600)
		p.run("unsearchable directory with --terms fails", 2, "", "--terms", p.terms, "shut")
		p.run("unsearchable directory is reported", 1, "locked.md:0: unreadable\nshut/a.md:0: unreadable", ".")
		// Intended difference: hush reports a directory it cannot read and
		// scans the rest, where the interim's find fails (ADR-001 section 5).
		chmod("shut", 0)
		p.differ("unreadable directory is reported", result{2, "", "*"},
			result{1, "locked.md:0: unreadable\nshut:0: unreadable\n", ""}, ".")
		chmod("shut", 0o755)
	}

	// "hush scan --help" is hush's own (HSH-11/D26), exits 0 only alone,
	// and prints no flagged token.
	t.Run("help", func(t *testing.T) {
		got := p.exec(p.hush, "scan", "--help")
		if got.code != 0 || !strings.HasPrefix(got.stdout, "usage: hush scan --destination DEST") || got.stderr != "" {
			t.Errorf("help: %+v", got)
		}
		lc.Check(t, got.stdout, got.stderr)
		got = p.exec(p.hush, "scan", "--terms", p.terms, "--help", ".")
		if got != hushFails("argument 3: --help is accepted only alone") {
			t.Errorf("help with other arguments: %+v", got)
		}
	})
}
