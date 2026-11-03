package target

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	lc "github.com/nonhumanhq/hush/internal/leakcheck"
	"github.com/nonhumanhq/hush/internal/output"
	"github.com/nonhumanhq/hush/internal/rule"
)

// ADR-002 negative tests 10 and 11 and the part of 4 the targets can show:
// the ip-address and email-address rules run in every target, through the
// registry, and a finding never prints what it matched.

// flaggedRow is a flagged row of ADR-002 sections 4.1, 4.2 and 4.3 and the
// rule it breaks. With no allowance, and outside reference/, every row of the
// three tables is flagged in every target.
type flaggedRow struct{ line, rule string }

func flaggedRows() []flaggedRow {
	var rows []flaggedRow
	for _, l := range lc.IPFlagged {
		rows = append(rows, flaggedRow{l, "ip-address"})
	}
	for _, l := range lc.EmailFlagged {
		rows = append(rows, flaggedRow{l, "email-address"})
	}
	for _, l := range lc.IDFlagged {
		rows = append(rows, flaggedRow{l, "id-prefix"})
	}
	return rows
}

// registryScan is a Scan with the generic rules cmd/hush builds, and no sets.
func registryScan(out *strings.Builder) *Scan {
	return &Scan{Rules: rule.Registry(nil), Out: output.New(out)}
}

// gitRepo makes a repository in a new directory, with git's own configuration
// and environment out of the way, and returns the directory and a function
// that runs git in it.
func gitRepo(t *testing.T) (string, func(args ...string) string) {
	t.Helper()
	dir, outside := t.TempDir(), t.TempDir()
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(outside))
	t.Setenv("HOME", outside)
	for _, k := range []string{"GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL", "EMAIL"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
	git := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("git %s: %v", args[0], err)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q")
	return dir, git
}

// commit makes a commit with the reserved identity, so the identity lines
// give no finding, and returns its first twelve characters.
func commit(t *testing.T, git func(args ...string) string, message string) string {
	t.Helper()
	git("-c", "user.name=alice", "-c", "user.email=alice@example.com", "commit", "-q", "--cleanup=verbatim", "-m", message)
	return git("rev-parse", "HEAD")[:12]
}

// rulesOf returns the rule of each finding line, in order.
func rulesOf(out string) []string {
	var got []string
	for _, l := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		if l != "" {
			got = append(got, l[strings.LastIndex(l, ": ")+2:])
		}
	}
	return got
}

func wantRules(rows []flaggedRow) []string {
	var want []string
	for _, r := range rows {
		want = append(want, r.rule)
	}
	return want
}

// lineNumbers returns the line number of each finding line, in order.
func lineNumbers(out string) []int {
	var got []int
	for _, l := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		if l == "" {
			continue
		}
		head := l[:strings.LastIndex(l, ": ")]
		n, err := strconv.Atoi(head[strings.LastIndex(head, ":")+1:])
		if err != nil {
			n = -1
		}
		got = append(got, n)
	}
	return got
}

// Negative test 10, lines: every flagged row is flagged in a tree file, a
// staged blob, standard input and the lines of a commit, with the line it is
// on, and nothing it matched is printed.
func TestAddressRowsAreFlaggedInEveryTarget(t *testing.T) {
	rows := flaggedRows()
	text := make([]string, len(rows))
	for i, r := range rows {
		text[i] = r.line
	}
	all := strings.Join(text, "\n") + "\n"
	seq := make([]int, len(rows))
	for i := range seq {
		seq[i] = i + 1
	}
	check := func(t *testing.T, out string, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("scan failed: %v", err)
		}
		if got := rulesOf(out); !slices.Equal(got, wantRules(rows)) {
			t.Errorf("%d findings, want %d, or the rules differ", len(got), len(rows))
		}
		if got := lineNumbers(out); !slices.Equal(got, seq) {
			t.Errorf("the findings are not on lines 1 to %d in order", len(rows))
		}
		lc.Check(t, out, fmt.Sprint(err))
	}

	t.Run("tree", func(t *testing.T) {
		dir := t.TempDir()
		write(t, dir, "rows.txt", all)
		var out strings.Builder
		s := registryScan(&out)
		err := s.Paths([]string{dir})
		s.Out.Flush()
		check(t, strings.ReplaceAll(out.String(), dir, "DIR"), err)
		if !strings.HasPrefix(out.String(), dir+"/rows.txt:1: ip-address\n") {
			t.Error("the first finding is not on line 1 of the file")
		}
	})
	t.Run("stdin", func(t *testing.T) {
		var out strings.Builder
		s := registryScan(&out)
		err := s.Stdin(strings.NewReader(all), "label")
		s.Out.Flush()
		check(t, out.String(), err)
	})
	t.Run("index", func(t *testing.T) {
		dir, git := gitRepo(t)
		write(t, dir, "rows.txt", all)
		git("add", "rows.txt")
		var out strings.Builder
		s := registryScan(&out)
		err := s.Index(dir)
		s.Out.Flush()
		check(t, out.String(), err)
	})
	t.Run("range, added lines", func(t *testing.T) {
		dir, git := gitRepo(t)
		write(t, dir, "rows.txt", all)
		git("add", "rows.txt")
		short := commit(t, git, "HSH-14: rows")
		var out strings.Builder
		s := registryScan(&out)
		err := s.Range(dir, head)
		s.Out.Flush()
		check(t, strings.ReplaceAll(out.String(), short+":rows.txt:", "X:"), err)
		if !strings.HasPrefix(out.String(), short+":rows.txt:1: ip-address\n") {
			t.Error("the first finding is not on line 1 of the added file")
		}
	})
	t.Run("range, message", func(t *testing.T) {
		dir, git := gitRepo(t)
		write(t, dir, "a.txt", "clean\n")
		git("add", "a.txt")
		short := commit(t, git, "HSH-14: rows\n\n"+all)
		var out strings.Builder
		s := registryScan(&out)
		err := s.Range(dir, head)
		s.Out.Flush()
		if err != nil {
			t.Fatalf("scan failed: %v", err)
		}
		if got := rulesOf(out.String()); !slices.Equal(got, wantRules(rows)) {
			t.Errorf("%d findings, want %d, or the rules differ", len(got), len(rows))
		}
		// The message follows the headers and a blank line; its findings are on
		// consecutive lines of the commit object.
		got := lineNumbers(out.String())
		for i := 1; i < len(got); i++ {
			if got[i] != got[i-1]+1 {
				t.Errorf("finding %d is not on the line after the one before", i)
			}
		}
		if !strings.HasPrefix(out.String(), short+":(commit):") {
			t.Error("the findings are not on the commit object")
		}
		lc.Check(t, out.String(), fmt.Sprint(err))
	})
}

// Negative test 10, paths: every flagged row, used as a path, is flagged
// wherever the rule finds it in the path as the target reports it, and the
// path prints redacted. A row that holds "/" is several components, and one
// that holds a quote or a backslash is a path git quotes in a diff (the range
// target's known gap, HSH-5/D7), so the range target skips the last two.
func TestAddressRowsAsPaths(t *testing.T) {
	rows := flaggedRows()
	list := rule.Registry(nil)
	// expected is what a target must print for the file path p reported as
	// where, without the directory the scan started from.
	expected := func(p string, escaped bool) string {
		var b strings.Builder
		ctx := rule.Context{Source: rule.Path, Path: p}
		where := rule.Redact(p, list.Start([]byte(p), ctx))
		if escaped {
			where = escape(where)
		}
		for _, name := range list.Check([]byte(p), ctx) {
			fmt.Fprintf(&b, "%s:0: %s in path\n", where, name)
		}
		return b.String()
	}
	rowPath := func(i int, r flaggedRow) string { return fmt.Sprintf("p%03d/%s/x.txt", i, r.line) }
	// The rule finds each row in the path it makes, with its own rule.
	for i, r := range rows {
		if p := filepath.ToSlash(filepath.Clean(rowPath(i, r))); !slices.Contains(list.Check([]byte(p), rule.Context{Source: rule.Path, Path: p}), r.rule) {
			t.Fatalf("row %d is not flagged as a path", i)
		}
	}

	t.Run("tree", func(t *testing.T) {
		t.Chdir(t.TempDir())
		var want strings.Builder
		for i, r := range rows {
			write(t, ".", rowPath(i, r), "ok\n")
		}
		var out strings.Builder
		s := registryScan(&out)
		err := s.Paths([]string{"."})
		s.Out.Flush()
		// The tree walk sorts the paths bytewise, and p000 to p999 sort by number.
		for i, r := range rows {
			want.WriteString(expected(filepath.ToSlash(filepath.Clean(rowPath(i, r))), false))
		}
		if err != nil || out.String() != want.String() {
			t.Errorf("tree: error %v, %d bytes of output, want %d", err, out.Len(), want.Len())
		}
		lc.Check(t, out.String(), fmt.Sprint(err))
	})
	t.Run("index", func(t *testing.T) {
		dir, git := gitRepo(t)
		t.Chdir(dir)
		var want strings.Builder
		for i, r := range rows {
			write(t, dir, rowPath(i, r), "ok\n")
		}
		git("add", "-A")
		var out strings.Builder
		s := registryScan(&out)
		err := s.Index(dir)
		s.Out.Flush()
		// ls-files lists the paths bytewise, as the tree walk does.
		for i, r := range rows {
			want.WriteString(expected(filepath.ToSlash(filepath.Clean(rowPath(i, r))), true))
		}
		if err != nil || out.String() != want.String() {
			t.Errorf("index: error %v, %d bytes of output, want %d", err, out.Len(), want.Len())
		}
		lc.Check(t, out.String(), fmt.Sprint(err))
	})
	t.Run("range", func(t *testing.T) {
		dir, git := gitRepo(t)
		var want strings.Builder
		var kept []string
		for i, r := range rows {
			p := filepath.ToSlash(filepath.Clean(rowPath(i, r)))
			write(t, dir, p, "ok\n")
			// Paths come from diff-tree's -z records as git's raw bytes
			// (HSH-11/T22), so the escaped-@ row, which HSH-5/D7's patch
			// headers wrote with a doubled backslash and the rule then
			// missed, is found here as in the tree and index targets
			// (HSH-14/D15).
			kept = append(kept, p)
		}
		git("add", "-A")
		short := commit(t, git, "HSH-14: paths")
		var out strings.Builder
		s := registryScan(&out)
		err := s.Range(dir, head)
		s.Out.Flush()
		slices.Sort(kept)
		for _, p := range kept {
			for _, l := range strings.Split(strings.TrimSuffix(expected(p, false), "\n"), "\n") {
				if l != "" {
					want.WriteString(short + ":" + l + "\n")
				}
			}
		}
		if err != nil || out.String() != want.String() {
			t.Errorf("range: error %v, %d bytes of output, want %d", err, out.Len(), want.Len())
		}
		lc.Check(t, out.String(), fmt.Sprint(err))
	})
}

// Negative test 11: the rules feed redaction. A path holding an address that
// the ip-address rule flags, or one that the email-address rule flags, is
// printed redacted from the component where the address begins, in every
// target that reports paths.
func TestAddressRulesFeedRedaction(t *testing.T) {
	ip := "203.0." + "114.7"
	mail := "bob@" + "acme.internal"
	for _, c := range []struct{ path, want, rule string }{
		{"docs/" + ip + "/a.md", "docs/<redacted>", "ip-address"},
		{"docs/" + mail + "/a.md", "docs/<redacted>", "email-address"},
		{"docs/ok/" + mail + ".md", "docs/ok/<redacted>", "email-address"},
		{ip + "-notes/a.md", "<redacted>", "ip-address"},
	} {
		want := c.want + ":0: " + c.rule + " in path\n"
		t.Run("tree "+c.rule, func(t *testing.T) {
			t.Chdir(t.TempDir())
			write(t, ".", c.path, "ok\n")
			var out strings.Builder
			s := registryScan(&out)
			err := s.Paths([]string{strings.SplitN(c.path, "/", 2)[0]})
			s.Out.Flush()
			if err != nil || out.String() != want {
				t.Errorf("tree: error %v, output %q", err, out.String())
			}
			lc.Check(t, out.String(), fmt.Sprint(err))
		})
		t.Run("index "+c.rule, func(t *testing.T) {
			dir, git := gitRepo(t)
			write(t, dir, c.path, "ok\n")
			git("add", "-A")
			var out strings.Builder
			s := registryScan(&out)
			err := s.Index(dir)
			s.Out.Flush()
			if err != nil || out.String() != want {
				t.Errorf("index: error %v, output %q", err, out.String())
			}
			lc.Check(t, out.String(), fmt.Sprint(err))
		})
		t.Run("range "+c.rule, func(t *testing.T) {
			dir, git := gitRepo(t)
			write(t, dir, c.path, "ok\n")
			git("add", "-A")
			short := commit(t, git, "HSH-14: path")
			var out strings.Builder
			s := registryScan(&out)
			err := s.Range(dir, head)
			s.Out.Flush()
			if err != nil || out.String() != short+":"+want {
				t.Errorf("range: error %v, output %q", err, out.String())
			}
			lc.Check(t, out.String(), fmt.Sprint(err))
		})
	}
}

// Negative test 4, as far as the targets go without an allowance (the CLI's
// --identities comes in a later part of HSH-11): a commit that carries an
// identity outside the reserved domains is flagged on its author, committer
// and trailer lines, whatever a file in the repository, .mailmap, git's
// configuration or the environment says,
// and the trailer is flagged on standard input as the commit-msg hook passes it.
func TestCommitIdentityIsFlaggedWhateverTheRepositorySays(t *testing.T) {
	dir, git := gitRepo(t)
	who := "Alice <" + lc.Identity + ">"
	// Everything the ADR names as a possible source of the allowance lists the
	// identity: files at the root and under .hush/, a .mailmap, git's
	// configuration and the environment.
	write(t, dir, "identities", lc.Identity+"\n")
	write(t, dir, ".hush/identities", lc.Identity+"\n")
	write(t, dir, ".mailmap", "Alice <alice@example.com> "+who[len("Alice "):]+"\n")
	write(t, dir, "a.txt", "clean\n")
	git("config", "user.email", lc.Identity)
	for _, k := range []string{"HUSH_IDENTITIES", "EMAIL", "GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL"} {
		t.Setenv(k, lc.Identity)
	}
	git("add", "-A")
	trailer := "Signed-off-by: " + who
	out, err := exec.Command("git", "-C", dir, "-c", "user.name=Alice", "commit", "-q", "--cleanup=verbatim", "-m", "HSH-14: identity\n\n"+trailer).CombinedOutput()
	if err != nil {
		t.Fatalf("git commit: %v\n%s", err, out)
	}
	short := git("rev-parse", "HEAD")[:12]

	var found strings.Builder
	s := registryScan(&found)
	err = s.Range(dir, head)
	s.Out.Flush()
	if err != nil {
		t.Fatalf("range: %v", err)
	}
	// The commit's author (line 2), committer (line 3) and trailer (line 7) are
	// flagged, and so is each file that lists the address: a file's line is never
	// an identity position, and no file widens what passes.
	want := "SHA:(commit):2: email-address\n" +
		"SHA:(commit):3: email-address\n" +
		"SHA:(commit):7: email-address\n" +
		"SHA:.hush/identities:1: email-address\n" +
		"SHA:.mailmap:1: email-address\n" +
		"SHA:identities:1: email-address\n"
	if got := strings.ReplaceAll(found.String(), short, "SHA"); got != want {
		t.Errorf("range: %d findings, want 6, or they differ from the listed ones", strings.Count(got, "\n"))
	}
	lc.Check(t, found.String())

	// The same trailer on standard input: no allowance there either.
	var stdin strings.Builder
	s = registryScan(&stdin)
	err = s.Stdin(strings.NewReader("HSH-14: identity\n\n"+trailer+"\n"), "commit-message")
	s.Out.Flush()
	if err != nil || stdin.String() != "commit-message:3: email-address\n" {
		t.Errorf("stdin: error %v, output %q", err, stdin.String())
	}
	lc.Check(t, stdin.String(), fmt.Sprint(err))
}
