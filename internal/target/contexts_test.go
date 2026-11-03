package target

import (
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"testing"

	lc "github.com/nonhumanhq/hush/internal/leakcheck"
	"github.com/nonhumanhq/hush/internal/output"
	"github.com/nonhumanhq/hush/internal/rule"
	"github.com/nonhumanhq/hush/internal/termset"
)

// recorder is a rule that breaks on nothing and records every line and
// context it is asked about.
type recorder struct{ seen []string }

func (*recorder) Name() string { return "recorder" }

func (r *recorder) Check(line []byte, ctx rule.Context) (int, bool) {
	r.seen = append(r.seen, fmt.Sprintf("%d/%d/%s/%s", ctx.Source, ctx.Part, ctx.Path, line))
	return -1, false
}

// seen formats a context as the recorder records it.
func seen(src rule.Source, part rule.Part, path, line string) string {
	return fmt.Sprintf("%d/%d/%s/%s", src, part, path, line)
}

// isolated is gitRepo for a test that changes directory into the repository.
func isolated(t *testing.T) (string, func(args ...string) string) {
	t.Helper()
	dir, git := gitRepo(t)
	t.Chdir(dir)
	return dir, git
}

// ADR-002 section 5.1 (decided item 8): every target fills Source, Path and
// Part for every line and path it hands the rules.
func TestContexts(t *testing.T) {
	F, P, O := rule.File, rule.Path, rule.Object
	scan := func(run func(s *Scan) error) []string {
		t.Helper()
		var out strings.Builder
		r := &recorder{}
		s := &Scan{Rules: rule.List{r}, Out: output.New(&out)}
		if err := run(s); err != nil {
			t.Fatalf("scan failed: %v", err)
		}
		s.Out.Flush()
		if out.Len() != 0 {
			t.Error("the recorder gave a finding")
		}
		slices.Sort(r.seen)
		return slices.Compact(r.seen)
	}
	expect := func(name string, got, want []string) {
		t.Helper()
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("%s: contexts\n%q\nwant\n%q", name, got, want)
		}
		lc.Check(t, got...)
	}

	_, git := isolated(t)
	write(t, ".", "docs/a.md", "x\ny\n")
	write(t, ".", "reference/b.md", "z\n")

	expect("tree", scan(func(s *Scan) error { return s.Paths([]string{"."}) }), []string{
		seen(P, rule.NoPart, "docs/a.md", "docs/a.md"),
		seen(F, rule.NoPart, "docs/a.md", "x"), seen(F, rule.NoPart, "docs/a.md", "y"),
		seen(P, rule.NoPart, "reference/b.md", "reference/b.md"),
		seen(F, rule.NoPart, "reference/b.md", "z"),
	})
	expect("stdin", scan(func(s *Scan) error { return s.Stdin(strings.NewReader("x\n"), "reference/a.md") }), []string{
		seen(rule.Stdin, rule.NoPart, "", "x"),
	})
	git("add", "-A")
	expect("index", scan(func(s *Scan) error { return s.Index("") }), []string{
		seen(P, rule.NoPart, "docs/a.md", "docs/a.md"),
		seen(F, rule.NoPart, "docs/a.md", "x"), seen(F, rule.NoPart, "docs/a.md", "y"),
		seen(P, rule.NoPart, "reference/b.md", "reference/b.md"),
		seen(F, rule.NoPart, "reference/b.md", "z"),
	})
	git("-c", "user.name=alice", "-c", "user.email=alice@example.com", "commit", "-q", "--cleanup=verbatim",
		"--date=2026-01-01T00:00:00Z", "-m", "HSH-11: subject\n\nbody")
	id := "alice <alice@example.com> 1767225600 +0000"
	got := scan(func(s *Scan) error { return s.Range("", "HEAD") })
	// The committer date is the clock's: compare the committer line by its start.
	for i, g := range got {
		if strings.HasPrefix(g, seen(O, rule.Committer, "", "committer alice <alice@example.com> ")) {
			got[i] = seen(O, rule.Committer, "", "committer")
		}
	}
	slices.Sort(got)
	expect("range", got, []string{
		seen(O, rule.Author, "", "author "+id),
		seen(O, rule.Committer, "", "committer"),
		seen(O, rule.Message, "", "HSH-11: subject"),
		seen(O, rule.Message, "", ""),
		seen(O, rule.Message, "", "body"),
		seen(P, rule.NoPart, "docs/a.md", "docs/a.md"),
		seen(F, rule.NoPart, "docs/a.md", "x"), seen(F, rule.NoPart, "docs/a.md", "y"),
		seen(P, rule.NoPart, "reference/b.md", "reference/b.md"),
		seen(F, rule.NoPart, "reference/b.md", "z"),
	})
}

// With the contexts filled, the email rule's identity allowance reaches the
// identity positions of a range and standard input, and nothing else (ADR-002
// section 4.3, decided item 6). The CLI cannot pass an allowance yet.
func TestTargetsFeedTheIdentityAllowance(t *testing.T) {
	dir, git := gitRepo(t)
	who := "Alice <" + lc.Identity + ">"
	trailer := "Signed-off-by: " + who
	write(t, dir, "a.txt", trailer+"\n")
	git("add", "-A")
	out, err := exec.Command("git", "-C", dir, "-c", "user.name=Alice", "-c", "user.email="+lc.Identity,
		"commit", "-q", "--cleanup=verbatim", "-m", "HSH-11: identity\n\n"+trailer).CombinedOutput()
	if err != nil {
		t.Fatalf("git commit: %v\n%s", err, out)
	}
	short := git("rev-parse", "HEAD")[:12]
	for _, c := range []struct {
		ids  []string
		want string
	}{
		{nil, "SHA:(commit):2: email-address\nSHA:(commit):3: email-address\nSHA:(commit):7: email-address\nSHA:a.txt:1: email-address\n"},
		{[]string{lc.Identity2, strings.ToUpper(lc.Identity)}, "SHA:a.txt:1: email-address\n"},
	} {
		var found strings.Builder
		s := &Scan{Rules: rule.Registry(c.ids), Out: output.New(&found)}
		err := s.Range(dir, "HEAD")
		s.Out.Flush()
		if got := strings.ReplaceAll(found.String(), short, "SHA"); err != nil || got != c.want {
			t.Errorf("range with %d identities: error %v, %d findings", len(c.ids), err, strings.Count(got, "\n"))
		}
		lc.Check(t, found.String(), fmt.Sprint(err))
		var stdin strings.Builder
		s = &Scan{Rules: rule.Registry(c.ids), Out: output.New(&stdin)}
		err = s.Stdin(strings.NewReader("HSH-11: x\n\n"+trailer+"\n"), "commit-message")
		s.Out.Flush()
		if want := len(c.ids) == 0; err != nil || (stdin.Len() > 0) != want {
			t.Errorf("stdin with %d identities: error %v, %d bytes of findings", len(c.ids), err, stdin.Len())
		}
		lc.Check(t, stdin.String(), fmt.Sprint(err))
	}
}

// ADR-002 negative test 9: the reference/ exception in every target. The
// commit that changes only reference/ carries the token in its message.
func TestNegative9IDPrefixAndReference(t *testing.T) {
	fleet := lc.IDFlagged[7]
	if !strings.HasPrefix(fleet, "FLEET") {
		t.Fatal("the leakcheck table moved")
	}
	run := func(name string, s func(*Scan) error, want string) {
		t.Helper()
		var out strings.Builder
		sc := &Scan{Rules: rule.Registry(nil), Out: output.New(&out)}
		err := s(sc)
		sc.Out.Flush()
		if err != nil || out.String() != want {
			t.Errorf("%s: error %v, output\n%s\nwant\n%s", name, err, out.String(), want)
		}
		lc.Check(t, out.String(), fmt.Sprint(err))
	}

	t.Run("a reference directory", func(t *testing.T) {
		dir, git := isolated(t)
		write(t, dir, "reference/notes.md", "cites "+fleet+"\n")
		write(t, dir, "reference/"+fleet+".md", "clean\n")
		write(t, dir, "docs/reference/a.md", fleet+"\n")
		write(t, dir, "Reference/a.md", fleet+"\n")
		flagged := "Reference/a.md:1: id-prefix\ndocs/reference/a.md:1: id-prefix\n"
		run("tree", func(s *Scan) error { return s.Paths([]string{"."}) }, flagged)
		git("add", "-A")
		run("index", func(s *Scan) error { return s.Index("") }, flagged)
		c1 := commit(t, git, "HSH-11: add the files")
		write(t, dir, "reference/notes.md", "cites "+fleet+"\nand "+fleet+" again\n")
		git("add", "-A")
		c2 := commit(t, git, "HSH-11: quote "+fleet)
		run("range", func(s *Scan) error { return s.Range("", "HEAD") },
			c1+":Reference/a.md:1: id-prefix\n"+c1+":docs/reference/a.md:1: id-prefix\n"+c2+":(commit):6: id-prefix\n")
		run("stdin", func(s *Scan) error { return s.Stdin(strings.NewReader(fleet+"\n"), "reference/notes.md") },
			"reference/notes.md:1: id-prefix\n")
		run("tree from the root, docs", func(s *Scan) error { return s.Paths([]string{"docs"}) }, "docs/reference/a.md:1: id-prefix\n")
		t.Chdir("docs") // the known limit: reported as reference/a.md
		run("tree rooted at docs", func(s *Scan) error { return s.Paths([]string{"."}) }, "")
	})
	t.Run("a file named reference", func(t *testing.T) {
		dir, git := isolated(t)
		write(t, dir, "reference", fleet+"\n")
		run("tree", func(s *Scan) error { return s.Paths([]string{"."}) }, "reference:1: id-prefix\n")
		git("add", "-A")
		run("index", func(s *Scan) error { return s.Index("") }, "reference:1: id-prefix\n")
		c := commit(t, git, "HSH-11: add the file")
		run("range", func(s *Scan) error { return s.Range("", "HEAD") }, c+":reference:1: id-prefix\n")
	})
}

// Term sets apply after the rules, in file order (HSH-11/D2), and redaction
// cuts from the earliest match of any rule or set.
func TestSetsAfterRules(t *testing.T) {
	sets, err := termset.Parse([]byte(lc.TermSetFile()))
	if err != nil {
		t.Fatal("parse failed")
	}
	var out strings.Builder
	s := &Scan{Rules: rule.Registry(nil), Sets: sets, Out: output.New(&out)}
	line := lc.Mirelda + " " + strings.ToUpper(lc.Quorvel) + " " + lc.Bad + " " + lc.QVL + "client"
	if err := s.Stdin(strings.NewReader(line+"\n"), "x"); err != nil {
		t.Fatal(err)
	}
	s.Out.Flush()
	if want := "x:1: id-prefix\nx:1: set:clients\nx:1: set:people\n"; out.String() != want {
		t.Errorf("findings %q, want %q", out.String(), want)
	}
	lc.Check(t, out.String())
	for i, c := range []struct{ path, want string }{
		{"a/" + lc.Bad + "/" + lc.Quorvel + "/b", "a/<redacted>"},
		{"a/x" + lc.Quorvel + "/" + lc.Bad + "/b", "a/<redacted>"},
		{"a/b/x-" + lc.MOP, "a/b/<redacted>"},
		{"a/b/x-" + strings.ToLower(lc.MOP), "a/b/x-" + strings.ToLower(lc.MOP)}, // case=exact
		{"a/b/c" + lc.MOP, "a/b/c" + lc.MOP},                                     // match=word
	} {
		if got := s.redact(c.path); got != c.want {
			t.Errorf("path %d redacts to %d bytes", i, len(got))
		}
	}
}

// ADR-002 negative test 8's paths, in a tree scan.
func TestNegative8Paths(t *testing.T) {
	sets, err := termset.Parse([]byte(lc.TermSetFile()))
	if err != nil {
		t.Fatal("parse failed")
	}
	t.Chdir(t.TempDir())
	q := lc.QVL
	write(t, ".", "docs/"+q+"/a.md", "ok\n")
	write(t, ".", "docs/"+strings.ToLower(q)+"/b.md", "ok\n")
	write(t, ".", "docs/A"+q+"B/c.md", "ok\n")
	write(t, ".", "docs/"+q+"Client/d.md", "ok\n")
	var out strings.Builder
	s := &Scan{Rules: rule.Registry(nil), Sets: sets, Out: output.New(&out)}
	err = s.Paths([]string{"."})
	s.Out.Flush()
	want := "docs/<redacted>:0: set:abbreviations in path\ndocs/<redacted>:0: set:abbreviations in path\n"
	if err != nil || out.String() != want {
		t.Errorf("error %v, output %q", err, out.String())
	}
	lc.Check(t, out.String(), fmt.Sprint(err))
}
