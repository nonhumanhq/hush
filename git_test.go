package hush

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	lc "github.com/nonhumanhq/hush/internal/leakcheck"
	"github.com/nonhumanhq/hush/internal/target"
)

// The tests of part d (HSH-11/T19 to T23): git run under ADR-001 section 5's
// rules. TestMain isolates them; each also leak-checks what it gets.

// marker returns an executable script that appends to a marker file when it
// runs, and a function that reports whether it ran and resets the marker.
func marker(t *testing.T) (script string, ran func() bool) {
	t.Helper()
	dir := t.TempDir()
	mark := filepath.Join(dir, "ran")
	script = filepath.Join(dir, "program")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho ran >> '"+mark+"'\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return script, func() bool {
		_, err := os.Stat(mark)
		os.Remove(mark)
		return err == nil
	}
}

// twoCommits makes a repository whose second commit adds a.md with a
// rejected ID token on line 2, and returns it with its git function and the
// second commit's id.
func twoCommits(t *testing.T) (string, func(args ...string) string, string) {
	t.Helper()
	dir, git := gitRepo(t)
	write(t, dir, "base.md", "clean\n")
	git("add", "-A")
	git("commit", "-q", "-m", "first")
	write(t, dir, "a.md", "clean\nsee "+lc.Bad+"\n")
	git("add", "-A")
	git("commit", "-q", "-m", "second")
	return dir, git, git("rev-parse", "HEAD")
}

// generic is a public, generic-only Scanner.
func generic(t *testing.T) *Scanner {
	return scanner(t, Config{Destination: Public(), GenericOnly: true})
}

// ADR-001 negative test 12, programs: the scanned repository configures a
// textconv driver, an external diff, an fsmonitor hook and a clean filter,
// each of which git's porcelain runs here (the controls). A range scan and an index scan
// run none of them, and still find the token.
func TestNegative12NoProgramRuns(t *testing.T) {
	s := generic(t)
	dir, git, head := twoCommits(t)
	program, ran := marker(t)
	write(t, dir, ".gitattributes", "*.md diff=conv\n")
	git("add", "-A")
	git("commit", "-q", "-m", "attributes")
	write(t, dir, "a.md", "clean\nsee "+lc.Bad+"\nmore\n")
	git("add", "-A")
	git("commit", "-q", "-m", "third")
	git("config", "diff.conv.textconv", program)
	exec.Command("git", "-C", dir, "diff", "HEAD~1", "HEAD").Run()
	if !ran() {
		t.Fatal("control: git diff did not run the textconv driver")
	}
	git("config", "diff.external", program)
	exec.Command("git", "-C", dir, "diff", "HEAD~1", "HEAD").Run()
	if !ran() {
		t.Fatal("control: git diff did not run the external diff")
	}
	git("config", "core.fsmonitor", program)
	git("update-index", "--fsmonitor")
	exec.Command("git", "-C", dir, "status").Run()
	if !ran() {
		t.Fatal("control: git status did not run the fsmonitor hook")
	}
	git("config", "--unset", "core.fsmonitor")
	write(t, dir, ".git/info/attributes", "*.md filter=clean\n")
	git("config", "filter.clean.clean", program)
	write(t, dir, "a.md", "changed\n")
	exec.Command("git", "-C", dir, "diff").Run()
	if !ran() {
		t.Fatal("control: git diff did not run the clean filter")
	}
	git("config", "core.fsmonitor", program)

	rep, err := s.ScanRange(bg, Repo{Dir: dir}, Range{Include: []string{"HEAD"}})
	if ExitCode(err) != 1 || !strings.Contains(plain(t, rep), head[:12]+":a.md:2: id-prefix\n") || ran() {
		t.Errorf("range: %v, %q, a program ran", err, plain(t, rep))
	}
	leak(t, rep, err)
	rep, err = s.ScanIndex(bg, Repo{Dir: dir})
	if ExitCode(err) != 1 || plain(t, rep) != "a.md:2: id-prefix\n" || ran() {
		t.Errorf("index: %v, %q, a program ran", err, plain(t, rep))
	}
	leak(t, rep, err)
}

// The fixed environment (ADR-001 section 5): git gets none of the caller's
// variables. Configuration passed through the environment, a global
// configuration under HOME, trace output, an external diff, another object
// directory and a namespace change nothing, and no program runs.
func TestFixedEnvironment(t *testing.T) {
	s := generic(t)
	dir, git, head := twoCommits(t)
	program, ran := marker(t)
	trace := filepath.Join(t.TempDir(), "trace")
	home := t.TempDir()
	write(t, home, ".gitconfig", "[diff]\n\texternal = "+program+"\n[core]\n\tfsmonitor = "+program+"\n")
	git("update-index", "--fsmonitor")
	empty := t.TempDir()
	for k, v := range map[string]string{
		"HOME": home, "GIT_CONFIG_GLOBAL": filepath.Join(home, ".gitconfig"),
		"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "diff.external", "GIT_CONFIG_VALUE_0": program,
		"GIT_CONFIG_PARAMETERS": "'core.fsmonitor'='" + program + "'",
		"GIT_EXTERNAL_DIFF":     program, "GIT_TRACE": trace, "GIT_TRACE2": trace,
		"GIT_OBJECT_DIRECTORY": empty, "GIT_NAMESPACE": "other", "GIT_NO_REPLACE_OBJECTS": "",
		"GIT_DIR": empty, "GIT_WORK_TREE": empty, "GIT_INDEX_FILE": filepath.Join(empty, "index"),
	} {
		t.Setenv(k, v)
	}
	rep, err := s.ScanRange(bg, Repo{Dir: dir}, Range{Include: []string{"HEAD"}})
	if ExitCode(err) != 1 || plain(t, rep) != head[:12]+":a.md:2: id-prefix\n" {
		t.Errorf("range: %v, %q", err, plain(t, rep))
	}
	leak(t, rep, err)
	rep, err = s.ScanIndex(bg, Repo{Dir: dir})
	if ExitCode(err) != 1 || plain(t, rep) != "a.md:2: id-prefix\n" {
		t.Errorf("index: %v, %q", err, plain(t, rep))
	}
	leak(t, rep, err)
	if ran() {
		t.Error("a program ran")
	}
	if _, err := os.Stat(trace); err == nil {
		t.Error("git wrote a trace")
	}
}

// ADR-001 negative test 12, network: a partial clone whose blob is not local
// exits 2 and fetches nothing. The source it was cloned from is still there,
// so a lazy fetch would have succeeded and found the token.
func TestNegative12NoLazyFetch(t *testing.T) {
	s := generic(t)
	src, git, _ := twoCommits(t)
	git("config", "uploadpack.allowFilter", "true")
	git("config", "uploadpack.allowAnySHA1InWant", "true")
	clone := filepath.Join(t.TempDir(), "clone")
	if out, err := exec.Command("git", "clone", "-q", "--no-checkout", "--filter=blob:none", "file://"+src, clone).CombinedOutput(); err != nil {
		t.Fatalf("partial clone: %v\n%s", err, out)
	}
	count := func() string {
		out, _ := exec.Command("git", "-C", clone, "count-objects").Output()
		return string(out)
	}
	before := count()
	rep, err := s.ScanRange(bg, Repo{Dir: clone}, Range{Include: []string{"HEAD"}})
	wantError(t, err, CodeGit)
	if rep != nil || !strings.HasPrefix(err.Error(), "cannot diff commit ") || count() != before {
		t.Errorf("partial clone: %v, objects %q then %q", err, before, count())
	}
	leak(t, rep, err)
}

// ADR-001 negative test 13: git's standard error never reaches the output. A
// missing blob and a missing commit each exit 2 with one fixed line, through
// the command line in TestNegative13GitStderr in cmd/hush, and here with the
// fixed message and the commit's id.
func TestNegative13MissingObjects(t *testing.T) {
	s := generic(t)
	dir, git, head := twoCommits(t)
	blob := git("rev-parse", "HEAD:a.md")
	// The work tree's copy goes too: git's diff may read a file from the work
	// tree when the index says it holds the same blob.
	for _, p := range []string{filepath.Join(dir, ".git", "objects", blob[:2], blob[2:]), filepath.Join(dir, "a.md")} {
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := s.ScanRange(bg, Repo{Dir: dir}, Range{Include: []string{"HEAD"}})
	wantError(t, err, CodeGit)
	if rep != nil || err.Error() != "cannot diff commit "+head[:12] || err.(*Error).Commit() != head {
		t.Errorf("missing blob: %v", err)
	}
	leak(t, rep, err)
	if err := os.Remove(filepath.Join(dir, ".git", "objects", head[:2], head[2:])); err != nil {
		t.Fatal(err)
	}
	rep, err = s.ScanRange(bg, Repo{Dir: dir}, Range{Include: []string{head}})
	wantError(t, err, CodeRange)
	leak(t, rep, err)

	// A missing ancestor: every revision resolves and peels, and rev-list
	// fails on the parent (part d, review round 1, HSH-11/D56).
	dir, git, head = twoCommits(t)
	parent := git("rev-parse", "HEAD~1")
	if err := os.Remove(filepath.Join(dir, ".git", "objects", parent[:2], parent[2:])); err != nil {
		t.Fatal(err)
	}
	for _, r := range []Range{{Include: []string{"HEAD"}}, {Include: []string{head}}} {
		rep, err = s.ScanRange(bg, Repo{Dir: dir}, r)
		wantError(t, err, CodeGit)
		if rep != nil || err.Error() != "cannot read commit "+parent[:12] || err.(*Error).Commit() != parent {
			t.Errorf("missing ancestor: %v", err)
		}
		leak(t, rep, err)
	}
}

// git 2.44 is the minimum (HSH-11/D6): a git that reports an older version,
// fails to run, or is missing exits 2 with code git, for every git target.
func TestGitMinimum(t *testing.T) {
	s := generic(t)
	dir, _, _ := twoCommits(t)
	bin := t.TempDir()
	fake := filepath.Join(bin, "git")
	for _, c := range []struct{ name, script string }{
		{"2.43", "#!/bin/sh\necho 'git version 2.43.0'\n"},
		{"1.99", "#!/bin/sh\necho 'git version 1.99.9'\n"},
		{"garbled", "#!/bin/sh\necho 'git version x'\n"},
		{"fails", "#!/bin/sh\nexit 129\n"},
		{"missing", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			os.Remove(fake)
			if c.script != "" {
				if err := os.WriteFile(fake, []byte(c.script), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("PATH", bin)
			for _, scan := range []func() (*Report, error){
				func() (*Report, error) { return s.ScanRange(bg, Repo{Dir: dir}, Range{Include: []string{"HEAD"}}) },
				func() (*Report, error) { return s.ScanIndex(bg, Repo{Dir: dir}) },
			} {
				rep, err := scan()
				wantError(t, err, CodeGit)
				if rep != nil || err.Error() != "git is missing or older than 2.44" {
					t.Errorf("got %v", err)
				}
				leak(t, rep, err)
			}
		})
	}
}

// ADR-001 negative test 11, grafts: a repository that holds info/grafts
// exits 2, for a range scan and an index scan, even when the grafts file
// would not shorten the range.
func TestNegative11Grafts(t *testing.T) {
	s := generic(t)
	dir, _, head := twoCommits(t)
	write(t, dir, ".git/info/grafts", head+"\n") // HEAD as a root: its parent unseen
	for name, scan := range map[string]func() (*Report, error){
		"range": func() (*Report, error) { return s.ScanRange(bg, Repo{Dir: dir}, Range{Include: []string{"HEAD"}}) },
		"index": func() (*Report, error) { return s.ScanIndex(bg, Repo{Dir: dir}) },
	} {
		rep, err := scan()
		wantError(t, err, CodeGit)
		if rep != nil || err.Error() != "the repository has grafts" {
			t.Errorf("%s: %v", name, err)
		}
		leak(t, rep, err)
	}
}

// Repo.Dir names the repository: its work tree's top, a directory below it,
// its git directory, a linked worktree, that worktree's git directory, or a
// bare clone. A directory outside every repository is ErrGit.
func TestRepoDir(t *testing.T) {
	s := generic(t)
	dir, git, head := twoCommits(t)
	write(t, dir, "sub/x.md", "clean\n")
	wt := filepath.Join(t.TempDir(), "wt")
	git("worktree", "add", "-q", wt)
	bare := filepath.Join(t.TempDir(), "bare.git")
	if out, err := exec.Command("git", "clone", "-q", "--bare", dir, bare).CombinedOutput(); err != nil {
		t.Fatalf("bare clone: %v\n%s", err, out)
	}
	want := head[:12] + ":a.md:2: id-prefix\n"
	for name, d := range map[string]string{
		"top": dir, "below": filepath.Join(dir, "sub"), "git dir": filepath.Join(dir, ".git"),
		"worktree": wt, "worktree git dir": filepath.Join(dir, ".git", "worktrees", "wt"), "bare": bare,
	} {
		rep, err := s.ScanRange(bg, Repo{Dir: d}, Range{Include: []string{head}})
		if ExitCode(err) != 1 || plain(t, rep) != want {
			t.Errorf("%s: range: %v, %q", name, err, plain(t, rep))
		}
		leak(t, rep, err)
		if name == "bare" {
			continue
		}
		rep, err = s.ScanIndex(bg, Repo{Dir: d})
		if ExitCode(err) != 1 || plain(t, rep) != "a.md:2: id-prefix\n" {
			t.Errorf("%s: index: %v, %q", name, err, plain(t, rep))
		}
		leak(t, rep, err)
	}
	rep, err := s.ScanRange(bg, Repo{Dir: t.TempDir()}, Range{Include: []string{"HEAD"}})
	wantError(t, err, CodeGit)
	if rep != nil || err.Error() != "not a git repository" {
		t.Errorf("outside: %v", err)
	}
	leak(t, rep, err)
}

// ADR-001 negative test 11, the refs a range walks (T20): --all walks a
// commit reachable only from an annotated tag, from refs/original/, from a
// linked worktree's HEAD, and from the notes ref, and not the stash;
// --branches walks only branches.
func TestNegative11Refs(t *testing.T) {
	s := generic(t)
	dir, git := gitRepo(t)
	write(t, dir, "base.md", "clean\n")
	git("add", "-A")
	git("commit", "-q", "-m", "base")
	main := git("symbolic-ref", "--short", "HEAD")
	// side makes a commit holding a token in name, off the base, reachable
	// from nothing but what keep does with it.
	side := func(name string, keep func(id string)) string {
		git("checkout", "-q", "--detach", main)
		write(t, dir, name, "see "+lc.Bad+"\n")
		git("add", "-A")
		git("commit", "-q", "-m", name)
		id := git("rev-parse", "HEAD")
		keep(id)
		git("checkout", "-q", main)
		return id
	}
	tagged := side("tagged.md", func(id string) { git("tag", "-a", "-m", "a tag", "v1", id) })
	original := side("original.md", func(id string) { git("update-ref", "refs/original/refs/heads/"+main, id) })
	wt := filepath.Join(t.TempDir(), "wt")
	git("worktree", "add", "-q", "--detach", wt, main)
	write(t, wt, "worktree.md", "see "+lc.Bad+"\n")
	git("-C", wt, "add", "-A")
	git("-C", wt, "commit", "-q", "-m", "in the worktree")
	worktree := git("-C", wt, "rev-parse", "HEAD")
	git("notes", "add", "-m", "see "+lc.Bad, main)
	notes := git("rev-parse", "refs/notes/commits")
	write(t, dir, "base.md", "clean\nsee "+lc.Bad+"\n")
	git("stash", "-q")

	rep, err := s.ScanRange(bg, Repo{Dir: dir}, Range{IncludeRefs: []RefSelector{AllRefs}})
	got := plain(t, rep)
	for name, id := range map[string]string{"tagged.md": tagged, "original.md": original, "worktree.md": worktree} {
		if !strings.Contains(got, id[:12]+":"+name+":1: id-prefix\n") {
			t.Errorf("--all: no finding in %s", name)
		}
	}
	if ExitCode(err) != 1 || !strings.Contains(got, notes[:12]+":") || strings.Contains(got, "base.md") {
		t.Errorf("--all: %v, %q", err, got)
	}
	leak(t, rep, err)
	rep, err = s.ScanRange(bg, Repo{Dir: dir}, Range{IncludeRefs: []RefSelector{Branches}})
	if err != nil || rep.Scanned().Commits != 1 {
		t.Errorf("--branches: %v, %+v", err, rep.Scanned())
	}
	leak(t, rep, err)
	rep, err = s.ScanRange(bg, Repo{Dir: dir}, Range{IncludeRefs: []RefSelector{Tags}, ExcludeRefs: []RefSelector{Branches}})
	if ExitCode(err) != 1 || plain(t, rep) != tagged[:12]+":tagged.md:1: id-prefix\n" {
		t.Errorf("--tags --not --branches: %v, %q", err, plain(t, rep))
	}
	leak(t, rep, err)
}

// ADR-001 negative test 11, non-commit targets (T20): a named revision, or a
// ref a selector lists, whose fully peeled target is a blob or a tree exits
// 2, never 0, even when the blob holds a token rev-list would never show.
// A subtracted selector skips such a ref, since it subtracts nothing.
func TestNegative11NonCommitPeel(t *testing.T) {
	s := generic(t)
	dir, git, _ := twoCommits(t)
	c := exec.Command("git", "-C", dir, "hash-object", "-w", "--stdin")
	c.Stdin = strings.NewReader("see " + lc.Bad + "\n")
	out, err := c.Output()
	if err != nil {
		t.Fatal(err)
	}
	blob := strings.TrimSpace(string(out))
	git("tag", "-a", "-m", "on a blob", "blobtag", blob)
	git("tag", "-a", "-m", "on a tag", "tagtag", "blobtag")
	for i, rg := range []Range{
		{Include: []string{"blobtag"}},
		{Include: []string{"tagtag"}},
		{Include: []string{"HEAD^{tree}"}},
		{Include: []string{"HEAD:a.md"}},
		{Include: []string{"HEAD"}, Exclude: []string{"blobtag"}},
		{Include: []string{"HEAD~1..blobtag"}},
	} {
		rep, err := s.ScanRange(bg, Repo{Dir: dir}, rg)
		wantError(t, err, CodeRange)
		if rep != nil || !strings.HasSuffix(err.Error(), " does not resolve to a commit") {
			t.Errorf("case %d: %v", i, err)
		}
		leak(t, rep, err)
	}
	for _, sel := range []RefSelector{AllRefs, Tags} {
		rep, err := s.ScanRange(bg, Repo{Dir: dir}, Range{IncludeRefs: []RefSelector{sel}})
		wantError(t, err, CodeRange)
		if rep != nil || err.Error() != "range: a listed ref does not point to a commit" {
			t.Errorf("selector %v: %v", sel, err)
		}
		leak(t, rep, err)
	}
	git("tag", "treetag", "HEAD^{tree}")
	rep, err := s.ScanRange(bg, Repo{Dir: dir}, Range{IncludeRefs: []RefSelector{Branches}, ExcludeRefs: []RefSelector{Tags}, AllowEmpty: true})
	if ExitCode(err) != 1 || rep.Scanned().Commits != 2 {
		t.Errorf("--branches --not --tags: %v", err)
	}
	leak(t, rep, err)
	missing := strings.Repeat("1", len(blob))
	rep, err = s.ScanRange(bg, Repo{Dir: dir}, Range{Include: []string{"HEAD", missing}})
	wantError(t, err, CodeRange)
	if rep != nil || err.Error() != "range: revision 2 does not resolve to a commit" {
		t.Errorf("missing object: %v", err)
	}
	leak(t, rep, err)
}

// ADR-001 negative test 11, shallow clones (T20): --all in a depth-1 clone
// exits 2; a range that stops above the boundary is scanned.
func TestNegative11Shallow(t *testing.T) {
	s := generic(t)
	src, git, head := twoCommits(t)
	write(t, src, "c.md", "clean\n")
	git("add", "-A")
	git("commit", "-q", "-m", "third")
	for _, depth := range []string{"1", "2"} {
		clone := filepath.Join(t.TempDir(), "clone")
		if out, err := exec.Command("git", "clone", "-q", "--depth="+depth, "file://"+src, clone).CombinedOutput(); err != nil {
			t.Fatalf("shallow clone: %v\n%s", err, out)
		}
		rep, err := s.ScanRange(bg, Repo{Dir: clone}, Range{IncludeRefs: []RefSelector{AllRefs}})
		wantError(t, err, CodeRange)
		if rep != nil || err.Error() != "range: reaches a shallow boundary" {
			t.Errorf("depth %s: %v", depth, err)
		}
		leak(t, rep, err)
	}
	clone := filepath.Join(t.TempDir(), "clone")
	if out, err := exec.Command("git", "clone", "-q", "--depth=2", "file://"+src, clone).CombinedOutput(); err != nil {
		t.Fatalf("shallow clone: %v\n%s", err, out)
	}
	rep, err := s.ScanRange(bg, Repo{Dir: clone}, Range{Include: []string{head + "..HEAD"}})
	if err != nil || rep.Scanned().Commits != 1 {
		t.Errorf("above the boundary: %v", err)
	}
	leak(t, rep, err)
}

// hush's selectors are the target's, value for value.
func TestSelectorValues(t *testing.T) {
	for _, c := range []struct {
		h  RefSelector
		tg target.Selector
	}{{AllRefs, target.AllRefs}, {Branches, target.Branches}, {Tags, target.Tags}, {Remotes, target.Remotes}} {
		if target.Selector(c.h) != c.tg {
			t.Errorf("%s: target value %d", c.h, c.tg)
		}
	}
}

// hashObject writes content as an object of type typ, as git hash-object
// checks it, and returns its id.
func hashObject(t *testing.T, dir, typ, content string) string {
	t.Helper()
	c := exec.Command("git", "-C", dir, "hash-object", "-t", typ, "-w", "--stdin")
	c.Stdin = strings.NewReader(content)
	out, err := c.Output()
	if err != nil {
		t.Fatalf("hash-object -t %s failed", typ)
	}
	return strings.TrimSpace(string(out))
}

// ADR-001 negative test 11, annotated tags (T21): --all scans a tag's
// message and tagger and walks its commit. A tag object comes right after
// the commit it points to, and a tag whose commit is outside the range comes
// after every commit, in the order the refs list them (section 6.2). A tag
// of a tag is scanned too.
func TestNegative11AnnotatedTags(t *testing.T) {
	s := scanner(t, Config{Destination: Public(), Terms: load(t, adrTerms())})
	dir, git := gitRepo(t)
	write(t, dir, "a.md", "clean\n")
	git("add", "-A")
	git("commit", "-q", "-m", "first")
	first := git("rev-parse", "HEAD")
	write(t, dir, "b.md", "clean\n")
	git("add", "-A")
	git("commit", "-q", "-m", "second")
	second := git("rev-parse", "HEAD")
	git("tag", "-a", "-m", "on the first, "+lc.Quorvel, "t1", first)
	git("tag", "-a", "-m", "on the second\n\nsee "+lc.Bad, "t2", second)
	git("tag", "-a", "-m", "a tag of a tag, "+lc.Quorvel, "t3", "t1")
	t1, t2, t3 := git("rev-parse", "t1"), git("rev-parse", "t2"), git("rev-parse", "t3")
	t.Setenv("GIT_COMMITTER_EMAIL", lc.Identity) // the tagger of t4
	git("tag", "-a", "-m", "clean", "t4", second)
	t4 := git("rev-parse", "t4")

	rep, err := s.ScanRange(bg, Repo{Dir: dir}, Range{IncludeRefs: []RefSelector{AllRefs}})
	want := t1[:12] + ":(tag):6: set:clients\n" +
		t3[:12] + ":(tag):6: set:clients\n" +
		t2[:12] + ":(tag):8: id-prefix\n" +
		t4[:12] + ":(tag):4: email-address\n"
	if ExitCode(err) != 1 || plain(t, rep) != want || rep.Scanned().Commits != 2 {
		t.Errorf("--all: %v, %q, want %q", err, plain(t, rep), want)
	}
	fs := rep.Findings()
	if len(fs) == 4 && (fs[0].Tag != t1 || fs[0].Part != Message || fs[0].Commit != "" || fs[3].Part != Tagger) {
		t.Errorf("findings: %+v", fs)
	}
	leak(t, rep, err)

	// Named, the tag's own commit already walked: the tag still comes last.
	rep, err = s.ScanRange(bg, Repo{Dir: dir}, Range{Include: []string{"t3", second}, Exclude: []string{first}})
	want = t3[:12] + ":(tag):6: set:clients\n" + t1[:12] + ":(tag):6: set:clients\n"
	if ExitCode(err) != 1 || plain(t, rep) != want || rep.Scanned().Commits != 1 {
		t.Errorf("t3 %s..: %v, %q, want %q", second[:12], err, plain(t, rep), want)
	}
	leak(t, rep, err)
	// Subtracted, a tag is not scanned.
	rep, err = s.ScanRange(bg, Repo{Dir: dir}, Range{Include: []string{second}, Exclude: []string{"t3"}})
	if err != nil || rep.Scanned().Commits != 1 {
		t.Errorf("^t3: %v, %q", err, plain(t, rep))
	}
	leak(t, rep, err)
	// The tag's commit outside the range, and the range empty: the tag is
	// scanned, and the range is still empty.
	rep, err = s.ScanRange(bg, Repo{Dir: dir}, Range{Include: []string{"t2"}, Exclude: []string{second}, AllowEmpty: true})
	if ExitCode(err) != 1 || plain(t, rep) != t2[:12]+":(tag):8: id-prefix\n" || rep.Scanned().Commits != 0 {
		t.Errorf("t2 ^t2: %v, %q", err, plain(t, rep))
	}
	leak(t, rep, err)
	rep, err = s.ScanRange(bg, Repo{Dir: dir}, Range{Include: []string{"t2"}, Exclude: []string{second}})
	wantError(t, err, CodeEmptyRange)
	leak(t, rep, err)
}

// ADR-001 negative test 17 (T21): mergetag and signature blocks, with
// fixtures built offline by git hash-object and, when it is installed,
// ssh-keygen.
func TestNegative17Signatures(t *testing.T) {
	s := scanner(t, Config{Destination: Public(), Terms: load(t, adrTerms())})
	dir, git := gitRepo(t)
	write(t, dir, "a.md", "clean\n")
	git("add", "-A")
	git("commit", "-q", "-m", "first")
	first, tree := git("rev-parse", "HEAD"), git("rev-parse", "HEAD^{tree}")
	who := "alice <alice@example.org> 1700000000 +0000"
	// A base64 line that spells a term is a known limit: skipped in a block.
	body := []string{"-----BEGIN PGP SIGNATURE-----", "", "iQEzBAAB" + lc.Quorvel + "CAAdFiEE", "=Ab12", "-----END PGP SIGNATURE-----"}
	scan := func(what, rev, want string) {
		t.Helper()
		rep, err := s.ScanRange(bg, Repo{Dir: dir}, Range{Include: []string{rev}, AllowEmpty: true})
		if got := plain(t, rep); want == "" && err != nil || want != "" && (ExitCode(err) != 1 || got != want) {
			t.Errorf("%s: %v, %q, want %q", what, err, got, want)
		}
		leak(t, rep, err)
	}

	// A merge whose mergetag's embedded message holds a term: part header.
	git("checkout", "-q", "-b", "side")
	write(t, dir, "b.md", "clean\n")
	git("add", "-A")
	git("commit", "-q", "-m", "side")
	side := git("rev-parse", "HEAD")
	merge := hashObject(t, dir, "commit", "tree "+tree+"\nparent "+first+"\nparent "+side+"\n"+
		"author "+who+"\ncommitter "+who+"\n"+
		"mergetag object "+side+"\n type commit\n tag v1\n tagger "+who+"\n \n see "+lc.Quorvel+"\n "+strings.Join(body, "\n ")+"\n"+
		"\nmerge\n")
	scan("mergetag", merge, merge[:12]+":(commit):11: set:clients\n")
	rep, _ := s.ScanRange(bg, Repo{Dir: dir}, Range{Include: []string{merge}, Exclude: []string{side}})
	if fs := rep.Findings(); len(fs) != 1 || fs[0].Part != Header || fs[0].Commit != merge {
		t.Errorf("mergetag: %+v", fs)
	}
	leak(t, rep)

	// A gpgsig header: its Comment: line is scanned, its base64 is not.
	signed := hashObject(t, dir, "commit", "tree "+tree+"\nparent "+first+"\n"+
		"author "+who+"\ncommitter "+who+"\n"+
		"gpgsig "+body[0]+"\n Comment: "+lc.Quorvel+"\n "+strings.Join(body[1:], "\n ")+"\n"+
		"\nsigned\n")
	scan("gpgsig", signed, signed[:12]+":(commit):6: set:clients\n")

	// A tag whose message ends in a signature: its base64 is skipped. One
	// whose message ends in a fake block of free text: found.
	tag := func(name, message string) string {
		return hashObject(t, dir, "tag", "object "+first+"\ntype commit\ntag "+name+"\ntagger "+who+"\n\n"+message)
	}
	clean := tag("v2", "a release\n"+strings.Join(body, "\n")+"\n")
	scan("signed tag", clean, "")
	fake := tag("v3", "a release\n-----BEGIN PGP SIGNATURE-----\nsee "+lc.Quorvel+" here\n-----END PGP SIGNATURE-----\n")
	scan("fake block", fake, fake[:12]+":(tag):8: set:clients\n")

	// A tag signed by git with an SSH key made here.
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Log("ssh-keygen is not installed: the SSH-signed tag is not checked")
		return
	}
	key := filepath.Join(t.TempDir(), "key")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}
	git("-c", "gpg.format=ssh", "-c", "user.signingkey="+key, "tag", "-s", "-m", "a release", "v4", first)
	if !strings.Contains(git("cat-file", "tag", "v4"), "-----BEGIN SSH SIGNATURE-----") {
		t.Fatal("setup: v4 is not signed")
	}
	scan("SSH-signed tag", "v4", "")
}

// A commit's ids are only its first line, "tree ID", and the "parent ID"
// lines straight after it, each one line (part d, review round 1). A
// continuation after a parent line, and tree and parent lines after the
// committer, are scanned as headers; a parent line after the committer is
// not a parent, so a root commit holding one is diffed against the empty
// tree. The objects are written by git hash-object --literally.
func TestCommitIDHeaders(t *testing.T) {
	s := scanner(t, Config{Destination: Public(), Terms: load(t, adrTerms())})
	dir, git := gitRepo(t)
	write(t, dir, "a.md", "see "+lc.Quorvel+"\n")
	git("add", "-A")
	git("commit", "-q", "-m", "first")
	first, tree := git("rev-parse", "HEAD"), git("rev-parse", "HEAD^{tree}")
	who := "alice <alice@example.org> 1700000000 +0000"
	literal := func(content string) string {
		t.Helper()
		c := exec.Command("git", "-C", dir, "hash-object", "--literally", "-t", "commit", "-w", "--stdin")
		c.Stdin = strings.NewReader(content)
		out, err := c.Output()
		if err != nil {
			t.Fatal("hash-object --literally failed")
		}
		return strings.TrimSpace(string(out))
	}
	for _, c := range []struct {
		what, obj, want string
		exclude         []string
	}{
		{"a continuation after parent",
			"tree " + tree + "\nparent " + first + "\n see " + lc.Quorvel + "\nauthor " + who + "\ncommitter " + who + "\n\nm\n",
			":(commit):3: set:clients\n", []string{first}},
		{"tree and parent after committer",
			"tree " + tree + "\nparent " + first + "\nauthor " + who + "\ncommitter " + who + "\ntree " + lc.Quorvel + "\nparent " + lc.Quorvel + "\n\nm\n",
			":(commit):5: set:clients\n@:(commit):6: set:clients\n", []string{first}},
		{"a root commit with a parent line after committer",
			"tree " + tree + "\nauthor " + who + "\ncommitter " + who + "\nparent " + first + "\n\nm\n",
			":a.md:1: set:clients\n", nil},
	} {
		id := literal(c.obj)
		rep, err := s.ScanRange(bg, Repo{Dir: dir}, Range{Include: []string{id}, Exclude: c.exclude})
		want := id[:12] + strings.ReplaceAll(c.want, "@", id[:12])
		if ExitCode(err) != 1 || plain(t, rep) != want {
			t.Errorf("%s: %v, %q, want %q", c.what, err, plain(t, rep), want)
		}
		leak(t, rep, err)
	}
}

// A commit whose encoding header names anything but UTF8 cannot be read:
// hush does not re-encode its message, and scanning the raw bytes would miss
// a non-ASCII term (part d, review round 1, HSH-11/D55). UTF8 named as
// "utf-8", "Utf-8", "utf8" or "UTF8" is scanned.
func TestCommitEncoding(t *testing.T) {
	s := scanner(t, Config{Destination: Public(), Terms: load(t, "[x]\n"+lc.Accented+"\n")})
	dir, git := gitRepo(t)
	write(t, dir, "a.md", "clean\n")
	git("add", "-A")
	git("commit", "-q", "-m", "first")
	first, tree := git("rev-parse", "HEAD"), git("rev-parse", "HEAD^{tree}")
	latin1 := strings.ReplaceAll(lc.Accented, "\u00e9", "\xe9")
	msg := filepath.Join(t.TempDir(), "msg")
	if err := os.WriteFile(msg, []byte("see "+latin1+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git("-c", "i18n.commitEncoding=latin1", "commit", "-q", "--allow-empty", "-F", msg)
	head := git("rev-parse", "HEAD")
	if !strings.Contains(git("cat-file", "commit", head), "\nencoding latin1\n") {
		t.Fatal("setup: no encoding header")
	}
	rep, err := s.ScanRange(bg, Repo{Dir: dir}, Range{Include: []string{"HEAD"}, Exclude: []string{first}})
	wantError(t, err, CodeGit)
	if rep != nil || err.Error() != "cannot read commit "+head[:12] {
		t.Errorf("latin1: %v", err)
	}
	leak(t, rep, err)
	who := "alice <alice@example.org> 1700000000 +0000"
	for _, enc := range []string{"utf-8", "Utf-8", "utf8", "UTF8"} {
		id := hashObject(t, dir, "commit", "tree "+tree+"\nparent "+first+"\nauthor "+who+"\ncommitter "+who+
			"\nencoding "+enc+"\n\nsee "+lc.Accented+"\n")
		rep, err := s.ScanRange(bg, Repo{Dir: dir}, Range{Include: []string{id}, Exclude: []string{first}})
		if want := id[:12] + ":(commit):7: set:x\n"; ExitCode(err) != 1 || plain(t, rep) != want {
			t.Errorf("%s: %v, %q, want %q", enc, err, plain(t, rep), want)
		}
		leak(t, rep, err)
	}
}

// ADR-001 negative test 11, typechanges (T22): a commit turns a file into a
// symlink and changes a second file whose added line holds a term. The term
// is reported at the second file's own path and line: the typechange's two
// sections do not shift the pairing of records and sections.
func TestNegative11Typechange(t *testing.T) {
	s := scanner(t, Config{Destination: Public(), Terms: load(t, adrTerms())})
	dir, git := gitRepo(t)
	write(t, dir, "a.md", "one\n")
	write(t, dir, "b.md", "one\n")
	git("add", "-A")
	git("commit", "-q", "-m", "first")
	os.Remove(filepath.Join(dir, "a.md"))
	if err := os.Symlink("b.md", filepath.Join(dir, "a.md")); err != nil {
		t.Fatal(err)
	}
	write(t, dir, "b.md", "one\ntwo\n"+lc.Quorvel+"\n")
	git("add", "-A")
	git("commit", "-q", "-m", "second")
	head := git("rev-parse", "HEAD")
	if !strings.Contains(git("diff-tree", "-r", "HEAD~1", "HEAD"), " T\ta.md") {
		t.Fatal("setup: no typechange")
	}
	rep, err := s.ScanRange(bg, Repo{Dir: dir}, Range{Include: []string{"HEAD~1..HEAD"}})
	if ExitCode(err) != 1 || plain(t, rep) != head[:12]+":b.md:3: set:clients\n" || rep.Scanned().Files != 2 {
		t.Errorf("got %v, %q, %+v", err, plain(t, rep), rep.Scanned())
	}
	leak(t, rep, err)
}

// ADR-001 negative test 12, attributes (T22): a committed .gitattributes
// with "* -diff", with core.bigFileThreshold=1, does not hide an added line
// that holds a term, since diff-tree runs with --text.
func TestNegative12Attributes(t *testing.T) {
	s := scanner(t, Config{Destination: Public(), Terms: load(t, adrTerms())})
	dir, git := gitRepo(t)
	write(t, dir, ".gitattributes", "* -diff\n")
	write(t, dir, "a.md", "one\n")
	git("add", "-A")
	git("commit", "-q", "-m", "first")
	git("config", "core.bigFileThreshold", "1")
	write(t, dir, "a.md", "one\n"+lc.Quorvel+"\n")
	git("add", "-A")
	git("commit", "-q", "-m", "second")
	head := git("rev-parse", "HEAD")
	if !strings.Contains(git("diff", "HEAD~1", "HEAD"), "Binary files") {
		t.Fatal("setup: git does not hide the change")
	}
	rep, err := s.ScanRange(bg, Repo{Dir: dir}, Range{Include: []string{"HEAD~1..HEAD"}})
	if ExitCode(err) != 1 || plain(t, rep) != head[:12]+":a.md:2: set:clients\n" {
		t.Errorf("got %v, %q", err, plain(t, rep))
	}
	leak(t, rep, err)
}

// The NUL rule on each new blob (T22): a blob that holds a NUL byte gives
// binary-unscanned and its lines are not scanned, even when the NUL is in a
// part the commit does not change; a change of mode alone adds no content and
// reads no blob; a gitlink names a commit, not a blob.
func TestRangeNULRule(t *testing.T) {
	s := generic(t)
	dir, git := gitRepo(t)
	write(t, dir, "bin.dat", "x\x00y\n")
	write(t, dir, "mode.sh", "see "+lc.Bad+"\n")
	git("add", "-A")
	git("commit", "-q", "-m", "first")
	first := git("rev-parse", "HEAD")
	write(t, dir, "bin.dat", "x\x00y\nsee "+lc.Bad+"\n")
	write(t, dir, "new.dat", "\x00")
	if err := os.Chmod(filepath.Join(dir, "mode.sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	git("add", "-A")
	git("update-index", "--add", "--cacheinfo", "160000,"+first+",sub")
	git("commit", "-q", "-m", "second")
	head := git("rev-parse", "HEAD")
	rep, err := s.ScanRange(bg, Repo{Dir: dir}, Range{Include: []string{first + "..HEAD"}})
	want := head[:12] + ":bin.dat:0: binary-unscanned\n" + head[:12] + ":new.dat:0: binary-unscanned\n"
	if ExitCode(err) != 1 || plain(t, rep) != want || rep.Scanned().Files != 4 {
		t.Errorf("got %v, %q, %+v", err, plain(t, rep), rep.Scanned())
	}
	leak(t, rep, err)
}

// Range paths are git's raw bytes from -z records (T22), so a tab before an
// address in a path is found, and the path is redacted from that component,
// in every target that reports paths; a newline in a name prints as
// <redacted> with unreadable in path, and the content is still scanned
// (negative test 15, range).
func TestRangeRawPaths(t *testing.T) {
	s := generic(t)
	dir, git := gitRepo(t)
	write(t, dir, "base.md", "clean\n")
	git("add", "-A")
	git("commit", "-q", "-m", "first")
	write(t, dir, "docs/at\t"+lc.IPFlagged[0]+"/a.md", "clean\n")
	write(t, dir, "docs/new\nline.md", "see "+lc.Bad+"\n")
	git("add", "-A")
	git("commit", "-q", "-m", "second")
	head := git("rev-parse", "HEAD")[:12]
	want := "docs/<redacted>:0: ip-address in path\n" + "docs/<redacted>:0: unreadable in path\n" +
		"docs/<redacted>:0: unreadable in path\n" + "docs/<redacted>:1: id-prefix\n"
	rep, err := s.ScanRange(bg, Repo{Dir: dir}, Range{Include: []string{"HEAD~1..HEAD"}})
	var ranged strings.Builder
	for _, l := range strings.SplitAfter(strings.TrimSuffix(want, "\n"), "\n") {
		ranged.WriteString(head + ":" + strings.TrimSuffix(l, "\n") + "\n")
	}
	if ExitCode(err) != 1 || plain(t, rep) != ranged.String() {
		t.Errorf("range: %v, %q, want %q", err, plain(t, rep), ranged.String())
	}
	leak(t, rep, err)
	rep, err = s.ScanIndex(bg, Repo{Dir: dir})
	if ExitCode(err) != 1 || plain(t, rep) != want {
		t.Errorf("index: %v, %q", err, plain(t, rep))
	}
	leak(t, rep, err)
	rep, err = s.ScanTree(bg, dir, "docs")
	if ExitCode(err) != 1 || plain(t, rep) != want {
		t.Errorf("tree: %v, %q", err, plain(t, rep))
	}
	leak(t, rep, err)
}

// A gitlink's path is scanned when a .gitmodules file the commit does not
// hold sets ignore = all for it: diff-tree runs with --ignore-submodules=none,
// so the record is not dropped (part d, review round 1).
func TestRangeIgnoredSubmodule(t *testing.T) {
	s := generic(t)
	dir, git, head := twoCommits(t)
	path := "lib/x" + lc.Bad
	git("update-index", "--add", "--cacheinfo", "160000,"+head+","+path)
	git("commit", "-q", "-m", "gitlink")
	write(t, dir, ".gitmodules", "[submodule \"x\"]\n\tpath = "+path+"\n\turl = ./x\n\tignore = all\n")
	commit := git("rev-parse", "HEAD")
	rep, err := s.ScanRange(bg, Repo{Dir: dir}, Range{Include: []string{"HEAD~1..HEAD"}})
	if want := commit[:12] + ":lib/<redacted>:0: id-prefix in path\n"; ExitCode(err) != 1 || plain(t, rep) != want {
		t.Errorf("got %v, %q, want %q", err, plain(t, rep), want)
	}
	leak(t, rep, err)
}

// ADR-001 negative test 5 and ADR-002 negative test 1, for index and range
// scans (T23): a repository whose work tree or git directory holds the term
// file, reached directly or through a symlink from outside, or that holds the
// file's bytes as a blob, staged or committed on any branch, exits 2 with
// code term-file before anything is scanned. A term file outside, with other
// bytes, scans as usual.
func TestNegative5TermFileInRepository(t *testing.T) {
	content := adrTerms()
	dir, git, _ := twoCommits(t)
	outside := termFile(t, content)
	at := dir // the repository scanned
	check := func(what, path, msg string) {
		t.Helper()
		ts, err := LoadTermSets(path)
		if err != nil {
			t.Fatalf("%s: LoadTermSets: %v", what, err)
		}
		s := scanner(t, Config{Destination: Public(), Terms: ts})
		for name, scan := range map[string]func() (*Report, error){
			"range": func() (*Report, error) { return s.ScanRange(bg, Repo{Dir: at}, Range{Include: []string{"HEAD"}}) },
			"index": func() (*Report, error) { return s.ScanIndex(bg, Repo{Dir: at}) },
		} {
			rep, err := scan()
			if msg == "" {
				if ExitCode(err) != 1 {
					t.Errorf("%s, %s: %v", what, name, err)
				}
			} else {
				wantError(t, err, CodeTermFile)
				if rep != nil || err.Error() != msg {
					t.Errorf("%s, %s: %v", what, name, err)
				}
			}
			leak(t, rep, err)
		}
	}
	const inside, committed = "the term file is inside the scanned repository", "the term file is committed to the scanned repository"
	check("outside", outside, "")
	for _, p := range []string{"terms", ".hush/terms", ".git/terms", ".git/info/terms"} {
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		check(p, full, inside)
		link := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(full, link); err != nil {
			t.Fatal(err)
		}
		check(p+" through a symlink", link, inside)
		os.Remove(full)
	}
	// A linked worktree, named by its work tree or its git directory: a term
	// file in the main work tree, or in the main .git, is inside the
	// repository too (part d, review round 1).
	wt := filepath.Join(t.TempDir(), "wt")
	git("worktree", "add", "-q", wt)
	for _, p := range []string{"terms", ".git/terms"} {
		full := filepath.Join(dir, p)
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, at = range []string{wt, filepath.Join(dir, ".git", "worktrees", "wt")} {
			check("a linked worktree, "+p, full, inside)
		}
		os.Remove(full)
	}
	// A linked worktree of a submodule, whose common directory lies in the
	// superproject's .git/modules: a term file in the submodule's work tree,
	// which that directory's core.worktree names (part d, review round 2).
	lib, _, _ := twoCommits(t)
	sup, supGit := gitRepo(t)
	supGit("-c", "protocol.file.allow=always", "submodule", "add", "-q", lib, "s")
	swt := filepath.Join(t.TempDir(), "swt")
	if out, err := exec.Command("git", "-C", filepath.Join(sup, "s"), "worktree", "add", "-q", swt).CombinedOutput(); err != nil {
		t.Fatalf("setup: worktree add: %s", out)
	}
	full := filepath.Join(sup, "s", "terms")
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, at = range []string{swt, filepath.Join(sup, ".git", "modules", "s", "worktrees", "swt")} {
		check("a submodule's linked worktree", full, inside)
	}
	// A repository whose core.worktree names another directory: a term file
	// there, named by the repository's directory or its .git.
	cw, cwGit, _ := twoCommits(t)
	other := t.TempDir()
	cwGit("config", "core.worktree", other)
	full = filepath.Join(other, "terms")
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, at = range []string{cw, filepath.Join(cw, ".git")} {
		check("core.worktree elsewhere", full, inside)
	}
	at = dir
	// The same bytes staged, then committed on a branch HEAD does not reach.
	write(t, dir, "copy.txt", content)
	git("add", "copy.txt")
	os.Remove(filepath.Join(dir, "copy.txt"))
	check("staged", outside, committed)
	git("checkout", "-q", "-b", "other")
	git("commit", "-q", "-m", "copy")
	git("checkout", "-q", "-")
	check("committed on another branch", outside, committed)
}

// The index scan reads stage 0 only (HSH-11/D19): a path with conflict
// stages has no stage 0, and git commits none of them.
func TestScanIndexStageZero(t *testing.T) {
	s := generic(t)
	dir, git := gitRepo(t)
	write(t, dir, "c.md", "base\n")
	git("add", "-A")
	git("commit", "-q", "-m", "base")
	base := git("symbolic-ref", "--short", "HEAD")
	git("checkout", "-q", "-b", "side")
	write(t, dir, "c.md", "see "+lc.Bad+"\n")
	git("commit", "-q", "-am", "side")
	git("checkout", "-q", base)
	write(t, dir, "c.md", "ours\n")
	write(t, dir, "d.md", "see "+lc.Bad+"\n")
	git("add", "-A")
	git("commit", "-q", "-m", "ours")
	exec.Command("git", "-C", dir, "merge", "-q", "side").Run()
	if !strings.Contains(git("ls-files", "--stage"), " 3\tc.md") {
		t.Fatal("setup: no conflict")
	}
	rep, err := s.ScanIndex(bg, Repo{Dir: dir})
	if ExitCode(err) != 1 || plain(t, rep) != "d.md:1: id-prefix\n" || rep.Scanned().Files != 1 {
		t.Errorf("got %v, %q, %+v", err, plain(t, rep), rep.Scanned())
	}
	leak(t, rep, err)
}
