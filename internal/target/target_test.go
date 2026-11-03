package target

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	lc "github.com/nonhumanhq/hush/internal/leakcheck"
	"github.com/nonhumanhq/hush/internal/output"
	"github.com/nonhumanhq/hush/internal/rule"
	"github.com/nonhumanhq/hush/internal/termset"
)

// scanner returns a Scan with the ID-prefix rule and the sets in file.
func scanner(t *testing.T, file string, out *strings.Builder) *Scan {
	t.Helper()
	sets, err := termset.Parse([]byte(file))
	if err != nil {
		t.Fatal("parse failed")
	}
	return &Scan{Rules: rule.List{rule.IDPrefix{}}, Sets: sets, Out: output.New(out)}
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A term that spans "/" is redacted from the component where it begins, so no
// part of it prints. The interim printed its first part (HSH-5/D5).
func TestTreeRedactsATermSpanningASlash(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "docs/"+lc.Span+"/plan.md", "see "+lc.Bad+"\n")
	var out strings.Builder
	s := scanner(t, "[places]\n"+strings.ToUpper(lc.Span)+"\n", &out)
	err := s.Paths([]string{dir + "/docs"})
	s.Out.Flush()
	got := strings.ReplaceAll(out.String(), dir, "DIR")
	if err != nil || got != "DIR/docs/<redacted>:0: set:places in path\nDIR/docs/<redacted>:1: id-prefix\n" {
		t.Errorf("got error %v and output %q", err, got)
	}
	lc.Check(t, out.String(), fmt.Sprint(err))
}

// The index target reads staged blobs, never the work tree (HSH-5/D6).
func TestIndex(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(outside))
	git := func(args ...string) string {
		out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("git %s: %v\n%s", args[0], err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q")
	write(t, dir, "docs/a.md", "clean\nsee "+lc.Bad+"\n")
	write(t, dir, "blob.bin", "x\x00y\n")
	write(t, dir, "docs/"+strings.ToLower(lc.Client)+"/x.md", "clean\n")
	write(t, dir, "reference/r.md", lc.Fleet+"\n")
	write(t, dir, "tab\there.md", lc.Person+"\n")
	write(t, dir, "docs/"+lc.Quoted+"/q.bin", "x\x00y\n") // terms holding characters git quotes
	write(t, dir, lc.Backslashed+".md", lc.Bad+"\n")
	write(t, dir, `q"\.md`, lc.Bad+"\n")
	if err := os.Symlink("docs/"+lc.Bad+".md", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	git("add", "-A")
	t.Setenv("GIT_LITERAL_PATHSPECS", "1")            // must not turn the whole-index pathspec into a literal one
	write(t, dir, "docs/a.md", "clean\n")             // unstaged: the index still has the token
	write(t, dir, "untracked.md", "see "+lc.Bad+"\n") // not in the index
	var out strings.Builder
	s := scanner(t, lc.TermFile()+"[marks]\n"+lc.Quoted+"\n"+lc.Backslashed+"\n", &out)
	err := s.Index(dir)
	s.Out.Flush()
	want := "blob.bin:0: binary-unscanned\n" +
		"docs/a.md:2: id-prefix\n" +
		"docs/<redacted>:0: set:marks in path\n" +
		"docs/<redacted>:0: binary-unscanned\n" +
		"docs/<redacted>:0: set:clients in path\n" +
		"<redacted>:0: set:marks in path\n" +
		"<redacted>:1: id-prefix\n" +
		"link:1: id-prefix\n" +
		`q\"\\.md:1: id-prefix` + "\n" +
		`tab\there.md:1: set:people` + "\n"
	if err != nil || out.String() != want {
		t.Errorf("got error %v and output %q", err, out.String())
	}
	lc.Check(t, out.String(), fmt.Sprint(err))

	out.Reset()
	err = s.Index(filepath.Join(dir, "docs"))
	s.Out.Flush()
	if err != nil || out.String() != want {
		t.Errorf("index from a subdirectory: error %v, output %q", err, out.String())
	}
	lc.Check(t, out.String(), fmt.Sprint(err))
	err = s.Index(outside)
	if fmt.Sprint(err) != "not a git repository" {
		t.Errorf("index outside a repository: %v", err)
	}
	lc.Check(t, fmt.Sprint(err))

	// The repository's fsmonitor hook never runs, although plain ls-files
	// runs it on this index.
	hooks := t.TempDir()
	marker, hook := filepath.Join(hooks, "runs"), filepath.Join(hooks, "hook")
	write(t, hooks, "hook", "#!/bin/sh\necho run >> '"+marker+"'\nexit 1\n")
	if err := os.Chmod(hook, 0o755); err != nil {
		t.Fatal(err)
	}
	git("config", "core.fsmonitor", hook)
	git("update-index", "--fsmonitor")
	git("ls-files")
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("setup: ls-files did not run the fsmonitor hook")
	}
	os.Remove(marker)
	out.Reset()
	err = s.Index(dir)
	s.Out.Flush()
	if _, serr := os.Stat(marker); serr == nil || err != nil || out.String() != want {
		t.Errorf("index with an fsmonitor hook: hook ran %t, error %v, output %q", serr == nil, err, out.String())
	}
	lc.Check(t, out.String(), fmt.Sprint(err))
	git("config", "--unset", "core.fsmonitor")

	// A missing object fails the scan, although cat-file still has more than a
	// pipe buffer of output to write after it.
	write(t, dir, "z.md", strings.Repeat("clean\n", 40000))
	git("add", "z.md")
	missing := strings.Repeat("1", len(git("rev-parse", ":z.md")))
	git("update-index", "--add", "--info-only", "--cacheinfo", "100644,"+missing+",b.md")
	out.Reset()
	done := make(chan error, 1)
	go func() { done <- s.Index(dir) }()
	select {
	case err = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("index with a missing object: no result after 10s")
	}
	s.Out.Flush()
	if fmt.Sprint(err) != "cannot read the index" || out.String() != "" {
		t.Errorf("index with a missing object: error %v, output %q", err, out.String())
	}
	lc.Check(t, out.String(), fmt.Sprint(err))
}
