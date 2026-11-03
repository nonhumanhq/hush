package hush_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/nonhumanhq/hush"
)

// An importer scans a buffer it is about to post, for the public destination,
// with the generic rules only, as an agent sandbox does where no term file
// exists. The token on the second line is assembled at run time, so this file
// itself scans clean.
func ExampleScanner_ScanBytes() {
	s, err := hush.New(hush.Config{Destination: hush.Public(), GenericOnly: true})
	if err != nil {
		fmt.Println(err)
		return
	}
	body := []byte("Fixes the parser.\nSee ticket " + "QPV" + "-17 for details.\n")
	rep, err := s.ScanBytes(context.Background(), "issue-body", body)
	fmt.Println("clean:", rep.Clean(), "exit:", hush.ExitCode(err))
	if err := rep.WritePlain(os.Stdout); err != nil {
		fmt.Println(err)
	}
	// Output:
	// clean: false exit: 1
	// issue-body:2: id-prefix
}

// An importer scans the last commit of a repository, as a publish step scans
// a range. The example builds a two-commit repository in a temporary
// directory first, with git's user and system configuration turned off, and
// prints where each finding is rather than the commit ids, which differ
// from run to run.
func ExampleScanner_ScanRange() {
	dir, err := os.MkdirTemp("", "hush-example-")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer os.RemoveAll(dir)
	git := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
			"GIT_AUTHOR_NAME=alice", "GIT_AUTHOR_EMAIL=alice@example.org",
			"GIT_COMMITTER_NAME=alice", "GIT_COMMITTER_EMAIL=alice@example.org",
			"GIT_AUTHOR_DATE=1700000000 +0000", "GIT_COMMITTER_DATE=1700000000 +0000")
		if err := cmd.Run(); err != nil {
			fmt.Println("git", args[0], "failed")
		}
	}
	file := func(name, text string) {
		os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755)
		os.WriteFile(filepath.Join(dir, name), []byte(text), 0o644)
	}
	git("init", "-q")
	file("README.md", "Notes.\n")
	git("add", "-A")
	git("commit", "-q", "-m", "Add the notes")
	file("docs/plan.md", "Steps:\nfollow up on "+"QPV"+"-17\n")
	git("add", "-A")
	git("commit", "-q", "-m", "Add the plan\n\nSee "+"QPV"+"-17.")

	s, err := hush.New(hush.Config{Destination: hush.Public(), GenericOnly: true})
	if err != nil {
		fmt.Println(err)
		return
	}
	rg, err := hush.ParseRange("HEAD~1..HEAD")
	if err != nil {
		fmt.Println(err)
		return
	}
	rep, err := s.ScanRange(context.Background(), hush.Repo{Dir: dir}, rg)
	fmt.Println("exit:", hush.ExitCode(err), "commits:", rep.Scanned().Commits)
	for _, f := range rep.Findings() {
		if f.Part != 0 {
			fmt.Printf("%s in the commit's %s, line %d\n", f.Rule, f.Part, f.Line)
		} else {
			fmt.Printf("%s in %s, line %d\n", f.Rule, f.Path, f.Line)
		}
	}
	// Output:
	// exit: 1 commits: 1
	// id-prefix in the commit's message, line 8
	// id-prefix in docs/plan.md, line 2
}
