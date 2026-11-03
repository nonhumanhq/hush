package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	lc "github.com/nonhumanhq/hush/internal/leakcheck"
)

// Part d's command-line tests (HSH-11/T19 to T23). Each runs the built hush
// in hookEnv's fixed environment, which leak-checks every output.

// ADR-001 negative test 13: git's standard error never reaches the output. A
// commit whose added blob is missing exits 2, standard output is empty, and
// standard error is the one fixed line, although git complains on its own
// standard error.
func TestNegative13GitStderr(t *testing.T) {
	h := newHookEnv(t)
	repo := h.repo()
	h.write(filepath.Join(repo, "a.md"), "clean\n")
	h.git(repo, "add", "a.md")
	h.git(repo, "commit", "-q", "-m", "first")
	h.write(filepath.Join(repo, "b.md"), "see "+lc.Bad+"\n")
	h.git(repo, "add", "b.md")
	h.git(repo, "commit", "-q", "-m", "second")
	head, blob := h.git(repo, "rev-parse", "HEAD"), h.git(repo, "rev-parse", "HEAD:b.md")
	for _, p := range []string{filepath.Join(repo, ".git", "objects", blob[:2], blob[2:]), filepath.Join(repo, "b.md")} {
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
	}
	code, out := h.run(repo, nil, h.hush, "scan", "--destination", "public", "--generic-only", "--range", "HEAD")
	h.expect("missing blob", code, out, 2, "hush: cannot diff commit "+head[:12]+"\n")
}

// ADR-001 section 2: in index mode the command line reads GIT_DIR, made
// absolute against its own working directory before -C applies, and passes
// it as the repository. A range scan never reads it.
func TestIndexGitDir(t *testing.T) {
	h := newHookEnv(t)
	clean, dirty := h.repo(), h.repo()
	h.write(filepath.Join(clean, "a.md"), "clean\n")
	h.git(clean, "add", "a.md")
	h.git(clean, "commit", "-q", "-m", "clean")
	h.write(filepath.Join(dirty, "b.md"), "see "+lc.Bad+"\n")
	h.git(dirty, "add", "b.md")
	rel, err := filepath.Rel(clean, filepath.Join(dirty, ".git"))
	if err != nil {
		t.Fatal(err)
	}
	scan := []string{"scan", "--destination", "public", "--generic-only"}
	code, out := h.run(clean, []string{"GIT_DIR=" + rel}, h.hush, append(scan, "--index")...)
	h.expect("GIT_DIR, relative", code, out, 1, "b.md:1: id-prefix\n")
	code, out = h.run(clean, []string{"GIT_DIR=" + rel}, h.hush, append(scan, "--index", "-C", clean)...)
	h.expect("GIT_DIR with -C", code, out, 1, "b.md:1: id-prefix\n")
	code, out = h.run(clean, []string{"GIT_DIR="}, h.hush, append(scan, "--index")...)
	h.expect("GIT_DIR empty", code, out, 0, "")
	code, out = h.run(clean, []string{"GIT_DIR=" + rel}, h.hush, append(scan, "--range", "HEAD")...)
	h.expect("range", code, out, 0, "")
}

// The pre-commit hook in a linked worktree, where git sets GIT_DIR to the
// worktree's git directory and GIT_INDEX_FILE to its index: the staged token
// is found, and a clean commit passes.
func TestPreCommitWorktree(t *testing.T) {
	h := newHookEnv(t)
	repo := h.repo()
	h.write(filepath.Join(repo, "a.md"), "clean\n")
	h.git(repo, "add", "a.md")
	h.git(repo, "commit", "-q", "-m", "first")
	code, out := h.run(repo, nil, h.hush, "hooks", "install")
	h.expect("install", code, out, 0, installed)
	wt := filepath.Join(h.root, "wt")
	h.git(repo, "worktree", "add", "-q", wt)
	h.write(filepath.Join(wt, "b.md"), "see "+lc.Bad+"\n")
	h.git(wt, "add", "b.md")
	code, out = h.run(wt, nil, "git", "commit", "-q", "-m", "add b")
	h.expect("token in the worktree", code, out, 1, "b.md:1: id-prefix\n")
	h.write(filepath.Join(wt, "b.md"), "clean\n")
	h.git(wt, "add", "b.md")
	code, out = h.run(wt, nil, "git", "commit", "-q", "-m", "add b")
	h.expect("clean commit in the worktree", code, out, 0, "")
}

// The pre-commit hook in a submodule, whose git directory lies in the
// superproject's .git/modules and names its work tree with core.worktree:
// a term file in the submodule's work tree is inside the scanned repository
// (ADR-001 section 5; part d, review round 1, HSH-11/D53). The hook exits 2,
// and git commit, refused, exits 1.
func TestPreCommitSubmoduleTermFile(t *testing.T) {
	h := newHookEnv(t)
	lib, top := h.repo(), h.repo()
	h.write(filepath.Join(lib, "a.md"), "clean\n")
	h.git(lib, "add", "a.md")
	h.git(lib, "commit", "-q", "-m", "first")
	h.git(top, "-c", "protocol.file.allow=always", "submodule", "add", "-q", lib, "sub")
	sub := filepath.Join(top, "sub")
	if !strings.Contains(h.read(filepath.Join(top, ".git", "modules", "sub", "config")), "worktree = ") {
		t.Fatal("setup: the submodule's git directory sets no core.worktree")
	}
	terms := filepath.Join(sub, "terms.txt")
	h.write(terms, lc.TermFile())
	if err := os.Chmod(terms, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out := h.run(sub, nil, h.hush, "hooks", "install", "--terms", terms)
	h.expect("install", code, out, 0, installed)
	h.write(filepath.Join(sub, "b.md"), "clean\n")
	h.git(sub, "add", "b.md")
	code, out = h.run(sub, nil, "git", "commit", "-q", "-m", "add b")
	h.expect("a term file in the submodule's work tree", code, out, 1, "hush: the term file is inside the scanned repository\n")
	hook := filepath.Join(top, ".git", "modules", "sub", "hooks", "pre-commit")
	code, out = h.run(sub, []string{"GIT_DIR=" + filepath.Join(top, ".git", "modules", "sub")}, hook)
	h.expect("the hook with GIT_DIR in .git/modules", code, out, 2, "hush: the term file is inside the scanned repository\n")
}

// The pre-push hook passes a pushed annotated tag as the tag object's id, so
// hush scans the tag's text as an object of its own (HSH-11/D23, T23): a tag
// whose message holds a token is refused although its commit is already on
// the remote, and a clean tag passes.
func TestPushedTagObject(t *testing.T) {
	h := newHookEnv(t)
	remote := filepath.Join(h.root, "remote.git")
	h.git(h.root, "init", "-q", "--bare", "-b", "main", remote)
	repo := h.repo()
	h.git(repo, "remote", "add", "origin", remote)
	h.write(filepath.Join(repo, "a.md"), "clean\n")
	h.git(repo, "add", "a.md")
	h.git(repo, "commit", "-q", "-m", "first")
	code, out := h.run(repo, nil, h.hush, "hooks", "install")
	h.expect("install", code, out, 0, installed)
	code, out = h.run(repo, nil, "git", "push", "-q", "origin", "main")
	h.expect("clean push", code, out, 0, "")

	h.git(repo, "tag", "-a", "-m", "a release\n\nsee "+lc.Bad, "v1")
	tag := h.git(repo, "rev-parse", "v1")
	code, out = h.run(repo, nil, "git", "push", "-q", "origin", "v1")
	if code == 0 || !strings.HasPrefix(out, tag[:12]+":(tag):8: id-prefix\n") {
		t.Errorf("push of a tag with a token: exit %d, output %q", code, out)
	}
	h.git(repo, "tag", "-a", "-m", "a clean release", "v2")
	code, out = h.run(repo, nil, "git", "push", "-q", "origin", "v2")
	h.expect("push of a clean tag", code, out, 0, "")
}

// A named revision or a listed ref whose fully peeled target is not a commit
// exits 2 in hush itself (ADR-001 section 5), as the pre-push hook's own
// check refuses such a pushed ref (TestHooksBlock).
func TestNonCommitPeel(t *testing.T) {
	h := newHookEnv(t)
	repo := h.repo()
	h.write(filepath.Join(repo, "a.md"), "clean\n")
	h.git(repo, "add", "a.md")
	h.git(repo, "commit", "-q", "-m", "first")
	h.git(repo, "tag", "-a", "-m", "on a tree", "treetag", "HEAD^{tree}")
	scan := []string{"scan", "--destination", "public", "--generic-only", "--range"}
	code, out := h.run(repo, nil, h.hush, append(scan, "treetag")...)
	h.expect("named", code, out, 2, "hush: argument 5: range: revision 1 does not resolve to a commit\n")
	code, out = h.run(repo, nil, h.hush, append(scan, "--all")...)
	h.expect("--all", code, out, 2, "hush: argument 5: range: a listed ref does not point to a commit\n")
}
