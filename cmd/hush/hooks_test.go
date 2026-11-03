package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nonhumanhq/hush/internal/hooks"
	lc "github.com/nonhumanhq/hush/internal/leakcheck"
)

// hookEnv builds hush and runs git, hush and the hooks in temporary
// repositories with a fixed environment: no user or system git
// configuration, so this machine's own core.hooksPath never applies, and
// identities at example.com, which every rule leaves alone (HSH-9/D13).
type hookEnv struct {
	t          *testing.T
	hush, root string
	env        []string
	n          int
}

func newHookEnv(t *testing.T) *hookEnv {
	for _, tool := range []string{"sh", "git", "go"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("the hook tests need %s", tool)
		}
	}
	h := &hookEnv{t: t, root: t.TempDir(), hush: filepath.Join(t.TempDir(), "hush")}
	// -buildvcs=false: the build never runs git with the caller's configuration.
	if out, err := exec.Command("go", "build", "-buildvcs=false", "-o", h.hush, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	home := filepath.Join(h.root, "home")
	if err := os.Mkdir(home, 0o755); err != nil {
		t.Fatal(err)
	}
	h.env = []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + home, "LC_ALL=C",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_CEILING_DIRECTORIES=" + filepath.Dir(h.root),
		"GIT_AUTHOR_NAME=alice", "GIT_AUTHOR_EMAIL=alice@example.com",
		"GIT_COMMITTER_NAME=alice", "GIT_COMMITTER_EMAIL=alice@example.com",
	}
	return h
}

// isolate keeps an in-process test of run away from this machine. The test
// runs in an empty temporary directory outside any repository, with no user
// or system git configuration, none of git's location variables from the
// caller, and a PATH that holds nothing, so neither git nor gh can be found.
// A regression then fails the test instead of writing into this machine's
// hooks directory or running the real gh (HSH-9/D13).
func isolate(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("PATH", t.TempDir())
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(dir))
	for _, v := range []string{"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"} {
		t.Setenv(v, "") // restored when the test ends
		os.Unsetenv(v)
	}
}

// run runs name in dir with the fixed environment plus extra, under a
// deadline so that a regression cannot hang the tests: at the deadline the
// whole process group is killed, so no git child is left waiting on a FIFO.
// It returns the exit status, -1 on the deadline, and the combined output,
// which it leak-checks.
func (h *hookEnv) run(dir string, extra []string, name string, args ...string) (int, string) {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, name, args...)
	c.Dir, c.Env, c.WaitDelay = dir, append(append([]string{}, h.env...), extra...), time.Second
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	c.Cancel = func() error { return syscall.Kill(-c.Process.Pid, syscall.SIGKILL) }
	out, err := c.CombinedOutput()
	lc.Check(h.t, string(out))
	var ee *exec.ExitError
	switch {
	case ctx.Err() != nil:
		h.t.Errorf("%s %s: no result after 20s", filepath.Base(name), strings.Join(args, " "))
		return -1, string(out)
	case errors.As(err, &ee):
		return ee.ExitCode(), string(out)
	case err != nil:
		h.t.Fatalf("%s: %v", name, err)
	}
	return 0, string(out)
}

// git runs git in dir and returns its trimmed output; it must succeed.
func (h *hookEnv) git(dir string, args ...string) string {
	h.t.Helper()
	code, out := h.run(dir, nil, "git", args...)
	if code != 0 {
		h.t.Fatalf("git %s: exit %d\n%s", args[0], code, out)
	}
	return strings.TrimSpace(out)
}

// repo creates a repository on branch main and returns its path.
func (h *hookEnv) repo() string {
	h.n++
	dir := filepath.Join(h.root, "r"+strconv.Itoa(h.n))
	h.git(h.root, "init", "-q", "-b", "main", dir)
	return dir
}

func (h *hookEnv) write(path, content string) {
	h.t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func (h *hookEnv) read(path string) string {
	h.t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		h.t.Fatal(err)
	}
	return string(data)
}

// expect fails the test unless a run gave code and out.
func (h *hookEnv) expect(what string, code int, out string, wantCode int, wantOut string) {
	h.t.Helper()
	if code != wantCode || out != wantOut {
		h.t.Errorf("%s: exit %d, output %q; want exit %d, output %q", what, code, out, wantCode, wantOut)
	}
}

// bypass commits the index without running any hook, for a commit the hooks
// would refuse.
func (h *hookEnv) bypass(repo, msg string) string {
	h.t.Helper()
	none := filepath.Join(h.root, "no-hooks")
	if err := os.MkdirAll(none, 0o755); err != nil {
		h.t.Fatal(err)
	}
	h.git(repo, "-c", "core.hooksPath="+none, "commit", "-q", "-m", msg)
	return h.git(repo, "rev-parse", "HEAD")[:12]
}

const installed = "pre-commit: installed\ncommit-msg: installed\npre-push: installed\n"

func TestHooksInstall(t *testing.T) {
	h := newHookEnv(t)
	repo := h.repo()
	code, out := h.run(repo, nil, h.hush, "hooks", "install")
	h.expect("install", code, out, 0, installed)
	for _, name := range hooks.Names {
		if got := h.read(filepath.Join(repo, ".git", "hooks", name)); got != hooks.Script(name, h.hush, "", "") {
			t.Errorf("%s: unexpected script\n%s", name, got)
		}
	}

	// The hooks run hush by the path it was started by, a symlink kept as one,
	// whether it was given as a path or found on PATH, so that moving the
	// symlink upgrades them (HSH-9/D1).
	profile := filepath.Join(h.root, "profile")
	link := filepath.Join(profile, "hush")
	if os.Mkdir(profile, 0o755) != nil || os.Symlink(h.hush, link) != nil {
		t.Fatal("setup failed")
	}
	for _, cmd := range [][]string{{link, "hooks", "install"}, {"sh", "-c", "hush hooks install"}} {
		repo = h.repo()
		code, out = h.run(repo, []string{"PATH=" + profile + string(os.PathListSeparator) + os.Getenv("PATH")}, cmd[0], cmd[1:]...)
		h.expect("install through a symlink", code, out, 0, installed)
		if got := h.read(filepath.Join(repo, ".git", "hooks", "pre-push")); got != hooks.Script("pre-push", link, "", "") {
			t.Errorf("install through a symlink, %s: the hook does not run the symlink\n%s", cmd[0], got)
		}
	}

	// A hook hush did not write is refused, and nothing is written, until
	// --force replaces it.
	repo = h.repo()
	other := filepath.Join(repo, ".git", "hooks", "pre-push")
	h.write(other, "#!/bin/sh\nexit 0\n")
	code, out = h.run(repo, nil, h.hush, "hooks", "install")
	h.expect("install over another hook", code, out, 2,
		"hush: the pre-push hook was not written by hush (give --force to replace it)\n")
	if _, err := os.Stat(filepath.Join(repo, ".git", "hooks", "pre-commit")); err == nil {
		t.Error("a refused install wrote pre-commit")
	}
	code, out = h.run(repo, nil, h.hush, "hooks", "install", "--force")
	h.expect("install --force", code, out, 0, installed)
	if !strings.Contains(h.read(other), " --allow-empty-range --range ") {
		t.Error("install --force left the other pre-push hook")
	}

	// Uninstall removes only hush's hooks.
	h.write(filepath.Join(repo, ".git", "hooks", "commit-msg"), "#!/bin/sh\nexit 0\n")
	code, out = h.run(repo, nil, h.hush, "hooks", "uninstall")
	h.expect("uninstall", code, out, 0, "pre-commit: removed\npre-push: removed\ncommit-msg: left in place, not written by hush\n")
	entries, _ := os.ReadDir(filepath.Join(repo, ".git", "hooks"))
	for _, e := range entries {
		if e.Name() == "pre-commit" || e.Name() == "pre-push" {
			t.Errorf("uninstall left %s", e.Name())
		}
	}
	if h.read(filepath.Join(repo, ".git", "hooks", "commit-msg")) != "#!/bin/sh\nexit 0\n" {
		t.Error("uninstall changed a hook hush did not write")
	}

	// core.hooksPath, relative to the top of the work tree, from a subdirectory.
	// That puts the hooks, which hold absolute paths, in the work tree, so
	// install refuses without --force and warns with it (HSH-9/D14).
	repo = h.repo()
	h.git(repo, "config", "core.hooksPath", ".githooks")
	sub := filepath.Join(repo, "docs")
	h.write(filepath.Join(sub, "a.md"), "see "+lc.Bad+"\n")
	code, out = h.run(sub, nil, h.hush, "hooks", "install")
	h.expect("install into the work tree", code, out, 2, "hush: the hooks directory is inside the work tree, "+
		"and the hooks hold absolute paths that must not be committed (give --force to install them there)\n")
	if _, err := os.Stat(filepath.Join(repo, ".githooks")); err == nil {
		t.Error("a refused install created .githooks")
	}
	code, out = h.run(sub, nil, h.hush, "hooks", "install", "--force")
	h.expect("install --force into the work tree", code, out, 0, installed+"hush: warning: the hooks directory "+
		"is inside the work tree; the hooks hold absolute paths and must not be committed\n")
	if _, err := os.Stat(filepath.Join(repo, ".githooks", "pre-commit")); err != nil {
		t.Error("install ignored core.hooksPath")
	}
	if _, err := os.Stat(filepath.Join(repo, ".git", "hooks", "pre-commit")); err == nil {
		t.Error("install wrote .git/hooks despite core.hooksPath")
	}
	h.git(repo, "add", "docs/a.md")
	code, out = h.run(repo, nil, "git", "commit", "-q", "-m", "add a")
	h.expect("commit through core.hooksPath", code, out, 1, "docs/a.md:1: id-prefix\n")

	// A bare repository has no work tree to commit the hooks into; inside a
	// git directory git finds none, and install refuses.
	bare := filepath.Join(h.root, "bare.git")
	h.git(h.root, "init", "-q", "--bare", bare)
	code, out = h.run(bare, nil, h.hush, "hooks", "install")
	h.expect("install in a bare repository", code, out, 0, installed)
	code, out = h.run(filepath.Join(repo, ".git"), nil, h.hush, "hooks", "install")
	h.expect("install inside the git directory", code, out, 2, "hush: cannot find the work tree\n")

	outside := filepath.Join(h.root, "outside")
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	code, out = h.run(outside, nil, h.hush, "hooks", "install")
	h.expect("install outside a repository", code, out, 2, "hush: not a git repository\n")
}

func TestHooksBlock(t *testing.T) {
	h := newHookEnv(t)
	remote := filepath.Join(h.root, "remote.git")
	h.git(h.root, "init", "-q", "--bare", "-b", "main", remote)
	repo := h.repo()
	h.git(repo, "remote", "add", "origin", remote)
	// Before the hooks, a commit with a token reaches the remote, and a
	// second one removes the file again: pre-commit scans the whole index.
	h.write(filepath.Join(repo, "old.md"), "see "+lc.Bad+"\n")
	h.git(repo, "add", "old.md")
	old := h.bypass(repo, "add old")
	h.git(repo, "rm", "-q", "old.md")
	h.bypass(repo, "remove old")
	h.git(repo, "push", "-q", "origin", "main")
	code, out := h.run(repo, nil, h.hush, "hooks", "install")
	h.expect("install", code, out, 0, installed)
	head := h.git(repo, "rev-parse", "HEAD")
	commit := func(what string, wantCode int, wantOut string, msg string) {
		t.Helper()
		code, out := h.run(repo, nil, "git", "commit", "-q", "-m", msg)
		h.expect(what, code, out, wantCode, wantOut)
		if now := h.git(repo, "rev-parse", "HEAD"); (now != head) != (wantCode == 0) {
			t.Errorf("%s: HEAD moved %t", what, now != head)
		}
	}

	// pre-commit scans the index, not the work tree.
	h.write(filepath.Join(repo, "a.md"), "clean\nsee "+lc.Bad+"\n")
	h.git(repo, "add", "a.md")
	h.write(filepath.Join(repo, "a.md"), "clean\n")
	commit("staged token", 1, "a.md:2: id-prefix\n", "add a")
	// commit-msg scans the message on standard input, as commit-message.
	h.git(repo, "add", "a.md")
	commit("token in the message", 1, "commit-message:1: id-prefix\n", "add a, see "+lc.Bad)
	commit("clean commit", 0, "", "add a")
	// Without a term file the hooks run the generic tier only.
	head = h.git(repo, "rev-parse", "HEAD")
	h.write(filepath.Join(repo, "t.md"), lc.Client+"\n")
	h.git(repo, "add", "t.md")
	commit("term, generic tier", 0, "", "add t")

	// pre-push scans the pushed range of an existing branch: the new commits,
	// not the remote's old one.
	code, out = h.run(repo, nil, "git", "push", "-q", "origin", "main")
	h.expect("clean push", code, out, 0, "")
	pushed := h.git(remote, "rev-parse", "main")
	h.write(filepath.Join(repo, "b.md"), "see "+lc.Bad+"\n")
	h.git(repo, "add", "b.md")
	bad := h.bypass(repo, "add b")
	code, out = h.run(repo, nil, "git", "push", "-q", "origin", "main")
	if code == 0 || !strings.HasPrefix(out, bad+":b.md:1: id-prefix\n") || h.git(remote, "rev-parse", "main") != pushed {
		t.Errorf("push of a token: exit %d, output %q", code, out)
	}
	h.git(repo, "reset", "-q", "--hard", "HEAD~1")

	// A new branch is scanned against what the remote already has.
	h.git(repo, "checkout", "-q", "-b", "topic")
	h.write(filepath.Join(repo, "c.md"), "clean\n")
	h.git(repo, "add", "c.md")
	h.git(repo, "commit", "-q", "-m", "add c")
	code, out = h.run(repo, nil, "git", "push", "-q", "origin", "topic")
	h.expect("new clean branch", code, out, 0, "")
	h.git(repo, "checkout", "-q", "-b", "bad")
	h.write(filepath.Join(repo, "d.md"), "see "+lc.Bad+"\n")
	h.git(repo, "add", "d.md")
	bad = h.bypass(repo, "add d")
	code, out = h.run(repo, nil, "git", "push", "-q", "origin", "bad")
	if code == 0 || !strings.HasPrefix(out, bad+":d.md:1: id-prefix\n") {
		t.Errorf("new branch with a token: exit %d, output %q", code, out)
	}
	if code, _ := h.run(remote, nil, "git", "rev-parse", "-q", "--verify", "refs/heads/bad"); code == 0 {
		t.Error("the remote got the branch with a token")
	}

	// Every pushed ref is scanned: neither a deletion (git lists it first) nor
	// a clean update before it lets a branch with a token through, and the
	// whole push is refused.
	h.git(repo, "checkout", "-q", "topic")
	h.write(filepath.Join(repo, "e.md"), "clean\n")
	h.git(repo, "add", "e.md")
	h.git(repo, "commit", "-q", "-m", "add e")
	topic := h.git(remote, "rev-parse", "topic")
	for _, refs := range [][]string{{":topic", "bad"}, {"topic", "bad"}} {
		code, out = h.run(repo, nil, "git", append([]string{"push", "-q", "origin"}, refs...)...)
		if code == 0 || !strings.HasPrefix(out, bad+":d.md:1: id-prefix\n") {
			t.Errorf("push of %s: exit %d, output %q", strings.Join(refs, " "), code, out)
		}
		if code, _ := h.run(remote, nil, "git", "rev-parse", "-q", "--verify", "refs/heads/bad"); code == 0 {
			t.Errorf("push of %s: the remote got the branch with a token", strings.Join(refs, " "))
		}
		if h.git(remote, "rev-parse", "topic") != topic {
			t.Errorf("push of %s: the remote's topic changed", strings.Join(refs, " "))
		}
	}

	// A deletion is skipped: its local id is all zeros, which no range takes.
	code, out = h.run(repo, nil, "git", "push", "-q", "origin", "--delete", "topic")
	h.expect("branch deletion", code, out, 0, "")
	if code, _ := h.run(remote, nil, "git", "rev-parse", "-q", "--verify", "refs/heads/topic"); code == 0 {
		t.Error("the deleted branch is still on the remote")
	}
	absent := func(what, remote, ref string) {
		t.Helper()
		if code, _ := h.run(remote, nil, "git", "rev-parse", "-q", "--verify", ref); code == 0 {
			t.Errorf("%s: the remote got %s", what, ref)
		}
	}

	// git hands the hook a refspec's source as typed, spaces included, so each
	// line is read from the right (HSH-9/D1).
	h.git(repo, "checkout", "-q", "-b", "steps", "main")
	h.write(filepath.Join(repo, "f.md"), "see "+lc.Bad+"\n")
	h.git(repo, "add", "f.md")
	bad = h.bypass(repo, "step 0 done")
	code, out = h.run(repo, nil, "git", "push", "-q", "origin", "HEAD^{/step 0 done}:refs/heads/x")
	if code == 0 || !strings.HasPrefix(out, bad+":f.md:1: id-prefix\n") {
		t.Errorf("push of a source with spaces: exit %d, output %q", code, out)
	}
	absent("push of a source with spaces", remote, "refs/heads/x")
	h.git(repo, "checkout", "-q", "main")

	// A pushed blob or tree has no commits for the range scan to walk, so it
	// is refused.
	h.write(filepath.Join(repo, "g.md"), "see "+lc.Bad+"\n")
	blob := h.git(repo, "hash-object", "-w", "g.md")
	h.git(repo, "add", "g.md")
	tree := h.git(repo, "write-tree")
	h.git(repo, "rm", "-q", "--cached", "g.md")
	if err := os.Remove(filepath.Join(repo, "g.md")); err != nil {
		t.Fatal(err)
	}
	for i, obj := range []string{blob, tree} {
		ref := "refs/tags/o" + strconv.Itoa(i)
		code, out = h.run(repo, nil, "git", "push", "-q", "origin", obj+":"+ref)
		if code == 0 || !strings.HasPrefix(out, "hush: a pushed ref does not point to a commit, so hush cannot scan it\n") {
			t.Errorf("push of a %s: exit %d, output %q", []string{"blob", "tree"}[i], code, out)
		}
		absent("push of a blob or a tree", remote, ref)
	}
	// So is that blob while a replace ref makes git read it as a commit: the
	// hook turns replace refs off, and git sends the blob itself.
	h.git(repo, "replace", "-f", blob, h.git(repo, "rev-parse", "HEAD"))
	code, out = h.run(repo, nil, "git", "push", "-q", "origin", blob+":refs/tags/o2")
	if code == 0 || !strings.HasPrefix(out, "hush: a pushed ref does not point to a commit, so hush cannot scan it\n") {
		t.Errorf("push of a blob that a replace ref makes a commit: exit %d, output %q", code, out)
	}
	absent("push of a blob that a replace ref makes a commit", remote, "refs/tags/o2")
	h.git(repo, "replace", "-d", blob)

	// The remote ref's name is published too, and scanned.
	h.git(repo, "checkout", "-q", "-b", "fix-"+lc.Bad, "main")
	code, out = h.run(repo, nil, "git", "push", "-q", "origin", "HEAD")
	if code == 0 || !strings.HasPrefix(out, "pushed-ref:1: id-prefix\n") {
		t.Errorf("push of a branch whose name holds a token: exit %d, output %q", code, out)
	}
	absent("push of a branch whose name holds a token", remote, "refs/heads/fix-"+lc.Bad)
	h.git(repo, "checkout", "-q", "main")

	// A new branch is scanned against the commits the destination advertises:
	// the commit with a token that reached origin before the hooks is scanned
	// when main goes to another remote, by name or by URL, which holds none of
	// them.
	public := filepath.Join(h.root, "public.git")
	h.git(h.root, "init", "-q", "--bare", "-b", "main", public)
	h.git(repo, "remote", "add", "public", public)
	for _, dest := range []string{"public", public} {
		code, out = h.run(repo, nil, "git", "push", "-q", dest, "main")
		if code == 0 || !strings.HasPrefix(out, old+":old.md:1: id-prefix\n") {
			t.Errorf("push of main to a second remote: exit %d, output %q", code, out)
		}
		absent("push of main to a second remote", public, "refs/heads/main")
	}

	// So is main pushed to a path that holds a space, which the hook hands to
	// ls-remote quoted, while a branch with a clean history passes.
	spaced := filepath.Join(h.root, "sp ace", "r.git")
	h.git(h.root, "init", "-q", "--bare", "-b", "main", spaced)
	h.git(repo, "checkout", "-q", "--orphan", "solo")
	h.git(repo, "commit", "-q", "-m", "start solo")
	code, out = h.run(repo, nil, "git", "push", "-q", spaced, "solo")
	h.expect("clean push to a path with a space", code, out, 0, "")
	h.git(spaced, "rev-parse", "-q", "--verify", "refs/heads/solo")
	code, out = h.run(repo, nil, "git", "push", "-q", spaced, "main")
	if code == 0 || !strings.HasPrefix(out, old+":old.md:1: id-prefix\n") {
		t.Errorf("push of main to a path with a space: exit %d, output %q", code, out)
	}
	absent("push of main to a path with a space", spaced, "refs/heads/main")

	// And to a relative path that holds a glob character.
	glob := filepath.Join(repo, "or*")
	h.git(h.root, "init", "-q", "--bare", "-b", "main", glob)
	code, out = h.run(repo, nil, "git", "push", "-q", "or*", "main")
	if code == 0 || !strings.HasPrefix(out, old+":old.md:1: id-prefix\n") {
		t.Errorf("push of main to a relative path with a glob character: exit %d, output %q", code, out)
	}
	absent("push of main to a relative path with a glob character", glob, "refs/heads/main")

	// And to a path that names a remote, origin/, which git hands the hook as
	// typed.
	slash := filepath.Join(repo, "origin")
	h.git(h.root, "init", "-q", "--bare", "-b", "main", slash)
	code, out = h.run(repo, nil, "git", "push", "-q", "origin/", "main")
	if code == 0 || !strings.HasPrefix(out, old+":old.md:1: id-prefix\n") {
		t.Errorf("push of main to a path that names a remote: exit %d, output %q", code, out)
	}
	absent("push of main to a path that names a remote", slash, "refs/heads/main")

	// And to a remote whose name nests with another's, pub beside pub/up.
	pub := filepath.Join(h.root, "pub.git")
	h.git(h.root, "init", "-q", "--bare", "-b", "main", pub)
	h.git(repo, "remote", "add", "pub", pub)
	h.git(repo, "config", "remote.pub/up.url", remote)
	code, out = h.run(repo, nil, "git", "push", "-q", "pub", "main")
	if code == 0 || !strings.HasPrefix(out, old+":old.md:1: id-prefix\n") {
		t.Errorf("push of main to a remote whose name nests with another: exit %d, output %q", code, out)
	}
	absent("push of main to a remote whose name nests with another", pub, "refs/heads/main")

	// And to a remote's separate push URL, which the hook asks, not origin.
	pushed2 := filepath.Join(h.root, "pushurl.git")
	h.git(h.root, "init", "-q", "--bare", "-b", "main", pushed2)
	h.git(repo, "config", "remote.origin.pushurl", pushed2)
	code, out = h.run(repo, nil, "git", "push", "-q", "origin", "main:p1")
	if code == 0 || !strings.HasPrefix(out, old+":old.md:1: id-prefix\n") {
		t.Errorf("push of main to a remote's push URL: exit %d, output %q", code, out)
	}
	absent("push of main to a remote's push URL", pushed2, "refs/heads/p1")
	h.git(repo, "config", "--unset", "remote.origin.pushurl")

	// The refs last fetched from origin say nothing about where it now
	// points: after set-url to a fresh repository, main is scanned whole.
	fresh := filepath.Join(h.root, "fresh.git")
	h.git(h.root, "init", "-q", "--bare", "-b", "main", fresh)
	h.git(repo, "remote", "set-url", "origin", fresh)
	code, out = h.run(repo, nil, "git", "push", "-q", "origin", "main")
	if code == 0 || !strings.HasPrefix(out, old+":old.md:1: id-prefix\n") {
		t.Errorf("push of main to origin after set-url: exit %d, output %q", code, out)
	}
	absent("push of main to origin after set-url", fresh, "refs/heads/main")
	h.git(repo, "remote", "set-url", "origin", remote)

	// A destination that holds a commit this repository lacks, pushed to
	// origin from a second clone without the hooks: cat-file reports it
	// missing, so it is not subtracted, and solo, whose history is clean,
	// passes.
	clone := filepath.Join(h.root, "clone")
	h.git(h.root, "clone", "-q", remote, clone)
	h.write(filepath.Join(clone, "h.md"), "clean\n")
	h.git(clone, "add", "h.md")
	h.git(clone, "commit", "-q", "-m", "add h")
	h.git(clone, "push", "-q", "origin", "HEAD:refs/heads/elsewhere")
	code, out = h.run(repo, nil, "git", "push", "-q", "origin", "solo")
	h.expect("clean push to a destination that holds a commit this repository lacks", code, out, 0, "")
	h.git(remote, "rev-parse", "-q", "--verify", "refs/heads/solo")

	// A remote fetched from a mirror and pushed to itself, git-config's
	// insteadOf and pushInsteadOf pattern: ls-remote would rewrite the URL
	// pushed to again and ask origin, so nothing is subtracted, and main is
	// scanned whole.
	h.git(repo, "config", "url."+remote+".insteadOf", pub)
	h.git(repo, "config", "url."+pub+".pushInsteadOf", pub)
	code, out = h.run(repo, nil, "git", "push", "-q", "pub", "main:mirror")
	if code == 0 || !strings.HasPrefix(out, old+":old.md:1: id-prefix\n") {
		t.Errorf("push of main to a remote fetched from a mirror: exit %d, output %q", code, out)
	}
	absent("push of main to a remote fetched from a mirror", pub, "refs/heads/mirror")
	h.git(repo, "config", "--unset", "url."+remote+".insteadOf")
	h.git(repo, "config", "--unset", "url."+pub+".pushInsteadOf")

	// Each advertised commit is subtracted once: with 3,300 lightweight tags
	// on origin's main, one id each would pass the 128 KiB limit on one
	// argument, and a clean new branch from main passes.
	var tags strings.Builder
	tip := h.git(remote, "rev-parse", "main")
	for i := range 3300 {
		tags.WriteString("create refs/tags/t" + strconv.Itoa(i) + " " + tip + "\n")
	}
	list := filepath.Join(h.root, "tags.txt")
	h.write(list, tags.String())
	if code, out := h.run(remote, nil, "sh", "-c", `git update-ref --stdin <"$0"`, list); code != 0 {
		t.Fatalf("git update-ref: exit %d\n%s", code, out)
	}
	h.git(repo, "checkout", "-q", "-b", "many", "main")
	h.write(filepath.Join(repo, "i.md"), "clean\n")
	h.git(repo, "add", "i.md")
	h.git(repo, "commit", "-q", "-m", "add i")
	code, out = h.run(repo, nil, "git", "push", "-q", "origin", "many")
	h.expect("clean push to a destination with 3,300 tags on one commit", code, out, 0, "")
	h.git(remote, "rev-parse", "-q", "--verify", "refs/heads/many")
}

// The private tier runs only when the hooks are installed with a term file.
func TestHooksTerms(t *testing.T) {
	h := newHookEnv(t)
	terms := filepath.Join(h.root, "terms.txt")
	h.write(terms, lc.TermFile())
	remote := filepath.Join(h.root, "remote.git")
	h.git(h.root, "init", "-q", "--bare", "-b", "main", remote)
	repo := h.repo()
	h.git(repo, "remote", "add", "origin", remote)
	code, out := h.run(repo, nil, h.hush, "hooks", "install", "--terms", "missing.txt")
	h.expect("install with a missing term file", code, out, 2, "hush: term file: missing or unreadable\n")
	code, out = h.run(repo, nil, h.hush, "hooks", "install", "--terms", "../terms.txt")
	h.expect("install with a term file others can read", code, out, 2, "hush: term file: readable or writable by group or others\n")
	if err := os.Chmod(terms, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out = h.run(repo, nil, h.hush, "hooks", "install", "--terms", "../terms.txt") // made absolute
	h.expect("install --terms", code, out, 0, installed)
	for _, name := range hooks.Names {
		if !strings.Contains(h.read(filepath.Join(repo, ".git", "hooks", name)), " --terms '"+terms+"'") {
			t.Errorf("%s does not pass the term file's absolute path", name)
		}
	}

	h.write(filepath.Join(repo, "x.md"), "about "+lc.Client+"\n")
	h.git(repo, "add", "x.md")
	code, out = h.run(repo, nil, "git", "commit", "-q", "-m", "add x")
	h.expect("staged term", code, out, 1, "x.md:1: set:clients\n")
	h.write(filepath.Join(repo, "x.md"), "clean\n")
	h.git(repo, "add", "x.md")
	code, out = h.run(repo, nil, "git", "commit", "-q", "-m", "ask "+lc.Person)
	h.expect("term in the message", code, out, 1, "commit-message:1: set:people\n")
	h.write(filepath.Join(repo, "y.md"), "about "+lc.Client+"\n")
	h.git(repo, "add", "y.md")
	bad := h.bypass(repo, "add y")
	code, out = h.run(repo, nil, "git", "push", "-q", "origin", "main")
	if code == 0 || !strings.HasPrefix(out, bad+":y.md:1: set:clients\n") {
		t.Errorf("push of a term: exit %d, output %q", code, out)
	}
}

// The GIT_INDEX_FILE check, tested by running the pre-commit hook directly,
// since git commit always hands the hook an index file that exists.
func TestPreCommitIndexFile(t *testing.T) {
	h := newHookEnv(t)
	repo := h.repo()
	code, out := h.run(repo, nil, h.hush, "hooks", "install")
	h.expect("install", code, out, 0, installed)
	hook := filepath.Join(repo, ".git", "hooks", "pre-commit")

	// Unset, in a new repository with nothing staged: there is no index file
	// yet, nothing is checked, and the scan passes.
	if _, err := os.Stat(filepath.Join(repo, ".git", "index")); err == nil {
		t.Fatal("setup: the new repository has an index file")
	}
	code, out = h.run(repo, nil, hook)
	h.expect("unset", code, out, 0, "")

	dir, fifo := filepath.Join(h.root, "dir"), filepath.Join(h.root, "fifo")
	dangling := filepath.Join(h.root, "dangling")
	if os.Mkdir(dir, 0o755) != nil || syscall.Mkfifo(fifo, 0o644) != nil || os.Symlink("none", dangling) != nil {
		t.Fatal("setup failed")
	}
	// An empty value names the working directory, so it is refused too.
	const notFile = "hush: the index file is missing or not a regular file\n"
	for _, c := range []struct{ what, value, want string }{
		{"empty", "", notFile},
		{"missing file", filepath.Join(h.root, "missing"), notFile},
		{"dangling symlink", dangling, notFile},
		{"directory", dir, notFile},
		{"FIFO", fifo, notFile},
	} {
		code, out := h.run(repo, []string{"GIT_INDEX_FILE=" + c.value}, hook)
		h.expect(c.what, code, out, 2, c.want)
	}

	// The repository's index by its own name and through a symlink, with a
	// token staged, gives the same finding and status as with it unset.
	h.write(filepath.Join(repo, "a.md"), "see "+lc.Bad+"\n")
	h.git(repo, "add", "a.md")
	link := filepath.Join(h.root, "index-link")
	if err := os.Symlink(filepath.Join(repo, ".git", "index"), link); err != nil {
		t.Fatal(err)
	}
	for _, env := range [][]string{nil, {"GIT_INDEX_FILE=.git/index"}, {"GIT_INDEX_FILE=" + link}} {
		code, out := h.run(repo, env, hook)
		h.expect("index "+strings.Join(env, ""), code, out, 1, "a.md:1: id-prefix\n")
	}
	// From a subdirectory, a relative value names a file relative to it, which
	// git would resolve from the top of the work tree instead (HSH-9/D5).
	sub := filepath.Join(repo, "docs")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	code, out = h.run(sub, []string{"GIT_INDEX_FILE=../.git/index"}, hook)
	h.expect("a relative index from a subdirectory", code, out, 1, "a.md:1: id-prefix\n")

	// An index file other than the repository's own, as git commit hands
	// the hook for a partial commit (index.lock or a temporary index): the
	// token is only there, so the scan must read that file, by its absolute
	// or its relative name (part d: git gets no inherited variable, so hush
	// must pass it).
	other := filepath.Join(h.root, "other-index")
	h.write(other, h.read(filepath.Join(repo, ".git", "index")))
	h.git(repo, "rm", "-q", "--cached", "a.md")
	code, out = h.run(repo, nil, hook)
	h.expect("the repository's own index, without the token", code, out, 0, "")
	code, out = h.run(repo, []string{"GIT_INDEX_FILE=" + other}, hook)
	h.expect("another index file", code, out, 1, "a.md:1: id-prefix\n")
	code, out = h.run(sub, []string{"GIT_INDEX_FILE=../../other-index"}, hook)
	h.expect("another index file, relative from a subdirectory", code, out, 1, "a.md:1: id-prefix\n")

	// An index other than the repository's own: git must read the one named,
	// so the finding is in b.md, which only that index stages. Every case
	// above names the repository's own index, which git reads by default.
	other2 := filepath.Join(h.root, "other-index-2")
	h.write(filepath.Join(repo, "b.md"), "see "+lc.Bad+"\n")
	if code, out := h.run(repo, []string{"GIT_INDEX_FILE=" + other2}, "git", "add", "b.md"); code != 0 {
		t.Fatalf("git add: %s", out)
	}
	code, out = h.run(repo, []string{"GIT_INDEX_FILE=" + other2}, hook)
	h.expect("another index", code, out, 1, "b.md:1: id-prefix\n")
}

func TestHooksArguments(t *testing.T) {
	isolate(t)
	for _, c := range []struct {
		args       []string
		code       int
		out, error string
	}{
		{[]string{"hooks", "--help"}, 0, hooksUsage, ""},
		{[]string{"hooks"}, 2, "", "hush: hooks needs install or uninstall (see hush hooks --help)\n"},
		{[]string{"hooks", lc.Client}, 2, "", "hush: hooks needs install or uninstall (see hush hooks --help)\n"},
		{[]string{"hooks", "pre-commit"}, 2, "", "hush: hooks needs install or uninstall (see hush hooks --help)\n"},
		{[]string{"hooks", "install", "--terms"}, 2, "", "hush: hooks install: unexpected argument 2 (see hush hooks --help)\n"},
		{[]string{"hooks", "install", "--force", "--force"}, 2, "", "hush: hooks install: unexpected argument 3 (see hush hooks --help)\n"},
		{[]string{"hooks", "install", "--terms", ""}, 2, "", "hush: term file: missing or unreadable\n"},
		{[]string{"hooks", "uninstall", "--terms", "t"}, 2, "", "hush: hooks uninstall: unexpected argument 2 (see hush hooks --help)\n"},
		{[]string{"hooks", "uninstall", "--identities", lc.Identity}, 2, "", "hush: hooks uninstall: unexpected argument 2 (see hush hooks --help)\n"},
		// --identities is checked as hush scan checks it, before anything
		// is written, and cited by position (HSH-11/D24).
		{[]string{"hooks", "install", "--identities", ""}, 2, "", "hush: argument 3: identities: address 1 is malformed\n"},
		{[]string{"hooks", "install", "--force", "--identities", lc.Identity + ",<" + lc.Identity2}, 2, "",
			"hush: argument 4: identities: address 2 is malformed\n"},
		{[]string{"hooks", "install", "--identities", lc.Identity, "--identities", lc.Identity}, 2, "",
			"hush: hooks install: unexpected argument 4 (see hush hooks --help)\n"},
		{[]string{"hooks", "install", "--identities"}, 2, "", "hush: hooks install: unexpected argument 2 (see hush hooks --help)\n"},
	} {
		var out, errs strings.Builder
		code := run(c.args, strings.NewReader(""), &out, &errs)
		if code != c.code || out.String() != c.out || errs.String() != c.error {
			t.Errorf("hush %d args: exit %d, stdout %q, stderr %q", len(c.args), code, out.String(), errs.String())
		}
		lc.Check(t, out.String(), errs.String())
	}
}
