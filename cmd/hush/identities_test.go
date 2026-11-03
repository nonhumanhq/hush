package main

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/nonhumanhq/hush/internal/hooks"
	lc "github.com/nonhumanhq/hush/internal/leakcheck"
)

// ADR-002 negative test 4: the human's identity passes only when the caller
// passes it with --identities, and only in identity positions. The fixture is
// a commit whose author, committer and Signed-off-by trailer carry the
// identity, at a domain that is not reserved (ADR-002 section 6, point 4).
func TestNegative4Identities(t *testing.T) {
	h := newHookEnv(t)
	repo := h.repo()
	who := []string{"GIT_AUTHOR_NAME=Alice", "GIT_AUTHOR_EMAIL=" + lc.Identity,
		"GIT_COMMITTER_NAME=Alice", "GIT_COMMITTER_EMAIL=" + lc.Identity}
	// A file listing the address at the root and under .hush/, and a
	// .mailmap that maps it, committed first: none of them is ever read.
	h.write(filepath.Join(repo, "identities"), lc.Identity+"\n")
	h.write(filepath.Join(repo, ".hush", "identities"), lc.Identity+"\n")
	h.write(filepath.Join(repo, ".mailmap"), "Alice <"+lc.Identity2+"> <"+lc.Identity+">\n")
	h.git(repo, "add", "-A")
	h.git(repo, "commit", "-q", "-m", "add the lists")
	h.git(repo, "config", "user.email", lc.Identity)
	msg := filepath.Join(h.root, "msg")
	h.write(msg, "add the notes\n\n"+lc.TrailerLine+"\n")
	h.write(filepath.Join(repo, "a.md"), "clean\n")
	h.git(repo, "add", "a.md")
	if code, out := h.run(repo, who, "git", "-c", "core.hooksPath=/dev/null", "commit", "-q", "-F", msg); code != 0 {
		t.Fatalf("commit: %s", out)
	}
	sha := h.git(repo, "rev-parse", "HEAD")[:12]
	scan := func(env []string, args ...string) (int, string) {
		t.Helper()
		return h.run(repo, env, h.hush, append([]string{"scan", "--destination", "public", "--generic-only"}, args...)...)
	}
	flagged := sha + ":(commit):3: email-address\n" + sha + ":(commit):4: email-address\n" + sha + ":(commit):8: email-address\n"

	// Without --identities: the author, committer and trailer lines.
	code, out := scan(nil, "--range", "HEAD~1..HEAD")
	h.expect("no allowance", code, out, 1, flagged)
	// With it, in any ASCII case and beside a second address: clean.
	for _, ids := range []string{lc.Identity, strings.ToUpper(lc.Identity), lc.Identity2 + "," + strings.ToUpper(lc.Identity[:1]) + lc.Identity[1:]} {
		code, out = scan(nil, "--identities", ids, "--range", "HEAD~1..HEAD")
		h.expect("the allowance", code, out, 0, "")
	}
	// The commit-msg hook's scan: the message on standard input.
	code, out = h.run(repo, nil, "sh", "-c", `"$0" scan --destination public --generic-only --identities "$1" --label commit-message --stdin <"$2"`,
		h.hush, lc.Identity, msg)
	h.expect("commit-msg with the allowance", code, out, 0, "")
	code, out = h.run(repo, nil, "sh", "-c", `"$0" scan --destination public --generic-only --label commit-message --stdin <"$1"`, h.hush, msg)
	h.expect("commit-msg without it", code, out, 1, "commit-message:3: email-address\n")

	// Nothing from the repository, git's configuration or the environment
	// makes it pass: the findings stay as without an allowance.
	env := []string{"HUSH_IDENTITIES=" + lc.Identity, "EMAIL=" + lc.Identity,
		"GIT_AUTHOR_EMAIL=" + lc.Identity, "GIT_COMMITTER_EMAIL=" + lc.Identity}
	code, out = scan(env, "--range", "HEAD~1..HEAD")
	h.expect("allowances from elsewhere", code, out, 1, flagged)

	// With the allowance, the address on a line of a file is flagged, even
	// on a trailer-shaped line, and so is a subject line that holds it.
	h.write(filepath.Join(repo, "b.md"), lc.TrailerLine+"\n")
	h.git(repo, "add", "b.md")
	if code, out := h.run(repo, who, "git", "-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", lc.SubjectLine); code != 0 {
		t.Fatalf("commit: %s", out)
	}
	sha = h.git(repo, "rev-parse", "HEAD")[:12]
	code, out = scan(nil, "--identities", lc.Identity, "--range", "HEAD~1..HEAD")
	h.expect("lines that are not identities", code, out, 1, sha+":(commit):6: email-address\n"+sha+":b.md:1: email-address\n")
}

// HSH-11/D24: "hush hooks install --identities V" writes V, shell-quoted, into
// every hook, and the hooks then pass the identity in a commit's author,
// committer and trailer, through commit and push.
func TestHooksIdentities(t *testing.T) {
	h := newHookEnv(t)
	remote := filepath.Join(h.root, "remote.git")
	h.git(h.root, "init", "-q", "--bare", "-b", "main", remote)
	repo := h.repo()
	h.git(repo, "remote", "add", "origin", remote)
	value := lc.Identity + ",o'brien@example.org"
	code, out := h.run(repo, nil, h.hush, "hooks", "install", "--identities", value)
	h.expect("install", code, out, 0, installed)
	for _, name := range hooks.Names {
		got := h.read(filepath.Join(repo, ".git", "hooks", name))
		if got != hooks.Script(name, h.hush, "", value) ||
			!strings.Contains(got, " --identities '"+lc.Identity+",o'\\''brien@example.org' ") {
			t.Errorf("%s does not pass the value shell-quoted:\n%s", name, got)
		}
	}
	who := []string{"GIT_AUTHOR_NAME=Alice", "GIT_AUTHOR_EMAIL=" + lc.Identity,
		"GIT_COMMITTER_NAME=Alice", "GIT_COMMITTER_EMAIL=" + lc.Identity}
	h.write(filepath.Join(repo, "a.md"), "clean\n")
	h.git(repo, "add", "a.md")
	code, out = h.run(repo, who, "git", "commit", "-q", "-m", "add a\n\n"+lc.TrailerLine)
	h.expect("commit with the identity", code, out, 0, "")
	code, out = h.run(repo, nil, "git", "push", "-q", "origin", "main")
	h.expect("push with the identity", code, out, 0, "")

	// The same commit with hooks installed without the value is refused at
	// the message, and its push at the author.
	code, out = h.run(repo, nil, h.hush, "hooks", "install")
	h.expect("reinstall", code, out, 0, installed)
	h.write(filepath.Join(repo, "b.md"), "clean\n")
	h.git(repo, "add", "b.md")
	code, out = h.run(repo, who, "git", "commit", "-q", "-m", "add b\n\n"+lc.TrailerLine)
	h.expect("commit without the value", code, out, 1, "commit-message:3: email-address\n")
	if code, out := h.run(repo, who, "git", "-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", "add b"); code != 0 {
		t.Fatalf("commit: %s", out)
	}
	sha := h.git(repo, "rev-parse", "HEAD")[:12]
	code, out = h.run(repo, nil, "git", "push", "-q", "origin", "main")
	if code == 0 || !strings.HasPrefix(out, sha+":(commit):3: email-address\n") {
		t.Errorf("push without the value: exit %d, output %q", code, out)
	}
}

// A listed identity followed by "@" or "\@" is only the start of a longer
// address, so the allowance does not cover it: with --identities the trailer
// is flagged on standard input and in a range, as it is without (HSH-11/D16).
func TestIdentityChainedAddress(t *testing.T) {
	h := newHookEnv(t)
	repo := h.repo()
	// The author and committer are at a reserved domain, so only the
	// trailer can be flagged.
	who := []string{"GIT_AUTHOR_NAME=Alice", "GIT_AUTHOR_EMAIL=alice@example.org",
		"GIT_COMMITTER_NAME=Alice", "GIT_COMMITTER_EMAIL=alice@example.org"}
	h.write(filepath.Join(repo, "a.md"), "clean\n")
	h.git(repo, "add", "a.md")
	if code, out := h.run(repo, who, "git", "-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", "start"); code != 0 {
		t.Fatalf("commit: %s", out)
	}
	for i, sep := range []string{"@", `\@`} {
		msg := filepath.Join(h.root, "msg"+strconv.Itoa(i))
		h.write(msg, "add the notes\n\nSigned-off-by: "+lc.Identity+sep+"evil.internal\n")
		h.write(filepath.Join(repo, "a.md"), "clean "+strconv.Itoa(i)+"\n")
		h.git(repo, "add", "a.md")
		if code, out := h.run(repo, who, "git", "-c", "core.hooksPath=/dev/null", "commit", "-q", "-F", msg); code != 0 {
			t.Fatalf("commit: %s", out)
		}
		sha := h.git(repo, "rev-parse", "HEAD")[:12]
		for _, ids := range [][]string{nil, {"--identities", lc.Identity}} {
			args := append([]string{"scan", "--destination", "public", "--generic-only"}, ids...)
			sh := append([]string{"-c", `"$0" "$@" --label commit-message --stdin <"$MSG"`, h.hush}, args...)
			code, out := h.run(repo, []string{"MSG=" + msg}, "sh", sh...)
			h.expect(sep+" on standard input", code, out, 1, "commit-message:3: email-address\n")
			code, out = h.run(repo, nil, h.hush, append(args, "--range", "HEAD^..HEAD")...)
			h.expect(sep+" in a range", code, out, 1, sha+":(commit):8: email-address\n")
		}
	}
}
