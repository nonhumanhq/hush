package hooks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	lc "github.com/nonhumanhq/hush/internal/leakcheck"
)

func TestScript(t *testing.T) {
	head := "#!/bin/sh\n" + marker + "\n"
	const exe = "'/opt/a b/hush' scan --destination public"
	for _, c := range []struct{ name, terms, ids, want string }{
		{"pre-commit", "", "", head + "exec " + exe + " --generic-only --index\n"},
		{"pre-commit", "/home/alice/terms.txt", "", head + "exec " + exe + " --terms '/home/alice/terms.txt' --index\n"},
		{"pre-commit", "", "alice@example.org", head + "exec " + exe + " --generic-only --identities 'alice@example.org' --index\n"},
		{"commit-msg", "", "", head + "exec " + exe + ` --generic-only --label commit-message --stdin < "$1"` + "\n"},
		{"commit-msg", "/t/it's", "", head + "exec " + exe + ` --terms '/t/it'\''s' --label commit-message --stdin < "$1"` + "\n"},
		// The value is written shell-quoted, whatever it holds (HSH-11/D24).
		{"commit-msg", "/t/x", "a'b@x,$(c)@y", head + "exec " + exe + ` --terms '/t/x' --identities 'a'\''b@x,$(c)@y' --label commit-message --stdin < "$1"` + "\n"},
	} {
		if got := Script(c.name, "/opt/a b/hush", c.terms, c.ids); got != c.want {
			t.Errorf("%s with terms %q and identities %q:\n got %q\nwant %q", c.name, c.terms, c.ids, got, c.want)
		}
	}
	push := Script("pre-push", "/opt/hush", "/t/terms", "bob@example.org")
	scan := "'/opt/hush' scan --destination public --terms '/t/terms' --identities 'bob@example.org'"
	if !strings.HasPrefix(push, head) || strings.Contains(push, "HUSH_SCAN") ||
		!strings.Contains(push, "\t"+scan+" --allow-empty-range --range \"$revs\" </dev/null || exit\n") ||
		!strings.Contains(push, "| "+scan+" --label pushed-ref --stdin || exit\n") {
		t.Errorf("pre-push:\n%s", push)
	}
	if Script("post-commit", "/opt/hush", "", "") != "" {
		t.Error("an unknown hook has a script")
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestInstall(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "hooks") // missing: Install creates it
	if err := Install(dir, "/opt/hush", "", "", false); err != nil {
		t.Fatal(err)
	}
	for _, name := range Names {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil || fi.Mode().Perm() != 0o755 || read(t, filepath.Join(dir, name)) != Script(name, "/opt/hush", "", "") {
			t.Errorf("%s: not written as expected (%v)", name, err)
		}
	}
	// Its own hooks are replaced without --force.
	if err := Install(dir, "/opt/hush", "/t/terms", "", false); err != nil || read(t, filepath.Join(dir, "pre-push")) != Script("pre-push", "/opt/hush", "/t/terms", "") {
		t.Errorf("reinstall: %v", err)
	}

	// Another hook, a symlink or a hook without the marker on its second
	// line is refused, and nothing is written.
	for _, other := range []func(string) error{
		func(p string) error { return os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o755) },
		func(p string) error { return os.WriteFile(p, []byte(marker+"\n#!/bin/sh\nexit 0\n"), 0o755) },
		func(p string) error { return os.Symlink("pre-commit.sample", p) },
	} {
		dir := t.TempDir()
		path := filepath.Join(dir, "commit-msg")
		if err := other(path); err != nil {
			t.Fatal(err)
		}
		before, _ := os.Readlink(path)
		if before == "" {
			before = read(t, path)
		}
		err := Install(dir, "/opt/hush", "", "", false)
		if fmt.Sprint(err) != "the commit-msg hook was not written by hush (give --force to replace it)" {
			t.Errorf("foreign hook: %v", err)
		}
		lc.Check(t, fmt.Sprint(err))
		entries, _ := os.ReadDir(dir)
		after, _ := os.Readlink(path)
		if after == "" {
			after = read(t, path)
		}
		if len(entries) != 1 || after != before {
			t.Errorf("foreign hook: %d entries after a refused install", len(entries))
		}
		// --force replaces it, and a symlink itself, not its target.
		if err := Install(dir, "/opt/hush", "", "", true); err != nil {
			t.Fatal(err)
		}
		if fi, err := os.Lstat(path); err != nil || !fi.Mode().IsRegular() || read(t, path) != Script("commit-msg", "/opt/hush", "", "") {
			t.Errorf("forced install: %v", err)
		}
		if _, err := os.Stat(filepath.Join(dir, "pre-commit.sample")); err == nil {
			t.Error("forced install wrote through the symlink")
		}
	}

	// A directory in a hook's place cannot be replaced, even with --force.
	dir = t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "pre-push"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Install(dir, "/opt/hush", "", "", false); err == nil {
		t.Error("a directory in a hook's place: no error")
	}
	err := Install(dir, "/opt/hush", "", "", true)
	if fmt.Sprint(err) != "cannot write the pre-push hook" {
		t.Errorf("forced install over a directory: %v", err)
	}
	lc.Check(t, fmt.Sprint(err))
	if entries, _ := os.ReadDir(dir); len(entries) != 3 {
		t.Errorf("forced install over a directory left %d entries, want 3 with no temporary file", len(entries))
	}
}

func TestUninstall(t *testing.T) {
	dir := t.TempDir()
	if err := Install(dir, "/opt/hush", "", "", false); err != nil {
		t.Fatal(err)
	}
	other := "#!/bin/sh\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "pre-commit"), []byte(other), 0o755); err != nil {
		t.Fatal(err)
	}
	removed, left, err := Uninstall(dir)
	if err != nil || fmt.Sprint(removed) != "[commit-msg pre-push]" || fmt.Sprint(left) != "[pre-commit]" {
		t.Errorf("uninstall: removed %v, left %v, error %v", removed, left, err)
	}
	if read(t, filepath.Join(dir, "pre-commit")) != other {
		t.Error("uninstall changed a hook hush did not write")
	}
	for _, name := range []string{"commit-msg", "pre-push"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
			t.Errorf("%s still exists", name)
		}
	}
	removed, left, err = Uninstall(t.TempDir())
	if err != nil || removed != nil || left != nil {
		t.Errorf("uninstall with no hooks: removed %v, left %v, error %v", removed, left, err)
	}
}
