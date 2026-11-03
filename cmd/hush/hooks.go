package main

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/nonhumanhq/hush"
	"github.com/nonhumanhq/hush/internal/hooks"
	"github.com/nonhumanhq/hush/internal/output"
	"github.com/nonhumanhq/hush/internal/target"
)

const hooksUsage = `usage: hush hooks install [--force] [--terms FILE] [--identities ADDR[,ADDR...]]
       hush hooks uninstall

  install       write the pre-commit, commit-msg and pre-push hooks into the
                repository's hooks directory (core.hooksPath, if set); a hook
                hush did not write is replaced, and a hooks directory inside
                the work tree is used, only with --force
  uninstall     remove the hooks hush wrote, and no others
  --terms FILE  scan with the term sets in FILE (the private tier, for the
                review machine); without it the hooks run the generic tier
                alone (--generic-only)
  --identities ADDR[,ADDR...]
                pass these addresses where they stand as an identity, as
                "hush scan --identities" does, in every hook

Every hook scans for the public destination. The hooks run this hush binary
by the path it was started by, made absolute. pre-commit scans the index
(hush scan --index), commit-msg scans the message as standard input labelled
commit-message, and pre-push scans each pushed ref's name, labelled
pushed-ref, and its range: a new branch against the commits the destination
advertises (heads and tags) that this repository has, and a deleted branch
not at all. pre-push refuses a pushed ref that does not point to a commit.
`

// hooksCommand runs "hush hooks ARGS".
func (p *process) hooksCommand(args []string) int {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		return p.text(hooksUsage)
	}
	if len(args) == 0 || args[0] != "install" && args[0] != "uninstall" {
		return p.fail("hooks needs install or uninstall (see hush hooks --help)")
	}
	sub := args[0]
	terms, hasTerms, identities, idsAt, force := "", false, "", 0, false
	for i := 1; i < len(args); i++ {
		switch {
		case args[i] == "--force" && sub == "install" && !force:
			force = true
		case args[i] == "--terms" && sub == "install" && !hasTerms && i+1 < len(args):
			terms, hasTerms = args[i+1], true
			i++
		case args[i] == "--identities" && sub == "install" && idsAt == 0 && i+1 < len(args):
			identities, idsAt = args[i+1], i+2
			i++
		default:
			return p.fail("hooks " + sub + ": unexpected argument " + strconv.Itoa(i+1) + " (see hush hooks --help)")
		}
	}
	if sub == "uninstall" {
		return p.hooksUninstall()
	}
	if idsAt > 0 {
		// Checked as hush scan checks it, before anything is written
		// (HSH-11/D24).
		if _, err := hush.NewIdentities(strings.Split(identities, ",")); err != nil {
			return p.failError(withArgument(err, idsAt))
		}
	}
	if hasTerms {
		// The file is checked now rather than at the first commit, and the
		// hooks, which run at the top of the work tree, get its absolute path.
		limitCore()
		if _, err := hush.LoadTermSets(terms); err != nil {
			return p.failError(err)
		}
		var err error
		if terms, err = filepath.Abs(terms); err != nil {
			return p.failError(nil)
		}
	}
	return p.hooksInstall(terms, identities, force)
}

// hooksInstall writes the hooks for the repository in the current directory.
func (p *process) hooksInstall(terms, identities string, force bool) int {
	exe, err := hushPath()
	if err != nil {
		return p.fail("cannot find the hush binary")
	}
	// The hooks hold absolute paths, so they must not land where they could be
	// committed (HSH-9/D14).
	dir, err := target.HooksDir("")
	inTree := false
	if err == nil {
		inTree, err = target.InWorkTree("", dir)
	}
	if err == nil && inTree && !force {
		err = errors.New("the hooks directory is inside the work tree, and the hooks hold absolute paths that must not be committed (give --force to install them there)")
	}
	if err == nil {
		err = hooks.Install(dir, exe, terms, identities, force)
	}
	if err != nil {
		return p.fail(err.Error())
	}
	var b strings.Builder
	for _, name := range hooks.Names {
		b.WriteString(name + ": installed\n")
	}
	code := p.text(b.String())
	if inTree {
		output.Error(p.stderr, "warning: the hooks directory is inside the work tree; the hooks hold absolute paths and must not be committed")
	}
	return code
}

// hushPath returns the path hush was started by, made absolute without
// resolving symlinks, so that hooks installed through a symlink, such as a
// profile's, run what it points to after an upgrade. A name without a slash
// is found on PATH, as the shell found it. When that fails, or the path does
// not lead to the running binary, it falls back to os.Executable, which
// resolves symlinks (HSH-9/D1).
func hushPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	p := os.Args[0]
	if !strings.Contains(p, "/") {
		if p, err = exec.LookPath(p); err != nil {
			return exe, nil
		}
	}
	p, err = filepath.Abs(p)
	a, errA := os.Stat(p)
	b, errB := os.Stat(exe)
	if err != nil || errA != nil || errB != nil || !os.SameFile(a, b) {
		return exe, nil
	}
	return p, nil
}

// hooksUninstall removes the hooks hush wrote for the repository in the
// current directory.
func (p *process) hooksUninstall() int {
	dir, err := target.HooksDir("")
	if err != nil {
		return p.fail(err.Error())
	}
	removed, left, err := hooks.Uninstall(dir)
	var b strings.Builder
	for _, name := range removed {
		b.WriteString(name + ": removed\n")
	}
	for _, name := range left {
		b.WriteString(name + ": left in place, not written by hush\n")
	}
	if err != nil {
		io.WriteString(p.stdout, b.String())
		return p.fail(err.Error())
	}
	return p.text(b.String())
}
