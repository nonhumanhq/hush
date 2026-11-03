package main

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/nonhumanhq/hush/internal/hooks"
	"github.com/nonhumanhq/hush/internal/output"
	"github.com/nonhumanhq/hush/internal/target"
)

const hooksUsage = `usage: hush hooks install [--force] [--terms FILE]
       hush hooks uninstall
       hush hooks pre-commit [--terms FILE]

  install       write the pre-commit, commit-msg and pre-push hooks into the
                repository's hooks directory (core.hooksPath, if set); a hook
                hush did not write is replaced, and a hooks directory inside
                the work tree is used, only with --force
  uninstall     remove the hooks hush wrote, and no others
  pre-commit    scan the git index, as the pre-commit hook does; exits 2 if
                GIT_INDEX_FILE is set but empty or names no regular file
  --terms FILE  also match the term sets in FILE (the private tier, for the
                review machine); without it the hooks run the generic tier

The hooks run this hush binary by the path it was started by, made
absolute. pre-commit scans the index, commit-msg scans the message as
standard input labelled commit-message, and pre-push scans each pushed ref's
name, labelled pushed-ref, and its range: a new branch against the commits
the destination advertises (heads and tags) that this repository has, and a
deleted branch not at all. pre-push refuses a pushed ref that does not point
to a commit.
`

// hooksCommand runs "hush hooks ARGS".
func hooksCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		io.WriteString(stdout, hooksUsage)
		return 0
	}
	if len(args) == 0 || args[0] != "install" && args[0] != "uninstall" && args[0] != "pre-commit" {
		output.Error(stderr, "hooks needs install, uninstall or pre-commit (see hush hooks --help)")
		return 2
	}
	sub := args[0]
	terms, hasTerms, force := "", false, false
	for i := 1; i < len(args); i++ {
		switch {
		case args[i] == "--force" && sub == "install" && !force:
			force = true
		case args[i] == "--terms" && sub != "uninstall" && !hasTerms && i+1 < len(args):
			terms, hasTerms = args[i+1], true
			i++
		default:
			output.Error(stderr, "hooks "+sub+": unexpected argument "+strconv.Itoa(i+1)+" (see hush hooks --help)")
			return 2
		}
	}
	if hasTerms && terms == "" {
		output.Error(stderr, "term file missing or unreadable")
		return 2
	}
	switch sub {
	case "install":
		return hooksInstall(terms, force, stdout, stderr)
	case "uninstall":
		return hooksUninstall(stdout, stderr)
	}
	return preCommit(terms, stdout, stderr)
}

// hooksInstall writes the hooks for the repository in the current directory.
func hooksInstall(terms string, force bool, stdout, stderr io.Writer) int {
	exe, err := hushPath()
	if err != nil {
		output.Error(stderr, "cannot find the hush binary")
		return 2
	}
	if terms != "" {
		// The hooks run at the top of the work tree, so they get an absolute
		// path, and the file is checked now rather than at the first commit.
		if terms, err = filepath.Abs(terms); err != nil {
			output.Error(stderr, "term file missing or unreadable")
			return 2
		}
		if _, err := loadTerms(terms); err != nil {
			output.Error(stderr, err.Error())
			return 2
		}
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
		err = hooks.Install(dir, exe, terms, force)
	}
	if err != nil {
		output.Error(stderr, err.Error())
		return 2
	}
	for _, name := range hooks.Names {
		io.WriteString(stdout, name+": installed\n")
	}
	if inTree {
		output.Error(stderr, "warning: the hooks directory is inside the work tree; the hooks hold absolute paths and must not be committed")
	}
	return 0
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
func hooksUninstall(stdout, stderr io.Writer) int {
	dir, err := target.HooksDir("")
	if err != nil {
		output.Error(stderr, err.Error())
		return 2
	}
	removed, left, err := hooks.Uninstall(dir)
	for _, name := range removed {
		io.WriteString(stdout, name+": removed\n")
	}
	for _, name := range left {
		io.WriteString(stdout, name+": left in place, not written by hush\n")
	}
	if err != nil {
		output.Error(stderr, err.Error())
		return 2
	}
	return 0
}

// preCommit scans the index of the repository in the current directory,
// which is where git runs the pre-commit hook. A GIT_INDEX_FILE that is set
// must name a regular file, or the index target would read an empty index
// and pass, and the index target gets it made absolute against this
// directory (HSH-9/D5).
func preCommit(terms string, stdout, stderr io.Writer) int {
	index := ""
	if value, ok := os.LookupEnv("GIT_INDEX_FILE"); ok {
		var err error
		if index, err = hooks.CheckIndexFile(value); err != nil {
			output.Error(stderr, err.Error())
			return 2
		}
	}
	out := output.New(stdout)
	s, err := newScan(terms, out, stderr)
	if err == nil {
		s.IndexFile = index
		err = s.Index("")
	}
	if out.Flush() != nil {
		return 2 // findings cannot be written (HSH-5/D13)
	}
	if err != nil {
		output.Error(stderr, err.Error())
		return 2
	}
	if out.Found > 0 {
		return 1
	}
	return 0
}

// newScan returns a scan with the generic rules and, when terms is not "",
// the sets in that term file, as hush scan builds it.
func newScan(terms string, out *output.Writer, stderr io.Writer) (*target.Scan, error) {
	s := &target.Scan{Rules: genericRules(), Out: out, Terms: terms, GitStderr: stderr}
	if terms != "" {
		sets, err := loadTerms(terms)
		if err != nil {
			return nil, err
		}
		for _, set := range sets {
			s.Rules = append(s.Rules, set)
		}
	}
	return s, nil
}
