// Package hooks writes and removes the git hooks hush installs. It is used by
// the CLI only.
package hooks

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Error is a refusal or failure of hush hooks: fixed text that the CLI
// prints as its error line. Every error this package returns is one, and
// holds no path, value or another program's output (ADR-001 section 6.6).
type Error struct{ msg string }

func (e *Error) Error() string { return e.msg }

// refuse returns an *Error with the fixed text msg.
func refuse(msg string) error { return &Error{msg: msg} }

// Names lists the hooks Install writes, in order.
var Names = []string{"pre-commit", "commit-msg", "pre-push"}

// marker is the second line of every hook hush writes. A hook is hush's only
// when it is a regular file with this line (HSH-9/D2).
const marker = `# Written by "hush hooks install"; "hush hooks uninstall" removes it.`

// The pre-push loop, as the interim's hook, with the review's four changes
// (HSH-9/D1): each line is read from the right, since git hands over a
// refspec's source as typed; a pushed object that is not a commit is refused,
// with git's replace refs off; the remote ref's name is scanned; and a new
// branch is scanned against the commits the destination advertises (heads and
// tags) that this repository has, each once, asked once per push and only
// when ls-remote reads the URL pushed to as given, and whole otherwise or when
// git ls-remote fails. HUSH_SCAN stands for hush's scan command with its
// destination, tier and identities (HSH-11/D23, D24). The advertised commits
// are handed to the range as revisions to exclude, after --not, which ADR-001
// section 5's range grammar accepts as Range.Exclude.
const prePush = `# Replace refs off, so that a blob or a tree cannot pass for a commit.
GIT_NO_REPLACE_OBJECTS=1; export GIT_NO_REPLACE_OBJECTS
asked=; not=
# Standard input: one line per ref, "<local ref> <local id> <remote ref> <remote id>".
# The local ref is the source as typed and may hold spaces; the other three never do.
while read -r line; do
	rsha=${line##* }; line=${line% *}; rref=${line##* }; line=${line% *}; lsha=${line##* }
	case $lsha in *[!0]*) ;; *) continue ;; esac # a branch deletion
	if ! git rev-parse -q --verify "$lsha^{commit}" >/dev/null 2>&1; then
		echo 'hush: a pushed ref does not point to a commit, so hush cannot scan it' >&2
		exit 2
	fi
	printf '%s\n' "$rref" | HUSH_SCAN --label pushed-ref --stdin || exit
	case $rsha in
	*[!0]*) revs="$rsha..$lsha" ;;
	*) # a new branch, against the commits the destination advertises (heads
		# and tags) that this repository has, each id once, asked once per push.
		# Only when ls-remote reads $2 as the URL pushed to: an insteadOf rule,
		# or a remote named $2, would make it ask another repository, so then
		# nothing is subtracted. When ls-remote fails, nothing is subtracted
		# either, and the whole history is scanned: it fails closed. Its
		# standard input is /dev/null, so no transport can read the ref list.
		if [ -z "$asked" ]; then
			asked=1
			if [ "$(git ls-remote --get-url -- "$2" 2>/dev/null)" = "$2" ]; then
				not=$(git ls-remote --heads --tags -- "$2" </dev/null 2>/dev/null | cut -f1 | GIT_NO_LAZY_FETCH=1 git cat-file --batch-check='%(objectname) %(objecttype)' 2>/dev/null | awk '$2 == "commit" && !seen[$1]++ { printf " %s", $1 }')
			fi
		fi
		revs="$lsha${not:+ --not$not}" ;;
	esac
	HUSH_SCAN --allow-empty-range --range "$revs" </dev/null || exit
done
`

// Script returns the text of the hook called name. exe is hush's absolute
// path; terms is an absolute term-file path, or "" for the generic tier only
// (HSH-9/D1, D4); and identities is the --identities value, or "" for none.
// Every hook scans for the public destination, and each value is written
// shell-quoted (HSH-11/D24).
func Script(name, exe, terms, identities string) string {
	scan := quote(exe) + " scan --destination public --generic-only"
	if terms != "" {
		scan = quote(exe) + " scan --destination public --terms " + quote(terms)
	}
	if identities != "" {
		scan += " --identities " + quote(identities)
	}
	head := "#!/bin/sh\n" + marker + "\n"
	switch name {
	case "pre-commit":
		return head + "exec " + scan + " --index\n"
	case "commit-msg":
		return head + "exec " + scan + ` --label commit-message --stdin < "$1"` + "\n"
	case "pre-push":
		return head + strings.ReplaceAll(prePush, "HUSH_SCAN", scan)
	}
	return ""
}

// quote returns s single-quoted for sh.
func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// Install writes the three hooks into dir, creating it if needed, with
// Script's arguments. If a hook exists that hush did not write, Install
// writes nothing and fails, unless force is set (HSH-9/D2).
func Install(dir, exe, terms, identities string, force bool) error {
	for _, name := range Names {
		exists, ours, err := owner(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		if exists && !ours && !force {
			return refuse("the " + name + " hook was not written by hush (give --force to replace it)")
		}
	}
	if os.MkdirAll(dir, 0o755) != nil {
		return refuse("cannot create the hooks directory")
	}
	for _, name := range Names {
		if err := write(dir, name, Script(name, exe, terms, identities)); err != nil {
			return err
		}
	}
	return nil
}

// Uninstall removes the hooks in dir that hush wrote. It returns the names of
// the hooks it removed and of those it left because hush did not write them.
func Uninstall(dir string) (removed, left []string, err error) {
	for _, name := range Names {
		path := filepath.Join(dir, name)
		exists, ours, err := owner(path)
		switch {
		case err != nil:
			return removed, left, err
		case ours:
			if os.Remove(path) != nil {
				return removed, left, refuse("cannot remove the " + name + " hook")
			}
			removed = append(removed, name)
		case exists:
			left = append(left, name)
		}
	}
	return removed, left, nil
}

// owner reports whether something exists at path and whether it is a hook
// hush wrote.
func owner(path string) (exists, ours bool, err error) {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, false, nil
	}
	if err != nil {
		return false, false, refuse("cannot read the hooks directory")
	}
	if !fi.Mode().IsRegular() {
		return true, false, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return true, false, refuse("cannot read a hook in the hooks directory")
	}
	lines := strings.SplitN(string(data), "\n", 3)
	return true, len(lines) == 3 && lines[1] == marker, nil
}

// write puts text at dir/name through a temporary file and a rename, so a
// symlink at that path is replaced rather than followed.
func write(dir, name, text string) error {
	bad := refuse("cannot write the " + name + " hook")
	f, err := os.CreateTemp(dir, "."+name+".hush-*")
	if err != nil {
		return bad
	}
	_, werr := f.WriteString(text)
	if cerr := f.Close(); werr != nil || cerr != nil ||
		os.Chmod(f.Name(), 0o755) != nil || os.Rename(f.Name(), filepath.Join(dir, name)) != nil {
		os.Remove(f.Name())
		return bad
	}
	return nil
}
