package target

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// Paths scans each path argument in turn, as found from the current
// directory. A directory is walked, skipping .git; anything else is scanned
// as one file.
func (s *Scan) Paths(paths []string) error { return s.Tree("", paths) }

// Tree scans each path argument in turn, as Paths does, but opens a relative
// path argument below root, or below the current directory when root is "".
// A finding's path is the path argument as given, followed by the part below
// it, normalized; so with root set, a relative argument gives a path relative
// to root. Every path argument is checked and listed before anything is
// scanned: one that does not exist, or that holds the term file, stops the
// scan before it reads a file (ADR-001 section 5).
func (s *Scan) Tree(root string, paths []string) error {
	type arg struct {
		name, open string
		list       []entry
	}
	terms, err := s.termsFile()
	if err != nil {
		return err
	}
	var args []arg
	for n, p := range paths {
		if s.stopped() {
			return fail(Interrupted, "interrupted")
		}
		open := p
		switch {
		case root != "" && !filepath.IsAbs(p):
			open = root + "/" + p
		case strings.HasPrefix(p, "-"):
			p = "./" + p
			open = p
		}
		fi, err := os.Lstat(open)
		if err != nil {
			return &Error{Kind: PathMissing, Arg: n + 1, text: fmt.Sprintf("path argument %d does not exist", n+1)}
		}
		if err := s.inside(open, n+1); err != nil {
			return err
		}
		list := []entry{{path: open}}
		if fi.IsDir() {
			list = walk(open)
		}
		if terms != nil && holds(list, terms) {
			return &Error{Kind: TermFileInside, Arg: n + 1, text: "the term file is inside a scanned path; keep term files outside repositories"}
		}
		args = append(args, arg{p, open, list})
	}
	for _, a := range args {
		for _, e := range a.list {
			if s.stopped() {
				return fail(Interrupted, "interrupted")
			}
			if err := s.file(e, a.name+strings.TrimPrefix(e.path, a.open)); err != nil {
				return err
			}
		}
	}
	return nil
}

// entry is one thing a tree scan reports: a file, symlink or special file,
// or a directory that cannot be walked.
type entry struct {
	path       string
	unwalkable bool
}

// file scans the entry e, reported as name: its path, then its lines. A
// symlink is scanned as its target text, without following it. A directory
// that cannot be walked, and anything that is not a regular file or a
// symlink, gives unreadable.
func (s *Scan) file(e entry, name string) error {
	at := Finding{Loc: InTree, Path: normalize(name)}
	if e.unwalkable {
		s.path(at)
		s.unscanned(at, "unreadable")
		return s.flush()
	}
	data, flag := read(e.path, s.MaxFile)
	if flag == tooLarge {
		return fail(TooLarge, "input over the size limit")
	}
	s.Counts.Files++
	s.path(at)
	if flag != "" {
		s.unscanned(at, flag)
	} else {
		s.text(at, data, fileContext(at.Path))
	}
	if s.failed != nil {
		return s.failed
	}
	return s.flush()
}

// tooLarge is read's flag for a file over the size limit.
const tooLarge = "too large"

// read returns what file scans for p, or the finding that replaces it, or
// tooLarge when p is a regular file over max bytes (max 0: no limit). A FIFO,
// socket or device is never opened.
func read(p string, max int) ([]byte, string) {
	if fi, err := os.Lstat(p); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
		t, err := os.Readlink(p)
		if err != nil {
			return nil, "unreadable"
		}
		return []byte(t + "\n"), ""
	}
	fi, err := os.Stat(p)
	switch {
	case err != nil || !fi.Mode().IsRegular():
		return nil, "unreadable"
	case max > 0 && fi.Size() > int64(max):
		return nil, tooLarge
	}
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, "unreadable"
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return nil, "unreadable" // swapped for something else since the check above
	}
	limit := int64(max) + 1
	if max <= 0 {
		limit = 1 << 62
	}
	data, err := io.ReadAll(io.LimitReader(f, limit))
	switch {
	case err != nil:
		return nil, "unreadable"
	case max > 0 && len(data) > max:
		return nil, tooLarge
	case bytes.IndexByte(data, 0) >= 0:
		return nil, "binary-unscanned"
	}
	return data, ""
}

// normalize collapses repeated slashes and strips leading "./".
func normalize(p string) string {
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	for strings.HasPrefix(p, "./") {
		p = p[2:]
	}
	return p
}

// walk lists what a tree scan reports under root, sorted bytewise: every
// file, symlink, FIFO, socket and device, and every directory that cannot be
// read, skipping each entry named .git and what lies below it. A name that
// holds a newline stays one entry (ADR-001 section 5; it was split as the
// interim's line-based list is, HSH-5/D9).
func walk(root string) []entry {
	var found []entry
	if filepath.Base(root) != ".git" {
		walkDir(root, &found)
	}
	sort.Slice(found, func(i, j int) bool { return found[i].path < found[j].path })
	return found
}

func walkDir(dir string, found *[]entry) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		*found = append(*found, entry{path: dir, unwalkable: true})
		return
	}
	for _, e := range entries {
		p := dir + "/" + e.Name()
		switch {
		case e.Name() == ".git":
		case e.Type().IsDir():
			walkDir(p, found)
		default:
			*found = append(*found, entry{path: p})
		}
	}
}

// termsFile returns what the term file at s.Terms is, symlinks followed, or
// nil when there is none.
func (s *Scan) termsFile() (fs.FileInfo, error) {
	if s.Terms == "" {
		return nil, nil
	}
	fi, err := os.Stat(s.Terms)
	if err != nil {
		return nil, fail(TermFileGone, "term file missing or unreadable")
	}
	return fi, nil
}

// holds reports whether an entry of list is the term file terms itself,
// reached by any name or hard link.
func holds(list []entry, terms fs.FileInfo) bool {
	for _, e := range list {
		if e.unwalkable {
			continue
		}
		if fi, err := os.Lstat(e.path); err == nil && fi.Mode().IsRegular() && os.SameFile(fi, terms) {
			return true
		}
	}
	return false
}

// inside refuses a path argument, the arg-th, that holds the term file.
func (s *Scan) inside(p string, arg int) error {
	if s.Terms == "" {
		return nil
	}
	t, err1 := abspath(s.Terms)
	a, err2 := abspath(p)
	if err1 != nil || err2 != nil {
		return &Error{Kind: PathUnresolved, Arg: arg, text: "cannot resolve a path argument"}
	}
	if t == a || strings.HasPrefix(t, strings.TrimSuffix(a, "/")+"/") {
		return &Error{Kind: TermFileInside, Arg: arg, text: "the term file is inside a scanned path; keep term files outside repositories"}
	}
	return nil
}

// abspath returns p with its directory resolved to a physical path, without
// following p itself. filepath.Dir and Base differ from dirname(1) and
// basename(1) only for trailing slashes, which never reach the second branch.
// In that branch the interim ignores a failed cd and scans; abspath fails.
// CDPATH is ignored (HSH-5/D9).
func abspath(p string) (string, error) {
	if fi, err := os.Lstat(p); err == nil && fi.IsDir() {
		return physical(p)
	}
	d, err := physical(filepath.Dir(p))
	if err != nil {
		return "", err
	}
	return d + "/" + filepath.Base(p), nil
}

// physical returns the directory dir as "cd DIR && pwd -P" prints it, and
// fails where cd does: resolving "a/." needs search permission on a.
func physical(dir string) (string, error) {
	a, err := filepath.Abs(dir)
	if err == nil {
		a, err = filepath.EvalSymlinks(a)
	}
	if err == nil {
		_, err = os.Stat(a + "/.")
	}
	return a, err
}
