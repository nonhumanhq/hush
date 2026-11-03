package target

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Paths scans each path argument in turn, as found from the current
// directory. A directory is walked, skipping .git; anything else is scanned
// as one file.
func (s *Scan) Paths(paths []string) error { return s.Tree("", paths) }

// Tree scans each path argument in turn, as Paths does, but opens a relative
// path argument below root, or below the current directory when root is "".
// A finding's path is the path argument as given, followed by the part below
// it, normalized; so with root set, a relative argument gives a path relative
// to root.
func (s *Scan) Tree(root string, paths []string) error {
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
		list := []string{open}
		if fi.IsDir() {
			if list, err = walk(open); err != nil {
				return &Error{Kind: PathUnwalkable, Arg: n + 1, text: fmt.Sprintf("cannot walk path argument %d", n+1)}
			}
		}
		for _, f := range list {
			if s.stopped() {
				return fail(Interrupted, "interrupted")
			}
			if err := s.file(f, p+strings.TrimPrefix(f, open)); err != nil {
				return err
			}
		}
	}
	return nil
}

// file scans the file at open, reported as name: its path, then its lines. A
// symlink is scanned as its target text, without following it.
func (s *Scan) file(open, name string) error {
	data, flag := read(open)
	at := Finding{Loc: InTree, Path: normalize(name)}
	s.Counts.Files++
	s.path(at)
	if flag != "" {
		s.unscanned(at, flag)
	} else {
		s.text(at, data, fileContext(at.Path))
	}
	return s.flush()
}

// read returns what file scans for p, or the finding that replaces it.
func read(p string) ([]byte, string) {
	if fi, err := os.Lstat(p); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
		t, err := os.Readlink(p)
		if err != nil {
			return nil, "unreadable"
		}
		return []byte(t + "\n"), ""
	}
	if fi, err := os.Stat(p); err != nil || !fi.Mode().IsRegular() {
		return nil, "unreadable"
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, "unreadable"
	}
	if bytes.IndexByte(data, 0) >= 0 {
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

// walk lists the regular files and symlinks under root as find prints them,
// skipping every entry named .git, sorted bytewise. The list is split on
// newlines, as the interim's line-based list is (HSH-5/D9).
func walk(root string) ([]string, error) {
	var found []string
	if filepath.Base(root) != ".git" {
		if err := walkDir(root, &found); err != nil {
			return nil, err
		}
	}
	if len(found) == 0 {
		return nil, nil
	}
	list := strings.Split(strings.Join(found, "\n"), "\n")
	sort.Strings(list)
	return list, nil
}

func walkDir(dir string, found *[]string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		p, t := dir+"/"+e.Name(), e.Type()
		switch {
		case e.Name() == ".git":
		case t.IsDir():
			if err := walkDir(p, found); err != nil {
				return err
			}
		case t.IsRegular() || t&fs.ModeSymlink != 0:
			*found = append(*found, p)
		}
	}
	return nil
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
