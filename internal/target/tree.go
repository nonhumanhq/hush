package target

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Paths scans each path argument in turn, as found from the repository root.
// A directory is walked, skipping .git; anything else is scanned as one file.
func (s *Scan) Paths(paths []string) error {
	for n, p := range paths {
		if strings.HasPrefix(p, "-") {
			p = "./" + p
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return fmt.Errorf("path argument %d does not exist", n+1)
		}
		if err := s.inside(p); err != nil {
			return err
		}
		list := []string{p}
		if fi.IsDir() {
			if list, err = walk(p); err != nil {
				return fmt.Errorf("cannot walk path argument %d", n+1)
			}
		}
		for _, f := range list {
			if err := s.file(f); err != nil {
				return err
			}
		}
	}
	return nil
}

// file scans one file: its path, then its lines. A symlink is scanned as its
// target text, without following it.
func (s *Scan) file(p string) error {
	data, flag := read(p)
	path := normalize(p)
	where := s.redact(path)
	s.path(where, path)
	if flag != "" {
		s.Out.Finding(where, 0, flag)
	} else {
		s.text(where, data, fileContext(path))
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

// inside refuses a path argument that holds the term file.
func (s *Scan) inside(p string) error {
	if s.Terms == "" {
		return nil
	}
	t, err1 := abspath(s.Terms)
	a, err2 := abspath(p)
	if err1 != nil || err2 != nil {
		return errors.New("cannot resolve a path argument")
	}
	if t == a || strings.HasPrefix(t, strings.TrimSuffix(a, "/")+"/") {
		return errors.New("the term file is inside a scanned path; keep term files outside repositories")
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
