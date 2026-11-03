package target

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// hookGit runs git for hush hooks, in the repository at repo ("" for the
// current directory), with the caller's environment: unlike a scan, the
// installer must see the caller's own configuration, where core.hooksPath is
// often set (HSH-9/D3, HSH-11/D51). It returns git's standard output.
func hookGit(repo string, args ...string) ([]byte, error) {
	if repo != "" {
		args = append([]string{"-C", repo}, args...)
	}
	return exec.Command("git", args...).Output()
}

// HooksDir returns the absolute path of the hooks directory of the repository
// at repo ("" for the current directory). git resolves it, so it honours
// core.hooksPath and linked worktrees (HSH-9/D3).
func HooksDir(repo string) (string, error) {
	if _, err := hookGit(repo, "rev-parse", "--git-dir"); err != nil {
		return "", fail(NotRepository, "not a git repository")
	}
	out, err := hookGit(repo, "rev-parse", "--path-format=absolute", "--git-path", "hooks")
	dir := strings.TrimSuffix(string(out), "\n")
	if err != nil || dir == "" {
		return "", errors.New("cannot find the hooks directory")
	}
	return dir, nil
}

// InWorkTree reports whether path, an absolute path as HooksDir returns it,
// lies in the work tree of the repository at repo ("" for the current
// directory) and outside its git directory, where a file written there could
// be committed (HSH-9/D14). A bare repository has no work tree; anywhere else
// that git finds none, such as inside the git directory, is an error.
func InWorkTree(repo, path string) (bool, error) {
	top, err := hookGit(repo, "rev-parse", "--show-toplevel")
	if err != nil {
		if bare, _ := hookGit(repo, "rev-parse", "--is-bare-repository"); string(bare) == "true\n" {
			return false, nil
		}
		return false, errors.New("cannot find the work tree")
	}
	common, err := hookGit(repo, "rev-parse", "--path-format=absolute", "--git-common-dir")
	if err != nil {
		return false, errors.New("cannot find the git directory")
	}
	return within(path, strings.TrimSuffix(string(top), "\n")) &&
		!within(path, strings.TrimSuffix(string(common), "\n")), nil
}

// within reports whether path is dir or lies below it. Both are absolute, and
// git gives both with symlinks resolved.
func within(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// ReadFile returns the contents of a file that the caller scans and passes
// on, such as a body file hush gh hands to gh as text (HSH-9/D9).
func ReadFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("cannot read a file")
	}
	return data, nil
}
