package target

import (
	"bytes"
	"strings"
)

// diffFlags give one commit's changes as diff-tree -z --raw records followed
// by -p sections (ADR-001 section 5, "How git is run"). --text keeps
// attributes and core.bigFileThreshold from hiding a file's lines; hush
// applies its own NUL rule to each new blob instead. --ignore-submodules=none
// keeps a gitlink's record when a .gitmodules file, committed or not, sets
// ignore for its path.
var diffFlags = []string{"diff-tree", "-r", "-z", "--raw", "-p", "-U0", "--no-commit-id", "--text",
	"--no-color", "--no-ext-diff", "--no-textconv", "--no-renames", "--ignore-submodules=none",
	"--src-prefix=a/", "--dst-prefix=b/"}

// record is one diff-tree -z --raw record: the status, the new side's mode
// and object id, and the path as git's raw bytes.
type record struct {
	status          byte
	oldID, mode, id string
	path            string
}

// rawRecords splits diff-tree -z --raw -p output into its records and the
// patch text after them. ok is false for output in another shape.
func rawRecords(data []byte) (recs []record, patch []byte, ok bool) {
	for len(data) > 0 {
		if data[0] == 0 { // the NUL between the records and the patch
			return recs, data[1:], true
		}
		head, rest, found := bytes.Cut(data, []byte{0})
		path, rest2, found2 := bytes.Cut(rest, []byte{0})
		f := strings.Fields(string(head))
		if !found || !found2 || head[0] != ':' || len(f) != 5 || len(f[4]) != 1 || len(path) == 0 {
			return nil, nil, false
		}
		recs = append(recs, record{status: f[4][0], oldID: f[2], mode: f[1], id: f[3], path: string(path)})
		data = rest2
	}
	return recs, nil, true
}

// sections splits patch text into its sections, each starting at a line
// "diff --git ". Inside a hunk every line starts with "+", "-", " " or "\",
// and git quotes a path that holds a newline in a section's header lines, so
// no other line starts that way.
func sections(patch []byte) ([][]string, bool) {
	var secs [][]string
	for _, line := range lines(patch) {
		if strings.HasPrefix(line, "diff --git ") {
			secs = append(secs, nil)
		} else if len(secs) == 0 {
			return nil, false
		}
		secs[len(secs)-1] = append(secs[len(secs)-1], line)
	}
	return secs, true
}

// diff scans one commit's diff-tree output: each path the commit adds or
// changes, then, unless its new blob holds a NUL byte, each line it adds,
// numbered in the new file. Records pair with sections in order; a
// typechange (T) has two sections, the old side's deletion and then the new
// side's creation. A deletion adds nothing. Any other mismatch is an error.
func (s *Scan) diff(b *batch, sha string, data []byte) error {
	bad := &Error{Kind: DiffFailed, Commit: sha, text: "cannot diff commit " + short(sha)}
	recs, patch, ok := rawRecords(data)
	secs, ok2 := sections(patch)
	if !ok || !ok2 {
		return bad
	}
	k := 0
	for _, r := range recs {
		n := 1
		if r.status == 'T' {
			n = 2
		}
		if !strings.ContainsRune("ADMT", rune(r.status)) || k+n > len(secs) {
			return bad
		}
		sec := secs[k+n-1]
		k += n
		if r.status == 'D' {
			continue
		}
		at := Finding{Loc: InDiff, Commit: sha, Path: r.path}
		s.Counts.Files++
		s.path(at)
		if r.mode != "160000" && r.id != r.oldID { // a gitlink names a commit, not a blob
			_, blob, err := b.contents(r.id, s.MaxFile)
			switch {
			case err == errTooLarge:
				return fail(TooLarge, "input over the size limit")
			case err != nil:
				return s.stopOr(bad)
			case bytes.IndexByte(blob, 0) >= 0:
				s.unscanned(at, "binary-unscanned")
				continue
			}
		}
		s.hunks(at, sec)
		if s.failed != nil {
			return s.failed
		}
	}
	if k != len(secs) {
		return bad
	}
	return nil
}

// hunks scans the lines a section adds, numbered in the new file.
func (s *Scan) hunks(at Finding, sec []string) {
	inHunk, ln := false, 0
	for _, line := range sec {
		switch {
		case strings.HasPrefix(line, "@@ "):
			inHunk, ln = true, hunkStart(line)
		case inHunk && strings.HasPrefix(line, "+"):
			s.emit(at, ln, line[1:], fileContext(at.Path))
			ln++
		}
	}
}
