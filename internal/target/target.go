// Package target scans the interim scanner's targets: files and directory
// trees, standard input, git ranges, and the git index. It is the only
// package that runs git or opens scanned files.
package target

import (
	"errors"
	"io"
	"strings"

	"github.com/nonhumanhq/hush/internal/output"
	"github.com/nonhumanhq/hush/internal/rule"
)

// Scan applies Rules to each target and prints findings to Out. Its methods
// return errors built from fixed text, integers and object ids only.
type Scan struct {
	Rules rule.List
	Out   *output.Writer
	// Terms is the term file's path, or "". A tree scan refuses any path
	// argument that holds it.
	Terms string
	// GitStderr receives git's standard error from the two calls whose
	// errors the interim relays (HSH-5/D7). Nil discards it.
	GitStderr io.Writer
	// GitStdin is rev-list's standard input, which --range's "--stdin" reads,
	// as in the interim (HSH-5/D7). Pass hush's own unwrapped, so exec hands
	// over the descriptor instead of copying it. Nil gives /dev/null.
	GitStdin io.Reader
	// IndexFile is the absolute path of the index file Index reads, or "" for
	// the one git finds itself (HSH-9/D5).
	IndexFile string
}

// ErrOutput stops a target at the first findings it cannot write. The caller
// prints nothing more: the interim has exited by then, its awk killed by
// SIGPIPE (HSH-5/D13).
var ErrOutput = errors.New("cannot write findings")

// flush writes the findings of one unit the interim scans with one awk run
// (a file, a commit object, a diff), so they print where the interim's do.
func (s *Scan) flush() error {
	if s.Out.Flush() != nil {
		return ErrOutput
	}
	return nil
}

// Stdin scans r as text under label.
func (s *Scan) Stdin(r io.Reader, label string) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return errors.New("cannot read standard input")
	}
	s.text(label, data, false)
	return s.flush()
}

// text scans each line of data, numbered from 1.
func (s *Scan) text(where string, data []byte, inRef bool) {
	for i, line := range lines(data) {
		s.emit(where, i+1, line, inRef)
	}
}

// emit reports the rules one line breaks.
func (s *Scan) emit(where string, ln int, line string, inRef bool) {
	for _, name := range s.Rules.Check(line, inRef) {
		s.Out.Finding(where, ln, name)
	}
}

// path reports the rules a path breaks, at line 0.
func (s *Scan) path(where, path string, inRef bool) {
	for _, name := range s.Rules.Check(path, inRef) {
		s.Out.Finding(where, 0, name+" in path")
	}
}

// lines splits data into awk records: lines ending in "\n", plus a last line
// without one. Empty data has no lines.
func lines(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
}
