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
	"github.com/nonhumanhq/hush/internal/termset"
)

// Scan applies Rules and then Sets to each target and prints findings to Out.
// Every line and path it checks carries its rule.Context. Its methods return
// errors built from fixed text, integers and object ids only.
type Scan struct {
	Rules rule.List
	// Sets are the term sets every finding applies, after the rules (HSH-11/D2),
	// or nil for none. Redaction uses them too.
	Sets *termset.Sets
	Out  *output.Writer
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

	all termset.Mask // every set in Sets, once computed
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
	s.text(label, data, rule.Context{Source: rule.Stdin})
	return s.flush()
}

// text scans each line of data, numbered from 1, in ctx.
func (s *Scan) text(where string, data []byte, ctx rule.Context) {
	for i, line := range lines(data) {
		s.emit(where, i+1, line, ctx)
	}
}

// emit reports the rules and sets one line breaks.
func (s *Scan) emit(where string, ln int, line string, ctx rule.Context) {
	for _, name := range s.check([]byte(line), ctx) {
		s.Out.Finding(where, ln, name)
	}
}

// path reports the rules and sets a path breaks, at line 0.
func (s *Scan) path(where, path string) {
	for _, name := range s.check([]byte(path), pathContext(path)) {
		s.Out.Finding(where, 0, name+" in path")
	}
}

// check returns what line breaks in ctx: the rules in list order, then
// "set:NAME" for each set in file order.
func (s *Scan) check(line []byte, ctx rule.Context) []string {
	names := s.Rules.Check(line, ctx)
	if s.Sets != nil {
		hit, _ := s.Sets.Match(line, s.apply())
		for i := 0; i < s.Sets.Len(); i++ {
			if hit.Has(i) {
				names = append(names, "set:"+s.Sets.Name(i))
			}
		}
	}
	return names
}

// Breaks reports whether text, as a bare string (rule.Text), breaks any rule
// or set of the scan. Callers use it to decide whether a word may be printed.
func (s *Scan) Breaks(text string) bool { return len(s.check([]byte(text), rule.Context{})) > 0 }

// redact returns path as a finding prints it: cut from the component where the
// earliest match of any rule or set begins (rule.Redact).
func (s *Scan) redact(path string) string {
	start := s.Rules.Start([]byte(path), pathContext(path))
	if s.Sets != nil {
		if _, at := s.Sets.Match([]byte(path), s.apply()); at >= 0 && (start < 0 || at < start) {
			start = at
		}
	}
	return rule.Redact(path, start)
}

func (s *Scan) apply() termset.Mask {
	if s.all == nil {
		s.all = s.Sets.All()
	}
	return s.all
}

// pathContext is the context of a path as hush reports it, before redaction.
func pathContext(path string) rule.Context { return rule.Context{Source: rule.Path, Path: path} }

// fileContext is the context of a line of the file at path.
func fileContext(path string) rule.Context { return rule.Context{Source: rule.File, Path: path} }

// lines splits data into awk records: lines ending in "\n", plus a last line
// without one. Empty data has no lines.
func lines(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
}
