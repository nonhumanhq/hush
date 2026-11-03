// Package target scans the interim scanner's targets: files and directory
// trees, standard input, git ranges, and the git index. It is the only
// package that runs git or opens scanned files.
package target

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"

	"github.com/nonhumanhq/hush/internal/output"
	"github.com/nonhumanhq/hush/internal/rule"
	"github.com/nonhumanhq/hush/internal/termset"
)

// Scan applies Rules and then Sets to each target and reports findings: to
// Sink when it is set, raw, and otherwise printed to Out, redacted as the
// interim scanner prints them. Every line and path it checks carries its
// rule.Context. Its methods return *Error values built from fixed text,
// integers and object ids only.
type Scan struct {
	Rules rule.List
	// Sets are the term sets findings apply, after the rules (HSH-11/D2), or
	// nil for none. Redaction uses every set.
	Sets *termset.Sets
	// Apply is the sets findings apply, or nil for every set in Sets.
	Apply termset.Mask
	// Sink receives every finding, raw, in output order. When it is set, Out
	// is not used and nothing is printed (HSH-11/D31), and git runs without
	// any inherited GIT_ variable (HSH-11/D31).
	Sink func(Finding)
	Out  *output.Writer
	// Ctx, when set, stops the scan between files, commits and index entries
	// once it is done, and ends the git commands the scan runs.
	Ctx context.Context
	// Counts is what the scan has scanned so far (HSH-11/D18).
	Counts Counts
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
	// MaxFile and MaxLine, when not 0, are the largest file or blob and the
	// longest line the scan reads, in bytes. More stops the scan with
	// TooLarge; nothing is skipped (HSH-11/D4).
	MaxFile, MaxLine int
	// Unsafe, when set, reports whether a path cannot print safely. Such a
	// path also gives "unreadable" in path at line 0 (ADR-001 section 5).
	Unsafe func(path string) bool

	failed error // TooLarge, once a line is over MaxLine

	every termset.Mask // every set in Sets, once computed
}

// Counts is what a scan scanned: tree files, index entries with a blob and
// each path a commit adds or changes; commits walked; and every line scanned,
// object lines included (HSH-11/D18).
type Counts struct{ Files, Commits, Lines int }

// Loc is the kind of place a finding is in.
type Loc uint8

// The places a finding can be in.
const (
	InTree   Loc = iota + 1 // a file of a tree scan: Path
	InIndex                 // an index entry: Path
	InStdin                 // standard input or a caller's buffer: Label
	InCommit                // a commit object: Commit and Part
	InDiff                  // a path a commit adds or changes: Commit and Path
)

// Finding is one finding as a target reports it, before redaction: where it
// is and which rule or set it broke. It never holds matched text.
type Finding struct {
	Loc    Loc
	Path   string    // the path as normalized, before redaction
	Label  string    // the stdin label
	Commit string    // the commit's full object id
	Part   rule.Part // the part of a commit object
	Line   int       // 1-based, or 0 for the path or the whole file
	Rule   string    // a rule's name, "set:NAME", "binary-unscanned" or "unreadable"
	InPath bool      // the path itself broke the rule
}

// ErrOutput stops a target at the first findings it cannot write. The caller
// prints nothing more: the interim has exited by then, its awk killed by
// SIGPIPE (HSH-5/D13).
var ErrOutput = errors.New("cannot write findings")

// flush writes the findings of one unit the interim scans with one awk run
// (a file, a commit object, a diff), so they print where the interim's do.
func (s *Scan) flush() error {
	if s.Sink != nil {
		return nil
	}
	if s.Out.Flush() != nil {
		return ErrOutput
	}
	return nil
}

// Stdin scans r as text under label.
func (s *Scan) Stdin(r io.Reader, label string) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return fail(StdinUnreadable, "cannot read standard input")
	}
	s.text(Finding{Loc: InStdin, Label: label}, data, rule.Context{Source: rule.Stdin})
	return s.flush()
}

// Buffer scans data as text under label, as ADR-001 section 5 scans standard
// input and buffers: data that holds a NUL byte is not scanned and gives
// binary-unscanned instead.
func (s *Scan) Buffer(data []byte, label string) {
	at := Finding{Loc: InStdin, Label: label}
	if bytes.IndexByte(data, 0) >= 0 {
		at.Rule = "binary-unscanned"
		s.report(at)
		return
	}
	s.text(at, data, rule.Context{Source: rule.Stdin})
}

// text scans each line of data, numbered from 1, in ctx.
func (s *Scan) text(at Finding, data []byte, ctx rule.Context) {
	for i, line := range lines(data) {
		s.emit(at, i+1, line, ctx)
	}
}

// emit reports the rules and sets one line breaks, at the place at. A line
// over MaxLine is not checked: it sets the scan's error, which the target
// returns.
func (s *Scan) emit(at Finding, ln int, line string, ctx rule.Context) {
	if s.MaxLine > 0 && len(line) > s.MaxLine {
		if s.failed == nil {
			s.failed = fail(TooLarge, "input over the size limit")
		}
		return
	}
	s.Counts.Lines++
	at.Line = ln
	for _, name := range s.check([]byte(line), ctx) {
		at.Rule = name
		s.report(at)
	}
}

// path reports the rules and sets at.Path breaks, at line 0, and then
// "unreadable" when the path cannot print safely.
func (s *Scan) path(at Finding) {
	at.Line, at.InPath = 0, true
	for _, name := range s.check([]byte(at.Path), pathContext(at.Path)) {
		at.Rule = name
		s.report(at)
	}
	if s.Unsafe != nil && s.Unsafe(at.Path) {
		at.Rule = "unreadable"
		s.report(at)
	}
}

// Err returns the error a line over MaxLine set, or nil. Buffer, which
// returns nothing, leaves it for its caller.
func (s *Scan) Err() error { return s.failed }

// unscanned reports that the file at at was not scanned, as rule
// "binary-unscanned" or "unreadable".
func (s *Scan) unscanned(at Finding, name string) {
	at.Line, at.Rule = 0, name
	s.report(at)
}

// report hands f to the sink or prints it as the interim scanner does.
func (s *Scan) report(f Finding) {
	if s.Sink != nil {
		s.Sink(f)
		return
	}
	name := f.Rule
	if f.InPath {
		name += " in path"
	}
	s.Out.Finding(s.where(f), f.Line, name)
}

// where is the interim scanner's location for f: the path redacted (and, in
// the index, escaped as git quotes it), the label, or the commit's first
// twelve characters.
func (s *Scan) where(f Finding) string {
	switch f.Loc {
	case InTree:
		return s.redact(f.Path)
	case InIndex:
		return escape(s.redact(f.Path))
	case InStdin:
		return f.Label
	case InCommit:
		return short(f.Commit) + ":(commit)"
	}
	return short(f.Commit) + ":" + s.redact(f.Path)
}

// short is an object id's first twelve characters.
func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// stopped reports whether Ctx is done.
func (s *Scan) stopped() bool { return s.Ctx != nil && s.Ctx.Err() != nil }

// check returns what line breaks in ctx: the rules in list order, then
// "set:NAME" for each set in file order.
func (s *Scan) check(line []byte, ctx rule.Context) []string {
	names := s.Rules.Check(line, ctx)
	if s.Sets != nil {
		apply := s.Apply
		if apply == nil {
			apply = s.all()
		}
		hit, _ := s.Sets.Match(line, apply)
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
		if _, at := s.Sets.Match([]byte(path), s.all()); at >= 0 && (start < 0 || at < start) {
			start = at
		}
	}
	return rule.Redact(path, start)
}

// all is the mask of every set in Sets, which redaction uses.
func (s *Scan) all() termset.Mask {
	if s.every == nil {
		s.every = s.Sets.All()
	}
	return s.every
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
