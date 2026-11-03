package hush

import (
	"strings"
	"unicode"
)

// RefSelector names a namespace of refs a range includes or excludes.
type RefSelector uint8

// The ref selectors of ADR-001 section 5. The zero value is not one.
const (
	AllRefs  RefSelector = iota + 1 // --all
	Branches                        // --branches
	Tags                            // --tags
	Remotes                         // --remotes
)

var selectorWords = [...]string{AllRefs: "--all", Branches: "--branches", Tags: "--tags", Remotes: "--remotes"}

// String returns the selector as the range text writes it, such as "--all",
// or "" for a value that is not a selector.
func (r RefSelector) String() string {
	if r == 0 || int(r) >= len(selectorWords) {
		return ""
	}
	return selectorWords[r]
}

// Range is the commits a range scan walks: those reachable from Include and
// IncludeRefs and not from Exclude and ExcludeRefs.
type Range struct {
	// Include holds revisions to walk: a name, an object id, or "A..B".
	Include []string
	// IncludeRefs holds ref selectors to walk.
	IncludeRefs []RefSelector
	// Exclude holds revisions to subtract, as "^REV" or after "--not" writes
	// them, without the "^".
	Exclude []string
	// ExcludeRefs holds ref selectors to subtract, as after "--not".
	ExcludeRefs []RefSelector
	// AllowEmpty accepts a range with no commits; otherwise it is
	// ErrEmptyRange.
	AllowEmpty bool
}

// ParseRange reads the command line's --range text: words separated by
// spaces, tabs or newlines, each a revision, "A..B", "^REV", "--not", or one
// of the selectors "--all", "--branches", "--tags" and "--remotes". Words
// after "--not" are subtracted; "--not" may appear once, and is followed by
// plain revisions and selectors only. A revision is not empty, does not start
// with "-" or "^", and holds no whitespace, NUL, "..", "^!", "^@" or "^-", so
// no rev-list option or revision suffix can narrow the range. At least one revision or selector must be included.
// The error is ErrRange, naming a word by its 1-based position, never its
// text.
func ParseRange(text string) (rg Range, err error) {
	defer recoverError(&err, func() { rg = Range{} })
	words := strings.FieldsFunc(text, func(r rune) bool { return r == ' ' || r == '\t' || r == '\n' })
	not := false
	for i, w := range words {
		n := i + 1
		sel := selector(w)
		switch {
		case w == "--not" && !not:
			not = true
		case sel != 0 && not:
			rg.ExcludeRefs = append(rg.ExcludeRefs, sel)
		case sel != 0:
			rg.IncludeRefs = append(rg.IncludeRefs, sel)
		case not && goodRevision(w):
			rg.Exclude = append(rg.Exclude, w)
		case not:
			return Range{}, newError(CodeRange, msgRangeWord, n)
		case strings.HasPrefix(w, "^") && goodRevision(w[1:]):
			rg.Exclude = append(rg.Exclude, w[1:])
		case goodRevision(w) || goodDots(w):
			rg.Include = append(rg.Include, w)
		default:
			return Range{}, newError(CodeRange, msgRangeWord, n)
		}
	}
	if len(rg.Include)+len(rg.IncludeRefs) == 0 {
		return Range{}, newError(CodeRange, msgRangeNothing, 0)
	}
	return rg, nil
}

func selector(w string) RefSelector {
	for i, s := range selectorWords {
		if s != "" && s == w {
			return RefSelector(i)
		}
	}
	return 0
}

// goodRevision reports whether w may be handed to git as one revision: not
// empty, not starting with "-" or "^", and holding no whitespace (any that
// unicode.IsSpace reports, as ADR-001 section 5 refuses), NUL, "..", or any
// of the suffixes "^!", "^@" and "^-", which make one word of rev-list's
// several: "R^!" is R without its parents, "R^@" R's parents without R, and
// "R^-" or "R^-N" "R^N..R", each a subtraction a plain revision must not
// hold (HSH-11/D36).
func goodRevision(w string) bool {
	return w != "" && w[0] != '-' && w[0] != '^' && !strings.Contains(w, "..") &&
		!strings.Contains(w, "^!") && !strings.Contains(w, "^@") && !strings.Contains(w, "^-") &&
		strings.IndexByte(w, 0) < 0 && strings.IndexFunc(w, unicode.IsSpace) < 0
}

// goodDots reports whether w is "A..B" with A and B good revisions; "A...B"
// is not.
func goodDots(w string) bool {
	a, b, ok := strings.Cut(w, "..")
	return ok && goodRevision(a) && goodRevision(b) && b[0] != '.'
}

// revListArgs checks rg as ParseRange would and returns rev-list's arguments
// for it: the included revisions and selectors, then "--not" and the excluded
// ones, then "--". The "--" makes git read every word as a revision: without
// it, a word that names no revision but names a file, or is a pathspec such
// as "*.md" or ":!a.md", narrows the walk to the commits that touch those
// paths. With it, such a word is a bad revision, ErrRange (HSH-11/D36).
func (rg Range) revListArgs() ([]string, error) {
	var args []string
	n := 0
	for _, w := range rg.Include {
		n++
		if !goodRevision(w) && !goodDots(w) {
			return nil, newError(CodeRange, msgRangeRevision, n)
		}
		args = append(args, w)
	}
	for i, sel := range rg.IncludeRefs {
		if sel.String() == "" {
			return nil, newError(CodeRange, msgRangeSelector, i+1)
		}
		args = append(args, sel.String())
	}
	if len(args) == 0 {
		return nil, newError(CodeRange, msgRangeNothing, 0)
	}
	if len(rg.Exclude)+len(rg.ExcludeRefs) == 0 {
		return append(args, "--"), nil
	}
	args = append(args, "--not")
	for _, w := range rg.Exclude {
		n++
		if !goodRevision(w) {
			return nil, newError(CodeRange, msgRangeRevision, n)
		}
		args = append(args, w)
	}
	for i, sel := range rg.ExcludeRefs {
		if sel.String() == "" {
			return nil, newError(CodeRange, msgRangeSelector, len(rg.IncludeRefs)+i+1)
		}
		args = append(args, sel.String())
	}
	return append(args, "--"), nil
}
