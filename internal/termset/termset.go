// Package termset parses a term file and matches its sets, as the interim
// scanner does: "[name]" starts a set, each other line is one term, and lines
// starting with "#" are comments. Terms are trimmed and matched as substrings,
// ignoring ASCII case. The package takes bytes, never a path.
package termset

import (
	"errors"
	"fmt"
	"strings"
)

// Set is one named term set. It is a rule for package rule: Name is the rule
// a match breaks and Index finds the earliest match.
type Set struct {
	name  string
	terms []string // ASCII lower case
}

// Name returns "set:" and the set's name.
func (s *Set) Name() string { return "set:" + s.name }

// Index returns the byte offset of the earliest term occurrence in text, or
// -1. Term sets have no reference/ exception, so the second argument is unused.
func (s *Set) Index(text string, _ bool) int {
	lc, first := Lower(text), -1
	for _, t := range s.terms {
		if i := strings.Index(lc, t); i >= 0 && (first < 0 || i < first) {
			first = i
		}
	}
	return first
}

// Format prints only the rule name, so formatting a Set never prints a term.
func (s *Set) Format(f fmt.State, _ rune) { fmt.Fprint(f, s.Name()) }

// Parse reads a term file. Sets come back in the order their names first
// appear; a name given twice adds to the earlier set. Errors give the line
// number only.
func Parse(data []byte) ([]*Set, error) {
	var sets []*Set
	var cur *Set
	byName := map[string]*Set{}
	nterms := 0
	for i, line := range lines(data) {
		line = strings.Trim(line, " \t\r")
		switch {
		case line == "" || line[0] == '#':
		case len(line) >= 2 && line[0] == '[' && line[len(line)-1] == ']':
			name := line[1 : len(line)-1]
			if !validName(name) {
				return nil, fmt.Errorf("term file: bad set name at line %d", i+1)
			}
			if cur = byName[name]; cur == nil {
				cur = &Set{name: name}
				byName[name] = cur
				sets = append(sets, cur)
			}
		case cur == nil:
			return nil, fmt.Errorf("term file: term outside a [set] section at line %d", i+1)
		default:
			cur.terms = append(cur.terms, Lower(line))
			nterms++
		}
	}
	if nterms == 0 {
		return nil, errors.New("term file holds no terms")
	}
	return sets, nil
}

// validName reports whether name matches ^[A-Za-z0-9_.-]+$.
func validName(name string) bool {
	for _, c := range []byte(name) {
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.IndexByte("_.-", c) >= 0) {
			return false
		}
	}
	return name != ""
}

// Lower returns s with ASCII capitals in lower case and every other byte
// unchanged, as awk's tolower does under LC_ALL=C.
func Lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// lines splits data into awk records: lines ending in "\n", plus a last line
// without one. Empty data has no lines.
func lines(data []byte) []string {
	s := string(data)
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}
