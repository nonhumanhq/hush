package termset

import (
	"bytes"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Parse reads a format 1 term file (ADR-002 section 1.1). Its errors are
// *ParseError, and the first error in file order is the one returned, in the
// order section 1.5 gives.
func Parse(b []byte) (*Sets, error) {
	if bytes.HasPrefix(b, []byte("\xef\xbb\xbf")) {
		return nil, &ParseError{1, TermOutsideSet} // a byte-order mark, whatever follows it
	}
	p := &parser{byName: map[string]bool{}}
	for i, line := range splitLines(b) {
		if err := p.line(i+1, bytes.Trim(line, " \t\r")); err != nil {
			return nil, err
		}
	}
	if err := p.endSet(); err != nil {
		return nil, err
	}
	if len(p.sets) == 0 {
		return nil, &ParseError{0, NoTerms}
	}
	return &Sets{sets: p.sets}, nil
}

type parser struct {
	sets   []set
	byName map[string]bool
}

// line reads one trimmed line, numbered n.
func (p *parser) line(n int, l []byte) error {
	// A set's emptiness is known at the next line that is a whole header,
	// before that line's own checks.
	if isHeader(l) {
		if err := p.endSet(); err != nil {
			return err
		}
	}
	if !goodChars(l) {
		return &ParseError{n, BadCharacter}
	}
	switch {
	case len(l) == 0:
		return nil
	case n == 1 && bytes.HasPrefix(l, []byte("#hush-terms")):
		if string(l) != "#hush-terms 1" {
			return &ParseError{1, UnsupportedFormat}
		}
		return nil
	case l[0] == '#':
		return nil
	case l[0] == '[' || l[len(l)-1] == ']':
		return p.header(n, l)
	case len(p.sets) == 0:
		return &ParseError{n, TermOutsideSet}
	case !goodTerm(l):
		return &ParseError{n, BadTerm}
	}
	cur := &p.sets[len(p.sets)-1]
	cur.raw = append(cur.raw, bytes.Clone(l))
	norm, _ := cur.normalizer().Normalize(nil, nil, l)
	cur.norm = append(cur.norm, norm)
	return nil
}

// endSet refuses the last set read if it holds no terms.
func (p *parser) endSet() error {
	if k := len(p.sets); k > 0 && len(p.sets[k-1].raw) == 0 {
		return &ParseError{p.sets[k-1].line, EmptySet}
	}
	return nil
}

// isHeader reports whether a trimmed line both starts with "[" and ends with
// "]".
func isHeader(l []byte) bool { return len(l) >= 2 && l[0] == '[' && l[len(l)-1] == ']' }

// header reads a header line, in section 1.5's order.
func (p *parser) header(n int, l []byte) error {
	if !isHeader(l) {
		return &ParseError{n, BadHeader}
	}
	inner := string(l[1 : len(l)-1])
	end := strings.IndexAny(inner, " \t]")
	if end < 0 {
		end = len(inner)
	}
	s := set{name: inner[:end], line: n}
	if !validName(s.name) {
		return &ParseError{n, BadSetName}
	}
	visible, ok := s.attributes(inner[end:])
	if !ok {
		return &ParseError{n, BadAttribute}
	}
	for _, v := range visible {
		if !ClientLabel(v) {
			return &ParseError{n, BadClientLabel}
		}
	}
	s.labels = visible
	if p.byName[s.name] {
		return &ParseError{n, SetDeclaredTwice}
	}
	p.byName[s.name] = true
	p.sets = append(p.sets, s)
	return nil
}

// attributes reads rest as *( 1*WSP attribute ), sets the set's case and match
// options, and returns the visible-to values. It reports false for a malformed
// attribute, an unknown key or value, or a repeated key or value.
func (s *set) attributes(rest string) (visible []string, ok bool) {
	seen := map[string]bool{}
	for rest != "" {
		trimmed := strings.TrimLeft(rest, " \t")
		if trimmed == rest || trimmed == "" {
			return nil, false // an attribute needs whitespace before it, and must follow it
		}
		rest = trimmed
		end := strings.IndexAny(rest, " \t")
		if end < 0 {
			end = len(rest)
		}
		key, vals, found := strings.Cut(rest[:end], "=")
		rest = rest[end:]
		if !found || seen[key] {
			return nil, false
		}
		seen[key] = true
		values := strings.Split(vals, ",")
		for i, v := range values {
			if !validValue(v) || contains(values[:i], v) {
				return nil, false
			}
		}
		switch {
		case key == "visible-to":
			visible = values
		case key == "case" && len(values) == 1 && (values[0] == "ignore" || values[0] == "exact"):
			s.exact = values[0] == "exact"
		case key == "match" && len(values) == 1 && (values[0] == "substring" || values[0] == "word"):
			s.word = values[0] == "word"
		default:
			return nil, false
		}
	}
	return visible, true
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func isAlnum(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9'
}

// validName reports whether name matches 1*64( ALPHA / DIGIT / "_" / "." / "-" ).
func validName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for i := 0; i < len(name); i++ {
		if c := name[i]; !isAlnum(c) && c != '_' && c != '.' && c != '-' {
			return false
		}
	}
	return true
}

// validValue reports whether v matches 1*( ALPHA / DIGIT / "_" / "-" ).
func validValue(v string) bool {
	if v == "" {
		return false
	}
	for i := 0; i < len(v); i++ {
		if c := v[i]; !isAlnum(c) && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// ClientLabel reports whether v is a client label in ADR-001's grammar: 1 to
// 32 characters from [a-z0-9_-], starting with a letter or digit, and neither
// "public" nor "private".
func ClientLabel(v string) bool {
	if v == "" || len(v) > 32 || v == "public" || v == "private" || v[0] == '_' || v[0] == '-' {
		return false
	}
	for i := 0; i < len(v); i++ {
		if c := v[i]; !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// goodChars reports whether l is valid UTF8 without a control character other
// than tab (C0, DEL, C1) and without U+2028 or U+2029.
func goodChars(l []byte) bool {
	for i := 0; i < len(l); {
		r, size := utf8.DecodeRune(l[i:])
		if r == utf8.RuneError && size == 1 ||
			r < 0x20 && r != '\t' || 0x7f <= r && r <= 0x9f || r == 0x2028 || r == 0x2029 {
			return false
		}
		i += size
	}
	return true
}

// goodTerm reports whether a term holds none of the characters section 1.1
// refuses in terms: a Unicode White_Space character other than space and tab,
// a format character other than the zero-width joiner and non-joiner and the
// prepended concatenation marks, or a space or tab followed by "#".
func goodTerm(l []byte) bool {
	for _, r := range string(l) {
		switch {
		case r == ' ' || r == '\t':
		case unicode.IsSpace(r):
			return false
		case r == 0x200c || r == 0x200d || unicode.Is(unicode.Prepended_Concatenation_Mark, r):
		case unicode.Is(unicode.Cf, r):
			return false
		}
	}
	return !bytes.Contains(l, []byte(" #")) && !bytes.Contains(l, []byte("\t#"))
}

// splitLines splits b into lines ending at LF, plus a last line without one.
// Empty input has no lines.
func splitLines(b []byte) [][]byte {
	if len(b) == 0 {
		return nil
	}
	return bytes.Split(bytes.TrimSuffix(b, []byte("\n")), []byte("\n"))
}
