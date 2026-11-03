package termset

import "bytes"

// Normalizer maps text to the form terms are compared in. Terms pass through
// the same normalizer at load (ADR-002 section 5.3).
type Normalizer interface {
	// Normalize appends the normalized src to dst and, for each byte appended,
	// the offset in src it came from, so a match maps back to the original
	// line. It never writes to src.
	Normalize(dst []byte, offs []int, src []byte) ([]byte, []int)
}

// ASCIILower lowers the bytes A to Z and keeps every other byte, one for one
// (ADR-002 section 2.2). It is the normalizer of a set with case=ignore.
type ASCIILower struct{}

// Normalize appends src with A to Z lowered.
func (ASCIILower) Normalize(dst []byte, offs []int, src []byte) ([]byte, []int) {
	for i, c := range src {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		dst, offs = append(dst, c), append(offs, i)
	}
	return dst, offs
}

// Exact keeps every byte. It is the normalizer of a set with case=exact.
type Exact struct{}

// Normalize appends src unchanged.
func (Exact) Normalize(dst []byte, offs []int, src []byte) ([]byte, []int) {
	for i := range src {
		offs = append(offs, i)
	}
	return append(dst, src...), offs
}

// Mask is a set of set indices, in file order.
type Mask []uint64

// All returns the mask of every set.
func (s *Sets) All() Mask {
	var m Mask
	for i := range s.sets {
		m.Add(i)
	}
	return m
}

// Add adds set i to the mask.
func (m *Mask) Add(i int) {
	for len(*m) <= i/64 {
		*m = append(*m, 0)
	}
	(*m)[i/64] |= 1 << (i % 64)
}

// Has reports whether set i is in the mask.
func (m Mask) Has(i int) bool { return i/64 < len(m) && m[i/64]&(1<<(i%64)) != 0 }

// normalized is a line passed through one normalizer, with its offsets.
type normalized struct {
	text []byte
	offs []int
}

// Match reports which sets in apply match line, as a mask, and the byte offset
// in line where the earliest match of any set in apply begins, or -1. It never
// says which term matched, and never writes to line.
func (s *Sets) Match(line []byte, apply Mask) (hit Mask, start int) {
	start = -1
	var lower, exact *normalized
	for i := range s.sets {
		if !apply.Has(i) {
			continue
		}
		st := &s.sets[i]
		n := &exact
		if !st.exact {
			n = &lower
		}
		if *n == nil {
			t, o := st.normalizer().Normalize(nil, nil, line)
			*n = &normalized{t, o}
		}
		if at := st.first(line, **n); at >= 0 {
			hit.Add(i)
			if start < 0 || at < start {
				start = at
			}
		}
	}
	return hit, start
}

// first returns the offset in line of the earliest occurrence of any of the
// set's terms that counts, or -1. With match=word, an occurrence counts only
// if the bytes just outside it in line are not ASCII letters.
func (st *set) first(line []byte, n normalized) int {
	first := -1
	for _, t := range st.norm {
		for from := 0; from+len(t) <= len(n.text); {
			k := bytes.Index(n.text[from:], t)
			if k < 0 {
				break
			}
			k += from
			s, e := n.offs[k], n.offs[k+len(t)-1]+1 // the occurrence in line
			if !st.word || (s == 0 || !isLetter(line[s-1])) && (e == len(line) || !isLetter(line[e])) {
				if first < 0 || s < first {
					first = s
				}
				break
			}
			from = k + 1
		}
	}
	return first
}

func isLetter(c byte) bool { return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }

// RefusesName reports whether the terms refuse a set name or client label:
// ADR-002 section 1.4's check 1, plain containment ignoring ASCII case, for
// every term of every set, whatever the set's case and match options.
func (s *Sets) RefusesName(name []byte) bool {
	n, _ := ASCIILower{}.Normalize(nil, nil, name)
	for i := range s.sets {
		for _, t := range s.sets[i].raw {
			lt, _ := ASCIILower{}.Normalize(nil, nil, t)
			if bytes.Contains(n, lt) {
				return true
			}
		}
	}
	return false
}

// CheckNames runs ADR-002 section 1.4's load-time checks on every set name and
// client label, in file order and, within a header, the name before its
// labels: check 1 (RefusesName), then check 2, breaks, which the caller
// supplies as the generic rules run on the name as written with Source Text.
// The error is a *ParseError naming the header's line.
func (s *Sets) CheckNames(breaks func(name []byte) bool) error {
	refused := func(v string) bool { return s.RefusesName([]byte(v)) || breaks([]byte(v)) }
	for _, st := range s.sets {
		if refused(st.name) {
			return &ParseError{st.line, SetNameRefused}
		}
		for _, l := range st.labels {
			if refused(l) {
				return &ParseError{st.line, ClientLabelRefused}
			}
		}
	}
	return nil
}
