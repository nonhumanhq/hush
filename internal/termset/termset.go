// Package termset parses a term file in ADR-002's format 1 and matches its
// sets. It takes bytes, never a path, and depends on no other package of hush:
// the caller runs the rules on set names and client labels (CheckNames).
package termset

import (
	"fmt"
	"log/slog"
	"strconv"
)

// Reason is why a term file was refused. Its text is fixed and holds nothing
// from the file (ADR-002 section 1.5).
type Reason uint8

// The reasons of ADR-002 section 1.5. Parse returns the ones up to NoTerms;
// CheckNames returns SetNameRefused and ClientLabelRefused.
const (
	TermOutsideSet Reason = iota + 1
	BadCharacter
	BadHeader
	BadSetName
	BadAttribute
	BadClientLabel
	SetDeclaredTwice
	BadTerm
	EmptySet
	UnsupportedFormat
	NoTerms
	SetNameRefused
	ClientLabelRefused
)

var reasons = [...]string{
	TermOutsideSet:     "term outside a set",
	BadCharacter:       "bad character",
	BadHeader:          "bad header",
	BadSetName:         "bad set name",
	BadAttribute:       "bad attribute",
	BadClientLabel:     "bad client label",
	SetDeclaredTwice:   "set declared twice",
	BadTerm:            "bad term",
	EmptySet:           "set has no terms",
	UnsupportedFormat:  "unsupported format",
	NoTerms:            "term file holds no terms",
	SetNameRefused:     "set name refused",
	ClientLabelRefused: "client label refused",
}

// String returns the reason's fixed text.
func (r Reason) String() string {
	if int(r) < len(reasons) && reasons[r] != "" {
		return reasons[r]
	}
	return "unknown reason"
}

// ParseError is a fixed reason and a line number. It holds no text from the
// file.
type ParseError struct {
	Line   int // 1-based; 0 when the reason concerns the whole file
	Reason Reason
}

// Error returns "term file: line N: REASON", or "term file holds no terms".
func (e *ParseError) Error() string {
	if e.Line == 0 {
		return e.Reason.String()
	}
	return "term file: line " + strconv.Itoa(e.Line) + ": " + e.Reason.String()
}

// set is one parsed set. Terms are kept as written in raw and, passed through
// the set's normalizer, in norm.
type set struct {
	name   string
	line   int
	labels []string
	exact  bool // case=exact
	word   bool // match=word
	raw    [][]byte
	norm   [][]byte
}

func (s *set) normalizer() Normalizer {
	if s.exact {
		return Exact{}
	}
	return ASCIILower{}
}

// Sets holds the parsed sets in file order. It is immutable and safe for
// concurrent use. It prints only a fixed summary (ADR-001 section 6.6).
type Sets struct {
	sets []set
}

// Len returns the number of sets.
func (s *Sets) Len() int { return len(s.sets) }

// Name returns set i's name, in file order.
func (s *Sets) Name(i int) string { return s.sets[i].name }

// Line returns the line of set i's header.
func (s *Sets) Line(i int) int { return s.sets[i].line }

// Labels returns a copy of set i's visible-to labels. They are never printed.
func (s *Sets) Labels(i int) []string { return append([]string(nil), s.sets[i].labels...) }

// summary is everything the formatting guards print.
const summary = "termset.Sets{...}"

// Format prints a fixed summary for every verb, so formatting Sets never
// prints a term, a set name or a label.
func (Sets) Format(f fmt.State, _ rune) { fmt.Fprint(f, summary) }

// GoString returns the fixed summary.
func (Sets) GoString() string { return summary }

// LogValue returns the fixed summary.
func (Sets) LogValue() slog.Value { return slog.StringValue(summary) }

// MarshalJSON returns the fixed summary as a JSON string.
func (Sets) MarshalJSON() ([]byte, error) { return []byte(strconv.Quote(summary)), nil }

// MarshalText returns the fixed summary.
func (Sets) MarshalText() ([]byte, error) { return []byte(summary), nil }

// GobEncode returns the fixed summary.
func (Sets) GobEncode() ([]byte, error) { return []byte(summary), nil }
