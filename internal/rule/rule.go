// Package rule holds the generic rules, the interface every rule implements
// (term sets included), and the checks and path redaction a list of rules
// gives.
package rule

import (
	"regexp"
	"strings"
)

// Rule is one check a scanned string can break.
type Rule interface {
	// Name is what a finding prints: "id-prefix" or "set:NAME".
	Name() string
	// Index returns the byte offset in s where the rule's first match begins,
	// or -1. inRef is true for content and paths under reference/.
	Index(s string, inRef bool) int
}

// List is the rules a scan applies, in the order findings print them.
type List []Rule

// Check returns the names of the rules s breaks, in list order.
func (l List) Check(s string, inRef bool) []string {
	var names []string
	for _, r := range l {
		if r.Index(s, inRef) >= 0 {
			names = append(names, r.Name())
		}
	}
	return names
}

// Redact returns path with everything from the component where the earliest
// match of any rule begins replaced by "<redacted>", so a finding never prints
// any part of what it found, even a term that spans a "/".
func (l List) Redact(path string, inRef bool) string {
	first := -1
	for _, r := range l {
		if i := r.Index(path, inRef); i >= 0 && (first < 0 || i < first) {
			first = i
		}
	}
	if first < 0 {
		return path
	}
	if k := strings.LastIndexByte(path[:first], '/'); k >= 0 {
		return path[:k] + "/<redacted>"
	}
	return "<redacted>"
}

// InRef reports whether path lies under reference/, where the reference pack's
// own prefixes are allowed.
func InRef(path string) bool { return strings.HasPrefix(path, "reference/") }

// IDPrefix is the ID-prefix rule: a token shaped [A-Z]+-[0-9]+ whose prefix
// is not allowed.
type IDPrefix struct{}

var (
	idToken    = regexp.MustCompile(`[A-Z]+-[0-9]+`)
	allowed    = map[string]bool{"HSH": true, "CHS": true, "FLT": true, "SWE": true, "ADR": true}
	refAllowed = map[string]bool{"FLEET": true, "VMWS": true}
)

// Name returns "id-prefix".
func (IDPrefix) Name() string { return "id-prefix" }

// Index returns the offset of the first rejected token, scanning tokens left
// to right as the interim's match loop does.
func (IDPrefix) Index(s string, inRef bool) int {
	for off := 0; ; {
		m := idToken.FindStringIndex(s[off:])
		if m == nil {
			return -1
		}
		tok := s[off+m[0] : off+m[1]]
		pre := tok[:strings.IndexByte(tok, '-')]
		if !allowed[pre] && !(inRef && refAllowed[pre]) {
			return off + m[0]
		}
		off += m[1]
	}
}
