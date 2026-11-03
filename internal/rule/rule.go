// Package rule holds the generic rules, the interface they implement, their
// registry, and the checks and path redaction a list of rules gives. Term sets
// are not rules: package termset matches them (HSH-11/D2).
package rule

import (
	"bytes"
	"regexp"
	"strings"
)

// Rule is one generic rule (ADR-002 section 5.1). A Rule is immutable and safe
// for concurrent use.
type Rule interface {
	// Name is the stable name printed in findings, such as "id-prefix".
	Name() string
	// Check reports whether line breaks the rule and, if it does, the byte
	// offset in line where the earliest breaking match begins. It keeps no
	// reference to line.
	Check(line []byte, ctx Context) (start int, broken bool)
}

// List is the rules a scan applies, in the order findings print them.
type List []Rule

// Check returns the names of the rules line breaks, in list order.
func (l List) Check(line []byte, ctx Context) []string {
	var names []string
	for _, r := range l {
		if _, broken := r.Check(line, ctx); broken {
			names = append(names, r.Name())
		}
	}
	return names
}

// Start returns the byte offset in line where the earliest match of any rule
// in the list begins, or -1.
func (l List) Start(line []byte, ctx Context) int {
	first := -1
	for _, r := range l {
		if i, broken := r.Check(line, ctx); broken && (first < 0 || i < first) {
			first = i
		}
	}
	return first
}

// Redact returns path with everything from the component where start lies
// replaced by "<redacted>", so a finding never prints any part of what it
// found, even a term that spans a "/". A negative start leaves path as it is.
func Redact(path string, start int) string {
	if start < 0 {
		return path
	}
	if k := strings.LastIndexByte(path[:start], '/'); k >= 0 {
		return path[:k] + "/<redacted>"
	}
	return "<redacted>"
}

// IDPrefix is the id-prefix rule (ADR-002 section 4.1): a token shaped
// [A-Z][0-9A-Z_]*-[0-9]+ whose prefix, the text before the hyphen, is not
// allowed.
type IDPrefix struct{}

var (
	idToken = regexp.MustCompile(`[A-Z][0-9A-Z_]*-[0-9]+`)
	allowed = map[string]bool{"HSH": true, "CHS": true, "FLT": true, "SWE": true, "ADR": true}
	// refAllowed holds the reference pack's own prefixes, allowed in a file's
	// lines and paths under reference/ only.
	refAllowed = map[string]bool{"FLEET": true, "VMWS": true}
)

// Name returns "id-prefix".
func (IDPrefix) Name() string { return "id-prefix" }

// Check reports whether line holds a token whose prefix is not allowed and,
// if so, the offset of the first one. Tokens are found left to right without
// overlaps. FLEET and VMWS pass when ctx is a file's line or a path (Source
// File or Path) and ctx.Path starts with "reference/".
func (IDPrefix) Check(line []byte, ctx Context) (start int, broken bool) {
	inRef := (ctx.Source == File || ctx.Source == Path) && strings.HasPrefix(ctx.Path, "reference/")
	for _, m := range idToken.FindAllIndex(line, -1) {
		tok := line[m[0]:m[1]]
		pre := string(tok[:bytes.IndexByte(tok, '-')])
		if !allowed[pre] && !(inRef && refAllowed[pre]) {
			return m[0], true
		}
	}
	return -1, false
}
