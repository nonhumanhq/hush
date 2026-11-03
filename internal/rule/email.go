package rule

import (
	"bytes"
	"regexp"
	"strings"
)

// EmailAddress is the email-address rule (ADR-002 section 4.3): it flags an
// email address unless its domain is reserved by RFC 2606, or the address is
// one the caller lists and it stands in an identity position. The zero value
// has no allowance. An EmailAddress never changes after NewEmailAddress.
type EmailAddress struct {
	ids map[string]struct{} // the allowance, with ASCII letters lowered
}

// NewEmailAddress returns the rule with the identity allowance ids: addresses
// the caller has already checked against section 5.4's form, or nil for none.
// They compare with ASCII letters lowered. The list is copied.
func NewEmailAddress(ids []string) EmailAddress {
	e := EmailAddress{}
	if len(ids) > 0 {
		e.ids = make(map[string]struct{}, len(ids))
		for _, id := range ids {
			e.ids[lowerASCII(id)] = struct{}{}
		}
	}
	return e
}

// Name returns "email-address".
func (EmailAddress) Name() string { return "email-address" }

var (
	// bareAddress is the bare candidate pattern of section 4.3. [^\x00-\x7f]
	// is any non-ASCII character; [\x80-\xff] would mean the runes U+0080 to
	// U+00FF in Go.
	bareAddress = regexp.MustCompile(`(?:(?:[A-Za-z0-9!#$%&'*+=?^_{|}~.-]|[^\x00-\x7f])+|"[^"\s]*")\\?@(?:[\p{L}\p{M}\p{N}-]+\.)+\p{L}[\p{L}\p{M}\p{N}-]*[\p{L}\p{M}\p{N}]`)
	// bracketedAddress is the bracketed candidate pattern; the address is the
	// text between the brackets.
	bracketedAddress = regexp.MustCompile(`<([^<>\s@]+@[^<>\s]+)>`)
	// identityTrailer is an identity trailer line, such as "Signed-off-by: ...".
	identityTrailer = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*-by: `)
)

// Check reports whether line holds an address the rule flags and, if it does,
// the offset where the earliest one begins. A listed address passes, ignoring
// ASCII case, when ctx is an identity position (decided item 6): the author,
// committer or tagger header of an object, or an identity trailer in an
// object's message or on standard input. Every other address passes only on
// its domain. It keeps no reference to line.
func (e EmailAddress) Check(line []byte, ctx Context) (start int, broken bool) {
	if bytes.IndexByte(line, '@') < 0 { // every candidate holds an @
		return -1, false
	}
	allowed := len(e.ids) > 0 && identityPosition(line, ctx)
	start = -1
	for _, m := range bareAddress.FindAllIndex(line, -1) {
		// The bare pattern's matches do not overlap, so in "A@B@C" or
		// "A@B\@C" the "@C" is never a candidate: a listed "A@B" passes
		// only when no "@" or "\@" follows it (HSH-11/D16).
		if e.flags(line[m[0]:m[1]], allowed && !chained(line[m[1]:])) {
			start = m[0]
			break
		}
	}
	for _, m := range bracketedAddress.FindAllSubmatchIndex(line, -1) {
		if e.flags(line[m[2]:m[3]], allowed) {
			if start < 0 || m[0] < start {
				start = m[0] // the "<", where the pattern's match begins
			}
			break
		}
	}
	return start, start >= 0
}

// chained reports whether rest, the text after a bare candidate, begins with
// "@" or "\@", so that the candidate is only the start of a longer address.
func chained(rest []byte) bool {
	return bytes.HasPrefix(rest, []byte("@")) || bytes.HasPrefix(rest, []byte(`\@`))
}

// flags reports whether the rule flags the candidate addr. allowed says an
// identity position lets a listed address pass.
func (e EmailAddress) flags(addr []byte, allowed bool) bool {
	if reservedDomain(domainOf(addr)) {
		return false
	}
	if allowed {
		_, listed := e.ids[lowerASCII(string(addr))]
		return !listed
	}
	return true
}

// identityPosition reports whether a line in ctx is one where a listed address
// may pass: an identity header of a commit or tag object, or an identity
// trailer in its message or on standard input. A line of a file, a path, a
// bare string and any other line of an object are not.
func identityPosition(line []byte, ctx Context) bool {
	switch ctx.Source {
	case Object:
		switch ctx.Part {
		case Author, Committer, Tagger:
			return true
		case Message:
			return identityTrailer.Match(line)
		}
	case Stdin:
		return identityTrailer.Match(line)
	}
	return false
}

// domainOf returns the text after the last "@" of addr, ended at the first
// "/", ":", "?" or "#" after it. A bare candidate holds none of those four in
// its domain, so the cut only shortens a bracketed one.
func domainOf(addr []byte) []byte {
	d := addr[bytes.LastIndexByte(addr, '@')+1:]
	if i := bytes.IndexAny(d, "/:?#"); i >= 0 {
		d = d[:i]
	}
	return d
}

// reservedDomain reports whether d is a domain RFC 2606 reserves: example.com,
// example.net or example.org or a subdomain of one, or a name whose last label
// is example, test, invalid or localhost. A domain with any non-ASCII
// character never passes. ASCII letters compare lowered.
func reservedDomain(d []byte) bool {
	for _, c := range d {
		if c >= 0x80 {
			return false
		}
	}
	name := lowerASCII(string(d))
	for _, r := range []string{"example.com", "example.net", "example.org"} {
		if name == r || strings.HasSuffix(name, "."+r) {
			return true
		}
	}
	switch name[strings.LastIndexByte(name, '.')+1:] {
	case "example", "test", "invalid", "localhost":
		return true
	}
	return false
}

// lowerASCII lowers the bytes A to Z and nothing else, so offsets and
// non-ASCII text stay as they are. strings.ToLower folds more.
func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
