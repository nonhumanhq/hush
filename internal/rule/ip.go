package rule

import (
	"bytes"
	"net/netip"
	"regexp"
	"strings"
)

// IPAddress is the ip-address rule (ADR-002 section 4.2): it flags an IPv4 or
// IPv6 address unless it is in a documentation range or is loopback or
// unspecified. Its candidates follow the ADR's rules, and net/netip's
// ParseAddr decides what is an address.
type IPAddress struct{}

// Name returns "ip-address".
func (IPAddress) Name() string { return "ip-address" }

// Index returns the offset of the earliest flagged address in s, or -1. It
// calls Check with the zero Context; inRef plays no part.
func (r IPAddress) Index(s string, inRef bool) int {
	if start, broken := r.Check([]byte(s), Context{}); broken {
		return start
	}
	return -1
}

// Check reports whether line holds an address the rule flags and, if it does,
// the offset where the earliest one begins. The context plays no part. It
// keeps no reference to line.
func (IPAddress) Check(line []byte, ctx Context) (start int, broken bool) {
	start = -1
	if bytes.Count(line, []byte{'.'}) >= 3 { // an IPv4 candidate has three dots
		start = ipv4(line)
	}
	if bytes.Count(line, []byte{':'}) >= 2 { // an IPv6 candidate has two colons
		if s := ipv6(line); s >= 0 && (start < 0 || s < start) {
			start = s
		}
	}
	return start, start >= 0
}

// The documentation ranges of RFC 5737 and RFC 3849 (decided item 5).
var documentation = []netip.Prefix{
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("2001:db8::/32"),
}

// outsideAllowlist reports whether the rule flags a: the allowlist is the
// documentation ranges and every loopback or unspecified address. Callers
// unmap an IPv4-mapped address first, so it lies in the IPv4 prefixes.
func outsideAllowlist(a netip.Addr) bool {
	for _, p := range documentation {
		if p.Contains(a) {
			return false
		}
	}
	return !a.IsLoopback() && !a.IsUnspecified()
}

func isDigit(b byte) bool  { return '0' <= b && b <= '9' }
func isLetter(b byte) bool { return 'a' <= b && b <= 'z' || 'A' <= b && b <= 'Z' }
func isAlnum(b byte) bool  { return isDigit(b) || isLetter(b) }

// ipv4Candidate is step 1 of the IPv4 candidates.
var ipv4Candidate = regexp.MustCompile(`[0-9]{1,3}(?:\.[0-9]{1,3}){3}`)

// ipv4 returns the offset of the earliest flagged IPv4 address in line, or -1.
func ipv4(line []byte) int {
	for _, m := range ipv4Candidate.FindAllIndex(line, -1) {
		s, e := m[0], m[1]
		// Step 2: what comes before. A letter or digit, or a dot with a digit
		// straight before it, means the candidate continues a longer token.
		if s > 0 && (isAlnum(line[s-1]) || line[s-1] == '.' && s > 1 && isDigit(line[s-2])) {
			continue
		}
		// Step 2: what comes after. The candidate ends the token, or a port follows.
		if !endsToken(line, e) && !portFollows(line, e) {
			continue
		}
		// Steps 3 and 4: a group above 255 is no address; a leading zero is flagged.
		over, zero := false, false
		for _, g := range bytes.Split(line[s:e], []byte{'.'}) {
			over = over || len(g) == 3 && string(g) > "255"
			zero = zero || len(g) > 1 && g[0] == '0'
		}
		if over {
			continue
		}
		if zero {
			return s
		}
		// Step 5.
		if a, err := netip.ParseAddr(string(line[s:e])); err == nil && outsideAllowlist(a) {
			return s
		}
	}
	return -1
}

// endsToken reports whether the position i ends a token: the byte there is not
// an ASCII letter or digit, nor a dot followed by a digit. The end of the line
// ends it.
func endsToken(line []byte, i int) bool {
	switch {
	case i >= len(line):
		return true
	case isAlnum(line[i]):
		return false
	case line[i] == '.':
		return i+1 >= len(line) || !isDigit(line[i+1])
	}
	return true
}

// portFollows reports whether a dot and 1 to 5 digits that end the token start
// at i, the way tcpdump and BSD netstat write an address and its port.
func portFollows(line []byte, i int) bool {
	if i >= len(line) || line[i] != '.' {
		return false
	}
	j := i + 1
	for j < len(line) && isDigit(line[j]) {
		j++
	}
	return j-i-1 >= 1 && j-i-1 <= 5 && endsToken(line, j)
}

func isRunByte(b byte) bool {
	return isDigit(b) || 'a' <= b && b <= 'f' || 'A' <= b && b <= 'F' || b == ':' || b == '.'
}

// ipv6 returns the offset of the earliest flagged IPv6 address in line, or -1.
// Each maximal run of [0-9A-Fa-f:.] is one candidate (step 1).
func ipv6(line []byte) int {
	for i := 0; i < len(line); {
		if !isRunByte(line[i]) {
			i++
			continue
		}
		j := i
		for j < len(line) && isRunByte(line[j]) {
			j++
		}
		if s := ipv6Run(line, i, j); s >= 0 {
			return s
		}
		i = j
	}
	return -1
}

// ipv6Run applies steps 2 to 5 to the run line[s:e]. It returns where the
// address begins if it is flagged, or -1.
func ipv6Run(line []byte, s, e int) int {
	// Step 2: first every dot at either end; then, on what is left, one colon
	// at the start unless it starts with "::", and one at the end unless it
	// ends with "::".
	for s < e && line[s] == '.' {
		s++
	}
	for e > s && line[e-1] == '.' {
		e--
	}
	startsDouble := e-s >= 2 && line[s] == ':' && line[s+1] == ':'
	endsDouble := e-s >= 2 && line[e-1] == ':' && line[e-2] == ':'
	if e > s && line[s] == ':' && !startsDouble {
		s++
	}
	if e > s && line[e-1] == ':' && !endsDouble {
		e--
	}
	// Step 3, and its one retry for a key before the address: a run takes in
	// the end of a word joined to it by a colon, as "6:" in "ip6:". When a
	// letter or "_" stands before what remains and its first colon is a single
	// colon, the text after that colon is checked once more.
	if !keepIPv6(line, s, e) {
		if s == 0 || !(isLetter(line[s-1]) || line[s-1] == '_') {
			return -1
		}
		c := bytes.IndexByte(line[s:e], ':')
		if c < 0 || s+c+1 < e && line[s+c+1] == ':' {
			return -1
		}
		if s += c + 1; !keepIPv6(line, s, e) {
			return -1
		}
	}
	// Step 4: ParseAddr must accept it. If it does not, a ".PORT" or ":PORT"
	// suffix of 1 to 5 decimal digits is dropped once, and what is left must
	// again qualify and parse.
	cand := string(line[s:e])
	a, err := netip.ParseAddr(cand)
	if err != nil {
		i := strings.LastIndexAny(cand, ".:")
		if i < 0 || !port(cand[i+1:]) || !shaped([]byte(cand[:i])) {
			return -1
		}
		if a, err = netip.ParseAddr(cand[:i]); err != nil {
			return -1
		}
	}
	// Step 5: an IPv4-mapped address, in any written form, is checked as IPv4.
	if a.Is4In6() {
		a = a.Unmap()
	}
	if outsideAllowlist(a) {
		return s
	}
	return -1
}

// shaped reports whether b holds at least two colons and one decimal digit.
func shaped(b []byte) bool {
	digit := false
	for _, c := range b {
		digit = digit || isDigit(c)
	}
	return digit && bytes.Count(b, []byte{':'}) >= 2
}

// port reports whether s is 1 to 5 decimal digits.
func port(s string) bool {
	if len(s) < 1 || len(s) > 5 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return true
}

// keepIPv6 is step 3's two conditions on line[s:e]: it holds at least two
// colons and a decimal digit, and the bytes just outside it are not ASCII
// letters, digits or "_". Here an underscore does stop a match, because code
// such as Rust's "x86_64::" module path would otherwise parse as an address.
func keepIPv6(line []byte, s, e int) bool {
	if !shaped(line[s:e]) {
		return false
	}
	if s > 0 && (isAlnum(line[s-1]) || line[s-1] == '_') {
		return false
	}
	return e >= len(line) || !(isAlnum(line[e]) || line[e] == '_')
}
