package rule

import (
	"slices"
	"strings"
	"testing"

	lc "github.com/nonhumanhq/hush/internal/leakcheck"
)

// ipPasses is the "Passes" table of ADR-002 section 4.2, every input of every
// row as the ADR writes it. A shape the rule must flag is assembled at run
// time, so this file scans clean under the rule.
var ipPasses = []string{
	// Documentation
	"192.0.2.10", "198.51.100.255", "203.0.113.0/24",
	// Documentation, in any form
	"[2001:db8::1]:443", "2001:DB8:0:0:0:0:0:1", "2001:0db8:0000:0000:0000:0000:0000:0001",
	// Mapped and embedded documentation addresses
	"::ffff:192.0.2.1", "2001:db8::192.0.2.1",
	// Mapped addresses written in hex are unmapped too: documentation, and unspecified
	"::ffff:c000:20a", "::ffff:" + "0:0",
	// Loopback and unspecified (decided item 5)
	"127.0." + "0.1:8080", "[:" + ":1]:8080", "0.0." + "0.0", ":" + ":1", "::ffff:127.0.0" + ".1",
	// Documentation, after a key
	"ip6:2001:db8::/32", "[IPv6:2001:db8::1]",
	// Documentation, with a port in tcpdump's form
	"192.0.2.10.443 > 198.51.100.7.53", "2001:db8::1.546",
	// Documentation, with a port after a colon and no brackets: eight groups, or seven and a ::
	"2001:db8:1:2:3:4:5:6:22", "2001:db8::3:4:5:6:7:443",
	// Documentation, inside a dotted hostname
	"app.192.0.2.7.example.com",
	// Every dot at the end is trimmed first, then a single colon only
	"see 2001:db8::1.", "see 2001:db8::.", "see 2001:db8::1...",
	// A letter touches it: a version
	"v1.2.3.4", "go1.2.3.4", "1.2.3.4rc1",
	// Six groups or more
	"1.2.3.4.5.6", "OID 1.3.6.1.4.1.99999",
	// Not an address
	"1.2.3", "300.1.2.3",
	// ParseAddr refuses it, or a letter touches it
	"12:30:45", "12:30:45.123", "2026-10-24T12:30:45Z", "00:1a:2b:3c:4d:5e",
	// No decimal digit
	"aa:bb:cc:dd:ee:ff",
	// No decimal digit, or a letter touches it
	"std::vector", "Foo::Bar", "E::A", "the :: operator", "Vec2::new", "u8::MAX", "sha256:0123abcd",
}

// registry judges a line as `hush scan` does before the term sets: a row in
// ADR-002's tables behaves as listed when it is alone on a line (negative
// test 3).
var registry = Registry(nil)

func names(line string) string { return strings.Join(registry.Check([]byte(line), Context{}), ",") }

// Each row of the Passes table, alone on a line, is flagged by no rule.
func TestIPAddressPasses(t *testing.T) {
	r := newReport(t)
	defer r.done()
	for i, line := range ipPasses {
		if got := names(line); got != "" {
			r.errorf("passes row %d is flagged by %s", i, got)
		}
		if _, broken := (IPAddress{}).Check([]byte(line), Context{}); broken {
			r.errorf("passes row %d is flagged by Check", i)
		}
	}
}

// Each row of the Flagged table, alone on a line, is flagged by ip-address
// and by no other rule, and the rule says where it begins.
func TestIPAddressFlagged(t *testing.T) {
	r := newReport(t)
	defer r.done()
	const lead = "see "
	for i, line := range lc.IPFlagged {
		if got := names(line); got != "ip-address" {
			r.errorf("flagged row %d gives %q, want ip-address", i, got)
			continue
		}
		start, broken := (IPAddress{}).Check([]byte(line), Context{})
		if !broken || start < 0 || start >= len(line) {
			r.errorf("flagged row %d: Check gives %d, %t", i, start, broken)
			continue
		}
		// The offset follows the text before it: a space is no boundary a
		// candidate needs.
		if again, _ := (IPAddress{}).Check([]byte(lead+line), Context{}); again != start+len(lead) {
			r.errorf("flagged row %d: offset %d after four bytes of text, want %d", i, again, start+len(lead))
		}
	}
}

// The context plays no part in the ip-address rule's verdict.
func TestIPAddressIgnoresTheContext(t *testing.T) {
	r := newReport(t)
	defer r.done()
	if got := (IPAddress{}).Name(); got != "ip-address" {
		r.errorf("Name is %q", got)
	}
	for i, line := range slices.Concat(ipPasses, lc.IPFlagged) {
		start, broken := (IPAddress{}).Check([]byte(line), Context{})
		want := -1
		if broken {
			want = start
		}
		if got, b := (IPAddress{}).Check([]byte(line), Context{Source: Path, Path: "reference/a"}); b != broken || got != want && b {
			r.errorf("row %d: a path context gives %d, want %d", i, got, want)
		}
		for _, ctx := range []Context{{Source: File, Path: "reference/a.md"}, {Source: Stdin}, {Source: Object, Part: Message}} {
			if s2, b2 := (IPAddress{}).Check([]byte(line), ctx); s2 != start || b2 != broken {
				r.errorf("row %d: the context changes the verdict", i)
			}
		}
	}
}

// Negative test 3's edges, and the first and last address of each range.
func TestIPAddressEdges(t *testing.T) {
	r := newReport(t)
	defer r.done()
	for _, line := range []string{
		"192.0.2.255", "192.0.2.0", "198.51.100.0", "198.51.100.255", "203.0.113.0", "203.0.113.255",
		"2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", "2001:db8::", "2001:db8:0:0:0:0:0:0",
	} {
		if got := names(line); got != "" {
			r.errorf("edge %q-shaped line of %d bytes is flagged by %s", line[:3], len(line), got)
		}
	}
	for i, line := range []string{
		"192.0." + "3.0", "2001:db9:" + ":",
		"192.0." + "1.255", "198.51." + "99.255", "198.51." + "101.0", "203.0." + "112.255", "203.0." + "114.0",
		"2001:db7:ffff:ffff:ffff:ffff:ffff:" + "ffff", "2001:db9:" + ":1",
	} {
		if got := names(line); got != "ip-address" {
			r.errorf("flagged edge %d gives %q", i, got)
		}
	}
}

// The examples section 4.2 gives outside its tables: the false positives it
// lists, and the remedies it gives, which pass.
func TestIPAddressProse(t *testing.T) {
	r := newReport(t)
	defer r.done()
	for i, line := range []string{
		"xs[1:" + ":2]", "xs[:" + ":2]", // extended slices parse as IPv6
		"x2001:db8:" + ":1",  // a letter straight before: read from its second group
		":" + ":1:8080",      // the loopback address and a port, no brackets
		"\u00a71." + "2.3.4", // a non-ASCII character before the number does not stop it
	} {
		if got := names(line); got != "ip-address" {
			r.errorf("flagged prose example %d gives %q", i, got)
		}
	}
	for i, line := range []string{
		"v1.0.0.0",                 // write a v first
		"section 1.2.3, item 4",    // fewer levels
		"libfoo v1.2.3.4",          // the version apart from the name, after a v
		"libfoo.so.1",              // fewer parts
		"ab12 :: cd", "xs[1 :: 2]", // spaces around the ::
		"[:" + ":1]:8080",              // brackets before the port, which the allowlist passes
		"x 2001:db8::1",                // a space before a documentation address
		"x(2001:db8::1)",               // punctuation before it
		"a netmask of /24",             // the prefix length
		"2001:db8::1 in 2001:db8::/32", // prefix notation
	} {
		if got := names(line); got != "" {
			r.errorf("remedy %d is flagged by %s", i, got)
		}
	}
}

// Section 4.2's "Known misses": each holds an address and passes.
func TestIPAddressKnownMisses(t *testing.T) {
	r := newReport(t)
	defer r.done()
	for i, line := range []string{
		"10.1", "10.1" + ".2", "167772161", "0x0a.0x00.0x00.0x01", // forms other than four decimal groups
		"ip10." + "1.2.3", "v10." + "1.2.3", // a letter touches it
		"\\n10." + "1.2.3", "%3A10." + "1.2.3", // the letter of a string escape or a percent escape
		"%2010." + "1.2.3",                       // the escape's digits join the address
		"2001:db9:" + ":1_", "2001:db9:" + ":1x", // a letter or _ straight after an IPv6 address
		"x2001:" + ":1",                // a letter straight before, with the first group followed by ::
		"10, 1, 2, 3", "{10, 1, 2, 3}", // separate integers
		"node1.10.1." + "2.3.example.com", // a label ending in a digit joins the address
		"10 .1.2.3", "10.1.2" + "%2E3",    // spaces and encodings inside an address
		"2001:db9:" + "\n:1", // a line break inside an address (two lines in one string)
	} {
		if got := names(line); got != "" {
			r.errorf("known miss %d is flagged by %s", i, got)
		}
	}
}

// Redaction cuts a path at the component where the earliest match begins
// (ADR-002 negative test 11).
func TestIPAddressRedactsPaths(t *testing.T) {
	r := newReport(t)
	defer r.done()
	for i, c := range []struct{ path, want string }{
		{"docs/" + "203.0." + "114.7" + "/a.md", "docs/<redacted>"},
		{"docs/ok/" + "10.1." + "2.3" + "-notes/a.md", "docs/ok/<redacted>"},
		{"203.0." + "114.7" + ".md", "<redacted>"},
		{"docs/192.0.2.10/a.md", "docs/192.0.2.10/a.md"},
		{"docs/" + "2001:db9:" + ":1" + "/a.md", "docs/<redacted>"},
	} {
		if got := Redact(c.path, registry.Start([]byte(c.path), Context{Source: Path, Path: c.path})); got != c.want {
			r.errorf("path %d redacts to %d bytes, want %d", i, len(got), len(c.want))
		}
		lc.Check(t, Redact(c.path, registry.Start([]byte(c.path), Context{Source: Path, Path: c.path})))
	}
}

// Both an IPv4 and an IPv6 candidate can flag a line; the earliest start wins,
// and a passing address before a flagged one does not hide it.
func TestIPAddressEarliest(t *testing.T) {
	r := newReport(t)
	defer r.done()
	four, six := "203.0."+"114.7", "2001:db9:"+":1"
	for i, c := range []struct {
		line string
		want int
	}{
		{four + " and " + six, 0},
		{six + " and " + four, 0},
		{"192.0.2.1 then " + four, len("192.0.2.1 then ")},
		{"2001:db8::1 then " + six, len("2001:db8::1 then ")},
		{"[2001:db8::1]:443 " + four + " " + six, len("[2001:db8::1]:443 ")},
		{"::ffff:203.0.114" + ".7", 0},
	} {
		if got, _ := (IPAddress{}).Check([]byte(c.line), Context{}); got != c.want {
			r.errorf("case %d: offset %d, want %d", i, got, c.want)
		}
	}
}

// The steps of section 4.2 in their order, on shapes the tables do not list: a
// group above 255 is ignored before a leading zero is looked at (steps 3 and
// 4); 1 to 5 digits make a port, and six do not; an underscore stops an IPv6
// run, so Rust's module path is no address, but not an IPv4 candidate, so an
// address in emphasis written with underscores is found. Step 2 trims the dots
// at the start of a run too; step 3 retries after a key that follows an
// underscore; and step 4 requires a decimal digit again once a port is dropped.
func TestIPAddressSteps(t *testing.T) {
	r := newReport(t)
	defer r.done()
	for i, c := range []struct {
		line string
		want string
	}{
		{"256.010." + "1.1", ""},              // step 3 first: ignored
		{"10.1." + "2.003", "ip-address"},     // a leading zero in the last group
		{"10.1." + "2.3.12345", "ip-address"}, // five digits are a port
		{"10.1." + "2.3.123456", ""},          // six are not
		{"10.1." + "2.3.0", "ip-address"},     // one digit is
		{"_10.1." + "2.3_", "ip-address"},     // an underscore does not stop an IPv4 candidate
		{"x86_64:" + ":{foo}", ""},            // an underscore before the run
		{"2001:db9:" + ":1 (x86_64)", "ip-address"},
		{"Trying ...2001:db9:" + ":1", "ip-address"}, // dots at the start are trimmed
		{"ipv6_dad:2001:db9:" + ":1", "ip-address"},  // the retry after a key, after an underscore
		{"a:b:c:d:e:f:aa:bb:22", ""},                 // no decimal digit once the port is dropped
	} {
		if got := names(c.line); got != c.want {
			r.errorf("case %d gives %q, want %q", i, got, c.want)
		}
	}
}
