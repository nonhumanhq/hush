package leakcheck

import "slices"

// The identity allowance the tests pass to the email rule, at a domain that is
// not reserved, so a test of the allowance exercises it (ADR-002 negative
// test 4, and section 6, point 4). Identity2 is a second listed address.
var (
	Identity  = "alice@" + "acme.internal"
	Identity2 = "bob@" + "acme.internal"
)

// Lines that carry the identity, as the rows of ADR-002 section 4.3 write them.
var (
	TrailerLine = "Signed-off-by: Alice <alice@" + "acme.internal>"
	AuthorLine  = "author Alice <alice@" + "acme.internal> 1700000000 +0000"
	WriteToLine = "write to alice@" + "acme.internal"
	SubjectLine = "HSH-3: write to alice@" + "acme.internal"
	NoteLine    = "Note: ask alice@" + "acme.internal"
)

// IPFlagged is the "Flagged" table of ADR-002 section 4.2, every input of every
// row as the ADR writes it. Each holds an address the ip-address rule flags.
var IPFlagged = []string{
	// Just outside a documentation range
	"203.0." + "114.7", "192.0." + "3.1", "2001:db9:" + ":1",
	// A leading single : and a trailing . are trimmed
	"addr:2001:db9:" + ":1", "at 2001:db9:" + ":1.",
	// Step 2's order: every dot first, then a single colon only
	"at 2001:db9:" + ":.", "Trying 2001:db9:" + ":1...",
	// Step 3's retry after a key
	"v=spf1 ip6:2001:db9:" + "abcd::/48 -all", "Received: from [IPv6:2001:db9:" + ":1]", "node:2001:db9:" + ":5",
	// An address and a port, as tcpdump and BSD netstat print them
	"IP 203.0." + "114.7.22 > 198.51.100.9.51234", "tcp4  0  0  203.0." + "114.7.22  198.51.100.9.51234",
	// An IPv6 address and a port, as tcpdump prints them
	"IP6 2001:db9:" + ":1.546 > 2001:db8::2.547",
	// An IPv6 address and a port after a colon, without brackets: eight groups, or seven and a ::
	"2001:db9:1:2:3:4:5:" + "6:22", "2001:db9:" + ":3:4:5:6:7:22",
	// An address inside a dotted hostname, after another label
	"app.203.0." + "114.7.example.com",
	// Shared address space, benchmarking
	"100.64." + "0.1", "198.18." + "0.1",
	// The IPv4 part decides
	"::ffff:203.0.114" + ".7", "2001:db8::203.0.114" + ".7",
	// A netmask
	"255.255." + "255.0",
	// Leading zeros
	"010.1." + "2.3", "192.000." + "002.001",
	// Four-part versions with nothing before them, or after a word and a dot
	"1.0." + "0.0", "1.2." + "3.4-beta", "libfoo.so.1.2." + "3.4",
	// Five groups read as an address and a port
	"1.2." + "3.4.5",
	// A reversed address is still an address
	"3.2." + "1.10.in-addr.arpa",
	// A hex word with a digit parses as IPv6
	"ab12:" + ":cd",
	// Private, unique local and link-local
	"10.1." + "2.3", "172.16." + "0.1", "192.168." + "1.1", "fd00:" + ":1", "fe80:" + ":1%eth0",
	// A private range in block notation; a mapped private address
	"10.0." + "0.0/8", "::ffff:10.1.2" + ".3",
	// A private address and a port
	"10.1." + "2.3.22",
	// A private address inside a dotted hostname
	"https://web.10.1." + "2.3.example.com/",
}

// EmailFlagged is the "Flagged" table of ADR-002 section 4.3, every input of
// every row. Each holds an address the email-address rule flags when no
// allowance applies. The rows from WriteToLine on carry the identity: they stay
// flagged even when the caller lists it, because no identity position applies.
var EmailFlagged = []string{
	// Not reserved
	"bob@" + "acme.local", "bob@" + "acme.internal",
	// They look reserved but are not
	"bob@example." + "community", "bob@example." + "co", "bob@acme-" + "example.com", "bob@example.com." + "acme.internal",
	// A non-ASCII domain, under any top-level domain
	"bob@ex" + "ämple.com", "bob@acme." + "рф",
	// An em dash ends the domain, so the reserved name after it does not count
	"bob@acme." + "internal—www.example.com",
	// An escaped @; a quoted local part
	"bob\\@acme." + "internal", "\"bob\"@acme." + "internal",
	// Bracketed, so any domain counts
	"<bob@" + "buildhost>",
	// A bracketed domain ends at the : or /, so a reserved name in the path does not count
	"<git@" + "buildhost:org/repo.test>", "<ssh://git@" + "buildhost/org/app.localhost>",
	// An address in a code span: its local part starts after the backtick
	"`bob@" + "acme.internal`",
	// Known false positives
	"icon@" + "2x.png", "git@host." + "acme.internal:org/repo",
	// An allowed identity, but not in an identity position
	WriteToLine,
	// Not an identity trailer
	SubjectLine, NoteLine,
	// A file's line is never an identity position (decided item 6), and the
	// allowance is explicit input only: the table's last two rows share this input
	TrailerLine,
}

// addresses is every string above that a test must never print, and the
// strings below.
var addresses = slices.Concat(IPFlagged, EmailFlagged, []string{Identity, Identity2}, []string{
	// The matched addresses of rows that hold more than the address. Such a row
	// is a token only as a whole, so the address the rule matches in it, printed
	// on its own, is listed too (ADR-002, negative tests: any matched text).
	"2001:db9:" + "abcd::", "2001:db9:" + ":5", "2001:db9:1:2:3:4:5:" + "6", "2001:db9:" + ":3:4:5:6:7", "2001:db9:" + ":",
	"1.2." + "3.4", "3.2." + "1.10", "fe80:" + ":1", "10.0." + "0.0",
	"bob@" + "buildhost", "git@" + "buildhost", "git@host." + "acme.internal",
})
