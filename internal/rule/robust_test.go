package rule

import (
	"bytes"
	"math/rand"
	"slices"
	"testing"

	lc "github.com/nonhumanhq/hush/internal/leakcheck"
)

// checkLine holds what ADR-002 section 5.1 asks of any rule on any bytes: no
// panic, an offset inside the line, a verdict that depends on the line and its
// context alone, a line left as it was, and Index agreeing with Check on the
// zero Context.
func checkLine(t *testing.T, line []byte) {
	t.Helper()
	orig := bytes.Clone(line)
	for _, r := range []interface {
		Index(string, bool) int
		Check([]byte, Context) (int, bool)
	}{IPAddress{}, EmailAddress{}, NewEmailAddress([]string{lc.Identity})} {
		start, b := r.Check(line, Context{})
		again, b2 := r.Check(line, Context{})
		if start != again || b != b2 {
			fatalf(t, "a rule's verdict changes between calls on a line of %d bytes", len(line))
		}
		if b && (start < 0 || start >= len(line)) || !b && start != -1 {
			fatalf(t, "offset %d, flagged %t, on a line of %d bytes", start, b, len(line))
		}
		want := -1
		if b {
			want = start
		}
		if got := r.Index(string(line), false); got != want {
			fatalf(t, "Index is %d, Check says %d, on a line of %d bytes", got, want, len(line))
		}
		for _, ctx := range []Context{{Source: Object, Part: Author}, {Source: Object, Part: Message}, {Source: Stdin}, {Source: File, Path: "a"}} {
			if s, _ := r.Check(line, ctx); s < -1 || s >= len(line) && len(line) > 0 {
				fatalf(t, "offset %d on a line of %d bytes in a context", s, len(line))
			}
		}
	}
	if !bytes.Equal(line, orig) {
		fatalf(t, "a rule changed the line it was given")
	}
}

// Every row of both tables, and lines made of the pieces the rules look at,
// including bytes that are not valid UTF8.
func TestRulesOnPiecesAndRandomBytes(t *testing.T) {
	var seeds []string
	seeds = append(seeds, ipPasses...)
	seeds = append(seeds, emailPasses...)
	seeds = append(seeds, lc.IPFlagged...)
	seeds = append(seeds, lc.EmailFlagged...)
	for _, s := range seeds {
		checkLine(t, []byte(s))
	}
	pieces := []string{
		"0", "1", "25", "255", "256", "010", "a", "F", "x", "_", ".", ":", "::", "-", "@", "<", ">", "\"", "\\", "/", "?", "#",
		" ", "\t", "é", "рф", "—", "\xff", "\xc3", "%", "[", "]", "example.com", "acme.", "ffff", "ip6:", "::ffff:", "192.0.2.1", "2001:db8::1", "Signed-off-by: ",
	}
	rng := rand.New(rand.NewSource(14))
	for i := 0; i < 20000; i++ {
		var b []byte
		for n := rng.Intn(14); n >= 0; n-- {
			if rng.Intn(8) == 0 {
				b = append(b, byte(rng.Intn(256)))
			} else {
				b = append(b, pieces[rng.Intn(len(pieces))]...)
			}
		}
		checkLine(t, b)
	}
	checkLine(t, nil)
	checkLine(t, []byte{})
}

// FuzzRules runs checkLine over the corpus under go test, and over generated
// lines under go test -fuzz.
func FuzzRules(f *testing.F) {
	for _, s := range slices.Concat(ipPasses, emailPasses, lc.IPFlagged, lc.EmailFlagged) {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, line []byte) { checkLine(t, line) })
}
