package hush

import (
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
)

// Identities is the email rule's identity allowance (ADR-002 sections 3.1, 4.3
// and 5.4): addresses that pass when they stand in an identity position, such
// as a commit's author line or a Signed-off-by trailer. Build it with
// NewIdentities. No method returns, prints, logs or encodes an address: String,
// Format, GoString and LogValue print "hush.Identities(N addresses)", and
// MarshalJSON, MarshalText and GobEncode always return an error. An Identities
// not made by NewIdentities, such as new(Identities), makes New return
// ErrUsage.
type Identities struct {
	// addrs holds the addresses, ASCII letters lowered. It is boxed so that
	// fmt's raw dump, which %p and every verb a type does not take print,
	// shows an address at any depth (HSH-11/D38).
	addrs *box[[]string]
}

// NewIdentities returns the allowance for addrs. Each address holds an "@"
// with text on both sides, and no space, tab, "<", ">" or ","; the list holds
// at least one. Addresses compare with ASCII letters lowered. The error is
// ErrUsage, and names an address by its 1-based position, never its text.
func NewIdentities(addrs []string) (ids *Identities, err error) {
	defer recoverError(&err, func() { ids = nil })
	if len(addrs) == 0 {
		return nil, newError(CodeUsage, msgIdentitiesEmpty, 0)
	}
	list := make([]string, len(addrs))
	for i, a := range addrs {
		if !goodIdentity(a) {
			return nil, newError(CodeUsage, msgIdentityBad, i+1)
		}
		list[i] = lowerASCII(a)
	}
	return &Identities{addrs: newBox(&list)}, nil
}

// goodIdentity reports whether a has section 5.4's form.
func goodIdentity(a string) bool {
	at := strings.IndexByte(a, '@')
	return at > 0 && a[len(a)-1] != '@' && !strings.ContainsAny(a, " \t<>,")
}

func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// Len returns the number of addresses.
func (ids *Identities) Len() int {
	if ids == nil {
		return 0
	}
	return ids.count()
}

// count returns the number of addresses.
func (ids Identities) count() int {
	if ids.addrs == nil {
		return 0
	}
	return len(*ids.addrs.get())
}

func (ids Identities) summary() string {
	return "hush.Identities(" + strconv.Itoa(ids.count()) + " addresses)"
}

var errEncodeIdentities = errors.New("hush: Identities cannot be encoded")

// String returns the fixed summary.
func (ids Identities) String() string { return ids.summary() }

// Format prints the fixed summary for every verb.
func (ids Identities) Format(f fmt.State, _ rune) { fmt.Fprint(f, ids.summary()) }

// GoString returns the fixed summary.
func (ids Identities) GoString() string { return ids.summary() }

// LogValue returns the fixed summary.
func (ids Identities) LogValue() slog.Value { return slog.StringValue(ids.summary()) }

// MarshalJSON returns an error.
func (Identities) MarshalJSON() ([]byte, error) { return nil, errEncodeIdentities }

// MarshalText returns an error.
func (Identities) MarshalText() ([]byte, error) { return nil, errEncodeIdentities }

// GobEncode returns an error.
func (Identities) GobEncode() ([]byte, error) { return nil, errEncodeIdentities }
