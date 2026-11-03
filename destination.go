package hush

import (
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"unique"
)

// class is a destination's kind, the only part of it hush ever prints.
type class uint8

const (
	classNone class = iota
	classPublic
	classClient
	classPrivate
)

var classNames = [...]string{classNone: "invalid", classPublic: "public", classClient: "client", classPrivate: "private"}

// Destination is where the scanned text may end up (ADR-001 section 4): Public,
// Private, or one client's destination, from Client. The zero value is
// invalid, and New refuses it. Its String, Format, GoString and LogValue
// print only the class, "public", "client" or "private", never a client's
// label; MarshalJSON, MarshalText and GobEncode return the same. Two
// destinations are == when they are the same destination.
type Destination struct {
	class class
	// label is the client label, for classClient, and the zero handle
	// otherwise. A unique.Handle is one pointer per distinct label, so ==
	// compares labels, and the runtime frees a label's entry once no handle
	// to it is left. fmt's raw dump, which %p and every verb a type does not
	// take print, shows the handle's pointer as an address at any depth
	// (HSH-11/D38).
	label unique.Handle[string]
}

// clientLabel returns the client label, or "" for a destination that is not
// a client's.
func (d Destination) clientLabel() string {
	if d.label == (unique.Handle[string]{}) {
		return ""
	}
	return d.label.Value()
}

// Public returns the public destination: anyone may eventually read the text.
// Every loaded set applies.
func Public() Destination { return Destination{class: classPublic} }

// Private returns the private destination: no one outside nonhumanhq's own
// machines and accounts may read the text. The generic rules run, and no set
// applies.
func Private() Destination { return Destination{class: classPrivate} }

// Client returns the destination of the one client whose code is label. It
// checks only the label's grammar: 1 to 32 characters from [a-z0-9_-],
// starting with a letter or a digit, and neither "public" nor "private". New
// checks the label against the term sets. The error is ErrDestination, and
// never echoes the label.
func Client(label string) (d Destination, err error) {
	defer recoverError(&err, func() { d = Destination{} })
	if !goodClientLabel(label) {
		return Destination{}, newError(CodeDestination, msgBadClientLabel, 0)
	}
	return Destination{class: classClient, label: unique.Make(label)}, nil
}

// ParseDestination reads a destination as the command line writes it:
// "public", "private" or "client:LABEL". The error is ErrDestination, and
// never echoes s.
func ParseDestination(s string) (d Destination, err error) {
	defer recoverError(&err, func() { d = Destination{} })
	switch s {
	case "public":
		return Public(), nil
	case "private":
		return Private(), nil
	}
	if label, ok := strings.CutPrefix(s, "client:"); ok {
		return Client(label)
	}
	return Destination{}, newError(CodeDestination, msgUnknownDest, 0)
}

// goodClientLabel reports whether label follows ADR-001 section 4's grammar.
func goodClientLabel(label string) bool {
	if len(label) < 1 || len(label) > 32 || label == "public" || label == "private" {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case 'a' <= c && c <= 'z', '0' <= c && c <= '9':
		case (c == '_' || c == '-') && i > 0:
		default:
			return false
		}
	}
	return true
}

// String returns the class: "public", "client", "private", or "invalid" for
// the zero value.
func (d Destination) String() string { return classNames[d.class] }

// Format prints the class for every verb.
func (d Destination) Format(f fmt.State, _ rune) { fmt.Fprint(f, d.String()) }

// GoString returns the class.
func (d Destination) GoString() string { return d.String() }

// LogValue returns the class.
func (d Destination) LogValue() slog.Value { return slog.StringValue(d.String()) }

// MarshalJSON returns the class as a JSON string.
func (d Destination) MarshalJSON() ([]byte, error) { return []byte(strconv.Quote(d.String())), nil }

// MarshalText returns the class.
func (d Destination) MarshalText() ([]byte, error) { return []byte(d.String()), nil }

// GobEncode returns the class.
func (d Destination) GobEncode() ([]byte, error) { return []byte(d.String()), nil }
