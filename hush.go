// Package hush keeps private names out of records that may become public.
//
// A Scanner scans buffers, readers, file trees, the git index and git ranges
// for one destination (Public, Private or a Client), with the generic rules
// and, unless the caller downgrades coverage with Config.GenericOnly, the term
// sets of a term file loaded with LoadTermSets. Every scan returns exactly one
// of three things:
//
//   - a *Report and a nil error: the scan completed and found nothing;
//   - a *Report and a *FindingsError: the scan completed with findings;
//   - a nil *Report and an *Error: the scan did not complete.
//
// So "if err != nil { return err }" fails closed. No output, error or
// formatted value holds matched text, a term, a client label or the term
// file's path (ADR-001 section 6.6).
// The guarantee covers fmt, the encoding packages and errors, at any nesting;
// it does not cover reflection into unexported fields or unsafe, which can
// read any Go value (HSH-11/D38).
package hush

import (
	"runtime/debug"
	"strings"
)

// modulePath is this module's path, under which an importer's build records
// the version of hush it uses.
const modulePath = "github.com/nonhumanhq/hush"

// Version returns the version of hush in the running binary, as the module
// system records it and without its leading "v", such as "0.1.0"; "(devel)"
// for a build from a work tree; or "unknown" when the binary records none.
func Version() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	v := ""
	if bi.Main.Path == modulePath {
		v = bi.Main.Version
	}
	for _, d := range bi.Deps {
		if d.Path == modulePath {
			v = d.Version
			if d.Replace != nil && d.Replace.Version != "" {
				v = d.Replace.Version
			}
		}
	}
	if v == "" {
		return "unknown"
	}
	return strings.TrimPrefix(v, "v")
}

// box holds a pointer to a value that may hold a term, a client label, an
// address or a path, one level further from fmt than the field that holds
// the box. fmt prints a pointer it meets below the top level as an address,
// except when a verb does not suit it, such as %s, %q, %t or %f: then it
// prints the pointer again from the top level, where it follows it once. A
// field holding the pointer itself would show what it points to; a field
// holding a *box shows the box, whose one field is again an address
// (HSH-11/D38).
type box[T any] struct{ v *T }

// newBox returns a box holding v.
func newBox[T any](v *T) *box[T] { return &box[T]{v: v} }

// get returns the boxed pointer, or nil for a nil box.
func (b *box[T]) get() *T {
	if b == nil {
		return nil
	}
	return b.v
}
