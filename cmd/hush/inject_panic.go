//go:build hushpanic

package main

import "errors"

// A test build of hush, made with "go build -tags hushpanic", panics just
// before it writes a scan's result, with a value that holds a synthetic term
// and a rejected token, for ADR-001 negative test 6 (HSH-11/T26). No other
// build holds this file, and the architecture tests read only what the
// default build builds.
func init() {
	testHook = func(claimed bool) {
		if !claimed {
			panic(errors.New("cannot write " + "quor" + "vel" + " near " + "QPV" + "-17"))
		}
	}
}
