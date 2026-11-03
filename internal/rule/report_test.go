package rule

import (
	"fmt"
	"testing"

	lc "github.com/nonhumanhq/hush/internal/leakcheck"
)

// report collects what a test prints, so the leak check sees it (AGENTS.md,
// "Tests"). A message holds row numbers and rule names, never a token.
type report struct {
	t    *testing.T
	msgs []string
}

func newReport(t *testing.T) *report { t.Helper(); return &report{t: t} }

func (r *report) errorf(format string, args ...any) {
	r.t.Helper()
	m := fmt.Sprintf(format, args...)
	r.msgs = append(r.msgs, m)
	r.t.Error(m)
}

// done passes everything the test printed through the leak check.
func (r *report) done() { r.t.Helper(); lc.Check(r.t, r.msgs...) }

// fatalf is t.Fatalf for a message that has first passed the leak check.
func fatalf(t testing.TB, format string, args ...any) {
	t.Helper()
	m := fmt.Sprintf(format, args...)
	lc.Check(t, m)
	t.Fatal(m)
}
