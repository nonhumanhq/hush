package output

import (
	"strings"
	"testing"

	"github.com/nonhumanhq/hush/internal/leakcheck"
)

func TestFormat(t *testing.T) {
	var out, errs strings.Builder
	o := New(&out)
	o.Finding("docs/a.md", 3, "id-prefix")
	o.Finding("0123456789ab:(commit)", 6, "set:clients")
	o.Finding("docs/<redacted>", 0, "set:people in path")
	if err := o.Flush(); err != nil || o.Found != 3 {
		t.Fatalf("flush: %v, found %d", err, o.Found)
	}
	Error(&errs, "bad --range")
	want := "docs/a.md:3: id-prefix\n0123456789ab:(commit):6: set:clients\ndocs/<redacted>:0: set:people in path\n"
	if out.String() != want || errs.String() != "hush-interim: bad --range\n" {
		t.Errorf("got %q and %q", out.String(), errs.String())
	}
	leakcheck.Check(t, out.String(), errs.String())
}
