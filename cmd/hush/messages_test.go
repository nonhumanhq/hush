package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	lc "github.com/nonhumanhq/hush/internal/leakcheck"
	"github.com/nonhumanhq/hush/internal/rule"
	"github.com/nonhumanhq/hush/internal/termset"
)

// The help text's rule names are the registry's, in its order (HSH-11/D59).
func TestRuleNames(t *testing.T) {
	var names []string
	for _, r := range rule.Registry(nil) {
		names = append(names, r.Name())
	}
	if strings.Join(names, " ") != strings.Join(ruleNames, " ") {
		t.Errorf("ruleNames %q, the registry %q", ruleNames, names)
	}
}

// table returns the patterns of every message hush scan may print after
// "hush: ": package hush's table, read from errors.go so that a message added
// there is covered without being listed here, with ADR-002 section 1.5's
// reasons after a term-file line, and the command line's own messages. "#" is
// an integer and "@" twelve hex digits, and a message of package hush may
// start with an argument's position (Error.WithArgument).
var table = sync.OnceValue(func() []*regexp.Regexp {
	f, err := parser.ParseFile(token.NewFileSet(), "../../errors.go", nil, 0)
	if err != nil {
		panic("cannot parse errors.go")
	}
	var msgs []string
	ast.Inspect(f, func(n ast.Node) bool {
		if vs, ok := n.(*ast.ValueSpec); ok {
			for i, name := range vs.Names {
				if strings.HasPrefix(name.Name, "msg") && i < len(vs.Values) {
					if lit, ok := vs.Values[i].(*ast.BasicLit); ok {
						m, _ := strconv.Unquote(lit.Value)
						msgs = append(msgs, m)
					}
				}
			}
		}
		return true
	})
	var reasons []string
	for r := termset.TermOutsideSet; r <= termset.ClientLabelRefused; r++ {
		reasons = append(reasons, regexp.QuoteMeta(r.String()))
	}
	pattern := func(m string) string {
		p := regexp.QuoteMeta(m)
		p = strings.ReplaceAll(p, "#", "[1-9][0-9]*")
		p = strings.ReplaceAll(p, "@", "[0-9a-f]{12}")
		if strings.HasSuffix(m, "line #: ") {
			p += "(" + strings.Join(reasons, "|") + ")"
		}
		return p
	}
	var out []*regexp.Regexp
	for _, m := range msgs {
		out = append(out, regexp.MustCompile("^(argument [1-9][0-9]*: )?"+pattern(m)+"$"))
	}
	for _, m := range cliMessages {
		out = append(out, regexp.MustCompile("^"+pattern(m)+"$"))
	}
	return out
})

// inTable reports whether msg, without "hush: ", is a message of the table.
func inTable(msg string) bool {
	for _, re := range table() {
		if re.MatchString(msg) {
			return true
		}
	}
	return false
}

// HSH-11/D43: the command line's own messages are fixed text that cites
// positions only, and the table reads package hush's.
func TestMessages(t *testing.T) {
	if len(table()) < 50 {
		t.Fatalf("read only %d messages", len(table()))
	}
	for _, m := range cliMessages {
		if strings.HasPrefix(m, "hush") || strings.Contains(m, "%") || !inTable(strings.ReplaceAll(m, "#", "3")) {
			t.Errorf("%q", m)
		}
	}
	for _, m := range []string{
		"argument 2: unknown destination",
		"argument 2: client label refused",
		"argument 4: stdin label refused",
		"argument 3: unknown option (see hush scan --help)",
		"term file: line 7: bad set name",
		"the public destination needs --terms FILE or --generic-only",
		"cannot diff commit 4d7f0a2c9e1b",
	} {
		if !inTable(m) {
			t.Errorf("ADR-001's message %q is not in the table", m)
		}
	}
	for _, m := range []string{"hush: interrupted", "argument x: unknown destination", "unknown option " + lc.Bad} {
		if inTable(m) {
			t.Errorf("%q should not match the table", m)
		}
	}
}
