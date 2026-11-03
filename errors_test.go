package hush

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/nonhumanhq/hush/internal/termset"
)

// table returns the message constants of errors.go, by name, read from the
// source so that a message added there is checked without being listed here.
var table = sync.OnceValue(func() map[string]string {
	f, err := parser.ParseFile(token.NewFileSet(), "errors.go", nil, 0)
	if err != nil {
		panic("cannot parse errors.go")
	}
	msgs := map[string]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		if vs, ok := n.(*ast.ValueSpec); ok {
			for i, name := range vs.Names {
				if strings.HasPrefix(name.Name, "msg") && i < len(vs.Values) {
					if lit, ok := vs.Values[i].(*ast.BasicLit); ok {
						msgs[name.Name], _ = strconv.Unquote(lit.Value)
					}
				}
			}
		}
		return true
	})
	return msgs
})

// fromTable reports whether msg is a message of the table, with "#" read as an
// integer, "@" as twelve hex digits, and a term-file line's reason taken from
// ADR-002 section 1.5's table, after an argument's position when
// Error.WithArgument added one.
func fromTable(msg string) bool {
	if rest, ok := strings.CutPrefix(msg, "argument "); ok {
		if n, after, ok := strings.Cut(rest, ": "); ok && regexp.MustCompile(`^[1-9][0-9]*$`).MatchString(n) {
			msg = after
		}
	}
	for name, m := range table() {
		pat := regexp.QuoteMeta(m)
		pat = strings.ReplaceAll(pat, "#", "[1-9][0-9]*")
		pat = strings.ReplaceAll(pat, "@", "[0-9a-f]{12}")
		if name == "msgTermLine" {
			var reasons []string
			for r := termset.TermOutsideSet; r <= termset.ClientLabelRefused; r++ {
				reasons = append(reasons, regexp.QuoteMeta(r.String()))
			}
			pat += "(" + strings.Join(reasons, "|") + ")"
		}
		if regexp.MustCompile("^" + pat + "$").MatchString(msg) {
			return true
		}
	}
	return false
}

// wantError fails t unless err is an *Error with code c whose message is from
// the table, and passes err through the leak check.
func wantError(t *testing.T, err error, c Code) {
	t.Helper()
	var e *Error
	switch {
	case !errors.As(err, &e):
		t.Errorf("got %v, want an *Error with code %s", err, c)
	case e.Code() != c:
		t.Errorf("got code %s (%q), want %s", e.Code(), e.Error(), c)
	case !fromTable(e.Error()):
		t.Errorf("message %q is not in the table", e.Error())
	}
	leak(t, err)
}

// HSH-11/D11: the closed message table. Every message is fixed text without the
// "hush: " prefix, unique, and holds no format verb; ADR-001 section 7's
// example messages that this package can produce are among them, word for
// word.
func TestMessageTable(t *testing.T) {
	seen := map[string]string{}
	for name, m := range table() {
		switch {
		case m == "" || strings.HasPrefix(m, "hush"):
			t.Errorf("%s: %q", name, m)
		case strings.Contains(m, "%"):
			t.Errorf("%s holds a format verb", name)
		case seen[m] != "":
			t.Errorf("%s repeats %s", name, seen[m])
		}
		seen[m] = name
	}
	if len(table()) < 40 {
		t.Fatalf("read only %d messages from errors.go", len(table()))
	}
	for _, m := range []string{
		"the client label is not declared in the term file",
		"the public destination needs --terms FILE or --generic-only",
		"no term applies to this destination",
		"term file: line 7: bad set name",
		"term file: line 9: client label refused",
		"term file: readable or writable by group or others",
		"path argument 2 does not exist",
		"cannot diff commit 4d7f0a2c9e1b",
		"the range holds no commits",
		"cannot read standard input",
		"input over the size limit",
		"cannot write output",
		"interrupted",
		"internal error; output withheld",
	} {
		if !fromTable(m) {
			t.Errorf("ADR-001's message %q is not in the table", m)
		}
	}
	for _, m := range []string{"hush: interrupted", "path argument x does not exist", "cannot diff commit 4D7F0A2C9E1B"} {
		if fromTable(m) {
			t.Errorf("%q should not match the table", m)
		}
	}
}

// ADR-001 section 7: an *Error matches the sentinel of its code and no other,
// has no Unwrap, and reports its parameters.
func TestErrorIs(t *testing.T) {
	sentinels := map[Code]error{
		CodeUsage: ErrUsage, CodeDestination: ErrDestination, CodeCoverage: ErrCoverage,
		CodeTermFile: ErrTermFile, CodeLabel: ErrLabel, CodeUnknownSet: ErrUnknownSet,
		CodeUnknownRule: ErrUnknownRule, CodePath: ErrPath, CodeGit: ErrGit, CodeRange: ErrRange,
		CodeEmptyRange: ErrEmptyRange, CodeRead: ErrRead, CodeOutput: ErrOutput,
		CodeInterrupted: ErrInterrupted, CodeInternal: ErrInternal,
	}
	for c, s := range sentinels {
		e := newError(c, msgInternal, 0)
		for c2, s2 := range sentinels {
			if errors.Is(e, s2) != (c == c2) {
				t.Errorf("errors.Is(%s error, %s sentinel) = %v", c, c2, !(c == c2))
			}
		}
		if errors.Is(e, ErrFindings) || s.(*Error).Code() != c || !regexp.MustCompile(`^[a-z]+(-[a-z]+)*$`).MatchString(string(c)) {
			t.Errorf("sentinel %s is wrong", c)
		}
		if _, ok := any(e).(interface{ Unwrap() error }); ok {
			t.Error("*Error has Unwrap")
		}
	}
	e := argError(CodePath, msgPathMissing, 2)
	if e.Error() != "path argument 2 does not exist" || e.Argument() != 2 || e.Line() != 0 || e.Commit() != "" {
		t.Errorf("argError: %q %d %d %q", e.Error(), e.Argument(), e.Line(), e.Commit())
	}
	id := strings.Repeat("4d7f0a2c9e1b", 3) + "abcd"
	e = commitError(CodeGit, msgDiffFailed, id)
	if e.Error() != "cannot diff commit 4d7f0a2c9e1b" || e.Commit() != id || e.Argument() != 0 {
		t.Errorf("commitError: %q %q", e.Error(), e.Commit())
	}
	leak(t, e, *e)
}

// ADR-001 section 7: FindingsError and ExitCode; negative test 19's last point,
// ExitCode is 0 only for a nil error.
func TestFindingsErrorAndExitCode(t *testing.T) {
	rep := &Report{done: true, findings: []Finding{{Kind: Match, Tier: TierGeneric, Rule: "id-prefix", Label: "<stdin>", Line: 1}}}
	fe := &FindingsError{report: rep}
	if fe.Error() != "hush: 1 findings" || fe.Report() != rep || !errors.Is(fe, ErrFindings) || errors.Is(fe, ErrInternal) {
		t.Errorf("FindingsError: %q", fe.Error())
	}
	var nilFE *FindingsError
	if nilFE.Report() == nil || nilFE.Report().Clean() || nilFE.Error() != "hush: 0 findings" {
		t.Error("a nil *FindingsError gives no report, or a clean one")
	}
	cases := []struct {
		err  error
		want int
	}{
		{nil, 0},
		{fe, 1},
		{fmt.Errorf("posting: %w", fe), 1},
		{ErrFindings, 1},
		{ErrUsage, 2},
		{newError(CodeInterrupted, msgInterrupted, 0), 2},
		{errors.New("any other error"), 2},
		{nilFE, 1},
	}
	for i, c := range cases {
		if got := ExitCode(c.err); got != c.want {
			t.Errorf("case %d: ExitCode = %d, want %d", i, got, c.want)
		}
	}
	leak(t, fe, nilFE)
}

// Version reports the module's version without its "v", or a fixed word; in a
// test binary, the main module is hush itself, built from a work tree.
func TestVersion(t *testing.T) {
	v := Version()
	if v == "" || strings.HasPrefix(v, "v") {
		t.Errorf("Version() = %q", v)
	}
	leak(t, v)
}
