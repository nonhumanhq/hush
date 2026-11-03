package rule

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	lc "github.com/nonhumanhq/hush/internal/leakcheck"
)

// ADR-002 section 5.2: the registry is id-prefix, ip-address, email-address,
// in that order, with names that follow section 5.1's contract.
func TestRegistryNames(t *testing.T) {
	r := newReport(t)
	defer r.done()
	var got []string
	for _, rl := range Registry(nil) {
		got = append(got, rl.Name())
	}
	if want := []string{"id-prefix", "ip-address", "email-address"}; !slices.Equal(got, want) {
		r.errorf("registry names are %v", got)
	}
	form := regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	seen := map[string]bool{}
	for _, name := range got {
		if !form.MatchString(name) || seen[name] || name == "binary-unscanned" || name == "unreadable" || name == "set" {
			r.errorf("rule name %q breaks the contract", name)
		}
		seen[name] = true
	}
}

// The allowance reaches the email rule only: the same list, passed to
// Registry, passes the identity in an identity position and nothing else.
func TestRegistryPassesTheAllowance(t *testing.T) {
	r := newReport(t)
	defer r.done()
	l := Registry([]string{lc.Identity})
	email, ok := l[2].(EmailAddress)
	if !ok {
		fatalf(t, "the third rule is %T", l[2])
	}
	if broken(email, lc.TrailerLine, inMessage) || !broken(email, lc.TrailerLine, inFile) {
		r.errorf("the registry's email rule does not apply the allowance as listed")
	}
	// The zero context, Text, is no identity position (ADR-002 section 5.1).
	if got := strings.Join(l.Check([]byte(lc.TrailerLine), Context{}), ","); got != "email-address" {
		r.errorf("a rule list with the allowance gives %q for the trailer line", got)
	}
	if got := Registry(nil)[2].(EmailAddress); len(got.ids) != 0 {
		r.errorf("Registry(nil) has an allowance")
	}
}

// A line that breaks all three rules gives one finding per rule, in registry
// order, whatever the order of the matches on the line (ADR-001 section 6.2).
func TestRegistryOrdersFindings(t *testing.T) {
	r := newReport(t)
	defer r.done()
	line := "bob@" + "acme.local" + " " + "10.1." + "2.3" + " " + lc.Bad
	if got := strings.Join(Registry(nil).Check([]byte(line), Context{}), ","); got != "id-prefix,ip-address,email-address" {
		r.errorf("findings are %q", got)
	}
	if got := strings.Join(Registry(nil).Check([]byte(line+line), Context{}), ","); got != "id-prefix,ip-address,email-address" {
		r.errorf("a line gives more than one finding per rule: %q", got)
	}
	lc.Check(t, strings.Join(Registry(nil).Check([]byte(line), Context{}), ","))
}

// Nothing is read from a file, git configuration, .mailmap, the environment or
// the repository (ADR-002 section 4.3, "Where it comes from"): the rules'
// sources import nothing that could.
func TestRulesImportNothingThatReadsFilesOrTheEnvironment(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatal("cannot list the package's files")
	}
	forbidden := map[string]bool{
		"os": true, "os/exec": true, "os/user": true, "io/ioutil": true, "io/fs": true,
		"path/filepath": true, "syscall": true, "net": true, "net/http": true, "plugin": true, "unsafe": true,
	}
	r := newReport(t)
	defer r.done()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("cannot parse a source file of the package")
		}
		for _, imp := range file.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			if forbidden[path] {
				r.errorf("%s imports %s", f, path)
			}
		}
	}
}
