package hush

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	lc "github.com/nonhumanhq/hush/internal/leakcheck"
)

// TestMain isolates every test and example in the package from this machine's
// git configuration and identity (HSH-9/D13): no global or system
// configuration, a temporary HOME, no repository discovered above the
// temporary directory, no inherited GIT_DIR or index, and a fixed identity at
// a reserved domain with fixed dates. No test starts gh.
func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", "hush-home-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot make a temporary HOME")
		os.Exit(2)
	}
	for _, k := range []string{"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
		"GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR", "EMAIL", "XDG_CONFIG_HOME"} {
		os.Unsetenv(k)
	}
	for k, v := range map[string]string{
		"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1", "HOME": home,
		"GIT_CEILING_DIRECTORIES": filepath.Dir(home),
		"GIT_AUTHOR_NAME":         "alice", "GIT_AUTHOR_EMAIL": "alice@" + "example.org",
		"GIT_COMMITTER_NAME": "alice", "GIT_COMMITTER_EMAIL": "alice@" + "example.org",
		"GIT_AUTHOR_DATE": "1700000000 +0000", "GIT_COMMITTER_DATE": "1700000000 +0000",
	} {
		os.Setenv(k, v)
	}
	code := m.Run()
	os.RemoveAll(home)
	os.Exit(code)
}

// leak fails t if any value, or the value nested in a struct with an
// exported field, a struct with an unexported field, a slice and a map, or
// converted to a type of the same fields and no methods, formatted with %v,
// %+v, %#v, %s, %q, %p, %x, %X, %d, %t, %f, %e, %g, %c and %U, or any error's
// text, holds a synthetic term, a rejected token or a test client label. Hex
// in every text is also checked decoded. fmt prints %p, and every verb a type
// does not take, before any Format method, as a raw dump of the value; below
// the top level it prints a pointer as an address, except for a verb that
// does not suit it, which dumps what the pointer points to (HSH-11/D38).
func leak(t *testing.T, values ...any) {
	t.Helper()
	lc.Check(t, formats(values...)...)
}

// formats returns every text leak checks for values.
func formats(values ...any) []string {
	var texts []string
	for _, v := range values {
		forms := []any{v, struct{ V any }{v}, struct{ v any }{v}, []any{v}, map[string]any{"k": v}}
		if o, ok := own(v); ok {
			forms = append(forms, o, struct{ v any }{o})
		}
		for _, w := range forms {
			for _, verb := range leakVerbs {
				text := fmt.Sprintf(verb, w)
				texts = append(texts, text, unhex(text))
			}
		}
		if err, ok := v.(error); ok && err != nil {
			texts = append(texts, err.Error())
		}
	}
	return texts
}

// leakVerbs are the verbs leak formats with: the ones a type's Format method
// sees, and ones fmt reports as bad for most kinds, which print a raw dump.
var leakVerbs = []string{"%v", "%+v", "%#v", "%s", "%q", "%p", "%x", "%X", "%d",
	"%t", "%f", "%e", "%g", "%c", "%U"}

// own returns v, a struct or a pointer to one, converted to an unnamed struct
// type of the same fields, as an importer's "type mine hush.Scanner" would
// convert it: the same fields and none of the methods, so fmt dumps it raw.
// ok is false for any other value.
func own(v any) (_ any, ok bool) {
	rv := reflect.ValueOf(v)
	ptr := rv.Kind() == reflect.Pointer
	if ptr {
		if rv.IsNil() {
			return nil, false
		}
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct || rv.NumField() == 0 {
		return nil, false
	}
	fields := make([]reflect.StructField, rv.NumField())
	for i := range fields {
		fields[i] = rv.Type().Field(i)
		fields[i].Index, fields[i].Offset = nil, 0
	}
	plain := reflect.StructOf(fields)
	if ptr {
		return rv.Addr().Convert(reflect.PointerTo(plain)).Interface(), true
	}
	return rv.Convert(plain).Interface(), true
}

// unhex returns s with each run of hex digits decoded, dropping a run's first
// digit when the run is odd.
func unhex(s string) string {
	var b strings.Builder
	run := func(r string) {
		if len(r)%2 == 1 {
			r = r[1:]
		}
		d, _ := hex.DecodeString(r)
		b.Write(d)
		b.WriteByte(' ')
	}
	start := -1
	for i := 0; i <= len(s); i++ {
		if i < len(s) && strings.IndexByte("0123456789abcdefABCDEF", s[i]) >= 0 {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			run(s[start:i])
			start = -1
		}
	}
	return b.String()
}

// termFile writes content to a new term file of mode 0600 and returns its
// path, outside every directory a test scans.
func termFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "terms")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// adrTerms is the term file of ADR-001's negative tests 2, 7, 8 and 20: set
// clients holds quorvel and declares the first label, and set people holds
// zantoph and declares the second (leakcheck's labels stand for k7 and k8).
func adrTerms() string {
	return "[clients visible-to=" + lc.LabelA + "]\n" + lc.Quorvel + "\n" +
		"[people visible-to=" + lc.LabelB + "]\n" + lc.Zantoph + "\n"
}

// load loads content as a term file and fails t on an error.
func load(t *testing.T, content string) *TermSets {
	t.Helper()
	ts, err := LoadTermSets(termFile(t, content))
	if err != nil {
		t.Fatalf("LoadTermSets: %v", err)
	}
	return ts
}

// scanner returns New(cfg) and fails t on an error.
func scanner(t *testing.T, cfg Config) *Scanner {
	t.Helper()
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

// client returns the client destination for label.
func client(t *testing.T, label string) Destination {
	t.Helper()
	d, err := Client(label)
	if err != nil {
		t.Fatalf("Client: %v", err)
	}
	return d
}

// write creates the file name below dir with content.
func write(t *testing.T, dir, name, content string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// gitRepo makes a repository in a new temporary directory and returns it with
// a function that runs git there.
func gitRepo(t *testing.T) (string, func(args ...string) string) {
	t.Helper()
	dir := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("git %s failed", args[0])
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q")
	return dir, git
}

// plain returns rep's findings in the plain format.
func plain(t *testing.T, rep *Report) string {
	t.Helper()
	var b strings.Builder
	if err := rep.WritePlain(&b); err != nil {
		t.Fatalf("WritePlain: %v", err)
	}
	return b.String()
}

// code returns err's code, or "" when err is not an *Error.
func code(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code()
	}
	return ""
}

// errorsAs is errors.As, for tests that only need the target filled.
func errorsAs(err error, target any) bool { return errors.As(err, target) }
