package hush

import (
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	lc "github.com/nonhumanhq/hush/internal/leakcheck"
)

// LoadTermSets loads a format 1 file and keeps its set names in file order.
func TestLoadTermSets(t *testing.T) {
	ts := load(t, lc.TermSetFile())
	want := []string{"clients", "clients-k", "people", "abbreviations", "abbreviations-exact"}
	if !slices.Equal(ts.Names(), want) {
		t.Errorf("Names() = %v", ts.Names())
	}
	if (*TermSets)(nil).Names() != nil || new(TermSets).Names() != nil {
		t.Error("an unloaded TermSets has names")
	}
	leak(t, ts, *ts, ts.Names())
	// The path is not synthetic, so the leak check cannot see it: look for
	// the term file's directory in a raw dump (HSH-11/D38).
	dir := filepath.Dir(*ts.path.get())
	cfg := Config{Destination: Public(), Terms: ts}
	s := scanner(t, cfg)
	for _, text := range formats(ts, *ts, struct{ T TermSets }{*ts}, cfg, &cfg, s, *s) {
		if strings.Contains(text, dir) {
			t.Errorf("the term file's path was printed: %d bytes", len(text))
		}
	}
}

// ADR-001 section 5's term-file conditions, in the API: missing, not a regular
// file once symlinks are followed, unreadable, and the parser's and the
// load-time checks' refusals with their line. No error names the path.
func TestLoadTermSetsRefusals(t *testing.T) {
	dir := t.TempDir()
	good := termFile(t, adrTerms())
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.Symlink(good, filepath.Join(dir, "link")))
	must(os.Symlink(filepath.Join(dir, "nowhere"), filepath.Join(dir, "dangling")))
	must(os.Mkdir(filepath.Join(dir, "adir"), 0o700))
	must(syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o600))
	must(os.Symlink(filepath.Join(dir, "fifo"), filepath.Join(dir, "fifolink")))
	unreadable := termFile(t, adrTerms())
	must(os.Chmod(unreadable, 0o200))

	if _, err := LoadTermSets(filepath.Join(dir, "link")); err != nil {
		t.Errorf("a symlink to a good file is refused: %v", err)
	}
	cases := []struct {
		path string
		msg  string
	}{
		{"", "term file: missing or unreadable"},
		{filepath.Join(dir, "missing"), "term file: missing or unreadable"},
		{filepath.Join(dir, "dangling"), "term file: missing or unreadable"},
		{filepath.Join(dir, "adir"), "term file: not a regular file"},
		{filepath.Join(dir, "fifo"), "term file: not a regular file"},
		{filepath.Join(dir, "fifolink"), "term file: not a regular file"},
		{"/dev/null", "term file: not a regular file"},
		{termFile(t, ""), "term file holds no terms"},
		{termFile(t, "# only a comment\n"), "term file holds no terms"},
		{termFile(t, "[people]\n"+lc.Zantoph+"\n[two words]\n"), "term file: line 3: bad attribute"},
		{termFile(t, lc.Quorvel+"\n"), "term file: line 1: term outside a set"},
		// The load-time checks of ADR-002 section 1.4 (negative test 6).
		{termFile(t, "[people]\n"+lc.Quorvel+"\n["+lc.Quorvel+"-notes]\n"+lc.Zantoph+"\n"), "term file: line 3: set name refused"},
		{termFile(t, "[people]\n"+lc.Zantoph+"\n["+lc.RefusedNames[0]+"]\n"+lc.Mirelda+"\n"), "term file: line 3: set name refused"},
		{termFile(t, "[people visible-to=k"+lc.Zantoph+"]\n"+lc.Zantoph+"\n"), "term file: line 1: client label refused"},
	}
	if os.Geteuid() != 0 { // root reads a file of mode 0200
		cases = append(cases, struct{ path, msg string }{unreadable, "term file: missing or unreadable"})
	}
	for i, c := range cases {
		ts, err := LoadTermSets(c.path)
		wantError(t, err, CodeTermFile)
		if ts != nil || err == nil || err.Error() != c.msg {
			t.Errorf("case %d: got %v, want %q", i, err, c.msg)
			continue
		}
		var e *Error
		if asError(err, &e); strings.Contains(c.msg, "line") != (e.Line() > 0) {
			t.Errorf("case %d: Line() = %d", i, e.Line())
		}
		if c.path != "" && strings.Contains(err.Error(), filepath.Dir(c.path)) {
			t.Errorf("case %d: the error names the file", i)
		}
	}
}

// ADR-001 negative test 20, in the API: LoadTermSets refuses a term file that
// group or others can read or write, by the mode of the file once symlinks are
// followed, and loads it at 0600, also through a symlink.
func TestNegative20Permissions(t *testing.T) {
	p := termFile(t, adrTerms())
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o620, 0o602, 0o666, 0o660} {
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{p, link} {
			ts, err := LoadTermSets(path)
			wantError(t, err, CodeTermFile)
			if ts != nil || err == nil || err.Error() != "term file: readable or writable by group or others" {
				t.Errorf("mode %o: got %v", mode, err)
			}
		}
	}
	for _, mode := range []os.FileMode{0o600, 0o400, 0o700, 0o611} {
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{p, link} {
			if _, err := LoadTermSets(path); err != nil {
				t.Errorf("mode %o: %v", mode, err)
			}
		}
	}
}

// ADR-002 section 1.1 and HSH-11/D4: a term file over the size limit exits 2
// with code read and no line number, and one at the limit loads.
func TestTermFileTooLarge(t *testing.T) {
	head := "[people]\n" + lc.Zantoph + "\n#"
	at := head + strings.Repeat("x", MaxTermFileSize-len(head)-1) + "\n"
	if _, err := LoadTermSets(termFile(t, at)); err != nil {
		t.Errorf("a file of exactly the limit is refused: %v", err)
	}
	ts, err := LoadTermSets(termFile(t, at+"\n"))
	wantError(t, err, CodeRead)
	var e *Error
	if ts != nil || !asError(err, &e) || e.Error() != "term file: over the size limit" || e.Line() != 0 {
		t.Errorf("got %v", err)
	}
}

// ADR-001 section 6.6: TermSets prints, logs and encodes no term, set name or
// label (negative test 6's TermSets point).
func TestTermSetsGuards(t *testing.T) {
	ts := load(t, lc.TermSetFile())
	var log strings.Builder
	slog.New(slog.NewTextHandler(&log, nil)).Info("load", "terms", ts, "value", *ts)
	cfg := Config{Destination: Public(), Terms: ts}
	texts := []string{log.String()}
	for _, v := range []any{ts, *ts, cfg, &cfg, []*TermSets{ts}, map[string]TermSets{"t": *ts}} {
		texts = append(texts, fmt.Sprintf("%v %+v %#v %s %q %x %d", v, v, v, v, v, v, v))
	}
	for _, s := range texts {
		if strings.Contains(s, "clients") || strings.Contains(s, "people") {
			t.Error("a set name was printed")
		}
	}
	if !strings.Contains(texts[1], "hush.TermSets(5 sets)") {
		t.Error("the summary is missing")
	}
	for i, enc := range []func() error{
		func() error { _, err := json.Marshal(ts); return err },
		func() error { _, err := json.Marshal(cfg); return err },
		func() error { _, err := ts.MarshalText(); return err },
		func() error { return gob.NewEncoder(&strings.Builder{}).Encode(ts) },
	} {
		if err := enc(); err == nil {
			t.Errorf("encoder %d succeeded", i)
		} else {
			leak(t, err)
		}
	}
	leak(t, texts, ts, *ts, cfg, &cfg, []*TermSets{ts}, map[string]TermSets{"t": *ts})
}

func asError(err error, e **Error) bool { return errors.As(err, e) }
