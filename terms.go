package hush

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/nonhumanhq/hush/internal/rule"
	"github.com/nonhumanhq/hush/internal/termset"
)

// MaxTermFileSize is the largest term file LoadTermSets reads, in bytes. A
// larger one is refused with ErrRead (HSH-11/D4).
const MaxTermFileSize = 1 << 20

// MaxInputSize is the largest buffer or stream ScanBytes and ScanReader scan,
// in bytes. A larger one is refused with ErrRead; nothing is ever skipped
// (HSH-11/D4).
const MaxInputSize = 64 << 20

// TermSets is the private tier: the sets of one term file, in ADR-002's
// format 1, held in memory. Load it with LoadTermSets. No method returns,
// prints, logs or encodes a term or a client label: String, Format, GoString
// and LogValue print "hush.TermSets(N sets)", and MarshalJSON, MarshalText and
// GobEncode always return an error. A TermSets not returned by LoadTermSets,
// such as new(TermSets), makes New return ErrTermFile.
type TermSets struct {
	// sets holds the sets, and path the file's absolute path, which tree
	// scans refuse to enter. Each is boxed so that fmt's raw dump, which %p
	// and every verb a type does not take print, shows an address at any
	// depth (HSH-11/D38).
	sets *box[termset.Sets]
	path *box[string]
}

// LoadTermSets reads the term file at path, the only way terms enter hush. The
// file must be a regular file once symlinks are followed, readable, neither
// readable nor writable by group or others, and at most MaxTermFileSize bytes.
// It must follow format 1, and every set name and client label must pass
// ADR-002 section 1.4's load-time checks. The error is an *Error with code
// term-file, or read for an over-size file. It never names the path, a term,
// a set name or a label; a line number is its only detail.
func LoadTermSets(path string) (t *TermSets, err error) {
	defer recoverError(&err, func() { t = nil })
	abs, err := filepath.Abs(path)
	if err != nil || path == "" {
		return nil, newError(CodeTermFile, msgTermMissing, 0)
	}
	data, err := readTermFile(abs)
	if err != nil {
		return nil, err
	}
	sets, err := termset.Parse(data)
	if err == nil {
		generic := rule.Registry(nil)
		err = sets.CheckNames(func(name []byte) bool {
			return len(generic.Check(name, rule.Context{Source: rule.Text})) > 0
		})
	}
	var pe *termset.ParseError
	switch {
	case errors.As(err, &pe) && pe.Reason == termset.NoTerms:
		return nil, newError(CodeTermFile, msgTermNoTerms, 0)
	case errors.As(err, &pe) && pe.Line > 0:
		e := newError(CodeTermFile, msgTermLine+pe.Reason.String(), pe.Line)
		e.line = pe.Line
		return nil, e
	case err != nil:
		return nil, errInternal()
	}
	return &TermSets{sets: newBox(sets), path: newBox(&abs)}, nil
}

// readTermFile reads the file at path, which is absolute, under
// LoadTermSets's conditions. The file is opened without blocking, so a FIFO
// put in its place after the first check cannot stall the read, and the
// conditions are checked again on the opened file.
func readTermFile(path string) ([]byte, error) {
	if err := termFileOK(os.Stat(path)); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, newError(CodeTermFile, msgTermMissing, 0)
	}
	defer f.Close()
	if err := termFileOK(f.Stat()); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxTermFileSize+1))
	switch {
	case err != nil:
		return nil, newError(CodeTermFile, msgTermMissing, 0)
	case len(data) > MaxTermFileSize:
		return nil, newError(CodeRead, msgTermTooLarge, 0)
	}
	return data, nil
}

// termFileOK checks what os.Stat or File.Stat says of the term file.
func termFileOK(fi os.FileInfo, err error) error {
	switch {
	case err != nil:
		return newError(CodeTermFile, msgTermMissing, 0)
	case !fi.Mode().IsRegular():
		return newError(CodeTermFile, msgTermNotRegular, 0)
	case fi.Mode().Perm()&0o066 != 0:
		return newError(CodeTermFile, msgTermMode, 0)
	case fi.Size() > MaxTermFileSize:
		return newError(CodeRead, msgTermTooLarge, 0)
	}
	return nil
}

// loaded reports whether t came from LoadTermSets.
func (t *TermSets) loaded() bool { return t != nil && t.sets != nil && t.path != nil }

// Names returns the set names, in file order. Set names are printed in
// findings, so they are safe to print; client labels are not, and no method
// returns them.
func (t *TermSets) Names() []string {
	if !t.loaded() {
		return nil
	}
	names := make([]string, t.sets.get().Len())
	for i := range names {
		names[i] = t.sets.get().Name(i)
	}
	return names
}

func (t TermSets) summary() string {
	n := 0
	if t.sets != nil {
		n = t.sets.get().Len()
	}
	return "hush.TermSets(" + strconv.Itoa(n) + " sets)"
}

var errEncodeTermSets = errors.New("hush: TermSets cannot be encoded")

// String returns the fixed summary.
func (t TermSets) String() string { return t.summary() }

// Format prints the fixed summary for every verb.
func (t TermSets) Format(f fmt.State, _ rune) { fmt.Fprint(f, t.summary()) }

// GoString returns the fixed summary.
func (t TermSets) GoString() string { return t.summary() }

// LogValue returns the fixed summary.
func (t TermSets) LogValue() slog.Value { return slog.StringValue(t.summary()) }

// MarshalJSON returns an error.
func (TermSets) MarshalJSON() ([]byte, error) { return nil, errEncodeTermSets }

// MarshalText returns an error.
func (TermSets) MarshalText() ([]byte, error) { return nil, errEncodeTermSets }

// GobEncode returns an error.
func (TermSets) GobEncode() ([]byte, error) { return nil, errEncodeTermSets }
