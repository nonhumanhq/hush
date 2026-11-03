// Package output writes the interim scanner's plain format: one finding per
// line, "WHERE:LINE: RULE", and one error line on standard error.
package output

import (
	"bufio"
	"io"
	"strconv"
)

// Prefix starts every error line. It keeps the interim scanner's name so that
// standard error stays byte-identical (HSH-5/D4).
const Prefix = "hush-interim: "

// Writer prints findings and counts them. Call Flush when the scan ends.
type Writer struct {
	w     *bufio.Writer
	Found int
}

// New returns a Writer that prints to w.
func New(w io.Writer) *Writer { return &Writer{w: bufio.NewWriter(w)} }

// Finding prints one finding. where is already redacted.
func (o *Writer) Finding(where string, line int, rule string) {
	o.w.WriteString(Line(where, line, rule) + "\n")
	o.Found++
}

// Line returns one finding in the plain format, "WHERE:LINE: RULE", without
// its newline (ADR-001 section 6.2). rule already ends in " in path" when the
// path itself broke the rule. where is already redacted.
func Line(where string, line int, rule string) string {
	return where + ":" + strconv.Itoa(line) + ": " + rule
}

// Flush writes any buffered findings.
func (o *Writer) Flush() error { return o.w.Flush() }

// Error prints msg as an error line.
func Error(w io.Writer, msg string) { io.WriteString(w, Prefix+msg+"\n") }
