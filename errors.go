package hush

import (
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
)

// Code is the class of an Error, shared by Error.Code and the JSON document's
// error.code field (ADR-001 section 7).
type Code string

// The codes of ADR-001 section 7's table.
const (
	CodeUsage       Code = "usage"
	CodeDestination Code = "destination"
	CodeCoverage    Code = "coverage"
	CodeTermFile    Code = "term-file"
	CodeLabel       Code = "label"
	CodeUnknownSet  Code = "unknown-set"
	CodeUnknownRule Code = "unknown-rule"
	CodePath        Code = "path"
	CodeGit         Code = "git"
	CodeRange       Code = "range"
	CodeEmptyRange  Code = "empty-range"
	CodeRead        Code = "read"
	CodeOutput      Code = "output"
	CodeInterrupted Code = "interrupted"
	CodeInternal    Code = "internal"
)

// Error is every failure other than findings: a code and a fixed message, with
// integers and object ids as its only parameters. It holds no scanned text, no
// term, no path and no argument value, and it wraps no other error: it has no
// Unwrap (ADR-001 section 6.6).
type Error struct {
	code   Code
	msg    string
	arg    int
	line   int
	commit string
}

// Error returns the fixed message, without the "hush: " the command line
// prints before it.
func (e *Error) Error() string { return e.msg }

// Code returns the error's code.
func (e *Error) Code() Code { return e.code }

// Argument returns the 1-based position of the argument the error concerns,
// or 0.
func (e *Error) Argument() int { return e.arg }

// Line returns the term-file line the error concerns, or 0.
func (e *Error) Line() int { return e.line }

// Commit returns the full object id of the commit the error concerns, or "".
func (e *Error) Commit() string { return e.commit }

// Is reports whether target is the sentinel for the error's code, such as
// ErrUsage, so that errors.Is(err, hush.ErrUsage) works.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.code == e.code
}

// The sentinels, one per code, for errors.Is. Each is an *Error whose message
// is its code. ErrFindings matches every *FindingsError.
var (
	ErrFindings          = errors.New("hush: findings")
	ErrUsage       error = sentinel(CodeUsage)
	ErrDestination error = sentinel(CodeDestination)
	ErrCoverage    error = sentinel(CodeCoverage)
	ErrTermFile    error = sentinel(CodeTermFile)
	ErrLabel       error = sentinel(CodeLabel)
	ErrUnknownSet  error = sentinel(CodeUnknownSet)
	ErrUnknownRule error = sentinel(CodeUnknownRule)
	ErrPath        error = sentinel(CodePath)
	ErrGit         error = sentinel(CodeGit)
	ErrRange       error = sentinel(CodeRange)
	ErrEmptyRange  error = sentinel(CodeEmptyRange)
	ErrRead        error = sentinel(CodeRead)
	ErrOutput      error = sentinel(CodeOutput)
	ErrInterrupted error = sentinel(CodeInterrupted)
	ErrInternal    error = sentinel(CodeInternal)
)

func sentinel(c Code) *Error { return &Error{code: c, msg: string(c)} }

// The message table (HSH-11/D11). Every message an *Error carries is one of
// these, with "#" standing for an integer and "@" for a commit's first twelve
// characters; a term-file line's reason comes from ADR-002 section 1.5's table.
// None names a value the caller passed, a path or scanned text.
const (
	msgNoContext        = "no context given"
	msgNoScanner        = "the scanner was not made by New"
	msgNoReport         = "no report"
	msgIdentitiesBuilt  = "the identities were not made by NewIdentities"
	msgIdentitiesEmpty  = "identities: no address given"
	msgIdentityBad      = "identities: address # is malformed"
	msgRepoDir          = "no repository directory given"
	msgNoDestination    = "no destination given"
	msgUnknownDest      = "unknown destination"
	msgBadClientLabel   = "malformed client label"
	msgClientRefused    = "client label refused"
	msgClientUndeclared = "the client label is not declared in the term file"
	msgPublicCoverage   = "the public destination needs --terms FILE or --generic-only"
	msgClientCoverage   = "a client destination needs --terms FILE"
	msgGenericOnlyDest  = "--generic-only is accepted only with the public destination"
	msgGenericAndTerms  = "--generic-only cannot be combined with --terms"
	msgPrivateTerms     = "the private destination takes no term file"
	msgNoTermApplies    = "no term applies to this destination"
	msgTermMissing      = "term file: missing or unreadable"
	msgTermNotRegular   = "term file: not a regular file"
	msgTermMode         = "term file: readable or writable by group or others"
	msgTermLine         = "term file: line #: " // followed by a reason
	msgTermNoTerms      = "term file holds no terms"
	msgTermNotLoaded    = "the term sets were not loaded by LoadTermSets"
	msgTermInside       = "the term file is inside a scanned path"
	msgTermTooLarge     = "term file: over the size limit"
	msgLabelRefused     = "stdin label refused"
	msgPathMissing      = "path argument # does not exist"
	msgPathUnwalkable   = "cannot walk path argument #"
	msgPathUnresolved   = "cannot resolve path argument #"
	msgRootNotDir       = "the scan root is not a directory"
	msgNotRepository    = "not a git repository"
	msgCommitUnreadable = "cannot read commit @"
	msgDiffFailed       = "cannot diff commit @"
	msgIndexUnreadable  = "cannot read the index"
	msgIndexFile        = "the index file is missing or not a regular file"
	msgRangeWord        = "range: word # is refused"
	msgRangeRevision    = "range: revision # is refused"
	msgRangeSelector    = "range: selector # is unknown"
	msgRangeNothing     = "range: nothing to include"
	msgRangeResolve     = "range: the revisions do not resolve"
	msgEmptyRange       = "the range holds no commits"
	msgStdinUnreadable  = "cannot read standard input"
	msgTooLarge         = "input over the size limit"
	msgOutput           = "cannot write output"
	msgInterrupted      = "interrupted"
	msgInternal         = "internal error; output withheld"
)

// newError returns an *Error with code c and message msg, in which the first
// "#" is replaced by n when n is not 0.
func newError(c Code, msg string, n int) *Error {
	e := &Error{code: c, msg: msg}
	if n != 0 {
		e.msg = replaceOnce(msg, "#", strconv.Itoa(n))
	}
	return e
}

// argError is newError for a message about the n-th argument or path argument.
func argError(c Code, msg string, n int) *Error {
	e := newError(c, msg, n)
	e.arg = n
	return e
}

// commitError returns an *Error about the commit id, which the message names
// by its first twelve characters.
func commitError(c Code, msg, id string) *Error {
	short := id
	if len(short) > 12 {
		short = short[:12]
	}
	return &Error{code: c, msg: replaceOnce(msg, "@", short), commit: id}
}

func replaceOnce(s, old, new string) string { return strings.Replace(s, old, new, 1) }

// errInternal is the fixed internal error, made afresh so that no caller can
// change a shared value.
func errInternal() *Error { return newError(CodeInternal, msgInternal, 0) }

// FindingsError is the error a scan returns when it completed and found
// something. Its report is the same one the scan returns. It holds the report
// through an unexported field, so it carries its own formatting guards: every
// verb, GoString and LogValue print its Error text, and MarshalJSON,
// MarshalText and GobEncode return an error (ADR-001 section 6.6).
type FindingsError struct {
	report *Report
}

// Error returns "hush: N findings". It names no location.
func (e *FindingsError) Error() string {
	if e == nil {
		return FindingsError{}.text()
	}
	return e.text()
}

func (e FindingsError) text() string {
	n := 0
	if e.report != nil {
		n = len(e.report.findings)
	}
	return "hush: " + strconv.Itoa(n) + " findings"
}

var errEncodeFindings = errors.New("hush: FindingsError cannot be encoded")

// Format prints the Error text for every verb.
func (e FindingsError) Format(f fmt.State, _ rune) { fmt.Fprint(f, e.text()) }

// GoString returns the Error text.
func (e FindingsError) GoString() string { return e.text() }

// LogValue returns the Error text.
func (e FindingsError) LogValue() slog.Value { return slog.StringValue(e.text()) }

// MarshalJSON returns an error.
func (FindingsError) MarshalJSON() ([]byte, error) { return nil, errEncodeFindings }

// MarshalText returns an error.
func (FindingsError) MarshalText() ([]byte, error) { return nil, errEncodeFindings }

// GobEncode returns an error.
func (FindingsError) GobEncode() ([]byte, error) { return nil, errEncodeFindings }

// Is reports whether target is ErrFindings.
func (e *FindingsError) Is(target error) bool { return target == ErrFindings }

// Report returns the scan's report. It is never nil: a FindingsError not made
// by a scan gives an empty report, which is not clean.
func (e *FindingsError) Report() *Report {
	if e == nil || e.report == nil {
		return &Report{}
	}
	return e.report
}

// ExitCode returns the exit status for err: 0 for nil, 1 for findings
// (errors.Is(err, ErrFindings)), and 2 for anything else.
func ExitCode(err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, ErrFindings):
		return 1
	}
	return 2
}
