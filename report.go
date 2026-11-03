package hush

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/nonhumanhq/hush/internal/output"
	"github.com/nonhumanhq/hush/internal/rule"
	"github.com/nonhumanhq/hush/internal/target"
)

// Kind is what a finding reports.
type Kind uint8

// The kinds. The zero value is not one.
const (
	Match     Kind = iota + 1 // a generic rule or a set matched
	Unscanned                 // the file or input was not scanned: binary-unscanned or unreadable
)

// String returns "match" or "unscanned", or "" for the zero value.
func (k Kind) String() string {
	switch k {
	case Match:
		return "match"
	case Unscanned:
		return "unscanned"
	}
	return ""
}

// Part is the part of a commit or tag object a finding is in.
type Part uint8

// The parts. The zero value means the finding is not in an object.
const (
	Author    Part = iota + 1 // the author header
	Committer                 // the committer header
	Tagger                    // the tagger header
	Header                    // any other header that is scanned
	Message                   // the message
)

// String returns the part as the JSON document writes it, such as "author",
// or "" for the zero value.
func (p Part) String() string {
	switch p {
	case Author:
		return "author"
	case Committer:
		return "committer"
	case Tagger:
		return "tagger"
	case Header:
		return "header"
	case Message:
		return "message"
	}
	return ""
}

// Counts is what a scan scanned: tree files, index entries with a blob and
// each path a commit adds or changes (Files); commits walked (Commits); and
// every line scanned, object lines included (Lines).
type Counts struct {
	Files   int // tree files, index entries with a blob, and paths a commit adds or changes
	Commits int // commits walked
	Lines   int // lines scanned
}

// Finding is one finding: where, and which rule or set. It never holds the
// matched text, a column, which term matched, a client label or an unredacted
// path (ADR-001 section 6.1). A scan builds every Finding it returns through
// one constructor, from redaction and the rule registry.
type Finding struct {
	Kind         Kind   // Match or Unscanned
	Tier         Tier   // TierGeneric or TierPrivate, for matches
	Rule         string // "id-prefix", "ip-address", "email-address", "set:NAME", "binary-unscanned" or "unreadable"
	InPath       bool   // the path itself broke the rule, not the content
	Commit       string // the commit's full object id, for findings in a commit
	Tag          string // the annotated tag object's full object id, for findings in a tag object
	Part         Part   // for findings in a commit or tag object
	Path         string // for file findings: slash-separated, already redacted
	PathRedacted bool   // Path holds the placeholder "<redacted>"
	Label        string // for standard input and buffer findings: the checked stdin label, or "<stdin>"
	Line         int    // 1-based, or 0 for the path or the whole file
}

// Where returns the finding's location as the plain format prints it: a path,
// "SHA12:PATH", "SHA12:(commit)", "SHA12:(tag)" or a label.
func (f Finding) Where() string {
	switch {
	case f.Tag != "":
		return shortID(f.Tag) + ":(tag)"
	case f.Commit != "" && f.Path != "":
		return shortID(f.Commit) + ":" + f.Path
	case f.Commit != "":
		return shortID(f.Commit) + ":(commit)"
	case f.Path != "":
		return f.Path
	}
	return f.Label
}

// String returns the finding as one line of the plain format, without its
// newline: "WHERE:LINE: RULE", with " in path" after the rule for InPath.
func (f Finding) String() string {
	name := f.Rule
	if f.InPath {
		name += " in path"
	}
	return output.Line(f.Where(), f.Line, name)
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// unscannedNames are the two rule names a finding may have besides the
// registry's and the sets' (ADR-001 section 6.1).
var unscannedNames = map[string]bool{"binary-unscanned": true, "unreadable": true}

// finding is the one constructor of Finding (ADR-001 section 6.6). It runs the
// output check, that raw.Rule is a rule in the scanner's registry, a loaded
// set or one of the two unscanned names, and redacts the path. ok is false
// when the check fails.
func (s *Scanner) finding(raw target.Finding) (f Finding, ok bool) {
	switch name, isSet := strings.CutPrefix(raw.Rule, "set:"); {
	case isSet && s.sets != nil && s.hasSet(name):
		f.Kind, f.Tier = Match, TierPrivate
	case !isSet && s.hasRule(raw.Rule):
		f.Kind, f.Tier = Match, TierGeneric
	case !isSet && unscannedNames[raw.Rule] && !raw.InPath:
		f.Kind = Unscanned
	default:
		return Finding{}, false
	}
	f.Rule, f.InPath, f.Line = raw.Rule, raw.InPath, raw.Line
	switch raw.Loc {
	case target.InTree, target.InIndex:
		f.Path, f.PathRedacted = s.redact(raw.Path)
	case target.InStdin:
		f.Label = raw.Label
	case target.InCommit:
		f.Commit, f.Part = raw.Commit, part(raw.Part)
		if f.Part == 0 {
			return Finding{}, false
		}
	case target.InDiff:
		f.Commit = raw.Commit
		f.Path, f.PathRedacted = s.redact(raw.Path)
	default:
		return Finding{}, false
	}
	if raw.Loc != target.InStdin && raw.Loc != target.InCommit && f.Path == "" {
		return Finding{}, false
	}
	return f, true
}

func (s *Scanner) hasRule(name string) bool {
	for _, r := range *s.rules.get() {
		if r.Name() == name {
			return true
		}
	}
	return false
}

func (s *Scanner) hasSet(name string) bool {
	for i := 0; i < s.sets.get().Len(); i++ {
		if s.sets.get().Name(i) == name {
			return true
		}
	}
	return false
}

func part(p rule.Part) Part {
	switch p {
	case rule.Author:
		return Author
	case rule.Committer:
		return Committer
	case rule.Tagger:
		return Tagger
	case rule.Header:
		return Header
	case rule.Message:
		return Message
	}
	return 0
}

// redact returns path as a finding holds it (ADR-001 section 6.4): unchanged
// when no generic rule and no loaded set matches anywhere in it and every
// component prints safely; otherwise cut from the component that holds the
// earliest byte where a match begins or an unsafe character stands, which
// prints as one "<redacted>". Every loaded set counts, including those the
// destination exempts.
func (s *Scanner) redact(path string) (string, bool) {
	start := s.rules.get().Start([]byte(path), rule.Context{Source: rule.Path, Path: path})
	if s.sets != nil {
		if _, at := s.sets.get().Match([]byte(path), s.all); at >= 0 && (start < 0 || at < start) {
			start = at
		}
	}
	if at := unsafeAt(path); at >= 0 && (start < 0 || at < start) {
		start = at
	}
	if start < 0 {
		return path, false
	}
	return rule.Redact(path, start), true
}

// unsafeAt returns the offset of the first byte of path that cannot print
// safely, or -1: a control character, a byte that is not valid UTF8, a line
// or paragraph separator, or a format character, which includes the bidi
// controls (ADR-001 section 5).
func unsafeAt(path string) int {
	for i, r := range path {
		switch {
		case r == utf8.RuneError:
			if _, n := utf8.DecodeRuneInString(path[i:]); n <= 1 {
				return i
			}
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r), r == ' ', r == ' ':
			return i
		}
	}
	return -1
}

// Report is the result of a scan that completed. It is immutable, and its
// methods are safe on a nil receiver, which is never clean. Its String,
// Format, GoString and LogValue print "hush.Report(CLASS, N findings)" with
// the destination's class only; MarshalJSON, MarshalText and GobEncode return
// an error.
type Report struct {
	done     bool // made by a scan that completed
	findings []Finding
	dest     Destination
	coverage Coverage
	sets     []string // the sets that applied, or nil
	counts   Counts
}

// Clean reports whether the scan completed and found nothing.
func (r *Report) Clean() bool { return r != nil && r.done && len(r.findings) == 0 }

// Findings returns a copy of the findings, in output order (ADR-001 section
// 6.2).
func (r *Report) Findings() []Finding {
	if r == nil {
		return nil
	}
	return append([]Finding(nil), r.findings...)
}

// Destination returns the destination the scan checked.
func (r *Report) Destination() Destination {
	if r == nil {
		return Destination{}
	}
	return r.dest
}

// Coverage returns Complete or GenericOnly.
func (r *Report) Coverage() Coverage {
	if r == nil {
		return 0
	}
	return r.coverage
}

// Tiers returns the tiers that ran: TierGeneric, and TierPrivate when a set
// applied.
func (r *Report) Tiers() []Tier {
	if r == nil || !r.done {
		return nil
	}
	if len(r.sets) > 0 {
		return []Tier{TierGeneric, TierPrivate}
	}
	return []Tier{TierGeneric}
}

// Sets returns the names of the sets that applied, in file order, or nil when
// the private tier did not run.
func (r *Report) Sets() []string {
	if r == nil {
		return nil
	}
	return append([]string(nil), r.sets...)
}

// Scanned returns what the scan scanned.
func (r *Report) Scanned() Counts {
	if r == nil {
		return Counts{}
	}
	return r.counts
}

// WritePlain writes the findings to w in the plain format, one line each,
// with a single write. A clean report writes nothing. The error is ErrOutput
// when w fails, and ErrUsage for a nil report.
func (r *Report) WritePlain(w io.Writer) (err error) {
	defer recoverError(&err, nil)
	if r == nil || !r.done || w == nil {
		return newError(CodeUsage, msgNoReport, 0)
	}
	var b strings.Builder
	for _, f := range r.findings {
		b.WriteString(f.String() + "\n")
	}
	if b.Len() == 0 {
		return nil
	}
	if n, err := io.WriteString(w, b.String()); err != nil || n != b.Len() {
		return newError(CodeOutput, msgOutput, 0)
	}
	return nil
}

func (r Report) summary() string {
	return "hush.Report(" + r.dest.String() + ", " + strconv.Itoa(len(r.findings)) + " findings)"
}

var (
	errEncodeReport  = errors.New("hush: Report is written with WritePlain")
	errEncodeScanner = errors.New("hush: Scanner cannot be encoded")
)

// String returns the fixed summary.
func (r Report) String() string { return r.summary() }

// Format prints the fixed summary for every verb.
func (r Report) Format(f fmt.State, _ rune) { fmt.Fprint(f, r.summary()) }

// GoString returns the fixed summary.
func (r Report) GoString() string { return r.summary() }

// LogValue returns the fixed summary.
func (r Report) LogValue() slog.Value { return slog.StringValue(r.summary()) }

// MarshalJSON returns an error.
func (Report) MarshalJSON() ([]byte, error) { return nil, errEncodeReport }

// MarshalText returns an error.
func (Report) MarshalText() ([]byte, error) { return nil, errEncodeReport }

// GobEncode returns an error.
func (Report) GobEncode() ([]byte, error) { return nil, errEncodeReport }
