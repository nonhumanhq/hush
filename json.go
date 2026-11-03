package hush

import (
	"bytes"
	"encoding/json"
	"io"
)

// Target is the kind of input a scan read, as the JSON document's target
// field names it.
type Target uint8

// The targets. The zero value is not one.
const (
	TargetTree  Target = iota + 1 // ScanTree
	TargetIndex                   // ScanIndex
	TargetStdin                   // ScanBytes and ScanReader
	TargetRange                   // ScanRange
)

// String returns "tree", "index", "stdin" or "range", or "" for the zero
// value.
func (t Target) String() string {
	switch t {
	case TargetTree:
		return "tree"
	case TargetIndex:
		return "index"
	case TargetStdin:
		return "stdin"
	case TargetRange:
		return "range"
	}
	return ""
}

// schemaID is the JSON document's schema identifier and major number
// (ADR-001 section 6.3).
const schemaID = "hush.scan/1"

// document is the JSON document. Its fields are in the schema's order, which
// encoding/json keeps, and each optional field is left out when it is absent
// (HSH-11/D7).
type document struct {
	Schema      string         `json:"schema"`
	Hush        string         `json:"hush"`
	Result      string         `json:"result"`
	Exit        int            `json:"exit"`
	Destination string         `json:"destination"`
	Coverage    string         `json:"coverage"`
	Tiers       []string       `json:"tiers"`
	Sets        []string       `json:"sets,omitempty"`
	Target      string         `json:"target"`
	Scanned     *counts        `json:"scanned,omitempty"`
	Findings    *[]jsonFinding `json:"findings,omitempty"`
	Error       *jsonError     `json:"error,omitempty"`
}

type counts struct {
	Files   int `json:"files"`
	Commits int `json:"commits"`
	Lines   int `json:"lines"`
}

// jsonFinding is a Finding as the document writes it, with the fields of
// ADR-001 section 6.1 in its order.
type jsonFinding struct {
	Kind         string `json:"kind"`
	Tier         string `json:"tier,omitempty"`
	Rule         string `json:"rule"`
	InPath       bool   `json:"in_path,omitempty"`
	Commit       string `json:"commit,omitempty"`
	Tag          string `json:"tag,omitempty"`
	Part         string `json:"part,omitempty"`
	Path         string `json:"path,omitempty"`
	PathRedacted *bool  `json:"path_redacted,omitempty"`
	Label        string `json:"label,omitempty"`
	Line         int    `json:"line"`
	Where        string `json:"where"`
}

type jsonError struct {
	Code     string `json:"code"`
	Message  string `json:"message"`
	Argument int    `json:"argument,omitempty"`
	Line     int    `json:"line,omitempty"`
	Commit   string `json:"commit,omitempty"`
}

// WriteJSON writes the report as one JSON document of ADR-001 section 6.3,
// on one line ended by a newline, with a single write: result "clean" and
// exit 0, or "findings" and exit 1. The error is ErrOutput when w fails, and
// ErrUsage for a report no scan made.
func (r *Report) WriteJSON(w io.Writer) (err error) {
	defer recoverError(&err, nil)
	if r == nil || !r.done || w == nil || r.target.String() == "" {
		return newError(CodeUsage, msgNoReport, 0)
	}
	doc := r.dest.document(r.coverage, r.target)
	doc.Result, doc.Exit = "clean", 0
	if len(r.findings) > 0 {
		doc.Result, doc.Exit = "findings", 1
	}
	doc.Tiers = nil
	for _, t := range r.Tiers() {
		doc.Tiers = append(doc.Tiers, t.String())
	}
	if len(r.sets) > 0 {
		doc.Sets = r.sets
	}
	doc.Scanned = &counts{r.counts.Files, r.counts.Commits, r.counts.Lines}
	list := make([]jsonFinding, 0, len(r.findings))
	for _, f := range r.findings {
		list = append(list, f.json())
	}
	doc.Findings = &list
	return writeDocument(w, doc)
}

// json returns f as the document writes it.
func (f Finding) json() jsonFinding {
	j := jsonFinding{Kind: f.Kind.String(), Tier: f.Tier.String(), Rule: f.Rule, InPath: f.InPath,
		Commit: f.Commit, Tag: f.Tag, Part: f.Part.String(), Path: f.Path, Label: f.Label,
		Line: f.Line, Where: f.Where()}
	if f.Path != "" {
		redacted := f.PathRedacted
		j.PathRedacted = &redacted
	}
	return j
}

// WriteErrorJSON writes the JSON document for a run that ended in err,
// through the same writer as Report.WriteJSON, with result "error", exit 2,
// no tiers, and err's code, message, argument, term-file line and commit. The
// command line uses it for every error after the destination and the target
// have been parsed (ADR-001 section 6.3). An err that is not a *Error,
// including nil and *FindingsError, is written as code "internal" with the
// fixed message and is never formatted. A zero Destination writes nothing and
// returns ErrDestination; a zero Coverage or Target writes nothing and returns
// ErrUsage. The error is ErrOutput when w fails.
func WriteErrorJSON(w io.Writer, d Destination, c Coverage, t Target, err error) (werr error) {
	defer recoverError(&werr, nil)
	switch {
	case d.class == classNone:
		return newError(CodeDestination, msgNoDestination, 0)
	case c.String() == "" || t.String() == "" || w == nil:
		return newError(CodeUsage, msgNoDocument, 0)
	}
	e, ok := err.(*Error)
	if !ok || e == nil {
		e = errInternal()
	}
	doc := d.document(c, t)
	doc.Result, doc.Exit = "error", 2
	doc.Error = &jsonError{Code: string(e.code), Message: e.msg, Argument: e.arg, Line: e.line, Commit: e.commit}
	return writeDocument(w, doc)
}

// document returns the fields every document shares: the destination's class
// only, never a client label.
func (d Destination) document(c Coverage, t Target) document {
	return document{Schema: schemaID, Hush: Version(), Destination: d.String(), Coverage: c.String(),
		Tiers: []string{}, Target: t.String()}
}

// writeDocument encodes doc on one line, without HTML escaping, and writes it to w at
// once.
func writeDocument(w io.Writer, doc document) error {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if enc.Encode(doc) != nil {
		return errInternal()
	}
	if n, err := w.Write(b.Bytes()); err != nil || n != b.Len() {
		return newError(CodeOutput, msgOutput, 0)
	}
	return nil
}
