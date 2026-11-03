package main

import (
	"bytes"
	"context"
	"errors"
	"strings"

	"github.com/nonhumanhq/hush"
	"github.com/nonhumanhq/hush/internal/ghwrap"
)

const ghUsage = `usage: hush gh --destination DEST [--terms FILE | --generic-only]
               [--identities ADDR[,ADDR...]] -- GH-ARGUMENTS

Scans the text the gh command would post for DEST, as hush scan does, and runs
the real gh, found on PATH, only if the scan is clean, handing it exactly the
bytes it scanned. --destination, --terms, --generic-only and --identities are
hush scan's (see hush scan --help); each is given at most once, before --.

Scanned, then run:
  issue create|new, edit, comment, close, reopen
  pr create|new, edit, comment, review, close, reopen
  api
Scanned: --title, --body, --comment, the contents of --body-file (a file, or
standard input for -), and for api the endpoint, also with its percent-escapes
decoded and + read as a space in its query, each --raw-field and --field (a
value @FILE or @- is read) and the contents of --input, also with its JSON
escapes decoded. A finding names the
text by a label: title, body, body-file, comment, endpoint, endpoint-decoded,
input, input-decoded, or field-N and raw-field-N for the Nth field, as
body:3: id-prefix. gh gets a body file's contents on its standard input.

Run as given, with nothing to scan:
  issue list|ls|view|status, pr list|ls|view|status|checks|diff,
  run list|ls|view, repo view

Refused, exit 2: every other command, flags before the command, flags gh
2.101.0 does not document for the command, and the flags whose text hush gh
cannot see: --editor, --web, --attach, --recover, --template, --fill,
--fill-first and --fill-verbose. Also refused: any scanned text that holds a
NUL byte, a second --body-file or --input, and for api, text that gh or
GitHub changes after the scan:
  an endpoint given as a full URL, or one with a percent sign that is not an
    escape
  a write to the contents or git blobs API, or createCommitOnBranch, whose
    file contents are base64
  {branch} or :branch in the endpoint, and {owner}, {repo}, {branch},
    :owner, :repo or :branch in a --field value (give it with --raw-field)
Not decoded, so not seen: base64 that hush gh does not refuse, and escapes
inside a GraphQL query's strings.

Exit status: 1 on findings, 2 on a refusal or an error, otherwise gh's own.
`

// The gh command's own messages, for its options before "--". "#" stands for
// an argument's 1-based position among gh's arguments; none names a value
// (HSH-11/D43, D60).
const (
	msgGHDashes        = "gh takes its options, then -- GH-ARGUMENTS (see hush gh --help)"
	msgGHUnknownOption = "argument #: unknown option (see hush gh --help)"
	msgGHMissingValue  = "argument #: missing value (see hush gh --help)"
	msgGHNoDest        = "gh needs --destination (see hush gh --help)"
)

// ghArgs is "hush gh"'s command line, parsed: the options of hush scan that
// choose what applies, and gh's own arguments after "--".
type ghArgs struct {
	dest, terms, identities, genericOnly option
	gh                                   []string
}

// parseGH reads gh's options before "--" by hush scan's rules: each takes the
// next argument verbatim, none is given twice. Everything after "--" is gh's.
func parseGH(args []string) (ghArgs, string) {
	var a ghArgs
	valued := map[string]*option{"--destination": &a.dest, "--terms": &a.terms, "--identities": &a.identities}
	for i := 0; i < len(args); i++ {
		w, n := args[i], i+1
		switch {
		case w == "--":
			a.gh = args[i+1:]
			if !a.dest.given() {
				return a, msgGHNoDest
			}
			return a, ""
		case w == "--generic-only":
			if a.genericOnly.given() {
				return a, at(msgGivenTwice, n)
			}
			a.genericOnly = option{pos: n}
		case valued[w] != nil:
			o := valued[w]
			switch {
			case o.given():
				return a, at(msgGivenTwice, n)
			case i+1 == len(args):
				return a, at(msgGHMissingValue, n)
			}
			*o = option{args[i+1], n + 1}
			i++
		case strings.HasPrefix(w, "-"):
			return a, at(msgGHUnknownOption, n)
		default:
			return a, msgGHDashes
		}
	}
	return a, msgGHDashes
}

// ghCommand runs "hush gh OPTIONS -- GH-ARGUMENTS" (ADR-001 section 2). It
// builds the Scanner as hush scan does, and internal/ghwrap scans every text
// the gh command would post through it. Findings are written as hush scan
// writes them, in one write, and gh never runs; an error is written as hush
// scan writes it. Only after a clean scan does gh run, and its exit status is
// hush gh's.
func (p *process) ghCommand(ctx context.Context, args []string) int {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		return p.text(ghUsage)
	}
	a, msg := parseGH(args)
	if msg != "" {
		return p.fail(msg)
	}
	dest, err := hush.ParseDestination(a.dest.value)
	if err != nil {
		return p.failError(withArgument(err, a.dest.pos))
	}
	cfg := hush.Config{Destination: dest, GenericOnly: a.genericOnly.given()}
	if a.identities.given() {
		ids, err := hush.NewIdentities(strings.Split(a.identities.value, ","))
		if err != nil {
			return p.failError(withArgument(err, a.identities.pos))
		}
		cfg.Identities = ids
	}
	s, err := newScanner(cfg, a.terms, a.dest)
	if err != nil {
		return p.failError(err)
	}
	code, reports, err := ghwrap.Run(ctx, s, a.gh, p.stdin, p.stdout, p.stderr)
	var refusal *ghwrap.Error
	switch {
	case errors.As(err, &refusal) && refusal != nil:
		return p.fail(refusal.Error())
	case err != nil:
		return p.failError(err)
	case len(reports) > 0:
		return p.findings(reports)
	}
	return code
}

// findings writes the plain findings of reports, in order, in one write, and
// returns 1, or 2 when the write fails.
func (p *process) findings(reports []*hush.Report) int {
	var b bytes.Buffer
	for _, rep := range reports {
		if rep.WritePlain(&b) != nil {
			return p.failError(nil)
		}
	}
	if !p.claim() {
		return 2
	}
	if _, err := p.stdout.Write(b.Bytes()); err != nil {
		return p.done(2, "cannot write output")
	}
	return p.done(1, "")
}
