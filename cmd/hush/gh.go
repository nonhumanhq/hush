package main

import (
	"github.com/nonhumanhq/hush/internal/ghwrap"
	"github.com/nonhumanhq/hush/internal/output"
	"github.com/nonhumanhq/hush/internal/target"
)

const ghUsage = `usage: hush gh -- GH-ARGUMENTS

Scans the text the gh command would post with the generic tier, and runs the
real gh, found on PATH, only if the scan is clean, handing it exactly the
bytes it scanned.

Scanned, then run:
  issue create|new, edit, comment, close, reopen
  pr create|new, edit, comment, review, close, reopen
  api
Scanned: --title, --body, --comment, the contents of --body-file (a file, or
standard input for -), and for api the endpoint, each --raw-field and --field
(a value @FILE or @- is read) and the contents of --input. A finding prints
the flag (and a field's key) and the line, as --body:3: id-prefix.

Run as given, with nothing to scan:
  issue list|ls|view|status, pr list|ls|view|status|checks|diff,
  run list|ls|view, repo view

Refused, exit 2: every other command, flags before the command, flags gh
2.101.0 does not document for the command, and the flags whose text hush gh
cannot see: --editor, --web, --attach, --recover, --template, --fill,
--fill-first and --fill-verbose. Also refused: any scanned text that holds a
NUL byte, and for api, text that gh or GitHub changes after the scan:
  an endpoint given as a full URL
  a write to the contents or git blobs API, or createCommitOnBranch, whose
    file contents are base64
  {branch} or :branch in the endpoint, and {owner}, {repo}, {branch},
    :owner, :repo or :branch in a --field value (give it with --raw-field)

Exit status: 1 on findings, 2 on a refusal or an error, otherwise gh's own.
`

// ghCommand runs "hush gh -- GH-ARGUMENTS". It takes no term file and still
// scans through the internal packages until HSH-11's part e brings ADR-001's
// grammar to it (HSH-9/D4).
func (p *process) ghCommand(args []string) int {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		return p.text(ghUsage)
	}
	if len(args) == 0 || args[0] != "--" {
		return p.fail("gh takes -- GH-ARGUMENTS (see hush gh --help)")
	}
	stdin, stdout, stderr := p.stdin, p.stdout, p.stderr
	out := output.New(stdout)
	s := &target.Scan{Rules: genericRules(), Out: out}
	code, err := ghwrap.Run(s, args[1:], stdin, stdout, stderr)
	if out.Flush() != nil {
		return 2 // findings cannot be written (HSH-5/D13)
	}
	if err != nil {
		output.Error(stderr, err.Error())
		return 2
	}
	return code
}
