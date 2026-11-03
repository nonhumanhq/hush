// Command hush keeps private names out of public records. "hush scan" scans
// files, the git index, git ranges or standard input for one destination
// (ADR-001 section 7), "hush hooks" installs git hooks that run it, and
// "hush gh" scans what a gh command would post before it runs gh.
package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"

	"github.com/nonhumanhq/hush"
)

const usage = `usage: hush scan --destination DEST [--terms FILE | --generic-only]
                 [--identities ADDR[,ADDR...]] [--format plain|json] TARGET
       hush hooks install [--force] [--terms FILE] [--identities ADDR[,ADDR...]]
       hush hooks uninstall
       hush gh --destination DEST [--terms FILE | --generic-only]
               [--identities ADDR[,ADDR...]] -- GH-ARGUMENTS
       hush version

hush keeps private names out of public records. "hush scan" scans files, the
git index, git ranges or standard input for one destination, and "hush scan
--help" describes it. "hush hooks" installs git hooks that scan commits and
pushes. "hush gh" scans the text a gh command would post before it runs gh.
"hush hooks --help" and "hush gh --help" describe them. "hush version" prints
the version.
`

// ruleNames names the generic rules in registry order, for the help text. The
// CLI reaches no internal package but internal/hooks and internal/ghwrap
// (ADR-001 section 2), so the names are written here, and TestRuleNames holds
// them to the registry (HSH-11/D26, D59).
var ruleNames = []string{"id-prefix", "ip-address", "email-address"}

// scanUsage returns "hush scan --help", with the rules named in registry
// order (HSH-11/D26). It prints no flagged token and no address.
func scanUsage() string {
	return `usage: hush scan --destination DEST [--terms FILE | --generic-only]
                 [--identities ADDR[,ADDR...]] [--format plain|json] TARGET

  DEST    public, private or client:LABEL
  TARGET  PATH... | --index [-C DIR] | --range REVS [-C DIR] [--allow-empty-range]
          | [--label NAME] (--stdin | -)

  --destination DEST   where the scanned text may end up, required: public
                       (anyone may read it), client:LABEL (only the client
                       whose code is LABEL) or private (no one outside
                       nonhumanhq)
  --terms FILE         the term sets in FILE, the private tier; public and
                       client destinations need it. FILE is a regular file
                       that group and others can neither read nor write, and
                       lies outside every scanned path
  --generic-only       the generic rules alone; public only, never with --terms
  --identities ADDR[,ADDR...]
                       addresses that pass the email-address rule where they
                       stand as an identity: an author, committer or tagger
                       line, or a trailer
  --format FORMAT      plain (the default) or json: one document, written once
  PATH...              files and directories; directories are walked in byte
                       order, .git is skipped, symlinks are scanned as their
                       link text
  --index              the git index: each staged path and its blob; reads
                       GIT_INDEX_FILE when it is set
  --range REVS         commits, oldest first: revisions, A..B, ^REV, --not and
                       the selectors --all, --branches, --tags and --remotes,
                       separated by spaces; each commit's author, committer,
                       message, changed paths and added lines
  -C DIR               the repository for --index and --range (default: the
                       current directory)
  --allow-empty-range  a range with no commits passes; otherwise it exits 2
  --stdin, -           standard input
  --label NAME         the name standard input gets in findings (default
                       <stdin>): a letter or digit, then up to 63 letters,
                       digits, dots, underscores or hyphens

Every option comes before the first path and takes the next argument as its
value. --help is accepted only alone.

Rules: ` + strings.Join(ruleNames, ", ") + `, and set:NAME for a term set.

Findings: one per line, WHERE:LINE: RULE, with " in path" when the path itself
broke the rule. Line 0 is the path or the whole file. A path component that
breaks a rule or cannot print safely prints as <redacted>. binary-unscanned
and unreadable report what could not be scanned.

Exit status: 0 clean, 1 findings, 2 an error, with one line on standard error.
`
}

func main() {
	limitCore()
	// A closed reader on standard output then fails the write, which exits
	// 2, instead of killing hush. Nothing reads this channel, and git
	// children keep the default SIGPIPE (HSH-5/D13).
	signal.Notify(make(chan os.Signal, 1), syscall.SIGPIPE)
	ctx, _ := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	p := &process{stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr}
	// A signal cancels the scan's context, which stops git and the walk; a
	// read of standard input cannot be stopped, so the signal also ends the
	// process here, with the interrupted error, unless the run has already
	// written its result (HSH-11/D44).
	context.AfterFunc(ctx, p.interrupt)
	os.Exit(p.run(ctx, os.Args[1:]))
}

// limitCore sets the core-dump size limit to zero, so that a crash cannot
// leave the terms in a core file (ADR-001 section 6.6).
func limitCore() { setCoreLimit() }

// setCoreLimit is what limitCore does. The tests replace it in their own
// process, whose hard limit it would otherwise lower for good, so that
// TestLimitCore can still raise the limit for the built binary it checks.
var setCoreLimit = func() { syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{}) }

// process is one run of hush: its standard streams and, once the JSON
// document is owed, what an error writes to standard output. Its result is
// claimed once, under mu, by fail, failError, report, text or interrupt;
// whichever comes first wins, and later ones write nothing. The claimant
// writes standard output after releasing mu, so that a signal can still end
// the process while a write blocks (HSH-11/D44).
type process struct {
	stdin          io.Reader
	stdout, stderr io.Writer

	mu      sync.Mutex
	ended   bool // the result is claimed
	writing bool // the claimant is writing standard output
	json    bool // a JSON document is owed
	dest    hush.Destination
	cov     hush.Coverage
	tgt     hush.Target
}

// testHook, when a test sets it, runs in report before the result is claimed
// (claimed false) and after (claimed true), so a test can inject a panic at
// either point. It is nil outside tests.
var testHook func(claimed bool)

// run executes one hush command and returns its exit status: 0 clean, 1
// findings, 2 an error. A panic is recovered into the fixed internal error,
// whose line is written even when the result was already claimed, so a panic
// never ends hush with standard error empty.
func (p *process) run(ctx context.Context, args []string) (code int) {
	defer func() {
		if recover() != nil {
			code = p.failError(nil)
			p.mu.Lock()
			defer p.mu.Unlock()
			if p.writing { // the claimant panicked while writing its result
				p.writing = false
				errorLine(p.stderr, msgInternal)
			}
		}
	}()
	switch {
	case len(args) == 0:
		return p.fail("no command (see hush --help)")
	case args[0] == "scan":
		return p.scanCommand(ctx, args[1:])
	case args[0] == "hooks":
		return p.hooksCommand(args[1:])
	case args[0] == "gh":
		return p.ghCommand(ctx, args[1:])
	case (args[0] == "-h" || args[0] == "--help") && len(args) == 1:
		return p.text(usage)
	case args[0] == "-h" || args[0] == "--help":
		return p.fail("--help is accepted only alone")
	case args[0] != "version":
		return p.fail("unknown command (see hush --help)")
	case len(args) > 1:
		return p.fail("version takes no arguments")
	}
	return p.text(version() + "\n")
}

// msgInternal is package hush's fixed internal message, which the CLI writes
// itself only when a panic follows a claimed result.
const msgInternal = "internal error; output withheld"

// owe records that every outcome from here writes a JSON document for d, c
// and t.
func (p *process) owe(d hush.Destination, c hush.Coverage, t hush.Target) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.json, p.dest, p.cov, p.tgt = true, d, c, t
}

// claim marks the result as claimed and being written, and reports whether
// this call claimed it. The caller then writes standard output without mu and
// calls done.
func (p *process) claim() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ended {
		return false
	}
	p.ended, p.writing = true, true
	return true
}

// done ends the claimant's write: under mu, it writes msg as the error line
// when msg is not "", and returns code.
func (p *process) done(code int, msg string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.writing {
		p.writing = false
		if msg != "" {
			errorLine(p.stderr, msg)
		}
	}
	return code
}

// text writes s to standard output and returns 0, or 2 when the write fails.
func (p *process) text(s string) int {
	if !p.claim() {
		return 2
	}
	if _, err := io.WriteString(p.stdout, s); err != nil {
		return p.done(2, "cannot write output")
	}
	return p.done(0, "")
}

// fail writes msg, one of the command line's own messages, as the one error
// line, and returns 2. It is used only before a JSON document is owed.
func (p *process) fail(msg string) int {
	if p.claim() {
		p.done(2, msg)
	}
	return 2
}

// failError writes err as the one error line, and as the JSON document when
// one is owed, and returns 2. Only a *hush.Error's text is printed; any other
// error, nil included, prints the fixed internal message (ADR-001 section
// 6.6).
func (p *process) failError(err error) int {
	if p.claim() {
		p.done(2, p.writeError(err))
	}
	return 2
}

// writeError writes err's JSON document when one is owed, and returns the
// error line to write: err's message, the fixed internal message for any
// error that is not a *hush.Error, or the output message when the document
// cannot be written. The caller has claimed the result.
func (p *process) writeError(err error) string {
	var e *hush.Error
	if !errors.As(err, &e) || e == nil {
		err, e = nil, nil
	}
	msg := msgInternal
	if e != nil {
		msg = e.Error()
	}
	if p.json && hush.WriteErrorJSON(p.stdout, p.dest, p.cov, p.tgt, err) != nil {
		msg = "cannot write output"
	}
	return msg
}

// report writes a scan's result: the report and exit 0 or 1, or the error
// and exit 2. Exit 0 is reached only here, after the report is written
// without error (ADR-001 section 5).
func (p *process) report(rep *hush.Report, err error, json bool) int {
	if testHook != nil {
		testHook(false)
	}
	if !p.claim() {
		return 2
	}
	if testHook != nil {
		testHook(true)
	}
	var findings *hush.FindingsError
	switch {
	case errors.As(err, &findings):
		rep = findings.Report()
	case err != nil:
		return p.done(2, p.writeError(err))
	}
	write := rep.WritePlain
	if json {
		write = rep.WriteJSON
	}
	if write(p.stdout) != nil {
		return p.done(2, "cannot write output")
	}
	return p.done(hush.ExitCode(err), "")
}

// interrupt ends the process with exit 2 once a signal cancels the context.
// Before the result is claimed, it writes the interrupted error (and the
// JSON document when one is owed). While the claimant writes standard
// output, which may block on a reader that never reads, it writes only the
// interrupted line, since a document cannot follow a partial write. Once the
// result is written, it does nothing.
func (p *process) interrupt() {
	p.mu.Lock()
	switch {
	case !p.ended:
		p.ended = true
		errorLine(p.stderr, p.writeError(hush.ErrInterrupted))
	case p.writing:
		errorLine(p.stderr, hush.ErrInterrupted.Error())
	default:
		p.mu.Unlock()
		return
	}
	os.Exit(2)
}

// errorPrefix starts every error line (ADR-001 section 6.2).
const errorPrefix = "hush: "

// errorLine writes msg to w as one error line.
func errorLine(w io.Writer, msg string) { io.WriteString(w, errorPrefix+msg+"\n") }

// version returns "hush", the module version and, when the build records
// one, the VCS revision.
func version() string {
	v := "hush unknown"
	if bi, ok := debug.ReadBuildInfo(); ok {
		v = "hush " + bi.Main.Version
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" {
				v += " " + s.Value
			}
		}
	}
	return v
}
