package main

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"

	"github.com/nonhumanhq/hush"
)

// The command line's own messages, for argument errors found before anything
// is read (ADR-001 section 5, "Arguments"). "#" stands for an argument's
// 1-based position among scan's arguments. None names a value (HSH-11/D43).
const (
	msgUnknownOption = "argument #: unknown option (see hush scan --help)"
	msgMissingValue  = "argument #: missing value (see hush scan --help)"
	msgGivenTwice    = "argument #: option given twice"
	msgAfterPath     = "argument #: option after a path"
	msgHelpAlone     = "argument #: --help is accepted only alone"
	msgUnknownFormat = "argument #: unknown format"
	msgNoDest        = "the scan needs --destination (see hush scan --help)"
	msgTargets       = "give exactly one target: PATH..., --index, --range REVS or --stdin (see hush scan --help)"
	msgDirAlone      = "-C needs --range or --index"
	msgLabelAlone    = "--label needs --stdin"
	msgAllowAlone    = "--allow-empty-range needs --range"
)

// cliMessages lists the messages above, for the tests.
var cliMessages = []string{msgUnknownOption, msgMissingValue, msgGivenTwice, msgAfterPath, msgHelpAlone,
	msgUnknownFormat, msgNoDest, msgTargets, msgDirAlone, msgLabelAlone, msgAllowAlone}

// at returns msg with "#" replaced by the position n.
func at(msg string, n int) string { return strings.Replace(msg, "#", strconv.Itoa(n), 1) }

// option is one option of "hush scan": its value, when it takes one, and the
// position of that value, or of the flag itself, among scan's arguments; 0
// when it was not given.
type option struct {
	value string
	pos   int
}

func (o option) given() bool { return o.pos > 0 }

// scanArgs is "hush scan"'s command line, parsed (ADR-001 section 7).
type scanArgs struct {
	dest, terms, identities, format, rng, dir, label option
	genericOnly, index, stdin, allowEmpty, help      option
	paths                                            []string
}

// parseScan reads scan's arguments by ADR-001 section 5's rules: an option
// that takes a value takes the next argument verbatim, even one that starts
// with "-"; no option may be given twice or after the first path; "-" alone
// is --stdin; "--" ends the options; --help is accepted only alone. It
// returns the first problem as a message that cites positions only.
func parseScan(args []string) (scanArgs, string) {
	var a scanArgs
	valued := map[string]*option{"--destination": &a.dest, "--terms": &a.terms, "--identities": &a.identities,
		"--format": &a.format, "--range": &a.rng, "-C": &a.dir, "--label": &a.label}
	flags := map[string]*option{"--generic-only": &a.genericOnly, "--index": &a.index, "--stdin": &a.stdin,
		"-": &a.stdin, "--allow-empty-range": &a.allowEmpty, "--help": &a.help}
	for i := 0; i < len(args); i++ {
		w, n := args[i], i+1
		if w == "--" {
			a.paths = append(a.paths, args[i+1:]...)
			break
		}
		isOption := strings.HasPrefix(w, "-")
		switch {
		case len(a.paths) > 0 && isOption:
			return a, at(msgAfterPath, n)
		case !isOption:
			a.paths = append(a.paths, w)
		case valued[w] != nil:
			o := valued[w]
			switch {
			case o.given():
				return a, at(msgGivenTwice, n)
			case i+1 == len(args):
				return a, at(msgMissingValue, n)
			}
			*o = option{args[i+1], n + 1}
			i++
		case flags[w] != nil:
			if flags[w].given() {
				return a, at(msgGivenTwice, n)
			}
			*flags[w] = option{pos: n}
		default:
			return a, at(msgUnknownOption, n)
		}
	}
	targets := 0
	for _, on := range []bool{len(a.paths) > 0, a.index.given(), a.rng.given(), a.stdin.given()} {
		if on {
			targets++
		}
	}
	switch {
	case a.help.given() && len(args) > 1:
		return a, at(msgHelpAlone, a.help.pos)
	case a.help.given():
		return a, ""
	case a.format.given() && a.format.value != "plain" && a.format.value != "json":
		return a, at(msgUnknownFormat, a.format.pos)
	case !a.dest.given():
		return a, msgNoDest
	case targets != 1:
		return a, msgTargets
	case a.dir.given() && !a.rng.given() && !a.index.given():
		return a, msgDirAlone
	case a.label.given() && !a.stdin.given():
		return a, msgLabelAlone
	case a.allowEmpty.given() && !a.rng.given():
		return a, msgAllowAlone
	}
	return a, ""
}

// scanCommand runs "hush scan ARGS" (ADR-001 sections 5 to 7). It parses the
// arguments, then the destination and the identities, and from there owes a
// JSON document for every outcome when --format json is given. It never
// chooses a destination or a tier, and never matches, redacts, filters,
// reorders or rewrites findings: package hush does.
func (p *process) scanCommand(ctx context.Context, args []string) int {
	a, msg := parseScan(args)
	switch {
	case msg != "":
		return p.fail(msg)
	case a.help.given():
		return p.text(scanUsage())
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

	// From here every outcome writes a document in JSON (ADR-001 section 6.3).
	cov, tgt := hush.Complete, hush.TargetTree
	if cfg.GenericOnly {
		cov = hush.GenericOnly
	}
	switch {
	case a.index.given():
		tgt = hush.TargetIndex
	case a.rng.given():
		tgt = hush.TargetRange
	case a.stdin.given():
		tgt = hush.TargetStdin
	}
	if a.format.value == "json" {
		p.owe(dest, cov, tgt)
	}

	// The combination of --terms, --generic-only and the destination is an
	// argument check, made before the term file is read: an empty TermSets
	// stands for the file, and New refuses the combination or reports that
	// the sets were not loaded (HSH-11/D42).
	probe := cfg
	if a.terms.given() {
		probe.Terms = new(hush.TermSets)
	}
	if _, err := hush.New(probe); err != nil && !(a.terms.given() && errors.Is(err, hush.ErrTermFile)) {
		return p.failError(err)
	}
	if a.terms.given() {
		// Before the term file is read, a crash leaves no core file.
		limitCore()
		if cfg.Terms, err = hush.LoadTermSets(a.terms.value); err != nil {
			return p.failError(err)
		}
	}
	s, err := hush.New(cfg)
	if errors.Is(err, hush.ErrDestination) {
		err = withArgument(err, a.dest.pos)
	}
	if err != nil {
		return p.failError(err)
	}

	var rep *hush.Report
	dir := "."
	if a.dir.given() {
		dir = a.dir.value
	}
	switch tgt {
	case hush.TargetTree:
		rep, err = s.ScanTree(ctx, "", a.paths...)
		// A path error counts the paths; the paths are scan's last
		// arguments, so path N is argument len(args)-len(paths)+N, after
		// "--" when it is given (HSH-11/D43).
		var e *hush.Error
		if errors.Is(err, hush.ErrPath) && errors.As(err, &e) && e.Argument() > 0 {
			err = e.WithArgument(len(args) - len(a.paths) + e.Argument())
		}
	case hush.TargetIndex:
		rep, err = s.ScanIndex(ctx, hush.Repo{Dir: dir, IndexFile: indexFile()})
	case hush.TargetRange:
		var rg hush.Range
		if rg, err = hush.ParseRange(a.rng.value); err != nil {
			return p.failError(withArgument(err, a.rng.pos))
		}
		rg.AllowEmpty = a.allowEmpty.given()
		rep, err = s.ScanRange(ctx, hush.Repo{Dir: dir}, rg)
	case hush.TargetStdin:
		label := a.label.value
		if a.label.given() && label == "" {
			// ScanReader reads "" as no label; a --label given empty is a
			// label the grammar refuses, as "-" is.
			label = "-"
		}
		rep, err = s.ScanReader(ctx, label, p.stdin)
		if errors.Is(err, hush.ErrLabel) {
			err = withArgument(err, a.label.pos)
		}
	}
	return p.report(rep, err, a.format.value == "json")
}

// indexFile returns GIT_INDEX_FILE, which the CLI reads only for --index, or
// "" when it is not set. ScanIndex makes a relative value absolute against
// the working directory, before -C applies (ADR-001 section 2). A value that
// is set but empty is passed as ".", the working directory, which is not a
// regular file, so ScanIndex refuses it rather than reading the repository's
// own index (HSH-11/D25).
func indexFile() string {
	if value, ok := os.LookupEnv("GIT_INDEX_FILE"); ok {
		if value == "" {
			return "."
		}
		return value
	}
	return ""
}

// withArgument returns err with the argument position n when it is a
// *hush.Error, and err otherwise.
func withArgument(err error, n int) error {
	var e *hush.Error
	if errors.As(err, &e) {
		return e.WithArgument(n)
	}
	return err
}
