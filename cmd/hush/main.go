// Command hush keeps private names out of public records. It is pre-release:
// "hush scan" takes the interim scanner's arguments and gives its output.
package main

import (
	"errors"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/nonhumanhq/hush/internal/output"
	"github.com/nonhumanhq/hush/internal/rule"
	"github.com/nonhumanhq/hush/internal/target"
	"github.com/nonhumanhq/hush/internal/termset"
)

const usage = `usage: hush scan [--terms FILE] PATH...
       hush scan [--terms FILE] [-C DIR] --range REVS
       hush scan [--terms FILE] [--label NAME] --stdin
       hush version

hush keeps private names out of public records. It is pre-release: "hush scan"
takes the interim scanner's arguments and gives its output, and "hush scan
--help" describes them. "hush version" prints the version.
`

const scanUsage = `usage: hush scan [--terms FILE] PATH...
       hush scan [--terms FILE] [-C DIR] --range REVS
       hush scan [--terms FILE] [--label NAME] --stdin

  PATH...       files or directories, as seen from the repository root;
                directories are walked and .git is skipped
  --range REVS  git rev-list arguments separated by spaces ("main..HEAD",
                "HEAD --not --remotes"); scans the lines each commit adds,
                the paths it touches, and its author, committer and message
  -C DIR        the repository for --range (default: current directory)
  --stdin, -    scan standard input
  --label NAME  the name standard input gets in findings (default: <stdin>)
  --terms FILE  also match the term sets in FILE; the scan fails unless FILE
                exists, is readable, holds at least one term and lies outside
                every scanned path

Findings: one per line, WHERE:LINE: RULE. RULE is id-prefix, set:NAME,
binary-unscanned or unreadable, with " in path" when the path itself broke
the rule. Line 0 is the path or the whole file. A path component that breaks
a rule prints as <redacted>.
`

func main() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		os.Exit(2)
	}()
	// A closed reader on standard output then fails the write, and scan exits
	// 2 silently, as the interim does when awk dies of SIGPIPE. Nothing reads
	// this channel, and git children keep the default SIGPIPE (HSH-5/D13).
	signal.Notify(make(chan os.Signal, 1), syscall.SIGPIPE)
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run executes one hush command and returns its exit status: 0 clean, 1
// findings, 2 usage or configuration error.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	switch {
	case len(args) == 0:
		output.Error(stderr, "no command (see hush --help)")
	case args[0] == "scan":
		return scan(args[1:], stdin, stdout, stderr)
	case args[0] == "-h" || args[0] == "--help":
		io.WriteString(stdout, usage)
		return 0
	case args[0] != "version":
		output.Error(stderr, "unknown command (see hush --help)")
	case len(args) > 1:
		output.Error(stderr, "version takes no arguments")
	default:
		io.WriteString(stdout, version()+"\n")
		return 0
	}
	return 2
}

// scan parses the interim scanner's arguments exactly as it does, in order,
// and runs one target.
func scan(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	out := output.New(stdout)
	fail := func(msg string) int {
		if out.Flush() != nil {
			return 2 // the interim's awk died of SIGPIPE before this (HSH-5/D13)
		}
		output.Error(stderr, msg)
		return 2
	}
	var terms, revs, repo string
	label, hasTerms, hasLabel, useStdin := "<stdin>", false, false, false
	i := 0
parse:
	for i < len(args) {
		a, more := args[i], i+1 < len(args)
		switch {
		case a == "--terms":
			if !more {
				return fail("--terms needs a file")
			}
			if hasTerms {
				return fail("--terms given twice")
			}
			if terms, hasTerms = args[i+1], true; terms == "" {
				return fail("term file missing or unreadable")
			}
		case a == "--range":
			if !more || args[i+1] == "" {
				return fail("--range needs revisions")
			}
			revs = args[i+1]
		case a == "-C":
			if !more || args[i+1] == "" {
				return fail("-C needs a directory")
			}
			repo = args[i+1]
		case a == "--label":
			if !more {
				return fail("--label needs a name")
			}
			label, hasLabel = args[i+1], true
		case a == "--stdin" || a == "-":
			useStdin = true
			i++
			continue
		case a == "-h" || a == "--help":
			io.WriteString(stdout, scanUsage)
			return 0
		case a == "--":
			i++
			break parse
		case strings.HasPrefix(a, "-"):
			return fail("unknown option " + a + " (see --help)") // the interim echoes it
		default:
			break parse
		}
		i += 2 // an option and its value
	}
	paths := args[i:]
	modes := 0
	for _, on := range []bool{useStdin, revs != "", len(paths) > 0} {
		if on {
			modes++
		}
	}
	switch {
	case modes != 1:
		return fail("give exactly one of PATH..., --range or --stdin (see --help)")
	case repo != "" && revs == "":
		return fail("-C works only with --range")
	case hasLabel && !useStdin:
		return fail("--label works only with --stdin")
	}
	s := &target.Scan{Rules: rule.List{rule.IDPrefix{}}, Out: out, Terms: terms, GitStderr: stderr, GitStdin: stdin}
	if terms != "" {
		sets, err := loadTerms(terms)
		if err != nil {
			return fail(err.Error())
		}
		for _, set := range sets {
			s.Rules = append(s.Rules, set)
		}
	}
	var err error
	switch {
	case useStdin:
		err = s.Stdin(stdin, label)
	case revs != "":
		err = s.Range(repo, revs)
	default:
		err = s.Paths(paths)
	}
	if err != nil {
		return fail(err.Error())
	}
	if out.Flush() != nil {
		return 2
	}
	if out.Found > 0 {
		return 1
	}
	return 0
}

// loadTerms reads and parses the term file named by --terms.
func loadTerms(path string) ([]*termset.Set, error) {
	missing := errors.New("term file missing or unreadable")
	if fi, err := os.Stat(path); err != nil || !fi.Mode().IsRegular() {
		return nil, missing
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, missing
	}
	return termset.Parse(data)
}

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
