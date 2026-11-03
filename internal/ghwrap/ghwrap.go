// Package ghwrap runs gh only after scanning the text the gh command would
// post (HSH-9/D6 to D11). It scans only through package hush, with the
// Scanner the CLI builds from hush gh's options (HSH-11/D8 to D10), and it is
// used by the CLI only.
package ghwrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/nonhumanhq/hush"
)

// Error is a refusal or failure of hush gh's own: fixed text, with argument
// positions and words that may print, which the CLI prints as its error line
// (ADR-001 section 6.6). Run returns it, or a *hush.Error from a scan.
type Error struct{ msg string }

func (e *Error) Error() string { return e.msg }

// refuse returns an *Error with the text msg.
func refuse(msg string) error { return &Error{msg: msg} }

// tables holds the flags of each command hush gh scans, as gh 2.101.0
// documents them (HSH-9/D7). Each entry is [SHORT:]NAME and a kind:
//
//	(none)  a boolean
//	=       takes a value that names something and is not scanned
//	+       text gh posts, scanned as given
//	<       a file whose contents gh posts; "-" is standard input
//	~       a gh api field, KEY=VALUE, scanned whole
//	*       the same, but a value @FILE or @- is read from that file
//	!       refused: gh would post text hush gh cannot see
//
// Every command also takes --help, and issue and pr commands -R, --repo.
var tables = map[string]string{
	"issue create": "a:assignee= attach! blocked-by= blocking= b:body+ F:body-file< e:editor! l:label= " +
		"m:milestone= parent= p:project= recover! T:template! t:title+ type= w:web!",
	"issue edit": "add-assignee= add-blocked-by= add-blocking= add-label= add-project= add-sub-issue= attach! " +
		"b:body+ F:body-file< m:milestone= parent= remove-assignee= remove-blocked-by= remove-blocking= " +
		"remove-label= remove-milestone remove-parent remove-project= remove-sub-issue= remove-type t:title+ type=",
	"issue comment": comment,
	"issue close":   "c:comment+ duplicate-of= r:reason=",
	"issue reopen":  "c:comment+",
	"pr create": "a:assignee= attach! B:base= b:body+ F:body-file< d:draft dry-run e:editor! f:fill! fill-first! " +
		"fill-verbose! H:head= l:label= m:milestone= no-maintainer-edit p:project= recover! r:reviewer= " +
		"T:template! t:title+ w:web!",
	"pr edit": "add-assignee= add-label= add-project= add-reviewer= attach! B:base= b:body+ F:body-file< " +
		"m:milestone= remove-assignee= remove-label= remove-milestone remove-project= remove-reviewer= t:title+",
	"pr comment": comment,
	"pr review":  "a:approve b:body+ F:body-file< c:comment r:request-changes",
	"pr close":   "c:comment+ d:delete-branch",
	"pr reopen":  "c:comment+",
	"api": "allow-escape-sequences cache= F:field* H:header= hostname= i:include input< q:jq= X:method= " +
		"paginate p:preview= f:raw-field~ silent slurp t:template= verbose",
}

const comment = "attach! b:body+ F:body-file< create-if-none delete-last edit-last e:editor! w:web! yes"

// aliases maps gh's own aliases of the commands in tables.
var aliases = map[string]string{"issue new": "issue create", "pr new": "pr create"}

// readOnly lists the commands hush gh runs as given, without a scan: they post
// no text.
var readOnly = map[string]bool{
	"issue list": true, "issue ls": true, "issue view": true, "issue status": true,
	"pr list": true, "pr ls": true, "pr view": true, "pr status": true, "pr checks": true, "pr diff": true,
	"run list": true, "run ls": true, "run view": true, "repo view": true,
}

// maxArg is the length Linux allows one argument, its terminating NUL
// included (MAX_ARG_STRLEN, 32 pages of 4 KiB). The rewritten flags put a
// whole text in one argument, so a longer one is refused before gh runs
// (HSH-9/D9).
const maxArg = 32 * 4096

// placeholder is the pattern gh 2.101.0 fills in a gh api endpoint and in a
// --field value, after hush gh has scanned them; only owner, repo and branch
// are filled (HSH-9/D8). It is gh's, as its binary holds it.
var placeholder = regexp.MustCompile(`(\:(owner|repo|branch)\b|\{[a-z]+\})`)

// fills reports whether gh would fill a placeholder in s: {owner}, {repo} or
// {branch}, or :owner, :repo or :branch, as gh's pattern matches them. With
// branchOnly, only {branch} and :branch count.
func fills(s string, branchOnly bool) bool {
	for _, m := range placeholder.FindAllString(s, -1) {
		name := strings.Trim(m, ":{}")
		if name == "branch" || !branchOnly && (name == "owner" || name == "repo") {
			return true
		}
	}
	return false
}

type flag struct {
	name string
	kind byte // 0 for a boolean, otherwise one of "=+<~*!"
}

// flags parses a table entry into its long and short flags.
func flags(spec string) (map[string]*flag, map[byte]*flag) {
	long, short := map[string]*flag{}, map[byte]*flag{}
	for _, f := range strings.Fields(spec) {
		s, name, ok := strings.Cut(f, ":")
		if !ok {
			s, name = "", f
		}
		fl := &flag{name: name}
		if k := name[len(name)-1]; strings.IndexByte("=+<~*!", k) >= 0 {
			fl.name, fl.kind = name[:len(name)-1], k
		}
		long[fl.name] = fl
		if s != "" {
			short[s[0]] = fl
		}
	}
	return long, short
}

// call is a gh command line ready to run once its texts scan clean.
type call struct {
	args     []string // gh's arguments
	stdin    []byte   // gh's standard input, if useStdin
	useStdin bool     // otherwise gh gets /dev/null
	texts    []text   // what gh would post, in order
}

// text is one text gh would post: the label its findings carry (HSH-11/D8),
// the flag a message names it by, and its bytes.
type text struct {
	label, where string
	data         []byte
}

// Run scans, through s, each text the gh command in args would post, as a
// buffer under its label. With findings, it returns 1 and the reports that
// hold them, in order, and runs nothing. Only when every text scans clean does
// it run the real gh, once, with exactly the bytes it scanned, and return gh's
// exit status. An error means exit 2, with no report: an *Error, hush gh's own
// refusal or failure (gh did not run, or did not exit normally), or the
// *hush.Error a scan returned.
func Run(ctx context.Context, s *hush.Scanner, args []string, stdin io.Reader, stdout, stderr io.Writer) (int, []*hush.Report, error) {
	// A word may print in a message when hush would take it as a stdin
	// label: the label grammar, no term of any loaded set, no client label
	// and nothing a generic rule flags (HSH-11/D35, D60).
	breaks := func(word string) bool {
		_, err := s.ScanBytes(ctx, word, nil)
		return err != nil
	}
	c, err := prepare(args, stdin, breaks)
	if err != nil {
		return 2, nil, err
	}
	var found []*hush.Report
	for _, t := range c.texts {
		rep, err := s.ScanBytes(ctx, t.label, t.data)
		var fe *hush.FindingsError
		switch {
		case errors.As(err, &fe):
			found = append(found, rep)
		case err != nil:
			return 2, nil, err // no partial report (HSH-11/D17)
		}
	}
	if len(found) > 0 {
		return 1, found, nil
	}
	code, err := launch(c, stdout, stderr)
	return code, nil, err
}

// launch runs the real gh, found on PATH, once, as c says.
func launch(c *call, stdout, stderr io.Writer) (int, error) {
	gh, err := exec.LookPath("gh")
	if err != nil {
		return 2, refuse("cannot find gh on PATH")
	}
	cmd := exec.Command(gh, c.args...)
	// The inherited environment, which gh needs to authenticate, with
	// prompts turned off as gh documents it; gh's standard input is not a
	// terminal either (HSH-9/D6).
	cmd.Env = append(os.Environ(), "GH_PROMPT_DISABLED=1")
	if c.useStdin {
		cmd.Stdin = bytes.NewReader(c.stdin)
	}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err = cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, nil
	case errors.As(err, &ee) && ee.ExitCode() > 0:
		return ee.ExitCode(), nil
	case errors.As(err, &ee):
		return 2, refuse("gh did not exit normally")
	}
	return 2, refuse("cannot run gh")
}

// prepare reads args as gh would and returns the call to make and the texts to
// scan first. Files and standard input are read here, once.
func prepare(args []string, stdin io.Reader, breaks func(string) bool) (*call, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return nil, refuse("give a gh command after -- (see hush gh --help)")
	}
	n := 2 // "group command", or "api" alone
	if args[0] == "api" {
		n = 1
	}
	if len(args) < n {
		return nil, notCovered(args, breaks)
	}
	if strings.HasPrefix(args[n-1], "-") {
		if !isGroup(args[0]) {
			return nil, notCovered(args[:1], breaks)
		}
		return nil, refuse("gh " + named(args[:n-1], breaks) + ": give the command before any flag (see hush gh --help)")
	}
	cmd := strings.Join(args[:n], " ")
	if readOnly[cmd] {
		return &call{args: args}, nil
	}
	label := "gh " + cmd // every word is in a table, so it prints as given
	if a, ok := aliases[cmd]; ok {
		cmd = a
	}
	spec, ok := tables[cmd]
	if !ok {
		return nil, notCovered(args[:n], breaks)
	}
	spec += " help"
	if args[0] != "api" {
		spec += " R:repo="
	}
	long, short := flags(spec)

	c := &call{}
	var flagArgs, pos []string
	var method string // gh api's last --method
	seen := map[string]bool{}
	readStdin := false
	read := func(path, what string) ([]byte, error) {
		if path == "-" {
			if readStdin {
				return nil, refuse(label + ": standard input is named twice")
			}
			readStdin = true
			data, err := io.ReadAll(stdin)
			if err != nil {
				return nil, refuse(label + ": cannot read standard input")
			}
			return data, nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, refuse(label + ": cannot read " + what)
		}
		return data, nil
	}
	fields := 0 // --field and --raw-field values so far, for their labels
	// use records one flag with its value, in the form gh will get.
	use := func(f *flag, value string, hasValue bool) error {
		if f.kind == '<' && seen[f.name] {
			// Its contents go on gh's standard input, which holds one text.
			return refuse(label + ": --" + f.name + " is given twice")
		}
		seen[f.name] = true
		arg, where := "--"+f.name, "--"+f.name
		switch f.kind {
		case 0:
			if hasValue {
				arg += "=" + value
			}
		case '=':
			if f.name == "method" {
				method = value
			}
			arg += "=" + value
		case '+':
			c.texts = append(c.texts, text{f.name, where, []byte(value)})
			arg += "=" + value
		case '<':
			data, err := read(value, "--"+f.name)
			if err != nil {
				return err
			}
			c.texts = append(c.texts, text{f.name, where, data})
			// gh reads --input, and --body-file given as "-", from its
			// standard input, which no other flag of these commands names,
			// so the scanned bytes go there, whatever their length
			// (HSH-9/D9, HSH-11/D9).
			c.stdin, c.useStdin = data, true
			arg += "=-"
			if f.name == "input" {
				// The checks below see an invalid byte only where the JSON walk
				// reaches it, so an --input that is not UTF8 is refused first
				// (HSH-9/D8).
				if !utf8.Valid(data) {
					return refuse(label + ": --input is not valid UTF8, so it is not text that hush gh can scan")
				}
				// GitHub decodes the escapes in a JSON body, which the raw
				// bytes hide, so its decoded strings are scanned too. Where
				// the walk stops early, an escape after that point could
				// hide text, so a backslash means a refusal (HSH-9/D8).
				strs, whole := decoded(data)
				if !whole && bytes.IndexByte(data, '\\') >= 0 {
					return refuse(label + ": --input holds an escape but is not JSON hush can read")
				}
				// A lone surrogate escape decodes to U+FFFD, which hides whatever
				// a server that drops it would post, so the decoded strings may
				// hold no more U+FFFD than the raw bytes do (HSH-9/D8).
				n := 0
				for _, s := range strs {
					n += strings.Count(s, "\uFFFD")
				}
				if n > bytes.Count(data, []byte("\uFFFD")) {
					return refuse(label + ": --input holds an escape or a byte that decodes to U+FFFD")
				}
				for _, s := range strs {
					c.texts = append(c.texts, text{"input-decoded", "--input (decoded)", []byte(s)})
				}
			}
		case '~', '*':
			fields++
			key, v, _ := strings.Cut(value, "=")
			where += " " + safe(key, breaks)
			if f.kind == '*' && strings.HasPrefix(v, "@") {
				data, err := read(v[1:], where)
				if err != nil {
					return err
				}
				value, arg = key+"="+string(data), "--raw-field" // gh reads both as the same string
			} else if f.kind == '*' && fills(v, false) {
				return refuse(label + ": " + where + " holds {owner}, {repo} or {branch}, or :owner, :repo or :branch, " +
					"which gh fills in after the scan; give it with --raw-field, which fills nothing")
			}
			c.texts = append(c.texts, text{f.name + "-" + strconv.Itoa(fields), where, []byte(value)})
			arg += "=" + value
		}
		if len(arg) >= maxArg {
			msg := label + ": " + where + " is too long for one argument to gh (128 KiB at most)"
			switch {
			case args[0] == "api":
				msg += "; --input has no such limit"
			case f.name == "body":
				msg += "; --body-file has no such limit"
			}
			return refuse(msg)
		}
		flagArgs = append(flagArgs, arg)
		return nil
	}
	refused := func(f *flag) error {
		return refuse(label + " --" + f.name + " is not covered by hush gh (see hush gh --help)")
	}
	unknown := func(i int) error {
		return refuse(label + ": argument " + strconv.Itoa(n+i+1) + " is a flag hush gh does not know (see hush gh --help)")
	}
	needs := func(f *flag) error { return refuse(label + ": --" + f.name + " needs a value") }

	// Parse the rest as gh's flag parser does: --NAME=VALUE, --NAME VALUE,
	// -X VALUE, -XVALUE, -X=VALUE and booleans grouped as -XY, with flags
	// and positional arguments in any order until "--".
	rest := args[n:]
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		switch {
		case a == "--":
			pos = append(pos, rest[i+1:]...)
			i = len(rest)
		case len(a) < 2 || a[0] != '-':
			pos = append(pos, a)
		case a[1] == '-':
			name, value, hasValue := strings.Cut(a[2:], "=")
			f := long[name]
			switch {
			case f == nil:
				return nil, unknown(i)
			case f.kind == '!':
				return nil, refused(f)
			case !hasValue && f.kind != 0:
				if i+1 == len(rest) {
					return nil, needs(f)
				}
				i++
				value, hasValue = rest[i], true
			}
			if err := use(f, value, hasValue); err != nil {
				return nil, err
			}
		default:
			for j := 1; j < len(a); j++ {
				f := short[a[j]]
				if f == nil {
					return nil, unknown(i)
				}
				var value string
				hasValue, more := true, a[j:]
				switch {
				case f.kind == '!':
					return nil, refused(f)
				case len(more) > 2 && more[1] == '=':
					value, j = more[2:], len(a)
				case f.kind == 0:
					hasValue = false
				case len(more) > 1:
					value, j = more[1:], len(a)
				case i+1 < len(rest):
					i++
					value = rest[i]
				default:
					return nil, needs(f)
				}
				if err := use(f, value, hasValue); err != nil {
					return nil, err
				}
			}
		}
	}
	if seen["body"] && seen["body-file"] {
		return nil, refuse(label + ": give --body or --body-file, not both") // as gh refuses them
	}
	if args[0] == "api" {
		if err := checkAPI(label, pos, method, seen["field"] || seen["raw-field"] || seen["input"]); err != nil {
			return nil, err
		}
		for _, p := range pos {
			c.texts = append(c.texts, text{"endpoint", "endpoint", []byte(p)})
			// GitHub decodes the endpoint's percent-escapes, in its query
			// too, where "+" is also a space, so the decoded text is scanned
			// as well when it differs (HSH-11/D10).
			d, err := decodeEndpoint(p)
			if err != nil {
				return nil, refuse(label + ": the endpoint holds a percent sign that is not an escape")
			}
			if d != p {
				c.texts = append(c.texts, text{"endpoint-decoded", "endpoint (decoded)", []byte(d)})
			}
		}
		for _, t := range c.texts {
			if bytes.Contains(t.data, []byte("createCommitOnBranch")) {
				return nil, refuse(label + ": createCommitOnBranch sends file contents as base64, which hush gh cannot scan")
			}
		}
	}
	for _, t := range c.texts {
		if bytes.IndexByte(t.data, 0) >= 0 {
			return nil, refuse(label + ": " + t.where + " holds a NUL byte, so it is not text that hush gh can scan")
		}
	}
	c.args = append(append([]string{}, args[:n]...), flagArgs...)
	for _, p := range pos {
		if strings.HasPrefix(p, "-") {
			c.args = append(c.args, "--")
			break
		}
	}
	c.args = append(c.args, pos...)
	return c, nil
}

// decoded walks data as JSON tokens, after a leading UTF8 byte order mark,
// and returns every string it decodes, keys and values in document order,
// across successive top-level values. Numbers are kept as text, so one that no
// Go number holds, such as 1e999, does not stop the walk. The walk stops at
// the first error; whole reports whether it reached the end of data instead.
func decoded(data []byte) (strs []string, whole bool) {
	d := json.NewDecoder(bytes.NewReader(bytes.TrimPrefix(data, []byte("\uFEFF"))))
	d.UseNumber()
	for {
		tok, err := d.Token()
		if err != nil {
			return strs, err == io.EOF
		}
		if s, ok := tok.(string); ok {
			strs = append(strs, s)
		}
	}
}

// decodeEndpoint decodes an endpoint as GitHub reads it: the path before the
// first "?" with its percent-escapes, and the query after it as a query
// string, where "+" is a space as well (HSH-11/D10).
func decodeEndpoint(p string) (string, error) {
	pathPart, query, hasQuery := strings.Cut(p, "?")
	d, err := url.PathUnescape(pathPart)
	if err != nil || !hasQuery {
		return d, err
	}
	q, err := url.QueryUnescape(query)
	return d + "?" + q, err
}

// checkAPI refuses a gh api endpoint whose text gh changes, or whose payload
// GitHub decodes, after hush gh has scanned it (HSH-9/D7, D8): a full URL, a
// write to the contents or git blobs API, which take file contents as base64,
// and {branch} or :branch, which gh fills. The request is a GET when --method
// says so, or when it is not given and no field or --input is. The path is
// matched unescaped and cleaned, as GitHub routes it, so that neither a
// percent-escape nor "//", "." or ".." hides it.
func checkAPI(label string, pos []string, method string, params bool) error {
	get := strings.EqualFold(method, "GET") || method == "" && !params
	for _, p := range pos {
		typed, _, _ := strings.Cut(p, "?")
		typed, _, _ = strings.Cut(typed, "#")
		unescaped, err := url.PathUnescape(typed)
		if err != nil {
			return refuse(label + ": the endpoint holds a percent sign that is not an escape")
		}
		path := strings.ToLower(path.Clean("/" + unescaped))
		switch {
		case strings.Contains(p, "://"):
			return refuse(label + ": an endpoint given as a full URL is not covered by hush gh (give its path)")
		case !get && (strings.Contains("/"+path+"/", "/contents/") || strings.HasSuffix(strings.TrimRight(path, "/"), "/git/blobs")):
			return refuse(label + ": a write to the contents or git blobs API sends file contents as base64, which hush gh cannot scan")
		case fills(p, true):
			return refuse(label + ": the endpoint holds {branch} or :branch, which gh fills in after the scan")
		}
	}
	return nil
}

// isGroup reports whether word starts a command hush gh covers or runs, such
// as issue.
func isGroup(word string) bool {
	for cmd := range tables {
		if strings.HasPrefix(cmd, word+" ") {
			return true
		}
	}
	for cmd := range readOnly {
		if strings.HasPrefix(cmd, word+" ") {
			return true
		}
	}
	return false
}

func notCovered(words []string, breaks func(string) bool) error {
	return refuse("gh " + named(words, breaks) + " is not covered by hush gh (see hush gh --help)")
}

// named returns words joined by spaces, each passed through safe.
func named(words []string, breaks func(string) bool) string {
	out := make([]string, len(words))
	for i, w := range words {
		out[i] = safe(w, breaks)
	}
	return strings.Join(out, " ")
}

// safe returns s when it is 1 to 64 characters from [A-Za-z0-9_.[]-] and
// breaks no rule, as a path component would print, and "<redacted>"
// otherwise, so a message or location never echoes what a rule finds
// (HSH-9/D8, D11).
func safe(s string, breaks func(string) bool) string {
	if s == "" || len(s) > 64 || breaks(s) {
		return "<redacted>"
	}
	for _, c := range []byte(s) {
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.IndexByte("_.[]-", c) >= 0) {
			return "<redacted>"
		}
	}
	return s
}
