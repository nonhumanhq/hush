package target

// Kind is the condition a target's error reports. Package hush maps each kind
// to its own code and message; the interim command prints Error's text.
type Kind uint8

// The conditions a target reports as errors.
const (
	PathMissing      Kind = iota + 1 // a path argument does not exist: Arg
	PathUnwalkable                   // a directory cannot be walked: Arg
	PathUnresolved                   // a path argument's directory cannot be resolved: Arg
	TermFileInside                   // a path argument holds the term file
	NotRepository                    // the directory is not a git repository
	BadRange                         // rev-list refused the revisions
	CommitUnreadable                 // a commit object cannot be read: Commit
	DiffFailed                       // a commit cannot be diffed: Commit
	IndexUnreadable                  // the index cannot be listed or read
	StdinUnreadable                  // standard input cannot be read
	Interrupted                      // Scan.Ctx is done
)

// Error is a target's error: a kind, the interim scanner's fixed text, and an
// argument position or a commit's object id. It never holds a path, a term or
// another program's output.
type Error struct {
	Kind   Kind
	Arg    int    // the 1-based path argument, or 0
	Commit string // the commit's full object id, or ""
	text   string
}

// Error returns the interim scanner's text for the error.
func (e *Error) Error() string { return e.text }

func fail(k Kind, text string) *Error { return &Error{Kind: k, text: text} }
