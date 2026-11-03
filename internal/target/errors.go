package target

// Kind is the condition a target's error reports. Package hush maps each kind
// to its own code and message; the interim command prints Error's text.
type Kind uint8

// The conditions a target reports as errors.
const (
	PathMissing       Kind = iota + 1 // a path argument does not exist: Arg
	PathUnresolved                    // a path argument's directory cannot be resolved: Arg
	TermFileInside                    // a path argument holds the term file
	NotRepository                     // the directory is not a git repository
	BadRange                          // rev-list refused the revisions
	CommitUnreadable                  // a commit object cannot be read: Commit
	DiffFailed                        // a commit cannot be diffed: Commit
	IndexUnreadable                   // the index cannot be listed or read
	StdinUnreadable                   // standard input cannot be read
	Interrupted                       // Scan.Ctx is done
	TooLarge                          // a file, blob or line is over Scan's size limits
	TermFileGone                      // the term file cannot be found again to compare with the tree
	GitTooOld                         // git is missing, fails, or is older than 2.44
	Grafts                            // the repository holds info/grafts
	GitOutput                         // a git command failed, or gave output hush does not recognise
	RevisionBad                       // a range's revision does not resolve to a commit: Arg is its number
	RefNotCommit                      // a ref a selector lists, to be walked, does not point to a commit
	Shallow                           // a range walks to a shallow boundary
	TagUnreadable                     // a tag object cannot be read
	TermFileInRepo                    // the scanned repository's work tree or git directory holds the term file
	TermFileCommitted                 // the scanned repository holds the term file's bytes as a blob
)

// Error is a target's error: a kind, the interim scanner's fixed text, and an
// argument position or a commit's object id. It never holds a path, a term or
// another program's output.
type Error struct {
	Kind   Kind
	Arg    int    // the 1-based path argument or range revision, or 0
	Commit string // the commit's full object id, or ""
	text   string
}

// Error returns the interim scanner's text for the error.
func (e *Error) Error() string { return e.text }

func fail(k Kind, text string) *Error { return &Error{Kind: k, text: text} }
