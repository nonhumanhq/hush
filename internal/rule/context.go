package rule

// Part is the part of a commit or tag object a line comes from (ADR-001
// section 6.1).
type Part uint8

// The parts, as ADR-002 section 5.1 sketches them.
const (
	NoPart    Part = iota // any Source other than Object
	Author                // the author header
	Committer             // the committer header
	Tagger                // the tagger header
	Header                // any other header
	Message               // the message
)

// Source is where a line comes from. The zero value is the strictest: no
// exception and no allowance applies to a bare string.
type Source uint8

// The sources, as ADR-002 section 5.1 sketches them.
const (
	Text   Source = iota // a bare string, such as a set name checked at load
	File                 // a line of a file, an index blob or an added diff hunk
	Path                 // the path itself
	Object               // a line of a commit or tag object
	Stdin                // a line of standard input or of a caller's buffer
)

// Context is everything a rule may know about a line besides its bytes. The
// targets fill it for every line and path they scan (ADR-002 section 5.1).
type Context struct {
	Source Source
	Path   string // for File and Path: the reported path before redaction (ADR-001 section 6.4 step 1)
	Part   Part   // for Object: Author, Committer, Tagger, Header or Message
}
