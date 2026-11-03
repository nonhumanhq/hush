package leakcheck

import "slices"

// The invented terms of ADR-002's negative tests, assembled at run time.
var (
	Quorvel      = "quor" + "vel"
	Zantoph      = "zan" + "toph"
	ZantophWorks = Zantoph + " works"
	Mirelda      = "mir" + "elda"
	Brindlemoor  = "brindle" + "moor"
	QVL          = "Q" + "VL"              // an abbreviation, for a match=word set
	MOP          = "M" + "OP"              // an abbreviation that spells a word, for case=exact match=word
	Kelvo        = "kel" + "vo"            // its first letter has a Kelvin-sign look-alike
	Accented     = "lum" + "\u00e9" + "ra" // holds a non-ASCII letter
)

// Client labels the tests declare with visible-to. They are longer than the
// ADR's k7 and k8 so that the check cannot find them in unrelated output.
var (
	LabelA = "korv" + "7"
	LabelB = "korv" + "8"
)

// RefusedNames are set names the load-time checks refuse in the tests, beyond
// those that hold a term above (ADR-002 negative test 6).
var RefusedNames = []string{"ZQX" + "-42", "203.0." + "114.7"}

// TermSetFile returns a format 1 term file with ADR-002 section 1.8's shape:
// the sets clients, clients-k (visible to LabelA), people, abbreviations
// (match=word) and abbreviations-exact (case=exact match=word).
func TermSetFile() string {
	return "#hush-terms 1\n# synthetic terms, for tests only\n" +
		"[clients]\n" + Quorvel + "\n" + ZantophWorks + "\n\n" +
		"[clients-k visible-to=" + LabelA + "]\n" + Brindlemoor + "\n\n" +
		"[people]\n" + Mirelda + "\n\n" +
		"[abbreviations match=word]\n" + QVL + "\n\n" +
		"[abbreviations-exact case=exact match=word]\n" + MOP + "\n"
}

// IDFlagged is the "Flagged" table of ADR-002 section 4.1, every input of every
// row as the ADR writes it. Each holds a token the id-prefix rule flags outside
// reference/.
var IDFlagged = []string{
	"ZQX" + "-42", "HSHX" + "-7", "ACMEHSH" + "-1",
	"AB1" + "-23", "A_B" + "-12",
	"ABC" + "-12x", "ABC" + "-12-3",
	"FLEET" + "-12",
	"UTF" + "-8", "SHA" + "-256",
	"SHA2" + "-256", "SHA3" + "-256", "[A-Z0" + "-9]", "Q3" + "-2026", "FY25" + "-26", "X86" + "-64",
}

// termWords is every string above that a test must never print. The
// abbreviation NT of negative test 6 is left out: two letters occur in too
// much ordinary output for the check to be meaningful.
var termWords = slices.Concat(
	[]string{Quorvel, Zantoph, Mirelda, Brindlemoor, QVL, MOP, Kelvo, Accented, LabelA, LabelB},
	RefusedNames, IDFlagged,
	// The tokens the rule matches in rows that hold more than the token.
	[]string{"ABC" + "-12", "Z0" + "-9"},
)
