package termset

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"testing"

	lc "github.com/nonhumanhq/hush/internal/leakcheck"
)

// failf reports a failure whose message has first passed the leak check.
func failf(t *testing.T, format string, args ...any) {
	t.Helper()
	m := fmt.Sprintf(format, args...)
	lc.Check(t, m)
	t.Error(m)
}

// parse parses file and fails the test on an error.
func parse(t *testing.T, file string) *Sets {
	t.Helper()
	s, err := Parse([]byte(file))
	if err != nil {
		lc.Check(t, err.Error())
		t.Fatalf("parse failed: %v", err)
	}
	return s
}

func TestParseReadsTheSets(t *testing.T) {
	s := parse(t, lc.TermSetFile())
	var got []string
	for i := 0; i < s.Len(); i++ {
		got = append(got, s.Name(i)+"@"+strconv.Itoa(s.Line(i))+"/"+strconv.Itoa(len(s.Labels(i))))
	}
	if g := strings.Join(got, " "); g != "clients@3/0 clients-k@7/1 people@10/0 abbreviations@13/0 abbreviations-exact@16/0" {
		failf(t, "sets: %s", g)
	}
	if l := s.Labels(1); len(l) != 1 || l[0] != lc.LabelA {
		t.Error("the visible-to label is not kept")
	}
	if !s.sets[3].word || s.sets[3].exact || !s.sets[4].word || !s.sets[4].exact || s.sets[0].word || s.sets[0].exact {
		t.Error("case and match options are not kept")
	}
	s.Labels(1)[0] = "x"
	if s.Labels(1)[0] != lc.LabelA {
		t.Error("Labels returns the set's own slice")
	}
}

// The sections of an error: "term file: line N: REASON", or the whole-file
// message. The texts are ADR-002 section 1.5's.
func TestParseErrorText(t *testing.T) {
	for _, c := range []struct {
		err  ParseError
		want string
	}{
		{ParseError{1, TermOutsideSet}, "term file: line 1: term outside a set"},
		{ParseError{2, BadCharacter}, "term file: line 2: bad character"},
		{ParseError{3, BadHeader}, "term file: line 3: bad header"},
		{ParseError{4, BadSetName}, "term file: line 4: bad set name"},
		{ParseError{5, BadAttribute}, "term file: line 5: bad attribute"},
		{ParseError{6, BadClientLabel}, "term file: line 6: bad client label"},
		{ParseError{7, SetDeclaredTwice}, "term file: line 7: set declared twice"},
		{ParseError{8, BadTerm}, "term file: line 8: bad term"},
		{ParseError{9, EmptySet}, "term file: line 9: set has no terms"},
		{ParseError{1, UnsupportedFormat}, "term file: line 1: unsupported format"},
		{ParseError{0, NoTerms}, "term file holds no terms"},
		{ParseError{10, SetNameRefused}, "term file: line 10: set name refused"},
		{ParseError{11, ClientLabelRefused}, "term file: line 11: client label refused"},
		{ParseError{1, 0}, "term file: line 1: unknown reason"},
	} {
		if got := c.err.Error(); got != c.want {
			failf(t, "%q, want %q", got, c.want)
		}
	}
}

// ADR-002 negative test 5: the format is strict. Each file exits with its
// line and reason; none of the files' text reaches the error.
func TestNegative5FormatIsStrict(t *testing.T) {
	q, set := lc.Quorvel, "[clients]\n"
	two := func(line string) string { return "[a]\nx\n" + line + "\ny\n[b]\nz\n" }
	for _, c := range []struct {
		file string
		line int
		why  Reason
	}{
		// bad character
		{set + q + "\x01s\n", 2, BadCharacter},
		{set + q + "\u0085\n", 2, BadCharacter},
		{set + "x\n# note\r" + q + "\n", 3, BadCharacter},
		{set + "x\n# note\u2028" + q + "\n", 3, BadCharacter},
		{set + "x\n# note\v" + q + "\n", 3, BadCharacter},
		{set + q + "\xff\n", 2, BadCharacter},
		{set + "x\n# \xfe " + q + "\n", 3, BadCharacter},
		{set + q + "\x7f\n", 2, BadCharacter},
		{set + q + "\u2029\n", 2, BadCharacter},
		// bad header
		{two("[clients-k7 visible-to=k7"), 3, BadHeader},
		{two("clients-k7 visible-to=k7]"), 3, BadHeader},
		{"[a]\n[clients-k7 visible-to=k7\nx\n", 2, BadHeader},
		{"[clients] ; note\nx\n", 1, BadHeader},
		// bad attribute
		{"[clients colour=red]\nx\n", 1, BadAttribute},
		{"[clients case=upper]\nx\n", 1, BadAttribute},
		{"[clients match=regex]\nx\n", 1, BadAttribute},
		{"[clients case=exact case=exact]\nx\n", 1, BadAttribute},
		{"[clients match=word case=exact match=substring]\nx\n", 1, BadAttribute},
		{"[clients visible-to=k7,k7]\nx\n", 1, BadAttribute},
		{"[clients visible-to=*]\nx\n", 1, BadAttribute},
		{"[clients visible-to=]\nx\n", 1, BadAttribute},
		{"[clients visible-to=k7,]\nx\n", 1, BadAttribute},
		{"[clients ]\nx\n", 1, BadAttribute},
		{"[clients] visible-to=k7]\nx\n", 1, BadAttribute},
		{"[clients case=ignore,exact]\nx\n", 1, BadAttribute},
		{"[clients case]\nx\n", 1, BadAttribute},
		{"[clients =k7]\nx\n", 1, BadAttribute},
		{"[clients\t\tvisible-to=k7 \t]\nx\n", 1, BadAttribute},
		// bad client label
		{"[clients visible-to=K7]\nx\n", 1, BadClientLabel},
		{"[clients visible-to=public]\nx\n", 1, BadClientLabel},
		{"[clients visible-to=k7,private]\nx\n", 1, BadClientLabel},
		{"[clients visible-to=_k7]\nx\n", 1, BadClientLabel},
		{"[clients visible-to=" + strings.Repeat("k", 33) + "]\nx\n", 1, BadClientLabel},
		// bad set name
		{"[ clients]\nx\n", 1, BadSetName},
		{"[clients=x]\nx\n", 1, BadSetName},
		{"[]\nx\n", 1, BadSetName},
		{"[" + strings.Repeat("c", 65) + "]\nx\n", 1, BadSetName},
		// set declared twice, set has no terms
		{"[a]\nx\n[a]\ny\n", 3, SetDeclaredTwice},
		{"[a]\nx\n[a case=exact]\ny\n", 3, SetDeclaredTwice},
		{"[a]\n[b]\nx\n", 1, EmptySet},
		{"[a]\nx\n\n[b]\n# nothing\n", 4, EmptySet},
		// term outside a set
		{q + "\n[a]\nx\n", 1, TermOutsideSet},
		{"\ufeff[a]\nx\n", 1, TermOutsideSet},
		{"\ufeff\x01", 1, TermOutsideSet},
		// bad term
		{set + "quor\u00a0vel\n", 2, BadTerm},
		{set + "\u00a0" + q + "\n", 2, BadTerm},
		{set + q + "\u00a0\n", 2, BadTerm},
		{set + "quor\u3000vel\n", 2, BadTerm},
		{set + "\u3000" + q + "\n", 2, BadTerm},
		{set + q + "\u3000\n", 2, BadTerm},
		{set + "quor\u200bvel\n", 2, BadTerm},
		{set + "quor\ufeffvel\n", 2, BadTerm},
		{set + "quor\u00advel\n", 2, BadTerm},
		{set + q + "\u200e\n", 2, BadTerm},
		{set + "\u2066" + q + "\u2069\n", 2, BadTerm},
		{set + q + "   # main client\n", 2, BadTerm},
		{set + q + "\t# main client\n", 2, BadTerm},
		// unsupported format
		{"#hush-terms 2\n[a]\nx\n", 1, UnsupportedFormat},
		{"#hush-terms\n[a]\nx\n", 1, UnsupportedFormat},
		{"#hush-terms 1 \x01\n[a]\nx\n", 1, BadCharacter},
		// no terms
		{"", 0, NoTerms},
		{"\n\n# only a comment: " + q + "\n\n", 0, NoTerms},
	} {
		_, err := Parse([]byte(c.file))
		pe, ok := err.(*ParseError)
		if !ok || pe.Line != c.line || pe.Reason != c.why {
			failf(t, "file of %d bytes: got %v, want line %d: %v", len(c.file), err, c.line, c.why)
		}
		if err != nil {
			lc.Check(t, err.Error(), fmt.Sprintf("%v %+v %#v", err, err, err))
		}
	}
}

// The controls of negative test 5 load.
func TestNegative5ControlsLoad(t *testing.T) {
	q, set := lc.Quorvel, "[clients]\n"
	for i, file := range []string{
		"#hush-terms 1\n" + set + q + "\n",
		"  #hush-terms 1 \r\n" + set + q + "\n",
		"# hush-terms 2\n" + set + q + "\n",
		set + q + "\n#hush-terms 2\n",
		"[a]\n#hush-terms 2\nx\n", // only line 1 can be the marker; on line 2 it is a comment
		"# see [notes]\n" + set + q + "\n",
		"[clients case=ignore]\n" + q + "\n",
		"[clients match=substring]\n" + q + "\n",
		"[clients visible-to=k7,k8 case=exact match=word]\n" + q + "\n",
		"[clients\tvisible-to=k-7]\n" + q + "\n",
		"[clients]\r\n" + q + "\r\n[people]\r\n" + lc.Mirelda + "\r\n",
		set + "quor\u200cvel\n" + "quor\u200dvel\n",
		set + "quo\u2764\ufe0f\n",
		set + "quor#vel\n",
		set + "\u0600" + q + "\n", // a prepended concatenation mark is visible
		"[" + strings.Repeat("c", 64) + "]\n" + q + "\n",
		set + q + "\n" + q + "\n[people]\n" + q + "\n", // terms may repeat
		set + q + "   inner   spaces\n",
		set + q + "\n[people]\n" + lc.Mirelda, // no final newline
	} {
		if _, err := Parse([]byte(file)); err != nil {
			failf(t, "control %d: %v", i, err)
		}
	}
}

// Section 1.5's order of errors within a line and across the file.
func TestParseErrorOrder(t *testing.T) {
	for _, c := range []struct {
		file string
		line int
		why  Reason
	}{
		{"[ clients colour=red]\nx\n", 1, BadSetName},                       // the name before the attributes
		{"[c visible-to=K7 colour=red]\nx\n", 1, BadAttribute},              // the attributes before the labels
		{"[a]\nx\n[a visible-to=K7]\ny\n", 3, BadClientLabel},               // the labels before the repeat
		{"\u00a0x\n[a]\ny\n", 1, TermOutsideSet},                            // outside a set before bad term
		{"[a]\n[b\x01]\nx\n", 1, EmptySet},                                  // emptiness before bad character
		{"[a]\n[b\x01\nx\n", 2, BadCharacter},                               // one bracket: bad character first
		{"[a]\n[b\nx\n", 2, BadHeader},                                      // one bracket: no emptiness check
		{"[a]\nx\n" + lc.Quorvel + "\x01\n[b]\n", 3, BadCharacter},          // the first error in file order
		{"[a]\nx\n[a]\n[b]\ny\n", 3, SetDeclaredTwice},                      // before the repeated set is found empty
		{"\ufeff#hush-terms 2\n[a]\nx\n", 1, TermOutsideSet},                // the byte-order mark first
		{"[a]\nx\n\ufeffy\n", 3, BadTerm},                                   // a mark after the start is just a character
		{"[a]\n" + lc.Quorvel + "\u00a0\n# \xff\n", 2, BadTerm},             // bad term on line 2 before line 3
		{"[a]\nx\n" + strings.Repeat("#\n", 3) + "[b]\n[c]\n", 6, EmptySet}, // the set's own header line
	} {
		_, err := Parse([]byte(c.file))
		pe, ok := err.(*ParseError)
		if !ok || pe.Line != c.line || pe.Reason != c.why {
			failf(t, "file of %d bytes: got %v, want line %d: %v", len(c.file), err, c.line, c.why)
		}
	}
}

// ADR-002 negative test 7: case is ASCII only.
func TestNegative7CaseIsASCIIOnly(t *testing.T) {
	s := parse(t, "[a]\n"+lc.Quorvel+"\n[b]\n"+lc.Accented+"\n[c]\n"+lc.Kelvo+"\n")
	for _, c := range []struct {
		line string
		set  int // the set that matches, or -1
	}{
		{strings.ToUpper(lc.Quorvel), 0},
		{"Quor" + "Vel", 0},
		{strings.Replace(lc.Accented, "\u00e9", "\u00c9", 1), -1},
		{strings.ToUpper(lc.Accented[:3]) + lc.Accented[3:], 1},
		{"\u212a" + lc.Kelvo[1:], -1},
		{strings.ToUpper(lc.Kelvo), 2},
	} {
		hit, start := s.Match([]byte(c.line), s.All())
		if c.set < 0 && (start != -1 || len(hit) > 0 && hit[0] != 0) || c.set >= 0 && (!hit.Has(c.set) || start != 0) {
			failf(t, "case of %d bytes: start %d", len(c.line), start)
		}
	}
}

// ADR-002 negative test 8: the per-set options.
func TestNegative8PerSetOptions(t *testing.T) {
	s := parse(t, lc.TermSetFile())
	abbr, exact := 3, 4
	q, m := lc.QVL, lc.MOP
	for _, c := range []struct {
		line string
		set  int
		want bool
	}{
		{q, abbr, true}, {strings.ToLower(q), abbr, true}, {q + "2", abbr, true}, {"x-" + q, abbr, true},
		{q + "_api", abbr, true}, {"docs/" + q + "/a.md", abbr, true}, {"docs/" + strings.ToLower(q) + "/a.md", abbr, true},
		{"A" + q + "B", abbr, false}, {q + "Client", abbr, false},
		{m, exact, true}, {"x-" + m, exact, true},
		{strings.ToLower(m), exact, false}, {m[:1] + strings.ToLower(m[1:]), exact, false}, {m + "S", exact, false},
	} {
		hit, start := s.Match([]byte(c.line), s.All())
		if hit.Has(c.set) != c.want {
			failf(t, "row of %d bytes, set %d: got %v, want %v", len(c.line), c.set, hit.Has(c.set), c.want)
		}
		if c.want && start < 0 {
			failf(t, "row of %d bytes: no start", len(c.line))
		}
	}
}

func TestMatch(t *testing.T) {
	s := parse(t, lc.TermSetFile())
	q, z := lc.QVL, lc.ZantophWorks
	for _, c := range []struct {
		line  string
		apply []int
		hit   []int
		start int
	}{
		{"clean", []int{0, 1, 2, 3, 4}, nil, -1},
		{"", []int{0, 1, 2, 3, 4}, nil, -1},
		// The earliest start across the sets applied, whichever set it is.
		{"see " + lc.Mirelda + " and " + strings.ToUpper(lc.Quorvel), []int{0, 1, 2, 3, 4}, []int{0, 2}, 4},
		{"see " + lc.Mirelda + " and " + strings.ToUpper(lc.Quorvel), []int{0}, []int{0}, 4 + len(lc.Mirelda) + 5},
		{"see " + lc.Mirelda, []int{0, 1, 3, 4}, nil, -1},
		// A word occurrence that does not count is skipped for a later one.
		{"A" + q + "B " + q, []int{3}, []int{3}, len(q) + 3},
		{"A" + q + "B", []int{3}, nil, -1},
		// A non-ASCII byte is a boundary, and the earliest term of a set counts.
		{"\u00e9" + q + "\u00e9", []int{3}, []int{3}, 2},
		{"x " + z + " " + lc.Quorvel, []int{0}, []int{0}, 2},
		{strings.Replace(z, " ", "  ", 1), []int{0}, nil, -1}, // inner spaces match exactly
		{"x" + lc.Brindlemoor + "y", []int{1}, []int{1}, 1},
	} {
		var apply Mask
		for _, i := range c.apply {
			apply.Add(i)
		}
		line := []byte(c.line)
		before := bytes.Clone(line)
		hit, start := s.Match(line, apply)
		var got []int
		for i := 0; i < s.Len(); i++ {
			if hit.Has(i) {
				got = append(got, i)
			}
		}
		if fmt.Sprint(got) != fmt.Sprint(c.hit) || start != c.start {
			failf(t, "line of %d bytes: hit %v start %d, want %v %d", len(c.line), got, start, c.hit, c.start)
		}
		if !bytes.Equal(line, before) {
			t.Error("Match wrote to the line")
		}
	}
}

func TestMask(t *testing.T) {
	var m Mask
	for _, i := range []int{0, 63, 64, 200} {
		m.Add(i)
	}
	for i := 0; i < 260; i++ {
		if want := i == 0 || i == 63 || i == 64 || i == 200; m.Has(i) != want {
			t.Errorf("Has(%d) = %v", i, m.Has(i))
		}
	}
	if (Mask{}).Has(5) || Mask(nil).Has(0) {
		t.Error("an empty mask holds a set")
	}
	var file strings.Builder
	for i := 0; i < 70; i++ {
		fmt.Fprintf(&file, "[s%d]\nt%d;\n", i, i)
	}
	s := parse(t, file.String())
	if hit, start := s.Match([]byte("x t69;"), s.All()); !hit.Has(69) || hit.Has(6) || start != 2 {
		t.Errorf("set 69 of 70: start %d", start)
	}
}

func TestNormalizers(t *testing.T) {
	src := []byte("AbZ-\u00c9\xff")
	before := bytes.Clone(src)
	got, offs := ASCIILower{}.Normalize([]byte("p"), []int{9}, src)
	if string(got) != "pabz-\u00c9\xff" || fmt.Sprint(offs) != "[9 0 1 2 3 4 5 6]" {
		t.Errorf("ASCIILower: %q %v", got, offs)
	}
	got, offs = Exact{}.Normalize(nil, nil, src)
	if string(got) != string(src) || fmt.Sprint(offs) != "[0 1 2 3 4 5 6]" {
		t.Errorf("Exact: %q %v", got, offs)
	}
	if !bytes.Equal(src, before) {
		t.Error("a normalizer wrote to its source")
	}
}

// Section 1.4's check 1, through RefusesName, and the examples of section 1.4.
func TestRefusesName(t *testing.T) {
	q := lc.QVL
	for _, c := range []struct {
		file, name string
		want       bool
	}{
		{"[a]\n" + lc.Quorvel + "\n", lc.Quorvel + "-notes", true},
		{"[a]\n" + lc.Quorvel + "\n", strings.ToUpper(lc.Quorvel) + "-notes", true},
		{"[a]\nNT\n", "clients", true},
		{"[a case=exact match=word]\nNT\n", "clients", true},
		{"[a match=word]\n" + q + "\n", strings.ToLower(q) + "notes", true},
		{"[a match=word]\n" + q + "\n", strings.ToLower(q) + "clients", true},
		{"[a match=word]\n" + q + "\n", "clients" + q, true},
		{"[a]\n" + lc.Quorvel + "\n", "clients", false},
		{"[a]\n" + lc.ZantophWorks + "\n", "notes-2026", false},
		{"[a]\n" + lc.ZantophWorks + "\n", lc.Zantoph, false},
		{"[a]\n" + lc.ZantophWorks + "\n", "clients-" + lc.Zantoph, false},
		{"[a]\n" + lc.ZantophWorks + "\n", lc.Zantoph + "clients", false},
		{"[a]\n" + lc.ZantophWorks + "\n", "Zan" + "tophClients", false},
		{"[a]\n" + lc.ZantophWorks + "\n" + lc.Zantoph + "\n", "Zan" + "tophClients", true},
	} {
		s := parse(t, c.file)
		if got := s.RefusesName([]byte(c.name)); got != c.want {
			failf(t, "name of %d bytes: %v, want %v", len(c.name), got, c.want)
		}
	}
}

// CheckNames runs check 1 and the caller's check 2 in file order, the name
// before its labels, and names the header's line.
func TestCheckNames(t *testing.T) {
	q, z := lc.Quorvel, lc.Zantoph
	never := func([]byte) bool { return false }
	dash := func(b []byte) bool { return bytes.Contains(b, []byte("--")) } // a stand-in for the rules
	for _, c := range []struct {
		file   string
		breaks func([]byte) bool
		want   *ParseError
	}{
		{"[clients]\n" + q + "\n", never, nil},
		{"[clients visible-to=k-7]\n" + q + "\n", never, nil},
		{"[a]\nx\n[" + q + "-notes]\n" + q + "\n", never, &ParseError{3, SetNameRefused}},
		{"[a]\n" + z + "\n[b visible-to=k7," + z + "-k]\ny\n", never, &ParseError{3, ClientLabelRefused}},
		{"[" + z + "-x visible-to=" + z + "]\n" + z + "\n", never, &ParseError{1, SetNameRefused}},
		{"[a]\nx\n[b--c]\ny\n", dash, &ParseError{3, SetNameRefused}},
		{"[a visible-to=k--7]\nx\n", dash, &ParseError{1, ClientLabelRefused}},
		{"[b--c]\nx\n[" + q + "]\n" + q + "\n", dash, &ParseError{1, SetNameRefused}},
	} {
		err := parse(t, c.file).CheckNames(c.breaks)
		if c.want == nil && err != nil || c.want != nil && (err == nil || *err.(*ParseError) != *c.want) {
			failf(t, "file of %d bytes: got %v, want %v", len(c.file), err, c.want)
		}
		if err != nil {
			lc.Check(t, err.Error())
		}
	}
}

// Formatting Sets in any way prints the fixed summary only (ADR-001 section
// 6.6's guards).
func TestSetsPrintNothing(t *testing.T) {
	s := parse(t, lc.TermSetFile())
	var outs []string
	for _, v := range []any{s, *s} {
		for _, f := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
			outs = append(outs, fmt.Sprintf(f, v))
		}
		j, err := json.Marshal(v)
		outs = append(outs, string(j), fmt.Sprint(err))
		var g bytes.Buffer
		err = gob.NewEncoder(&g).Encode(v)
		outs = append(outs, g.String(), fmt.Sprint(err))
		var l bytes.Buffer
		slog.New(slog.NewTextHandler(&l, nil)).Info("sets", "v", v)
		outs = append(outs, l.String())
	}
	outs = append(outs, fmt.Sprintf("%v", struct{ S *Sets }{s}))
	all := strings.Join(outs, "\n")
	lc.Check(t, all)
	for _, name := range []string{"clients", "abbreviations", "people"} {
		if strings.Contains(all, name) {
			t.Error("a set name was printed")
		}
	}
}
