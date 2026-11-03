package hush

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	lc "github.com/nonhumanhq/hush/internal/leakcheck"
)

// ADR-001 section 4's table, in New: which destinations take a term file or
// the downgrade, the coverage, tiers and sets each gives, and the error each
// misconfiguration gives.
func TestNewTable(t *testing.T) {
	ts := load(t, adrTerms())
	k7, k8 := client(t, lc.LabelA), client(t, lc.LabelB)
	good := []struct {
		name string
		cfg  Config
		cov  Coverage
		sets []string
	}{
		{"public, terms", Config{Destination: Public(), Terms: ts}, Complete, []string{"clients", "people"}},
		{"public, generic-only", Config{Destination: Public(), GenericOnly: true}, GenericOnly, nil},
		{"client k7", Config{Destination: k7, Terms: ts}, Complete, []string{"people"}},
		{"client k8", Config{Destination: k8, Terms: ts}, Complete, []string{"clients"}},
		{"private", Config{Destination: Private()}, Complete, nil},
	}
	for _, c := range good {
		s, err := New(c.cfg)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		rep, err := s.ScanBytes(context.Background(), "", []byte("clean\n"))
		tiers := []Tier{TierGeneric}
		if c.sets != nil {
			tiers = append(tiers, TierPrivate)
		}
		if err != nil || !rep.Clean() || rep.Coverage() != c.cov || !slices.Equal(rep.Sets(), c.sets) ||
			!slices.Equal(rep.Tiers(), tiers) || rep.Destination() != c.cfg.Destination {
			t.Errorf("%s: got %v, %v, %v, %v", c.name, err, rep.Coverage(), rep.Sets(), rep.Tiers())
		}
		leak(t, s, rep, c.cfg)
	}
}

// ADR-001 negative test 1, in the API: a public or client destination without
// a term file and without the downgrade fails with ErrCoverage.
func TestNegative1PrivateTierWithoutTermFile(t *testing.T) {
	for _, d := range []Destination{Public(), client(t, lc.LabelA)} {
		s, err := New(Config{Destination: d})
		wantError(t, err, CodeCoverage)
		if s != nil {
			t.Error("got a scanner")
		}
	}
	_, err := New(Config{Destination: Public()})
	if err == nil || err.Error() != "the public destination needs --terms FILE or --generic-only" {
		t.Errorf("got %v", err)
	}
}

// ADR-001 negative test 8: client labels. One no set declares, and one that
// holds a term, are refused and never echoed; one that leaves no term to
// apply fails with ErrCoverage; and the label is printed by no output form.
func TestNegative8ClientLabels(t *testing.T) {
	ts := load(t, adrTerms())
	undeclared := client(t, "k9")
	_, err := New(Config{Destination: undeclared, Terms: ts})
	wantError(t, err, CodeDestination)
	if err == nil || err.Error() != "the client label is not declared in the term file" {
		t.Errorf("undeclared: %v", err)
	}
	for _, label := range []string{"x" + lc.Quorvel, strings.ToLower(lc.Zantoph) + "-1"} {
		_, err := New(Config{Destination: client(t, label), Terms: ts})
		wantError(t, err, CodeDestination)
		if err == nil || err.Error() != "client label refused" {
			t.Errorf("a label holding a term: %v", err)
		}
	}
	both := load(t, "[clients visible-to="+lc.LabelA+"]\n"+lc.Quorvel+"\n[people visible-to="+lc.LabelA+","+lc.LabelB+"]\n"+lc.Zantoph+"\n")
	_, err = New(Config{Destination: client(t, lc.LabelA), Terms: both})
	wantError(t, err, CodeCoverage)
	if err == nil || err.Error() != "no term applies to this destination" {
		t.Errorf("no term applies: %v", err)
	}

	// The label is forbidden in every output form of a client:k7 scan; the
	// leak check knows leakcheck.LabelA.
	dir := t.TempDir()
	write(t, dir, "docs/a.md", lc.Zantoph+"\n")
	cfg := Config{Destination: client(t, lc.LabelA), Terms: ts}
	s := scanner(t, cfg)
	rep, err := s.ScanTree(context.Background(), dir)
	if ExitCode(err) != 1 || plain(t, rep) != "docs/a.md:1: set:people\n" {
		t.Errorf("got %v", err)
	}
	var fe *FindingsError
	errorsAs(err, &fe)
	leak(t, cfg, &cfg, cfg.Destination, rep, *rep, rep.Findings(), err, fe, *fe, s, *s,
		struct{ C Config }{cfg}, []Config{cfg}, map[string]Report{"r": *rep}, plain(t, rep))
}

// ADR-001 negative test 9, in the API: the coverage combinations, and a
// private scan runs the generic tier.
func TestNegative9CoverageCombinations(t *testing.T) {
	ts := load(t, adrTerms())
	bad := []Config{
		{Destination: Public(), Terms: ts, GenericOnly: true},
		{Destination: client(t, lc.LabelA), GenericOnly: true},
		{Destination: client(t, lc.LabelA), Terms: ts, GenericOnly: true},
		{Destination: Private(), GenericOnly: true},
		{Destination: Private(), Terms: ts},
	}
	for i, cfg := range bad {
		s, err := New(cfg)
		wantError(t, err, CodeCoverage)
		if s != nil {
			t.Errorf("case %d: got a scanner", i)
		}
	}
	s := scanner(t, Config{Destination: Private()})
	rep, err := s.ScanBytes(context.Background(), "notes", []byte("clean\nsee "+lc.Bad+"\n"))
	if ExitCode(err) != 1 || plain(t, rep) != "notes:2: id-prefix\n" || rep.Sets() != nil {
		t.Errorf("private: %v", err)
	}
	leak(t, rep, err)
}

// ADR-001 negative test 19: zero values and nil receivers never scan.
func TestNegative19ZeroValues(t *testing.T) {
	ctx := context.Background()
	_, err := New(Config{})
	wantError(t, err, CodeDestination)
	_, err = New(Config{Destination: Public(), Terms: new(TermSets)})
	wantError(t, err, CodeTermFile)
	_, err = New(Config{Destination: Public(), GenericOnly: true, Identities: new(Identities)})
	wantError(t, err, CodeUsage)
	if (*Report)(nil).Clean() || new(Report).Clean() {
		t.Error("a nil or zero report is clean")
	}
	var nilScanner *Scanner
	for _, s := range []*Scanner{nilScanner, new(Scanner)} {
		scans := []func() (*Report, error){
			func() (*Report, error) { return s.ScanBytes(ctx, "", nil) },
			func() (*Report, error) { return s.ScanReader(ctx, "", strings.NewReader("")) },
			func() (*Report, error) { return s.ScanTree(ctx, t.TempDir()) },
			func() (*Report, error) { return s.ScanIndex(ctx, Repo{Dir: t.TempDir()}) },
			func() (*Report, error) {
				return s.ScanRange(ctx, Repo{Dir: t.TempDir()}, Range{Include: []string{"HEAD"}})
			},
		}
		for i, scan := range scans {
			rep, err := scan()
			wantError(t, err, CodeUsage)
			if rep != nil {
				t.Errorf("scan %d returned a report", i)
			}
		}
	}
	s := scanner(t, Config{Destination: Public(), GenericOnly: true})
	var nilCtx context.Context
	rep, err := s.ScanBytes(nilCtx, "", nil)
	wantError(t, err, CodeUsage)
	_, err2 := s.ScanIndex(ctx, Repo{})
	wantError(t, err2, CodeUsage)
	_, err3 := s.ScanRange(ctx, Repo{}, Range{Include: []string{"HEAD"}})
	wantError(t, err3, CodeUsage)
	for _, e := range []error{(*Report)(nil).WritePlain(&strings.Builder{}), new(Report).WritePlain(&strings.Builder{})} {
		wantError(t, e, CodeUsage)
	}
	var nilRep *Report
	if rep != nil || nilRep.Findings() != nil || nilRep.Sets() != nil || nilRep.Tiers() != nil ||
		nilRep.Coverage() != 0 || nilRep.Scanned() != (Counts{}) || nilRep.Destination() != (Destination{}) {
		t.Error("a nil report's methods")
	}
	leak(t, nilScanner, new(Scanner), nilRep, fmt.Sprint(new(Report)))
}

// ADR-002 section 5.4 and decided item 6: Config.Identities reaches the email
// rule, and a listed address passes only in an identity position.
func TestConfigIdentities(t *testing.T) {
	ids, err := NewIdentities([]string{lc.Identity})
	if err != nil {
		t.Fatal(err)
	}
	text := []byte(lc.TrailerLine + "\n" + lc.WriteToLine + "\n")
	for _, c := range []struct {
		ids  *Identities
		want string
	}{
		{nil, "body:1: email-address\nbody:2: email-address\n"},
		{ids, "body:2: email-address\n"},
	} {
		for _, d := range []Destination{Public(), Private()} {
			cfg := Config{Destination: d, Identities: c.ids, GenericOnly: d == Public()}
			rep, err := scanner(t, cfg).ScanBytes(context.Background(), "body", text)
			if ExitCode(err) != 1 || plain(t, rep) != c.want {
				t.Errorf("%v with %v: got %v", d, c.ids, err)
			}
			leak(t, rep, err)
		}
	}
}
