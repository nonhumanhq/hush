package hush

import (
	"fmt"
	"log/slog"

	"github.com/nonhumanhq/hush/internal/rule"
	"github.com/nonhumanhq/hush/internal/termset"
)

// Config is what a Scanner checks: one destination, the private tier or the
// one downgrade, and the identity allowance. Its exported fields carry their
// own formatting guards, so formatting a Config prints no term, label or
// address.
type Config struct {
	// Destination is where the scanned text may end up. It is required.
	Destination Destination
	// Terms is the private tier, from LoadTermSets. It is required for Public
	// and Client destinations unless GenericOnly is set, and refused for
	// Private.
	Terms *TermSets
	// GenericOnly downgrades a Public scan to the generic rules alone. It is
	// accepted only with Public, and never together with Terms.
	GenericOnly bool
	// Identities is the email rule's identity allowance, from NewIdentities,
	// or nil for none. It is accepted with every destination.
	Identities *Identities
}

// Coverage is how much of the tiers a destination calls for a scan ran.
type Coverage uint8

// The coverages. The zero value is not one.
const (
	Complete    Coverage = iota + 1 // every tier the destination calls for
	GenericOnly                     // the generic rules alone, by Config.GenericOnly
)

// String returns "complete" or "generic-only", as the JSON document writes
// the coverage, or "" for the zero value.
func (c Coverage) String() string {
	switch c {
	case Complete:
		return "complete"
	case GenericOnly:
		return "generic-only"
	}
	return ""
}

// Tier is the kind of check a match comes from.
type Tier uint8

// The tiers. The zero value is not one.
const (
	TierGeneric Tier = iota + 1 // the generic rules
	TierPrivate                 // the term sets
)

// String returns "generic" or "private", or "" for the zero value.
func (t Tier) String() string {
	switch t {
	case TierGeneric:
		return "generic"
	case TierPrivate:
		return "private"
	}
	return ""
}

// Scanner scans for one Config. It is immutable and safe for concurrent use,
// and every policy check happens in New. A Scanner not made by New, such as
// new(Scanner) or a nil *Scanner, returns an error from every scan. Its
// String, Format, GoString and LogValue print "hush.Scanner(CLASS)" with the
// destination's class only; MarshalJSON, MarshalText and GobEncode return an
// error.
type Scanner struct {
	dest     Destination
	coverage Coverage
	rules    *box[rule.List]    // the generic rules with the identity allowance, boxed (HSH-11/D38)
	sets     *box[termset.Sets] // every loaded set, or nil, boxed (HSH-11/D38)
	all      termset.Mask       // every loaded set, which redaction uses
	apply    termset.Mask       // the sets findings apply
	applied  []string           // their names, in file order
	terms    *TermSets
}

// New checks cfg against ADR-001 section 4's table and returns a Scanner for
// it. A misconfiguration fails here, before anything is scanned:
//   - ErrDestination for a zero Destination, or a client label that contains
//     a term, breaks a generic rule, or is declared by no set;
//   - ErrCoverage when the destination's tiers do not match Terms and
//     GenericOnly, or when no term applies to a client destination;
//   - ErrTermFile for a TermSets not made by LoadTermSets;
//   - ErrUsage for an Identities not made by NewIdentities.
func New(cfg Config) (s *Scanner, err error) {
	defer recoverError(&err, func() { s = nil })
	d, terms := cfg.Destination, cfg.Terms
	switch {
	case d.class == classNone:
		return nil, newError(CodeDestination, msgNoDestination, 0)
	case terms != nil && !terms.loaded():
		return nil, newError(CodeTermFile, msgTermNotLoaded, 0)
	case cfg.Identities != nil && cfg.Identities.Len() == 0:
		return nil, newError(CodeUsage, msgIdentitiesBuilt, 0)
	case cfg.GenericOnly && terms != nil:
		return nil, newError(CodeCoverage, msgGenericAndTerms, 0)
	case cfg.GenericOnly && d.class != classPublic:
		return nil, newError(CodeCoverage, msgGenericOnlyDest, 0)
	case d.class == classPublic && !cfg.GenericOnly && terms == nil:
		return nil, newError(CodeCoverage, msgPublicCoverage, 0)
	case d.class == classClient && terms == nil:
		return nil, newError(CodeCoverage, msgClientCoverage, 0)
	case d.class == classPrivate && terms != nil:
		return nil, newError(CodeCoverage, msgPrivateTerms, 0)
	}
	s = &Scanner{dest: d, coverage: Complete, terms: terms}
	var ids []string
	if cfg.Identities != nil {
		ids = *cfg.Identities.addrs.get()
	}
	rules := rule.Registry(ids)
	s.rules = newBox(&rules)
	if cfg.GenericOnly {
		s.coverage = GenericOnly
	}
	if terms == nil {
		return s, nil
	}
	s.sets, s.all = terms.sets, terms.sets.get().All()
	if d.class == classClient {
		if err := s.checkClientLabel(d.clientLabel()); err != nil {
			return nil, err
		}
	}
	for i := 0; i < s.sets.get().Len(); i++ {
		if d.class == classPublic || !declares(s.sets.get().Labels(i), d.clientLabel()) {
			s.apply.Add(i)
			s.applied = append(s.applied, s.sets.get().Name(i))
		}
	}
	if len(s.applied) == 0 { // every set holds a term, so no set means no term
		return nil, newError(CodeCoverage, msgNoTermApplies, 0)
	}
	return s, nil
}

// checkClientLabel refuses a client label that contains a term of any loaded
// set, ignoring ASCII case, or breaks a generic rule as a bare string, and
// one that no set declares (ADR-001 section 4).
func (s *Scanner) checkClientLabel(label string) error {
	if s.sets.get().RefusesName([]byte(label)) || s.breaksText(label) {
		return newError(CodeDestination, msgClientRefused, 0)
	}
	for i := 0; i < s.sets.get().Len(); i++ {
		if declares(s.sets.get().Labels(i), label) {
			return nil
		}
	}
	return newError(CodeDestination, msgClientUndeclared, 0)
}

// breaksText reports whether text, as a bare string (rule.Text), breaks a
// generic rule.
func (s *Scanner) breaksText(text string) bool {
	return len(s.rules.get().Check([]byte(text), rule.Context{Source: rule.Text})) > 0
}

func declares(labels []string, label string) bool {
	for _, l := range labels {
		if l == label {
			return true
		}
	}
	return false
}

// ready reports whether s was made by New.
func (s *Scanner) ready() bool { return s != nil && s.dest.class != classNone && s.rules != nil }

func (s Scanner) summary() string { return "hush.Scanner(" + s.dest.String() + ")" }

// String returns the fixed summary.
func (s Scanner) String() string { return s.summary() }

// Format prints the fixed summary for every verb.
func (s Scanner) Format(f fmt.State, _ rune) { fmt.Fprint(f, s.summary()) }

// GoString returns the fixed summary.
func (s Scanner) GoString() string { return s.summary() }

// LogValue returns the fixed summary.
func (s Scanner) LogValue() slog.Value { return slog.StringValue(s.summary()) }

// MarshalJSON returns an error.
func (Scanner) MarshalJSON() ([]byte, error) { return nil, errEncodeScanner }

// MarshalText returns an error.
func (Scanner) MarshalText() ([]byte, error) { return nil, errEncodeScanner }

// GobEncode returns an error.
func (Scanner) GobEncode() ([]byte, error) { return nil, errEncodeScanner }
