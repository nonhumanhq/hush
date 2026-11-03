package hush

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	lc "github.com/nonhumanhq/hush/internal/leakcheck"
	"github.com/nonhumanhq/hush/internal/schema"
)

// ADR-001 negative test 6 (HSH-11/T26): matched text is absent from every
// output form. Each of the four targets scans matches in content, paths,
// commit messages, author lines and an annotated tag's message, for the
// public destination and for a client the clients set is visible to, with
// the identity allowance given; the findings are written in both formats;
// and the leak check runs over both, over every error's text, and over every
// formatted form of the report, its findings, the error, the term sets, the
// scanner, the configuration and the destination (the leak helper's verbs
// include %v, %+v and %#v). The identity is leakcheck's, at a domain that is
// not reserved (ADR-002 section 6, point 4), and so are the client labels.
func TestNegative6NoMatchedText(t *testing.T) {
	terms := load(t, adrTerms())
	ids, err := NewIdentities([]string{lc.Identity})
	if err != nil {
		t.Fatal("NewIdentities failed")
	}
	content := "see " + lc.Quorvel + "\nand " + lc.Zantoph + "\nand " + lc.Bad + "\nwrite to " + lc.Identity + "\n"

	dir, git := gitRepo(t)
	write(t, dir, "docs/"+lc.Quorvel+"/plan.md", content)
	write(t, dir, "notes/"+lc.Bad+".md", "clean\n")
	git("add", "-A")
	t.Setenv("GIT_AUTHOR_NAME", lc.Zantoph)
	t.Setenv("GIT_AUTHOR_EMAIL", lc.Identity) // allowed where it stands as an identity
	t.Setenv("GIT_COMMITTER_EMAIL", lc.Identity)
	git("commit", "-q", "-m", "about "+lc.Quorvel+"\n\nsee "+lc.Bad+"\n\nSigned-off-by: "+lc.Zantoph+" <"+lc.Identity+">")
	git("tag", "-a", "-m", "tagged "+lc.Zantoph+", "+lc.Bad, "v1")
	write(t, dir, "staged.md", content) // in the index, after the commit
	git("add", "staged.md")

	pub := Config{Destination: Public(), Terms: terms, Identities: ids}
	cli := Config{Destination: client(t, lc.LabelA), Terms: terms, Identities: ids}
	for _, cfg := range []Config{pub, cli} {
		s := scanner(t, cfg)
		for _, c := range []struct {
			target string
			scan   func() (*Report, error)
			want   []string // in the plain findings
		}{
			{"tree", func() (*Report, error) { return s.ScanTree(bg, dir) }, []string{"docs/<redacted>:2: set:people",
				"docs/<redacted>:4: email-address", "notes/<redacted>:0: id-prefix in path", "staged.md:3: id-prefix"}},
			{"index", func() (*Report, error) { return s.ScanIndex(bg, Repo{Dir: dir}) }, []string{"docs/<redacted>:2: set:people",
				"notes/<redacted>:0: id-prefix in path", "staged.md:3: id-prefix", "staged.md:4: email-address"}},
			{"stdin", func() (*Report, error) { return s.ScanBytes(bg, "notes", []byte(content)) }, []string{"notes:2: set:people",
				"notes:3: id-prefix", "notes:4: email-address"}},
			{"range", func() (*Report, error) {
				return s.ScanRange(bg, Repo{Dir: dir}, Range{IncludeRefs: []RefSelector{AllRefs}})
			}, []string{":(commit):2: set:people", ":(commit):7: id-prefix", ":(commit):9: set:people",
				":docs/<redacted>:4: email-address", ":(tag):6: id-prefix", ":(tag):6: set:people"}},
		} {
			rep, err := c.scan()
			var fe *FindingsError
			if !errors.As(err, &fe) || rep == nil {
				t.Fatalf("%s, %s: no findings: %v", cfg.Destination, c.target, err)
			}
			text := plain(t, rep)
			for _, w := range c.want {
				if !strings.Contains(text, w) {
					t.Errorf("%s, %s: no %q in the findings", cfg.Destination, c.target, w)
				}
			}
			// The clients set applies to public and is exempt for its
			// client, where its matches still redact (ADR-001 negative
			// tests 2 and 7). The identity passes in the author, committer
			// and trailer lines.
			if (cfg.Destination == pub.Destination) != strings.Contains(text, "set:clients") {
				t.Errorf("%s, %s: set:clients findings, or none, against the destination", cfg.Destination, c.target)
			}
			if c.target != "stdin" && (cfg.Destination == pub.Destination) != strings.Contains(text, "docs/<redacted>:0: set:clients in path") {
				t.Errorf("%s, %s: the path finding, or none, against the destination", cfg.Destination, c.target)
			}
			if strings.Contains(text, ":(commit):2: email-address") || strings.Contains(text, ":(commit):9: email-address") {
				t.Errorf("%s, %s: the identity is flagged where it stands as an identity", cfg.Destination, c.target)
			}
			doc := jsonOf(t, rep)
			var findings []any
			for _, f := range rep.Findings() {
				findings = append(findings, f, &f, f.Where(), f.String())
			}
			lc.Check(t, text, doc, err.Error(), fe.Report().String())
			leak(t, append(findings, rep, *rep, err, fe, *fe, terms, *terms, s, *s, cfg, &cfg, cfg.Destination, ids, *ids)...)
		}
	}
}

// ADR-001 negative test 6's failure cases in the API: a term-file syntax
// error on a line that holds a term, a refused stdin label that holds a term,
// a git failure in a repository whose ref names hold a term, and
// WriteErrorJSON given a foreign error whose text is a term. The command
// line's cases, an unknown option and an injected panic, are in cmd/hush.
func TestNegative6Failures(t *testing.T) {
	_, err := LoadTermSets(termFile(t, "#hush-terms 1\n[clients]\n"+lc.Quorvel+"\n[people "+lc.Zantoph+"]\nx\n"))
	wantError(t, err, CodeTermFile)
	leak(t, err)
	_, err = LoadTermSets(termFile(t, lc.Quorvel+"\n[clients]\nx\n"))
	wantError(t, err, CodeTermFile)
	leak(t, err)

	s := scanner(t, Config{Destination: Public(), Terms: load(t, adrTerms())})
	for _, label := range []string{lc.Quorvel, "a-" + lc.Zantoph, lc.Bad, lc.LabelA} {
		rep, err := s.ScanBytes(bg, label, []byte("x\n"))
		wantError(t, err, CodeLabel)
		leak(t, rep, err)
	}

	// A repository whose branch and tag hold a term, with the commit they
	// point to gone.
	dir, git := gitRepo(t)
	write(t, dir, "a.md", "clean\n")
	git("add", "-A")
	git("commit", "-q", "-m", "first")
	git("branch", lc.Quorvel)
	git("tag", "-a", "-m", "x", "v-"+lc.Zantoph)
	id := git("rev-parse", "HEAD")
	if err := os.Remove(filepath.Join(dir, ".git", "objects", id[:2], id[2:])); err != nil {
		t.Fatal(err)
	}
	for _, rg := range []Range{{IncludeRefs: []RefSelector{AllRefs}}, {Include: []string{lc.Quorvel}}, {Include: []string{"v-" + lc.Zantoph}}} {
		rep, err := s.ScanRange(bg, Repo{Dir: dir}, rg)
		if ExitCode(err) != 2 || rep != nil {
			t.Errorf("a missing commit: %v", err)
		}
		leak(t, rep, err)
	}
	rep, err := s.ScanIndex(bg, Repo{Dir: dir})
	leak(t, rep, err)

	var b bytes.Buffer
	if err := WriteErrorJSON(&b, Public(), Complete, TargetTree, errors.New("cannot read "+lc.Quorvel)); err != nil {
		t.Fatal("WriteErrorJSON failed")
	}
	if err := schema.CheckLine(b.String()); err != nil || !strings.Contains(b.String(), `"code":"internal"`) {
		t.Errorf("a foreign error's document: %v", err)
	}
	lc.Check(t, b.String())
}
