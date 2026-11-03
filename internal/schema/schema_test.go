package schema

import (
	"fmt"
	"os"
	"strings"
	"testing"

	lc "github.com/nonhumanhq/hush/internal/leakcheck"
)

// examples returns the JSON documents of ADR-001 section 6.3's synthetic
// examples, each on one line (the second is wrapped there for reading).
func examples(t *testing.T) []string {
	b, err := os.ReadFile("../../docs/adr/001-what-hush-is.md")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	s = s[strings.Index(s, "Synthetic examples."):strings.Index(s, "#### 6.4")]
	var docs []string
	for _, block := range strings.Split(s, "```json\n")[1:] {
		block = block[:strings.Index(block, "```")]
		docs = append(docs, strings.ReplaceAll(block, "\n", "")+"\n")
	}
	if len(docs) != 4 {
		t.Fatalf("read %d examples from ADR-001, want 4", len(docs))
	}
	return docs
}

// The ADR's own examples pass.
func TestExamples(t *testing.T) {
	for i, doc := range examples(t) {
		err := CheckLine(doc)
		if err != nil {
			t.Errorf("example %d: %v", i, err)
		}
		lc.Check(t, doc, fmt.Sprint(err))
	}
}

// Each change of an example that the closed schema refuses is refused, so a
// mistake in the checker that lets a bad document through fails here.
func TestRefusals(t *testing.T) {
	ex := examples(t)
	clean, found, generic, failed := ex[0], ex[1], ex[2], ex[3]
	for i, c := range []struct{ doc, old, new string }{
		{clean, `"schema":"hush.scan/1"`, `"schema":"hush.scan/2"`},
		{clean, `"schema":"hush.scan/1",`, ``},
		{clean, `"hush":"0.1.0"`, `"hush":1`},
		{clean, `"exit":0`, `"exit":1`},
		{clean, `"exit":0`, `"exit":0.5`},
		{clean, `"destination":"public"`, `"destination":"client:k7"`},
		{clean, `"coverage":"complete"`, `"coverage":"partial"`},
		{clean, `"tiers":["generic","private"]`, `"tiers":["generic","generic"]`},
		{clean, `"sets":["clients","people"]`, `"sets":["set:clients"]`},
		{clean, `"target":"tree"`, `"target":"file"`},
		{clean, `"files":42,`, ``},
		{clean, `"lines":3170`, `"lines":-1`},
		{clean, `"lines":3170`, `"lines":3170,"bytes":1`},
		{clean, `,"findings":[]`, ``},
		{clean, `"findings":[]`, `"findings":[],"extra":true`},
		{clean, `"schema":"hush.scan/1","hush":"0.1.0"`, `"hush":"0.1.0","schema":"hush.scan/1"`},
		{clean, `"findings":[]`, `"findings":[],"error":{"code":"usage","message":"x"}`},
		{found, `"exit":1`, `"exit":0`},
		{found, `"kind":"match","tier":"private",`, `"kind":"match",`},
		{found, `"rule":"set:people"`, `"rule":"Set:people"`},
		{found, `"commit":"9c1e5b7a2f04d3b6a8e1c0f9d2b7a4e6c3f1a0b9","part":"author"`, `"part":"author"`},
		{found, `"part":"author"`, `"part":"body"`},
		{found, `"commit":"9c1e5b7a2f04d3b6a8e1c0f9d2b7a4e6c3f1a0b9","part"`, `"commit":"9c1e5b7a2f04","part"`},
		{found, `"path":"docs/a.md","path_redacted":false,`, `"path":"docs/a.md",`},
		{found, `"in_path":true`, `"in_path":false`},
		{found, `"line":3,`, `"line":-1,`},
		{found, `"line":3,`, `"line":3,"column":4,`},
		{found, `"kind":"match","tier":"private","rule":"set:people"`, `"tier":"private","kind":"match","rule":"set:people"`},
		{generic, `"findings":[]`, `"findings":[{"kind":"match","tier":"generic","rule":"id-prefix","label":"a b","line":1,"where":"a b"}]`},
		{generic, `"result":"clean","exit":0`, `"result":"findings","exit":1`},
		{failed, `"exit":2`, `"exit":1`},
		{failed, `"error":{"code":"term-file",`, `"error":{"code":"Term_file",`},
		{failed, `,"line":7}`, `,"line":0}`},
		{failed, `,"line":7}`, `,"line":7,"term":"x"}`},
		{failed, `"tiers":[]`, `"tiers":[],"scanned":{"files":0,"commits":0,"lines":0}`},
		{failed, `"target":"tree",`, `"target":"tree","findings":[],`},
		{failed, `"message":"term file: line 7: bad set name",`, ``},
	} {
		if !strings.Contains(c.doc, c.old) {
			t.Fatalf("case %d: the example does not hold %s", i, c.old)
		}
		doc := strings.Replace(c.doc, c.old, c.new, 1)
		err := CheckLine(doc)
		if err == nil {
			t.Errorf("case %d accepted: %s", i, doc)
		}
		lc.Check(t, fmt.Sprint(err))
	}
	for i, doc := range []string{clean[:len(clean)-1], clean + clean, "[]\n", clean[:20] + "\n" + clean[20:]} {
		if CheckLine(doc) == nil {
			t.Errorf("framing case %d accepted", i)
		}
	}
}
