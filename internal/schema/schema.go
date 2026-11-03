// Package schema checks a JSON document against the closed variant of ADR-001
// section 6.3's schema: the schema's keywords, written out by hand for its
// one document type, with every unknown field refused and every object's keys
// in the order hush writes them (HSH-11/D7). It is used by tests only, and
// uses the standard library only.
package schema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
)

// The keys of each object, in the order hush writes them.
var (
	docKeys     = []string{"schema", "hush", "result", "exit", "destination", "coverage", "tiers", "sets", "target", "scanned", "findings", "error"}
	findingKeys = []string{"kind", "tier", "rule", "in_path", "commit", "tag", "part", "path", "path_redacted", "label", "line", "where"}
	errorKeys   = []string{"code", "message", "argument", "line", "commit"}
	countKeys   = []string{"files", "commits", "lines"}
)

var (
	setName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	code    = regexp.MustCompile(`^[a-z]+(-[a-z]+)*$`)
	id      = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
	ruleRe  = regexp.MustCompile(`^([a-z0-9]+(-[a-z0-9]+)*|set:[A-Za-z0-9_.-]{1,64})$`)
	labelRe = regexp.MustCompile(`^(<stdin>|[A-Za-z0-9][A-Za-z0-9._-]{0,63})$`)
)

// object is a decoded JSON object with its keys in document order.
type object struct {
	keys []string
	vals map[string]any
}

// Check returns an error unless doc is one document that the closed schema
// accepts, with each object's keys in hush's order.
func Check(doc []byte) error {
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	v, err := decode(dec)
	if err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("more than one document")
	}
	o, ok := v.(*object)
	if !ok {
		return errors.New("not an object")
	}
	return checkDoc(o)
}

// CheckLine is Check for a document as hush writes it: one line, ended by a
// newline.
func CheckLine(out string) error {
	if len(out) == 0 || out[len(out)-1] != '\n' || bytes.Count([]byte(out), []byte("\n")) != 1 {
		return errors.New("not one line ended by a newline")
	}
	return Check([]byte(out))
}

// decode reads one value, objects as *object, numbers as json.Number.
func decode(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch tok {
	case json.Delim('{'):
		o := &object{vals: map[string]any{}}
		for dec.More() {
			k, err := dec.Token()
			if err != nil {
				return nil, err
			}
			key := k.(string)
			if _, dup := o.vals[key]; dup {
				return nil, fmt.Errorf("key %q repeated", key)
			}
			if o.vals[key], err = decode(dec); err != nil {
				return nil, err
			}
			o.keys = append(o.keys, key)
		}
		_, err := dec.Token()
		return o, err
	case json.Delim('['):
		list := []any{}
		for dec.More() {
			v, err := decode(dec)
			if err != nil {
				return nil, err
			}
			list = append(list, v)
		}
		_, err := dec.Token()
		return list, err
	}
	return tok, nil
}

// closed checks that o holds only keys from order, in that order, and every
// key of required.
func closed(o *object, what string, order []string, required ...string) error {
	last := -1
	for _, k := range o.keys {
		i := slices.Index(order, k)
		switch {
		case i < 0:
			return fmt.Errorf("%s: unknown field %q", what, k)
		case i < last:
			return fmt.Errorf("%s: field %q out of order", what, k)
		}
		last = i
	}
	for _, k := range required {
		if !o.has(k) {
			return fmt.Errorf("%s: no %q", what, k)
		}
	}
	return nil
}

func (o *object) has(k string) bool { _, ok := o.vals[k]; return ok }

func str(v any) (string, bool) { s, ok := v.(string); return s, ok }

// integer returns v as an integer, or false when it is not one.
func integer(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	return i, err == nil
}

func oneOf(v any, values ...string) bool {
	s, ok := str(v)
	return ok && slices.Contains(values, s)
}

func checkDoc(o *object) error {
	if err := closed(o, "document", docKeys, "schema", "hush", "result", "exit", "destination", "coverage", "tiers", "target"); err != nil {
		return err
	}
	exit, ok := integer(o.vals["exit"])
	switch {
	case o.vals["schema"] != "hush.scan/1":
		return errors.New("schema is not hush.scan/1")
	case !isString(o.vals["hush"]):
		return errors.New("hush is not a string")
	case !oneOf(o.vals["result"], "clean", "findings", "error"):
		return errors.New("bad result")
	case !ok || exit < 0 || exit > 2:
		return errors.New("bad exit")
	case !oneOf(o.vals["destination"], "public", "client", "private"):
		return errors.New("bad destination")
	case !oneOf(o.vals["coverage"], "complete", "generic-only"):
		return errors.New("bad coverage")
	case !oneOf(o.vals["target"], "tree", "index", "stdin", "range"):
		return errors.New("bad target")
	}
	tiers, ok := o.vals["tiers"].([]any)
	if !ok {
		return errors.New("tiers is not an array")
	}
	seen := map[string]bool{}
	for _, t := range tiers {
		if !oneOf(t, "generic", "private") || seen[t.(string)] {
			return errors.New("bad tiers")
		}
		seen[t.(string)] = true
	}
	if o.has("sets") {
		sets, ok := o.vals["sets"].([]any)
		if !ok {
			return errors.New("sets is not an array")
		}
		for _, s := range sets {
			if v, ok := str(s); !ok || !setName.MatchString(v) {
				return errors.New("bad set name")
			}
		}
	}
	if o.has("scanned") {
		c, ok := o.vals["scanned"].(*object)
		if !ok {
			return errors.New("scanned is not an object")
		}
		if err := closed(c, "scanned", countKeys, countKeys...); err != nil {
			return err
		}
		for _, k := range countKeys {
			if n, ok := integer(c.vals[k]); !ok || n < 0 {
				return fmt.Errorf("scanned: bad %s", k)
			}
		}
	}
	var findings []any
	if o.has("findings") {
		if findings, ok = o.vals["findings"].([]any); !ok {
			return errors.New("findings is not an array")
		}
		for i, f := range findings {
			if err := checkFinding(f); err != nil {
				return fmt.Errorf("finding %d: %v", i, err)
			}
		}
	}
	if o.has("error") {
		if err := checkError(o.vals["error"]); err != nil {
			return err
		}
	}
	// The schema's allOf: what each result requires and refuses.
	switch o.vals["result"] {
	case "clean":
		if !o.has("findings") || !o.has("scanned") || exit != 0 || len(findings) != 0 || o.has("error") {
			return errors.New("a clean result needs exit 0, scanned and no findings, and no error")
		}
	case "findings":
		if !o.has("findings") || !o.has("scanned") || exit != 1 || len(findings) == 0 || o.has("error") {
			return errors.New("a findings result needs exit 1, scanned and findings, and no error")
		}
	case "error":
		if !o.has("error") || exit != 2 || o.has("findings") || o.has("scanned") {
			return errors.New("an error result needs exit 2 and an error, and no findings or scanned")
		}
	}
	return nil
}

func isString(v any) bool { _, ok := v.(string); return ok }

func checkFinding(v any) error {
	f, ok := v.(*object)
	if !ok {
		return errors.New("not an object")
	}
	if err := closed(f, "finding", findingKeys, "kind", "rule", "line", "where"); err != nil {
		return err
	}
	line, ok := integer(f.vals["line"])
	switch {
	case !oneOf(f.vals["kind"], "match", "unscanned"):
		return errors.New("bad kind")
	case f.has("tier") && !oneOf(f.vals["tier"], "generic", "private"):
		return errors.New("bad tier")
	case !matches(ruleRe, f.vals["rule"]):
		return errors.New("bad rule")
	case f.has("in_path") && f.vals["in_path"] != true:
		return errors.New("in_path is not true")
	case f.has("commit") && !matches(id, f.vals["commit"]):
		return errors.New("bad commit")
	case f.has("tag") && !matches(id, f.vals["tag"]):
		return errors.New("bad tag")
	case f.has("part") && !oneOf(f.vals["part"], "author", "committer", "tagger", "header", "message"):
		return errors.New("bad part")
	case f.has("path") && (!isString(f.vals["path"]) || f.vals["path"] == ""):
		return errors.New("bad path")
	case f.has("path_redacted") && f.vals["path_redacted"] != true && f.vals["path_redacted"] != false:
		return errors.New("bad path_redacted")
	case f.has("label") && !matches(labelRe, f.vals["label"]):
		return errors.New("bad label")
	case !ok || line < 0:
		return errors.New("bad line")
	case !isString(f.vals["where"]):
		return errors.New("bad where")
	// dependentRequired, dependentSchemas and the if/then on kind.
	case f.has("path") && !f.has("path_redacted"):
		return errors.New("path without path_redacted")
	case f.has("part") && !f.has("commit") && !f.has("tag"):
		return errors.New("part without commit or tag")
	case f.vals["kind"] == "match" && !f.has("tier"):
		return errors.New("a match without tier")
	}
	return nil
}

func checkError(v any) error {
	e, ok := v.(*object)
	if !ok {
		return errors.New("error is not an object")
	}
	if err := closed(e, "error", errorKeys, "code", "message"); err != nil {
		return err
	}
	switch {
	case !matches(code, e.vals["code"]):
		return errors.New("error: bad code")
	case !isString(e.vals["message"]):
		return errors.New("error: bad message")
	case e.has("argument") && !positive(e.vals["argument"]):
		return errors.New("error: bad argument")
	case e.has("line") && !positive(e.vals["line"]):
		return errors.New("error: bad line")
	case e.has("commit") && !matches(id, e.vals["commit"]):
		return errors.New("error: bad commit")
	}
	return nil
}

func positive(v any) bool { n, ok := integer(v); return ok && n >= 1 }

func matches(re *regexp.Regexp, v any) bool {
	s, ok := str(v)
	return ok && re.MatchString(s)
}
