package target

import (
	"strings"

	"github.com/nonhumanhq/hush/internal/rule"
)

// object scans a commit or tag object as git cat-file prints it, with at's
// location (ADR-001 section 5, "What a commit scan covers"). A header runs
// from its keyword line through the lines after it that start with a space.
// In a commit, the ids idHeaders counts at its top are skipped; in a tag,
// object and type headers are. Every other header is scanned, with its part:
// author, committer and tagger as themselves, any other, such as encoding,
// mergetag, gpgsig, a tag's tag line, or a tree or parent header that is not
// one of those ids, as Header. The message follows the first empty line.
// Lines carry their numbers in the object.
//
// Signature blocks are skipped as HSH-11/D15 says: in gpgsig and gpgsig-sha256
// headers, a block anywhere; in a mergetag header and in a tag's message, a
// block that ends the header or the message, as a signature does.
func (s *Scan) object(at Finding, obj []byte, tag bool) {
	ls := lines(obj)
	i := 0
	if !tag {
		i, _ = idHeaders(ls)
	}
	for i < len(ls) && ls[i] != "" {
		key, _, _ := strings.Cut(ls[i], " ")
		end := i + 1
		for end < len(ls) && strings.HasPrefix(ls[end], " ") {
			end++
		}
		skipped := tag && (key == "object" || key == "type")
		if !skipped {
			content := make([]string, end-i)
			content[0] = strings.TrimPrefix(ls[i][len(key):], " ")
			for k := i + 1; k < end; k++ {
				content[k-i] = ls[k][1:]
			}
			var skip []bool
			switch key {
			case "gpgsig", "gpgsig-sha256":
				skip = signatures(content, false)
			case "mergetag":
				skip = signatures(content, true)
			}
			part := headerPart(key)
			for k := i; k < end; k++ {
				if skip == nil || !skip[k-i] {
					s.line(at, part, k, ls[k])
				}
			}
		}
		i = end
	}
	if i >= len(ls) {
		return
	}
	msg := ls[i+1:]
	var skip []bool
	if tag {
		skip = signatures(msg, true)
	}
	for k, line := range msg {
		if skip == nil || !skip[k] {
			s.line(at, rule.Message, i+1+k, line)
		}
	}
}

// idHeaders returns how many lines at the top of the commit object ls are
// the ids git reads as its tree and parents, and the parents' ids: the first
// line, when it is "tree ID", and the "parent ID" lines straight after it,
// each counted only when no continuation line follows it and ID is a full
// object id. Any other tree or parent line, a continuation line included, is
// scanned as a header, and is not a parent.
func idHeaders(ls []string) (n int, parents []string) {
	single := func(k int, key string) (string, bool) {
		if k >= len(ls) || k+1 < len(ls) && strings.HasPrefix(ls[k+1], " ") {
			return "", false
		}
		id, ok := strings.CutPrefix(ls[k], key+" ")
		return id, ok && isID(id)
	}
	if _, ok := single(0, "tree"); !ok {
		return 0, nil
	}
	n = 1
	for {
		id, ok := single(n, "parent")
		if !ok {
			return n, parents
		}
		parents = append(parents, id)
		n++
	}
}

// line scans the object line at 0-based index k with part.
func (s *Scan) line(at Finding, part rule.Part, k int, line string) {
	at.Part = part
	s.emit(at, k+1, line, rule.Context{Source: rule.Object, Part: part})
}

// headerPart is the part of a header with keyword key.
func headerPart(key string) rule.Part {
	switch key {
	case "author":
		return rule.Author
	case "committer":
		return rule.Committer
	case "tagger":
		return rule.Tagger
	}
	return rule.Header
}

// signatureKinds are the armor names a signature block may carry.
var signatureKinds = []string{"PGP SIGNATURE", "PGP MESSAGE", "SSH SIGNATURE"}

// signatures marks the lines of ls that signature blocks let hush skip
// (HSH-11/D15). A block starts at a line "-----BEGIN KIND-----" and ends at
// the next "-----END KIND-----" of the same kind; with atEnd, only a block
// after which nothing but empty lines follows counts. Inside a block only the
// BEGIN and END lines, lines of nothing but base64 characters with up to two
// "=" at the end, and one checksum line ("=" and base64 characters) are
// skipped; every other line, such as an armor header "Comment: ...", is
// scanned. An unterminated block is scanned whole.
func signatures(ls []string, atEnd bool) []bool {
	skip := make([]bool, len(ls))
	for i := 0; i < len(ls); i++ {
		kind := ""
		for _, k := range signatureKinds {
			if ls[i] == "-----BEGIN "+k+"-----" {
				kind = k
			}
		}
		if kind == "" {
			continue
		}
		end := -1
		for j := i + 1; j < len(ls); j++ {
			if ls[j] == "-----END "+kind+"-----" {
				end = j
				break
			}
		}
		if end < 0 {
			break
		}
		if atEnd {
			rest := strings.Join(ls[end+1:], "")
			if rest != "" {
				i = end
				continue
			}
		}
		skip[i], skip[end] = true, true
		checksum := false
		for j := i + 1; j < end; j++ {
			switch {
			case base64Line(ls[j]):
				skip[j] = true
			case !checksum && len(ls[j]) > 1 && ls[j][0] == '=' && base64Line(ls[j][1:]) && !strings.Contains(ls[j][1:], "="):
				skip[j], checksum = true, true
			}
		}
		i = end
	}
	return skip
}

// base64Line reports whether l holds only base64 characters, with up to two
// "=" at the end. An empty line, the armor's separator, counts.
func base64Line(l string) bool {
	l = strings.TrimSuffix(strings.TrimSuffix(l, "="), "=")
	for i := 0; i < len(l); i++ {
		c := l[i]
		if !('A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '+' || c == '/') {
			return false
		}
	}
	return true
}
