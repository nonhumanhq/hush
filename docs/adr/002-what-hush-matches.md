---
kind: decision
status: accepted
verified: 2026-10-25
supersedes: []
---

# ADR-002: What hush matches

## Context

hush keeps private names out of records that may become public. Its **private tier** matches term sets that only the human holds; its **generic tier** runs rules that hold nothing secret and so can run anywhere (`reference/bootstrap-loop.md`, "Hush in the loop"). This ADR decides what those parts match: the term-set file and how its terms match, where the files live, the three v0.1 generic rules, and the internal interfaces that v0.2's hostname and secret-format rules and its normalization steps plug into.

**The interim scanner** (`reference/interim-hush/`) is the starting point.
- **Term file.** `[name]` starts a set, there is one term per line, and a line starting with `#` is a comment. Lines are trimmed of spaces, tabs and CRs. Set names use letters, digits, `_`, `.` and `-`. A term before any `[name]`, a bad set name or a file with no terms exits 2. A repeated `[name]` continues the earlier set.
- **Matching.** Terms match as substrings of each line and of each whole path, ignoring ASCII case only. Inner spaces must match exactly.
- **Generic tier.** Only the ID-prefix rule: any token shaped `[A-Z]+-[0-9]+` whose prefix is not `HSH`, `CHS`, `FLT`, `SWE` or `ADR`, with `FLEET` and `VMWS` also allowed in paths under `reference/`.
- **Known limits.** No IP, email, hostname or secret rules; no normalization; substring matching gives false positives for short terms; the ID-prefix rule flags standard names written with a hyphen.

**ADR-001** (HSH-1, accepted on 2026-10-24 in PR #8) owns destinations, failing closed, output and the API. Its section 9 asks this ADR for a per-set visibility declaration, load-time checks of set names and client labels, a rule registry with stable names, the source of the ID-prefix allowlist, and the email identity allowance as explicit caller input. This ADR follows ADR-001 and cites its decided items by number. Section 6 answers each ask and lists the two places where this ADR extends ADR-001's accepted text; ADR-001 was amended to record them when this ADR was accepted (decided item 7).

**The siblings.** HSH-5 ports the interim scanner at parity, so it keeps the interim format and pattern. HSH-14 builds the IP and email rules from sections 4.2, 4.3 and 5. HSH-11 applies the rest of this ADR and ADR-001.

Five forces shape the decisions.
1. **The term sets are the secret.** Every tool, file or process that reads them is one more place they can leak.
2. **A miss at the publish gate is worse than a false positive.** A false positive costs the writer a rephrase. A miss is permanent once published. Rules are broad where the cost is a rephrase and narrow only where the noise would never stop.
3. **Short terms.** Client abbreviations are short, and short substrings occur everywhere (section 2.3 measures it).
4. **v0.2 must plug in without a redesign:** hostname and secret-format rules, and normalization beyond ASCII case.
5. **hush scans its own repository** (HSH-11): the whole tree, `reference/` and this file included.

**Conventions in this ADR.**
- A rule *flags* a line when it reports a finding for it.
- A token that a rule must flag is written as a Go string concatenation, such as `"10.1." + "2.3"`, the way tests assemble it at run time. So this file scans clean under its own rules.
- For the same reason, special-purpose address ranges other than the documentation ranges are named by RFC and by `net/netip` predicate, never in block notation.
- Patterns use Go `regexp` (RE2) syntax.
- "Decided item N" alone refers to row N of this ADR's "Decided at acceptance", where the human's answers are recorded. ADR-001's are cited as "ADR-001's decided item N", or "its decided item N" right after ADR-001 is named.
- Claims about `net/netip`, `regexp` and case folding, and every address and email example, were checked with Go 1.26 against a prototype of the rules.

## Decision

### 1. The term-set file

**Format 1** is the interim format, extended with attributes on set headers (decided item 1).

#### 1.1 Grammar

The file is UTF8 text without a byte-order mark. Each line is trimmed of spaces, tabs and CRs at both ends, as the interim does, and is then read as the first of these that fits:

| After trimming, the line | is a | and must |
| --- | --- | --- |
| is empty | blank line | — |
| starts with `#hush-terms`, on line 1 | format marker | be exactly `#hush-terms 1` (section 1.6) |
| starts with `#` | comment | — |
| starts with `[` or ends with `]` | header | start with `[`, end with `]`, and match `header` below |
| is anything else | term of the set named by the nearest header above it | match `term` below |

```
header     = "[" name *( 1*WSP attribute ) "]"     ; WSP is a space or a tab
name       = 1*64( ALPHA / DIGIT / "_" / "." / "-" )
attribute  = key "=" value *( "," value )
key        = "visible-to" / "case" / "match"
value      = 1*( ALPHA / DIGIT / "_" / "-" )
term       = 1*( any character that is not refused below )
```

The grammar is in the style of ABNF (RFC 5234), with the term's characters in prose. Further rules:
- **Headers.** There is no space after `[` or before `]`.
  - Each set name appears in exactly one header.
  - Each key appears at most once in a header, and each value at most once for its key.
  - `case` and `match` take one value each: `case` is `ignore` or `exact`, and `match` is `substring` or `word`. Writing a default, such as `case=ignore`, is allowed.
  - A line that starts with `[` but does not end with `]`, or ends with `]` but does not start with `[`, is refused (`bad header`). Read as a term, it would join the set above it, and so would every term under it, taking that set's `visible-to`: one client's names would go unchecked in another client's scans.
- **Terms.**
  - A term is the trimmed line, kept exactly.
  - Each set holds at least one term, so the file does too.
  - Terms may repeat, within a set or across sets.
- **Characters no line may hold.** No line, whatever it is read as, may hold a control character other than tab (U+0000 to U+001F, U+007F, and the C1 controls U+0080 to U+009F), the line and paragraph separators U+2028 and U+2029, or bytes that are not valid UTF8 (`bad character`). An editor may show any of the characters as a line break, so a term written after one in a comment would look listed and never load. Invalid UTF8 is checked on every line, comments included, so every implementation reads a comment the same way.
- **Characters a term may not hold.** Each would make the term match only text that carries the same stray character, a silent miss, so each is refused at load (`bad term`):
  - Unicode White_Space characters other than the ASCII space and tab, such as a no-break space or U+3000 (in Go, `unicode.IsSpace`, which follows that property exactly; checked);
  - format characters (general category Cf, `unicode.Cf` in Go), which are invisible and which pasting from documents, web pages and right-to-left text often leaves behind: among them the zero-width space U+200B, U+FEFF, the soft hyphen U+00AD, the left-to-right and right-to-left marks U+200E and U+200F, the bidi embeddings, overrides and isolates, the word joiner U+2060, U+180E and the tag characters;
  - a space or a tab followed by `#`, the shape of a comment written after a term on the same line.

  Three kinds of character stay allowed. The zero-width joiner and non-joiner (U+200D, U+200C) are format characters that some scripts need inside a word. The prepended concatenation marks, such as U+0600, are format characters that are visible. Variation selectors and the combining grapheme joiner U+034F are marks, not format characters, and some names need them. (Checked with Go 1.26, whose tables are Unicode 15.0.0.) v0.2's step 1 removes the invisible ones from terms and text alike (section 2.5).
- **What cannot be written.** A term cannot start with `#` or `[`, cannot end with `]`, cannot start or end with a space or a tab, and cannot hold the characters above. Format 1 has no escapes (section 1.6).
  - A line written with a leading `#` is a comment, so write such a term without the `#`, which matches at least as much.
- **Size.** The explicit size limits that HSH-11 sets (ADR-001 section 5) apply to the term file as well. An over-size term file exits 2 with ADR-001's code `read` and its fixed message, with no line number.

#### 1.2 What a set means

- A **set** is a named list of terms. A line, path or object text that matches any term of a set gives one `set:NAME` finding for that line (ADR-001 section 6.1).
- **`visible-to=k7,k9`** means the set does not apply to a `client:k7` or `client:k9` scan. It applies to `public` and to every client destination other than those it names (ADR-001 section 4). A set without the attribute applies to `public` and to every client destination. The `private` destination applies no sets.
  - The values are client labels in ADR-001's grammar: 1 to 32 characters from `[a-z0-9_-]`, starting with a letter or digit, and neither `public` nor `private`. So there is no wildcard.
  - ADR-001 owns the policy: deny by default, every set applies to `public`, and redaction uses every set.
- **`case=exact`** and **`match=word`** (decided item 3) change how the set's terms match (section 2). Their defaults are `case=ignore` and `match=substring`, which may also be written.
- **Nothing else.** The file holds no paths, includes, rule names, references to other sets, destinations other than client labels, or allowances. So ADR-001's `unknown-set` and `unknown-rule` errors cannot arise in v0.1.

#### 1.3 Naming sets

- **Set names are printed:** in findings as `set:NAME`, in the JSON `sets` field, and on staging PRs when the human relays a finding (ADR-001 section 3). Name a set for the kind of thing it holds, never for what it holds: `clients`, `people`, `domains`, `hosts`, `abbreviations`.
- **A set for one client** takes that client's code from ADR-001, as in `clients-k7` with `visible-to=k7`. It never takes the client's name or abbreviation, nor any part of one.
- **Grammar.** 1 to 64 characters from `[A-Za-z0-9_.-]`, so a name never holds `:` and `set:NAME` always parses. Lowercase is recommended but not enforced.
- **Refused at load** if it contains a term, in any ASCII case, or breaks a generic rule (section 1.4). Some names that reveal a word of a term still load, such as `zantoph`, `clients-zantoph` and `zantophclients` beside the term `zantoph works`. Section 1.4 lists them, and this naming rule is the guard against them.
- **List a distinctive word on its own.** When a word of a longer term matters alone, such as a client's distinctive word beside the addresses, URLs and full names that hold it, list that word as a term of its own. It is then caught in content too, and check 1 of section 1.4 refuses every set name and client label that holds it.
- **What that costs.** A term refuses every name that contains it, whatever its set's `case` and `match` options (decided item 3): a two-letter term refuses at least one of the five names above in 31 of the 676 possible cases (checked). When a name is refused, the human picks another kind-word.

#### 1.4 Load-time checks

After the file parses, package `hush` checks every set name and every client label in a `visible-to` attribute. Check 1 ignores ASCII case, whatever a set's `case` option says, because a name in another case still reveals the term. Check 2 runs the rules on the name as written.
1. **A term inside the name.** A name or label that contains a term, ignoring ASCII case, is refused. This is plain containment for every term, as ADR-001 section 5 reads, whatever its set's `case` and `match` options (decided item 3). A `match=word` term glued to letters in a printed name would still reveal the term.
2. **Against every generic rule in the registry,** as a bare string (`Source` `Text`, section 5.1), on the name as written. So neither the `reference/` exception nor the identity allowance applies. A client label holds only lowercase letters, digits, `_` and `-`, so no v0.1 rule can refuse one (checked); the check runs for the rules later versions add.

A refusal exits 2 with `term file: line N: set name refused` or `term file: line N: client label refused`, where N is the header's line. For example:
- the term `quorvel` refuses the set name `quorvel-notes` (check 1);
- a term `NT` refuses the set name `clients`, whatever its set's `case` and `match` options (check 1);
- the term `QVL` in a `match=word` set refuses the set names `qvlnotes`, `qvlclients` and `clientsQVL` (check 1);
- the set name `notes-2026` loads: `id-prefix` needs an uppercase letter, and check 2 does not fold case.

**What the checks still let through.** Each of these loads, and section 1.3's naming rule is the guard against it:
- a name that holds part of a term's word, such as its first syllable;
- a name that holds a word of a term but not the whole term, such as `zantoph`, `clients-zantoph`, `zantophclients` or `ZantophClients` beside the term `zantoph works`. Once `zantoph` is listed as a term of its own (section 1.3), check 1 refuses each of them. A check that refuses a name with a part equal to a word of a term is deferred to v0.2 (Alternatives).

ADR-001 checks a label given with `--destination` the same way, with its code `destination`.

**Stdin labels.** ADR-001 section 5 also refuses a stdin label that contains a term or breaks a rule. That check keeps ADR-001's plain containment, ignoring ASCII case, the same as check 1. So a short term can refuse a fixed label that a hook passes, such as `commit-message`: 11 of the 676 two-letter terms do. That hook's scans then exit 2 until the term or the label changes.

#### 1.5 Errors

Every error below exits 2 with ADR-001's code `term-file`. Each message is fixed text with a line number. None holds a term, a set name, a label, a line's text or the file's path.

| Condition | Message, after `hush: ` |
| --- | --- |
| A term before the first header, or a byte-order mark at the start of the file | `term file: line N: term outside a set` |
| A line that holds a control character other than tab, U+2028 or U+2029, or bytes that are not valid UTF8 | `term file: line N: bad character` |
| A line that starts with `[` but does not end with `]`, or ends with `]` but does not start with `[` | `term file: line N: bad header` |
| A header whose name is empty or breaks the grammar | `term file: line N: bad set name` |
| A malformed attribute, an unknown key or value, or a repeated key or value | `term file: line N: bad attribute` |
| A `visible-to` value outside the client-label grammar | `term file: line N: bad client label` |
| A set name that an earlier header already declared | `term file: line N: set declared twice` |
| A term that holds a character section 1.1 refuses in terms | `term file: line N: bad term` |
| A set with no terms (N is its header's line) | `term file: line N: set has no terms` |
| A set name or client label refused by section 1.4 | `term file: line N: set name refused`, `term file: line N: client label refused` |
| Line 1 starts with `#hush-terms` but is not `#hush-terms 1` | `term file: line 1: unsupported format` |
| The file holds no term | `term file holds no terms` |

**Which error is reported.**
- **Across the file:** the first error in file order. A set's emptiness is known at the next line that starts with `[` and ends with `]`, before that line's other checks, `bad character` included, or at the end of the file, and its message gives the set's header line. So a line with only one bracket gives `bad header` on its own line wherever it stands, even as the first line under its header. The load-time checks of section 1.4 run only on a file that parses, in file order; within a header, the set name is checked before its client labels. `term file holds no terms` is reported only when no line has an error.
- **At the start of the file,** a byte-order mark gives `term outside a set` on line 1 before any other check, whatever follows it, as in the interim.
- **Then, on every line,** `bad character` is checked before the line is read as anything.
- **Within a header line,** in this order:
  1. A line that does not both start with `[` and end with `]` gives `bad header`.
  2. The name is the text from `[` to the first space, tab or `]`. If it is empty or breaks `name`, the reason is `bad set name`.
  3. The rest, up to the closing `]`, must parse as `*( 1*WSP attribute )`, with known keys, a known value for `case` and `match`, and no key or value repeated. Otherwise the reason is `bad attribute`.
  4. A `visible-to` value that matches `value` but not ADR-001's client-label grammar gives `bad client label`.
  5. A header that parses but names a set declared earlier gives `set declared twice`.
- **Within a term line:** `term outside a set` comes before `bad term`.

A file that is missing, unreadable, too widely readable or inside a scanned path fails as ADR-001 section 5 says, and one over the size limit as section 1.1 says.

#### 1.6 Versioning

- **Format 1** is the interim format plus header attributes and the optional marker. Every interim file is a format 1 file with the same meaning, unless it meets one of the refusals in section 1.7. Each of those exits 2 with a line number, so no interim file changes meaning silently.
- **Within format 1,** changes only add attribute keys or values. An older hush refuses a key or value it does not know (`bad attribute`), so it never applies a set differently from what the file says. The interim scanner already refuses any header with an attribute (`bad set name`, checked), so a file that uses attributes cannot be fed to it by mistake.
- **A new format** is needed for a change that would give a line an older hush accepts a different meaning, such as an escape syntax for terms that start with `#`. A format-N file must start with `#hush-terms N`. v0.1 refuses any N other than 1 (`unsupported format`). A change that only adds matches keeps format 1: an older hush then matches less than a newer one, but never applies a set the file does not ask for. v0.2's normalization is such a change only under section 2.5's constraint that no step removes a match v0.1 gives, with `match=word` boundaries judged on the original bytes.
- **Release notes** say which formats a hush release reads. The format number and hush's version are independent.

#### 1.7 Migration from the interim format

An interim file loads unchanged unless one of these applies. In each case hush exits 2 and names the line.

| Interim | Format 1 | What the human does |
| --- | --- | --- |
| A repeated `[name]` continues the set | `set declared twice` | Merge the sections |
| A set may hold no terms | `set has no terms` | Delete the header, or add terms |
| A set name may be any length | 1 to 64 characters | Shorten it |
| A term may hold any bytes, and a `#` after a term is part of it | `bad term` for a term that holds a Unicode space other than space and tab, a format character other than those section 1.1 allows (such as U+200B, U+FEFF, a soft hyphen or a bidi mark), or a space or tab followed by `#` | Fix the term; move a trailing comment to a line of its own. A term that holds such a character on purpose, as a variant, cannot be kept: that variant stays a miss until v0.2 (section 2.4) |
| A term or a comment may hold control characters, so a comment may hold a lone CR with text after it, and any line may hold bytes that are not valid UTF8 | `bad character` for a control character other than tab, U+2028, U+2029 or bytes that are not valid UTF8, on any line, comments included | Remove the character, and put any text after it on a line of its own; save the file as UTF8 |
| A line that starts with `[` or ends with `]`, but not both, is a term | `bad header` | Fix the header. A term that starts with `[` or ends with `]` drops that bracket, which matches at least as much |
| Set names are not checked | `set name refused` when section 1.4 refuses a name | Rename the set |
| Line 1 may be any comment | A line 1 that starts with `#hush-terms` must be `#hush-terms 1` (`unsupported format`) | Reword the comment |

ADR-001 adds two more changes:
- the file's permissions (ADR-001 section 5 and its decided item 8);
- for client destinations, each client's own names move into a set named by the client's code, with `visible-to`.

There is no converter, because the edits are few and every extra tool that reads the term file is another place it can leak. HSH-11's migration guide carries this table.

#### 1.8 Example

Synthetic: every term is invented, and `MOP` stands for an abbreviation that spells a common word.

```
# Keep this file outside every repository (section 3).
[clients]
quorvel
zantoph works

[clients-k7 visible-to=k7]
brindlemoor

[people]
mirelda

[abbreviations match=word]
QVL

[abbreviations-exact case=exact match=word]
MOP
```

Short abbreviations go in a `match=word` set, which matches them in any ASCII case (decided item 3). An abbreviation that spells a common word, such as `MOP`, goes in a set that also takes `case=exact`, so the word in ordinary text is not flagged; that set then matches only the case written, so each other case form that matters is listed as a term of its own. Section 2.3 gives the cost of each mode.

### 2. Matching in v0.1

#### 2.1 What is compared

- **Lines.** Each line of each file, blob or added diff hunk, and of commit and tag object text and standard input, as ADR-001's targets define them. Lines end at LF and no term holds an LF, so a term never matches across a line break.
- **Paths.** Each path, as one string with its `/` separators, so a term that spans a `/` matches. ADR-001 section 6.4 redacts from the component where the match begins.
- **Names and labels.** Set names and client labels, at load (section 1.4).

#### 2.2 Case

- **ASCII only.** ASCII letters match regardless of case, so `quorvel` matches `QuorVel`. Every other byte must be equal: a term holding `é` does not match `É`, and the Kelvin sign (U+212A) does not match `k`.
- **How.** hush lowers the bytes `A` to `Z` in each term once, at load. It lowers each scanned line byte for byte into a copy, through section 5.3's `Normalizer`, and matches terms against the copy. Lowering byte for byte keeps offsets, which redaction needs.
- **The raw line is kept.** The rules see the raw line (section 4), so `id-prefix` still sees uppercase keys. Matching never writes to the scanned bytes, so the buffer a caller passes to `ScanBytes` stays as it was, and `hush gh` posts exactly the bytes it scanned (ADR-001 section 2).
- **Not Go's folding.** `strings.ToLower` and `strings.EqualFold` must not be used. They fold non-ASCII letters too, turning the Kelvin sign into `k`, and `ToLower` can change byte lengths: U+0130 becomes the one byte `i`, U+023A grows from two bytes to three, and the Kelvin sign shrinks from three bytes to one (checked).
- **`case=exact`** (decided item 3) skips the folding for that set.

#### 2.3 Substring or word

- **Substring** (the default, decided item 2). A term matches wherever its bytes occur in the folded line. This is the interim's rule.
- **Word** (`match=word`, decided item 3). An occurrence counts only if neither the byte before it nor the byte after it is an ASCII letter; the start and end of the line count as boundaries. A line matches if any occurrence counts.
  - Digits, `_`, `-`, `.`, `/` and non-ASCII bytes are boundaries, so with the term `QVL`, the forms `QVL2`, `QVL_api`, `x-QVL` and `docs/QVL/` match.
  - `AQVLB` and `QVLClient` do not match.
- **No regular expressions.** Terms never enter a pattern's source (ADR-001 section 6.6).

**The false-positive cost, measured.** The corpus is the `.go` files under Go 1.26.7's `src`, toolchain and vendored packages included and testdata directories excluded: 2,764,357 lines. For every possible term of two, three and four ASCII letters, this counts the share of lines the term matches, ignoring case:

| Term length | Substring: terms matching over 1 line in 100 | Substring: worst term | Word: terms matching over 1 line in 100 | Word: worst term |
| --- | --- | --- | --- | --- |
| 2 letters (676 terms) | 34.5% | 22.9% of lines | 1.6% | 6.6% of lines |
| 3 letters (17,576) | 0.9%, and 7.6% over 1 in 1,000 | 10.0% | 0.1%, and 0.5% over 1 in 1,000 | 4.7% |
| 4 letters (456,976) | 0.0%, and 0.2% over 1 in 1,000 | 5.4% | 0.0% | 3.9% |

English prose looks the same or worse. In the runbook's 415 lines, 39.9% of two-letter terms match over 1 line in 100 as substrings, and 3.0% as words.

What it means:
- **Two letters.** A third of all two-letter terms match over one line in a hundred as substrings. In a repository of 10,000 lines that is a hundred findings or more on every scan. Word mode cuts that roughly twentyfold.
- **Three letters** are usually fine as substrings. About one in a hundred, a common letter sequence, still flags over one line in a hundred.
- **Four letters or more** cost almost nothing as substrings.
- **Word mode's cost is misses.** An abbreviation glued to letters, as in `QVLClient` or `getQvl`, does not match, so the human lists such forms as extra terms.
- **`case=exact` costs misses too.** With it, `qvl` in a path or a package name does not match `QVL`. So it is kept for abbreviations that spell a common word (section 1.8).
- **Before adding a short term,** the human can search the repositories for it to see what it would flag.

#### 2.4 What v0.1 does not normalize

Each of these is a known miss in v0.1. Section 2.5 outlines the steps v0.2 adds for them; where no step covers a miss, the list says so:
- non-ASCII case (`É` and `é`);
- separators: `zantoph works` against `zantoph-works`, `zantoph_works`, `zantophworks`, two spaces or a tab. A variant split across a line break is a miss no step covers, because a term never spans lines (section 2.1);
- abbreviation variants, such as a dotted form against `QVL`. Step 5 covers dotted and separated forms; other variants are left to v0.2's ADR (step 6);
- an accented letter written as one character against the same letter written with a combining mark;
- invisible and space characters: a no-break space or another Unicode space between words, and a soft hyphen or a zero-width or other format character inside a word;
- look-alike characters: a Cyrillic letter for a Latin one, fullwidth letters;
- encodings: percent-encoding, HTML entities, base64, punycode. No step in the outline decodes them; v0.2's ADR decides whether one should.

v0.1's answer is the epic's: list each variant that matters as its own term. Agents never see the sets, so they cannot steer around a variant the human has listed.
- **Variants v0.1 can list:** a hyphen, an underscore or no separator between words, two spaces, a tab, a dotted or otherwise separated abbreviation, a non-ASCII case form, a look-alike spelling, and an accented letter written either way. Each loads as a term of its own.
- **Variants v0.1 cannot list:** a no-break space or another Unicode space, a soft hyphen, and a zero-width or other format character inside a word. Format 1 refuses these in terms (section 1.1, `bad term`), because pasted by accident they make a term silently match nothing. So such variants stay misses until v0.2's step 1 removes the invisible ones and step 2 maps Unicode spaces to a space, in terms and text alike. Where one word of a client's name is distinctive, listing that word alone (section 1.3) still catches a variant that differs only by the space between its words; a name made of common words has no such remedy in v0.1.

#### 2.5 The v0.2 normalization pipeline, in outline

The steps apply in this order, to terms at load and to text at scan:
1. Remove default-ignorable characters: zero-width spaces and joiners, soft hyphens, bidi controls.
2. Compatibility normalization (NFKC): fullwidth forms, ligatures, superscripts.
3. Fold look-alike characters to a skeleton (Unicode Technical Standard #39, confusables).
4. Unicode case folding.
5. Fold separators: drop spaces, hyphens, underscores and dots, so `zantoph works` also matches `ZantophWorks`.
6. Other abbreviation variants, such as letters left out or reordered, are left to v0.2's ADR. If it adds a step for them, such as a per-set list of variants, a set opts in through a new attribute key, which v0.1 refuses (section 1.6). Until then the human lists each variant that matters as a term.

Every step maps each byte of its output back to the input offset it came from. So a match in normalized text still gives ADR-001's redaction the earliest original byte.

**No step removes a match v0.1 gives.** v0.2 may only add matches (section 1.6).
- For `match=word` sets, section 2.3's boundaries are judged on the original line, at the bytes just before and just after the span that the offsets map back to, never on the normalized copy. Judged on the copy, step 5 would glue `x-QVL`, `QVL_api` and `the QVL team` into words, and step 1 would do the same to an abbreviation after a zero-width space, so word sets would lose matches v0.1 gives.
- Word sets take every step, step 5 included: step 5 is what covers the dotted and separated forms of abbreviations (section 2.4), which word sets exist for.
- Section 5.3's offsets give a source start for each output byte, so the end of a span is implied. For steps 1, 4 and 5 it can be found by decoding the source character at the last mapped offset. Whether composing steps such as NFKC need the `Normalizer` to report spans is v0.2's ADR to decide.

**The extension point** is the `Normalizer` interface in `internal/termset` (section 5.3).
- v0.1 has one normalizer per set: ASCII lowering, or none with `case=exact` (decided item 3).
- v0.2 adds steps to the chain.
- If sets need to choose steps, that is a new attribute key, such as `normalize=`. A v0.1 hush refuses it (section 1.6), so a file that relies on it never loads in a hush that cannot honour it.

**What the standard library lacks.** Go's standard library has Unicode case mapping, but no Unicode normalization or confusables data that can be imported. `golang.org/x/text/unicode/norm` is vendored inside it, and importing it is refused (checked with Go 1.26). Steps 2 and 3 therefore need one of two things:
- tables generated into hush from the Unicode data files, with their generator and tests;
- an exception to ADR-001's standard-library-only rule.

v0.2's ADR decides. Generic rules may also want normalized text, such as an ID token written with a Unicode dash; section 5.5 shows how that plugs in.

### 3. Where term sets live

| Machine | Term sets | How hush is told | Requirements |
| --- | --- | --- | --- |
| The review machine, the human's own hardware (now) | One term file | `--terms PATH` on each command: building the reference pack, both publish scans, the full-history scan, and hooks installed there with HSH-9's term-file flag. Such a hook holds the path, never the terms | hush refuses the file inside a scanned path, and when group or others can read or write it (ADR-001 section 5 and its decided item 8). Setup advice that hush does not check: keep it outside every repository, clone and worktree, outside any folder that syncs to a service or is shared with another account, and in a directory of mode 0700 that the human owns |
| The publish step (now) | The same file | It runs on the review machine | A release build of hush (ADR-001 section 2) |
| The scanner account on the fleet Mac (v0.2) | Its own copy | `--terms PATH` in the scanner's own configuration, never inside a mirror it scans | A separate OS account. The agent account cannot read its copy. The human copies the file in. Scanner mode's ADR (HSH-13) decides the rest |
| Agent machines, cloud runs, staging CI | Never, in any form | — | They scan with `--generic-only` (ADR-001) |

- **How hush is told.** Only by the path the caller passes (ADR-001 section 1 and its negative tests 3 to 5).
  - One term file per scan holds every set.
  - It is refused inside a scanned path (ADR-001 section 5).
  - It names no other file (section 1.2).
- **Copies.** The human moves the file between machines over a channel no agent can read. Never through a repository, an issue or PR, a CI secret or variable, or a conversation with a model.

**Why agent machines never hold term sets.**
1. **The sets are the secret.** They list exactly what the public record must not hold.
2. **What an agent reads can travel.** It can enter the model's context, which leaves the machine for the model provider, and resurface in transcripts, logs, commits and posts. The clean-room bar is that a run "never sees private term sets or client data".
3. **Hashing does not help.** Short abbreviations can be brute-forced from their hashes in seconds (runbook).
4. **A private tier is an oracle.** An agent that could run it could test candidate words: pass or fail tells it whether a word is a term. For the same reason ADR-001 section 3 (its decided item 7) limits what the human relays, and blocks a unit for the human after its second private-tier failure.
5. **Agents do not need them.** The generic tier gives them feedback at commit time, and the private tier is the human's gate at publish.

#### 3.1 The identity allowance

The email rule's identity allowance (section 4.3) is a list of addresses the caller passes as a flag value, `--identities ADDR[,ADDR…]`, or in the API as `Config.Identities` (section 5.4). The addresses are not secret: the human's address is in every published `Signed-off-by:` trailer, and the agent identity's is in every staging commit. They come only from the caller's command line or configuration, never from the scanned repository, so no change in the repository can widen what passes (ADR-001 section 1).

| Machine | It lists | Passed with `--identities` by |
| --- | --- | --- |
| The review machine | The human's commit address, plus any platform address the full-history scan meets | The publish scans, the full-history scan and the review machine's hooks |
| Each agent machine | The agent identity's commit address, and nothing else | The hooks HSH-9 installs (HSH-11 adds the flag) |
| Staging CI, if it scans ranges | The agent identity's commit address | The workflow, a human-only file, which takes it from a repository variable |

- **No file to guard.** A value cannot sit inside a scanned path and has no file mode, so hush checks neither. Changing an address means changing the commands that pass it, and reinstalling the hooks.
- **On an agent machine** the agent's own account can edit its hooks, and so the value. That is acceptable: agent-side scans give early feedback, and the gate is the publish scan on the review machine.
- **Form:** section 5.4.

### 4. The generic rules in v0.1

What all three rules share:
- **What a rule returns.** A rule reports whether a line breaks it and where its earliest breaking match begins, for redaction (section 5.1). It never reports what matched. A line gives at most one finding per rule (ADR-001 section 6.1).
- **Where rules run.** On every target and on every path. In v0.1 they see the raw line, not a normalized one.
- **Registry order,** which is the order of findings within a line (ADR-001 section 6.2): `id-prefix`, `ip-address`, `email-address`.
- **How patterns are applied.** Each is found left to right without overlaps (`FindAllIndex`), and its character classes are ASCII unless a rule says otherwise.
- **"Before" and "after"** mean the byte just outside a candidate on the same line. The start and the end of the line are neither letters nor digits.
- **The example tables** were run through a prototype of these rules with Go 1.26.

#### 4.1 `id-prefix`

| Name | `id-prefix` |
| --- | --- |
| Pattern | `[A-Z][0-9A-Z_]*-[0-9]+`. The prefix is the text before the hyphen |
| Passes when | The prefix is exactly `HSH`, `CHS`, `FLT`, `SWE` or `ADR`; or it is `FLEET` or `VMWS` and the line is in a file under `reference/` or is such a path |
| Checked | Every match on the line. One disallowed prefix flags the line |
| Allowlist source | Built in and fixed in v0.1. Never read from the scanned repository |

**Token boundaries.**
- **On the left, none.** A match starts at the first uppercase letter of the run of uppercase letters, digits and underscores that ends at the hyphen, so the prefix is that whole run.
  - `"ACMEHSH" + "-1"` has the prefix `ACMEHSH` and is flagged.
  - A lowercase letter is not part of the run, so `xHSH-7` has the prefix `HSH` and passes.
- **On the right, none.** The digits are all the digits that follow, and what comes after them does not matter. `"ABC" + "-12x"` is flagged on its `ABC` prefix.
- **A departure from the interim.** The interim's pattern takes uppercase letters only, so it misses `"AB1" + "-23"` entirely and flags `"A_B" + "-12"` only on its last letter. Tracker keys may hold digits and underscores after their first letter, so v0.1 widens the prefix. The cost: on the text files under Go 1.26.7's `src`, the widened pattern flags 4,718 lines against the interim's 4,072, about 16% more (checked). The new shapes are listed under the known false positives below.

**The `reference/` exception.**
- **When it applies.** The line is a file's line or a path (`Source` `File` or `Path`), and the path as hush reports it starts with `reference/`, as the interim and HSH-5 test it. That path is relative to the scan root for tree scans and to the repository root for index and range scans, after ADR-001 section 6.4 step 1.
- **What it covers.** That path and that file's lines, for this rule only.
- **What it never covers:**
  - commit or tag object text, even for a commit that touches only `reference/`;
  - standard input;
  - a file or path named `reference` alone, `Reference/`, or `docs/reference/` in a scan whose paths start at the repository root.
- **A known limit.** A tree scan reports paths relative to its own root, so a `reference/` folder directly under that root gets the exception. With the root `docs`, the file `docs/reference/a.md` is reported as `reference/a.md`, and a `FLEET` or `VMWS` key in its lines passes. hush infers nothing from where it runs (ADR-001 section 1), and the interim behaves the same. So gates scan from the repository root, or scan the index or a range, whose paths are relative to the repository root.

| Flagged | Why |
| --- | --- |
| `"ZQX" + "-42"` | The prefix is not allowed |
| `"HSHX" + "-7"` | An allowed prefix with a letter added |
| `"ACMEHSH" + "-1"` | The prefix is the whole run |
| `"AB1" + "-23"`, `"A_B" + "-12"` | Digits and underscores after the first letter |
| `"ABC" + "-12x"`, `"ABC" + "-12-3"` | What follows the digits is ignored |
| `"FLEET" + "-12"` in `docs/a.md`, in a commit message, or on standard input | The exception covers files under `reference/` only |
| `"UTF" + "-8"`, `"SHA" + "-256"` | Standard names (decided item 4) |
| `"SHA2" + "-256"`, `"SHA3" + "-256"`, `"[A-Z0" + "-9]"`, `"Q3" + "-2026"`, `"FY25" + "-26"`, `"X86" + "-64"` | Shapes the widened pattern adds: known false positives, below |

| Passes | Why |
| --- | --- |
| `HSH-1`, `CHS-22`, `FLT-3`, `SWE-404`, `ADR-001`, `chassis ADR-002` | Allowed prefixes |
| `xHSH-7` | A lowercase letter is not part of the prefix |
| `HSH-12-34` | `HSH-12`, then `-34` starts no match |
| `"FLEET" + "-12"` in `reference/notes.md` | The exception |
| `abc-123`, `Abc-123` | Not uppercase before the hyphen: no match, a known miss |
| `ABC 123`, `ABC_123`, `ABC123`, `UTF8`, `SHA256` | No hyphen before the digits |

**Known false positives, and how a writer avoids them.**
- **Standard names written with a hyphen:** character encodings, hash functions, date and language standards, CVE identifiers, and RFC 5737's own names for its ranges. Write them without the hyphen (`UTF8`, `SHA256`, `ISO 8601`). v0.1 has no list of standard names that pass (decided item 4).
- **SHA2 and SHA3 sizes written with a hyphen,** such as `"SHA2" + "-256"` and `"SHA3" + "-512"`, which the widened pattern adds: write the size after a space or an underscore (`SHA3 512`, `SHA3_512`), or write the name in lowercase (`sha3-512`).
- **Character classes with an uppercase range before the digits,** such as `"[A-Z0" + "-9]"`: write the digits first, `[0-9A-Z]`.
- **Quarter and fiscal labels written with a hyphen,** such as `"Q3" + "-2026"` and `"FY25" + "-26"`: write a space or words (`Q3 2026`, `FY25 to FY26`).
- **Uppercase architecture names,** such as `"X86" + "-64"`: write them in lowercase (`x86-64`, `x86_64`).
- **Other projects' keys.** Describe them in words or leave them out: the public record needs only nonhumanhq's.

**Known misses:**
- lowercase and mixed-case keys;
- keys written with a Unicode dash or fullwidth letters (v0.2's look-alike step);
- keys split across a line break;
- keys without a hyphen.

A client's own key prefix belongs in the private sets as a term. A term matches in any case and with any number after it.

#### 4.2 `ip-address`

| Name | `ip-address`, for IPv4 and IPv6 alike |
| --- | --- |
| Decided by | `net/netip`'s `ParseAddr`, after the candidate rules below |
| Passes when | The address is in `192.0.2.0/24`, `198.51.100.0/24` or `203.0.113.0/24` (RFC 5737) or in `2001:db8::/32` (RFC 3849), or it is loopback or unspecified (decided item 5) |

**IPv4 candidates.**
1. The pattern is `[0-9]{1,3}(?:\.[0-9]{1,3}){3}`.
2. A candidate is kept only if:
   - the byte before it is not an ASCII letter or digit, nor a `.` with an ASCII digit straight before that dot; and
   - it ends the token, or a port follows it.

   A dot with a digit before it means the candidate continues a longer run of dotted numbers, such as a version or an object identifier of six groups or more. A dot after anything else does not stop the candidate, so an address written inside a dotted hostname after another label, as wildcard DNS names in development and cluster documents write it, is still found. The start of the line is not a digit, so a dot that starts the line does not stop it either.

   A position *ends the token* when the byte there is not an ASCII letter or digit, nor a `.` followed by a digit. A *port follows* when the candidate is followed by `.` and 1 to 5 digits that end the token: tcpdump and BSD netstat write an address and its port that way. The four groups are then the candidate.

   An underscore does not stop a match, so an address in Markdown emphasis written with underscores is still found.
3. A group above 255 means it is not an address, and it is ignored.
4. A group with a leading zero, such as `010`, is flagged whatever its range. Some parsers read such a group as octal, and `ParseAddr` refuses it (checked).
5. Otherwise `ParseAddr` and the allowlist decide.

**IPv6 candidates.**
1. Find each run of `[0-9A-Fa-f:.]`, as long as possible.
2. Trim the run, in this order:
   - first remove every `.` at either end;
   - then, on what is left, remove one `:` at the start unless it starts with `::`, and one `:` at the end unless it ends with `::`.

   So an address or prefix that ends in `::` keeps both colons before a sentence's full stop, and an ellipsis after an address is removed whole.
3. What remains is kept only if:
   - it holds at least two `:` and at least one decimal digit; and
   - the byte before it and the byte after it are not ASCII letters, digits or `_`. Here an underscore does stop a match, because code such as Rust's `x86_64::` module path would otherwise parse as an address.

   **One retry for a key before the address.** A run takes in the end of a word joined to it by a colon when that word ends in hex digits, as `6:` in `ip6:` or `de:` in `node:`, and the letter before the run then drops it. So when the byte before what remains is an ASCII letter or `_`, and its first `:` is a single colon rather than part of `::`, the text after that colon is checked once more under step 3, with the colon as the byte before it. Scope paths such as `x86_64::sse` and `Vec2::new` hold only `::` and get no retry.
4. `ParseAddr` must accept it. If it does not, and it ends in `.` or `:` followed by 1 to 5 decimal digits, that suffix is dropped once; what is left must again hold two `:` and a decimal digit, and `ParseAddr` must accept it. Otherwise it is not an address. tcpdump writes an IPv6 address and its port with a `.`. Linux's netstat and the socket-address strings of older Java releases write them with a `:` and no brackets; an address with eight groups, or with seven and a `::`, then has one group too many, and `ParseAddr` refuses it (checked).
5. Every address for which `Is4In6` is true, in any written form, is unmapped with `Unmap` and checked as IPv4: `::ffff:` followed by dotted IPv4, and the same address written in hex. Without that, a mapped address never lies inside an IPv4 prefix (checked).

What follows from these rules:
- **Zones, prefix lengths and brackets** never reach `ParseAddr`, because `%`, `/`, `[` and `]` end a run. `2001:db8::/32` is checked as `2001:db8::`, and an address with a zone is checked without it. `Prefix.Contains` is false for any address that carries a zone, which is another reason to drop it (checked).
- **An IPv4 address embedded in an IPv6 one** is also an IPv4 candidate of its own, after the `:`. It is checked both ways, and either check can flag it.
- **The digit requirement** keeps scope operators out: a bare `::`, `a::b` and `E::A` all parse as addresses, but they hold no decimal digit.
- **A port after a colon** is dropped only from a run that `ParseAddr` refuses. A compressed address followed by `:PORT` parses as another address and is judged as that one: `2001:db8::1:443` lies in the documentation prefix and passes, while the same form outside it is flagged. Times such as `12:30:45` still pass: what is left after the drop holds one `:` or does not parse.

**The allowlist** (decided item 5) is the four documentation prefixes, plus every address for which `IsLoopback()` or `IsUnspecified()` is true. Loopback and unspecified addresses identify no machine, and documents about servers need them.

Everything else is flagged, including:
- private, unique local and link-local addresses, those for which `IsPrivate()` (RFC 1918, RFC 4193) or `IsLinkLocalUnicast()` is true: they reveal a network's layout, so writers use documentation addresses;
- the shared address space (RFC 6598) and the benchmarking range (RFC 2544), which `IsPrivate` does not cover (checked);
- netmasks;
- multicast and broadcast addresses.

| Passes | Why |
| --- | --- |
| `192.0.2.10`, `198.51.100.255`, `203.0.113.0/24` | Documentation |
| `[2001:db8::1]:443`, `2001:DB8:0:0:0:0:0:1`, `2001:0db8:0000:0000:0000:0000:0000:0001` | Documentation, in any form |
| `::ffff:192.0.2.1`, `2001:db8::192.0.2.1` | Mapped and embedded documentation addresses |
| `::ffff:c000:20a`, `"::ffff:" + "0:0"` | Mapped addresses written in hex are unmapped too: documentation, and unspecified |
| `"127.0." + "0.1:8080"`, `"[:" + ":1]:8080"`, `"0.0." + "0.0"`, `":" + ":1"`, `"::ffff:127.0.0" + ".1"` | Loopback and unspecified (decided item 5) |
| `ip6:2001:db8::/32`, `[IPv6:2001:db8::1]` | Documentation, after a key |
| `192.0.2.10.443 > 198.51.100.7.53`, `2001:db8::1.546` | Documentation, with a port in tcpdump's form |
| `2001:db8:1:2:3:4:5:6:22`, `2001:db8::3:4:5:6:7:443` | Documentation, with a port after a colon and no brackets: eight groups, or seven and a `::` |
| `app.192.0.2.7.example.com` | Documentation, inside a dotted hostname |
| `see 2001:db8::1.`, `see 2001:db8::.`, `see 2001:db8::1...` | Every dot at the end is trimmed first, then a single colon only |
| `v1.2.3.4`, `go1.2.3.4`, `1.2.3.4rc1` | A letter touches it: a version |
| `1.2.3.4.5.6`, `OID 1.3.6.1.4.1.99999` | Six groups or more |
| `1.2.3`, `300.1.2.3` | Not an address |
| `12:30:45`, `12:30:45.123`, `2026-10-24T12:30:45Z`, `00:1a:2b:3c:4d:5e` | `ParseAddr` refuses it, or a letter touches it |
| `aa:bb:cc:dd:ee:ff` | No decimal digit |
| `std::vector`, `Foo::Bar`, `E::A`, `the :: operator`, `Vec2::new`, `u8::MAX`, `sha256:0123abcd` | No decimal digit, or a letter touches it |

| Flagged | Why |
| --- | --- |
| `"203.0." + "114.7"`, `"192.0." + "3.1"`, `"2001:db9:" + ":1"` | Just outside a documentation range |
| `"addr:2001:db9:" + ":1"`, `"at 2001:db9:" + ":1."` | A leading single `:` and a trailing `.` are trimmed |
| `"at 2001:db9:" + ":."`, `"Trying 2001:db9:" + ":1..."` | Step 2's order: every dot first, then a single colon only |
| `"v=spf1 ip6:2001:db9:" + "abcd::/48 -all"`, `"Received: from [IPv6:2001:db9:" + ":1]"`, `"node:2001:db9:" + ":5"` | Step 3's retry after a key |
| `"IP 203.0." + "114.7.22 > 198.51.100.9.51234"`, `"tcp4  0  0  203.0." + "114.7.22  198.51.100.9.51234"` | An address and a port, as tcpdump and BSD netstat print them |
| `"IP6 2001:db9:" + ":1.546 > 2001:db8::2.547"` | An IPv6 address and a port, as tcpdump prints them |
| `"2001:db9:1:2:3:4:5:" + "6:22"`, `"2001:db9:" + ":3:4:5:6:7:22"` | An IPv6 address and a port after a colon, without brackets: eight groups, or seven and a `::` |
| `"app.203.0." + "114.7.example.com"` | An address inside a dotted hostname, after another label |
| `"100.64." + "0.1"`, `"198.18." + "0.1"` | Shared address space, benchmarking |
| `"::ffff:203.0.114" + ".7"`, `"2001:db8::203.0.114" + ".7"` | The IPv4 part decides |
| `"255.255." + "255.0"` | A netmask |
| `"010.1." + "2.3"`, `"192.000." + "002.001"` | Leading zeros |
| `"1.0." + "0.0"`, `"1.2." + "3.4-beta"`, `"libfoo.so.1.2." + "3.4"` | Four-part versions with nothing before them, or after a word and a dot |
| `"1.2." + "3.4.5"` | Five groups read as an address and a port |
| `"3.2." + "1.10.in-addr.arpa"` | A reversed address is still an address |
| `"ab12:" + ":cd"` | A hex word with a digit parses as IPv6 |
| `"10.1." + "2.3"`, `"172.16." + "0.1"`, `"192.168." + "1.1"`, `"fd00:" + ":1"`, `"fe80:" + ":1%eth0"` | Private, unique local and link-local |
| `"10.0." + "0.0/8"`, `"::ffff:10.1.2" + ".3"` | A private range in block notation; a mapped private address |
| `"10.1." + "2.3.22"` | A private address and a port |
| `"https://web.10.1." + "2.3.example.com/"` | A private address inside a dotted hostname |

Mapped and embedded tokens with a dotted IPv4 part in these tables are split inside that part, after three groups. A split after two groups would leave `::ffff:` and two groups in one piece, which step 4 reads as an address and a port, so this file would flag itself.

**Known false positives, and how a writer avoids them.**
- **Four- and five-part version numbers** with nothing before them: write a `v` first (`v1.0.0.0`).
- **Netmasks:** write the prefix length (`/24`).
- **Four- and five-part section or figure numbers:** use fewer levels, or words, as in `section 1.2.3, item 4`. A `§` or another non-ASCII character before the number does not stop the match, because only an ASCII letter or digit does, or a `.` with a digit before it.
- **Four-part versions after a word and a dot,** such as a shared library's `"libfoo.so.1.2." + "3.4"`: write the version apart from the name, after a `v` (`libfoo v1.2.3.4`), or with fewer parts (`libfoo.so.1`).
- **Public addresses everyone knows,** such as public resolvers: use a documentation address.
- **Special-purpose ranges in block notation:** name the range by its RFC, and in code by its `netip` predicate.
- **Hex words with a digit** that parse as IPv6 and touch no letter, such as `"ab12:" + ":cd"`: put spaces around the `::` (`ab12 :: cd`), or name the thing in words.
- **Extended slices,** as in Python, such as `"xs[1:" + ":2]"` and `"xs[:" + ":2]"`, which parse as IPv6: put spaces around the `::` (`xs[1 :: 2]`).
- **The IPv6 loopback address with a port and no brackets,** as Linux's netstat prints it: the compressed loopback address and the port parse as another address, which is not loopback, so it is flagged (checked). Write the address in brackets before the port, which the allowlist passes.
- **A documentation IPv6 address with a letter straight before it,** such as `"x2001:db8:" + ":1"`: step 3's retry reads it from its second group, which lies outside the documentation prefix. Put a space or punctuation before it.

**Known misses:**
- IPv4 forms other than four decimal groups: short forms such as two groups, a single integer, hex groups;
- an IPv4 address with a letter touching it, such as `ip` or `v` written straight before it, or the letter of a string escape such as `\n` or `\t` in source code or a JSON log, or of a percent escape such as `%3A`. That is the price of the version rule;
- an address straight after a percent escape that ends in a digit, such as `%20`: the escape's digits join the address;
- an IPv6 address with a letter or `_` straight after it, such as one in Markdown emphasis written with underscores, or with one straight before it when its first group is followed by `::`;
- look-alike dots or colons, spaces or a line break inside an address, URL-encoded forms;
- hostnames that embed an address with hyphens (v0.2's hostname rule);
- reverse names under `ip6.arpa`, which write an IPv6 address as single hex digits separated by dots. The `in-addr.arpa` form of an IPv4 address is flagged (table above);
- addresses written as separate integers, such as the four arguments of a function call or the elements of a byte array;
- an address in a dotted hostname straight after a label that ends in a digit, such as `node1.` before it: to the rule, that digit and the address form one longer run of dotted numbers, like a version (v0.2's hostname rule);
- MAC addresses, which are not IP addresses and are not checked.

#### 4.3 `email-address`

| Name | `email-address` |
| --- | --- |
| Candidates | Bare and bracketed, below |
| Passes when | The domain is reserved by RFC 2606; or the address is in the caller's identity allowance and sits in an identity position |

**Bare candidates.**

```
(?:(?:[A-Za-z0-9!#$%&'*+=?^_{|}~.-]|[^\x00-\x7f])+|"[^"\s]*")\\?@(?:[\p{L}\p{M}\p{N}-]+\.)+\p{L}[\p{L}\p{M}\p{N}-]*[\p{L}\p{M}\p{N}]
```

- **The local part** is either RFC 5322's atom characters other than `/` and the backtick, dots, and any non-ASCII character; or a quoted string without spaces, as in `"$USER"@` in a shell command. A `\` may stand before the `@`, as Perl strings and some Makefiles write it.
  - Leaving out `/` makes a match in a path start in the component that holds the address, so redaction keeps the components before it.
  - Leaving out the backtick keeps a Markdown code span that puts a backtick straight before an `@` name, such as a file name or a dotted decorator, from being a candidate. An address inside a code span is still one, because its local part starts after the backtick.
- **The domain** is one or more labels, each followed by a dot, then a final label of at least two characters that starts with a letter.
  - Every label, the final one included, is made of letters, marks and digits of any script (`\p{L}`, `\p{M}`, `\p{N}`) and `-`. So an internationalized domain is still a candidate, under any top-level domain, and a domain ends at punctuation or spacing of any script, such as a no-break space, an em dash or a fullwidth comma.
  - A domain that holds any non-ASCII character never passes (allowed domains, below). So a private address that runs on into text of another script stays flagged, whatever reserved name follows it.
- **Non-ASCII in Go.** The class for "any non-ASCII character" is `[^\x00-\x7f]`. In Go, `[\x80-\xff]` means the runes U+0080 to U+00FF, not bytes, and would miss most of them (checked).
- **Why the dot and the letter:** they keep package specifiers such as `react@18.3.1` and `pkg@latest` out.

**Bracketed candidates.**

```
<([^<>\s@]+@[^<>\s]+)>
```

This is text in angle brackets that holds an `@` and no space. The address is the text between the brackets. Its domain is the text after the last `@`, up to the first `/`, `:`, `?` or `#` after it, whatever that text looks like. Commit headers and trailers write identities this way (`Name <address>`), so the form also catches a domain without a dot, as in git's fallback identity. Ending the domain there judges a bracketed URL or remote by its host, never by the last label of its path.

**Allowed domains.**
- The domain is the text after the last `@`, with ASCII letters lowered. In a bracketed candidate it ends at the first `/`, `:`, `?` or `#` after that `@`.
- A domain that holds any non-ASCII character never passes. No reserved name is non-ASCII, and writers do not need internationalized subdomains of one.
- It passes when it is `example.com`, `example.net` or `example.org`, or ends with `.` followed by one of them.
- It also passes when its last label is `example`, `test`, `invalid` or `localhost`.
- The local part is never checked.

**The identity allowance.**
- **What passes.** An address equal to one in the caller's identity allowance, ignoring ASCII case, passes, but only in an identity position (decided item 6). The identity positions are:
  - the `author`, `committer` and `tagger` headers of commit and tag objects (ADR-001's parts);
  - an identity trailer, a line matching `^[A-Za-z][A-Za-z0-9-]*-by: ` such as `Signed-off-by: …` or `Co-authored-by: …`, in a commit or tag message or on standard input, which the `commit-msg` hook scans.
- **What is no identity position.** A line of a file or a path, a subject line in the form `<ID>: summary`, and any other line that starts with a word and `: `, such as `Note: …`.
- **Standard input means every buffer.** hush cannot tell the `commit-msg` hook's standard input from any other standard input or caller's buffer: the `gh` wrapper's bodies, `dispatch.sh block` questions, and importers' `ScanBytes` and `ScanReader` buffers (ADR-001 sections 2 and 7). So an identity trailer in any of them passes when that scan is given the address with `--identities`. Section 3.1 gives the allowance to hooks, publish and full-history scans and staging CI only, not to the `gh` wrapper or `dispatch.sh block`; an importer that sets `Config.Identities` applies it to its buffers too.
- **What it exempts.** This rule only. An allowed identity that contains a term still gives a `set:` finding.
- **Where it comes from.** Only the `--identities` value or the `Config.Identities` list the caller passes (sections 3.1 and 5.4). Never a file, git configuration, `.mailmap`, the environment or the repository.

In the examples below, the identity allowance lists `"alice@" + "acme.internal"`.

| Passes | Why |
| --- | --- |
| `alice@example.com`, `ALICE@EXAMPLE.ORG`, `bob@mail.example.net` | Reserved second-level names, and their subdomains |
| `bob@acme.test`, `bob@acme.example`, `bob@acme.invalid`, `bob@acme.localhost` | Reserved top-level names |
| `<alice@example.org>`, `mailto:alice@example.com` | Any form |
| `<mailto:alice@example.com?subject=hi>`, `<https://bob@example.com/>`, `<git@example.com:org/repo.git>` | A bracketed domain ends at the first `/`, `:`, `?` or `#` |
| `` `@AGENTS.md` ``, `` `@pytest.fixture` `` | In a code span, a backtick is no local part |
| `alice@example.com—see www.example.org`, `“alice@example.com”` | The domain ends at the em dash and at the quotation mark |
| `react@18.3.1`, `golang.org/x/tools@v0.1.0`, `pkg@latest`, `pkg@v1.0.0-rc.1` | The final label is not a word |
| `@property`, `HEAD@{1}`, `image@sha256:0123` | No address |
| `bob@buildhost` | Bare and without a dot: not a candidate, a known miss |
| `ssh alice@192.0.2.10` | Not an email candidate; the IP rule checks the address |
| `"Signed-off-by: Alice <alice@" + "acme.internal>"` in a commit message or on standard input | An allowed identity on a trailer line |
| `"author Alice <alice@" + "acme.internal> 1700000000 +0000"` in a commit object | An allowed identity in a header |

| Flagged | Why |
| --- | --- |
| `"bob@" + "acme.local"`, `"bob@" + "acme.internal"` | Not reserved |
| `"bob@example." + "community"`, `"bob@example." + "co"`, `"bob@acme-" + "example.com"`, `"bob@example.com." + "acme.internal"` | They look reserved but are not |
| `"bob@ex" + "ämple.com"`, `"bob@acme." + "рф"` | A non-ASCII domain, under any top-level domain |
| `"bob@acme." + "internal—www.example.com"` | An em dash ends the domain, so the reserved name after it does not count |
| `"bob\\@acme." + "internal"`, `"\"bob\"@acme." + "internal"` | An escaped `@`; a quoted local part |
| `"<bob@" + "buildhost>"` | Bracketed, so any domain counts |
| `"<git@" + "buildhost:org/repo.test>"`, `"<ssh://git@" + "buildhost/org/app.localhost>"` | A bracketed domain ends at the `:` or `/`, so a reserved name in the path does not count |
| `` "`bob@" + "acme.internal`" `` | An address in a code span: its local part starts after the backtick |
| `"icon@" + "2x.png"`, `"git@host." + "acme.internal:org/repo"` | Known false positives |
| `"write to alice@" + "acme.internal"` in a commit message | An allowed identity, but not in an identity position |
| `"HSH-3: write to alice@" + "acme.internal"` as a commit's subject line, `"Note: ask alice@" + "acme.internal"` in a commit message | Not an identity trailer |
| `"Signed-off-by: Alice <alice@" + "acme.internal>"` as a line of a file | A file's line is never an identity position (decided item 6) |
| `"Signed-off-by: Alice <alice@" + "acme.internal>"` with no `--identities` | The allowance is explicit input only |

**Known false positives, and how a writer avoids them.**
- **SSH remotes** (`git@` and a host): write HTTPS URLs, or use a reserved domain, which passes in angle brackets too.
- **An `@` name in emphasis or single quotes,** such as `"*" + "@pytest.fixture*"` or `"'" + "@AGENTS.md'"`: the `*` or the quote is read as a local part. Write the name in a code span.
- **An `@` inside a bracketed URL's path,** such as a profile handle, a scoped package or a module version, as in `"<https://example.com/" + "@alice>"`: the domain is read after the last `@`. Write a Markdown link, `[text](url)`, or the URL without brackets.
- **Asset names with `@2x`:** name them `icon-2x.png`.
- **Package specifiers whose version ends in a word,** such as `"pkg@1.0.0-alpha." + "beta"`: write a space instead of the `@` (`pkg 1.0.0-alpha.beta`).
- **URLs with user information,** such as an account name before a host: drop the user information, or use a reserved domain.
- **A reserved address followed directly by letters of another script,** as in text written without spaces between words: the domain runs on into those letters and is no longer reserved. Put a space or punctuation after the address.
- **Platform identities:** a hosting platform's no-reply addresses on merge commits and on the agent identity's commits. Add the exact address to the `--identities` value of the scans that meet them.
- **An identity inside a `mergetag` header:** the tagger line and any trailer line of a merged tag's embedded text are part `header`, which is no identity position, so an allowed identity there is flagged. No allowance passes it; the human checks it by hand. Git writes a `mergetag` header only when a signed tag is merged, so it is met mostly in the full-history scan.

**Known misses:**
- the local part: `alice@example.com` passes whoever alice is. Usernames are caught only as terms (ADR-001 section 8);
- obfuscated (`bob at acme dot internal`), percent-encoded and entity-encoded forms, and addresses split across lines;
- bare addresses whose domain has no dot;
- quoted local parts with spaces;
- a domain broken by a character that is not a letter, mark, digit, `-` or dot, such as an invalid UTF8 byte: the candidate ends before it, so a domain with no dot before that character is missed.

### 5. Interfaces

These packages are internal. ADR-001 section 2 places them and says that HSH-5 picks the names, so the sketches below are indicative; the behaviour is what is decided.

#### 5.1 Rules

```go
package rule // internal/rule

// Part is the part of a commit or tag object a line comes from (ADR-001 section 6.1).
type Part uint8

const (
	NoPart Part = iota // any Source other than Object
	Author
	Committer
	Tagger
	Header
	Message
)

// Source is where a line comes from. The zero value is the strictest: no
// exception and no allowance applies to a bare string.
type Source uint8

const (
	Text   Source = iota // a bare string, such as a set name checked at load
	File                 // a line of a file, an index blob or an added diff hunk
	Path                 // the path itself
	Object               // a line of a commit or tag object
	Stdin                // a line of standard input or of a caller's buffer
)

// Context is everything a rule may know about a line besides its bytes.
type Context struct {
	Source Source
	Path   string // for File and Path: the reported path before redaction (ADR-001 section 6.4 step 1)
	Part   Part   // for Object: Author, Committer, Tagger, Header or Message
}

// Rule is one generic rule. A Rule is immutable and safe for concurrent use.
type Rule interface {
	// Name is the stable name printed in findings, such as "id-prefix".
	Name() string
	// Check reports whether line breaks the rule and, if it does, the byte offset
	// in line where the earliest breaking match begins. It keeps no reference to line.
	Check(line []byte, ctx Context) (start int, broken bool)
}

// Registry returns the v0.1 rules in output order: id-prefix, ip-address,
// email-address. ids is the caller's identity allowance, a list of addresses
// already checked against section 5.4's form, or nil for none.
func Registry(ids []string) []Rule
```

**The contract.**
- **Names** match `^[a-z0-9]+(-[a-z0-9]+)*$` (ADR-001's schema) and are unique. They are never `binary-unscanned`, `unreadable` or `set`.
- **A name is never reused** for a different rule. A rule that grows keeps its name. One that narrows keeps it too, and the release notes say so.
- **A verdict depends only on the line and its context.** Rules keep no state across lines and must not panic on any byte sequence: invalid UTF8 is just bytes. The generic rules hold no term sets. Whether term sets stay in the same list as the rules, as in HSH-5's port, is HSH-11's choice.
- **`start` stays inside package `hush`,** where it serves redaction (ADR-001 sections 6.4 and 9).
- **HSH-11 makes the targets fill `Source`, `Path` and `Part`** (decided item 8), `tagger` included, when it adds ADR-001's object parts. The interim's rule call, which HSH-5 ports at parity, passes a line and an in-reference flag only. Until a target fills them, no identity allowance applies in that target.
- **The bridge for HSH-14.** HSH-14 keeps HSH-5's `rule.Rule` (`Name`, `Index(s, inRef)`) and appends `ip-address` and `email-address` after `id-prefix` in the list `cmd/hush` builds, leaving the targets unchanged. Each new rule's `Index` calls a check that takes a `Context`, passing the zero `Context`, so no scan applies the allowance before HSH-11. The allowance's table tests call that check directly, with `Object` and `Stdin` contexts. The sketch above is the shape that check and HSH-11's wiring follow; the names stay HSH-5's and HSH-11's to pick.

#### 5.2 The registry

| Order | Name | Tier | Since | Section |
| --- | --- | --- | --- | --- |
| 1 | `id-prefix` | generic | v0.1, from the interim | 4.1 |
| 2 | `ip-address` | generic | v0.1 (HSH-14) | 4.2 |
| 3 | `email-address` | generic | v0.1 (HSH-14) | 4.3 |

v0.2 appends to the registry and never reorders it. ADR-001's output check accepts a finding's rule only when it is a name in the registry, `set:` followed by a loaded set's name, or one of ADR-001's two fixed unscanned names, `binary-unscanned` and `unreadable` (its sections 5 and 6.1, as amended with this ADR's acceptance).

#### 5.3 The term loader and matcher

```go
package termset // internal/termset

// Parse reads a format 1 term file. It takes bytes, never a path (ADR-001 section 2).
// Its errors are *ParseError.
func Parse(b []byte) (*Sets, error)

// ParseError is a fixed reason and a line number. It holds no text from the file.
type ParseError struct {
	Line   int    // 1-based; 0 when the reason concerns the whole file
	Reason Reason // TermOutsideSet, BadCharacter, BadHeader, BadSetName, BadAttribute,
	              // BadClientLabel, SetDeclaredTwice, BadTerm, EmptySet,
	              // UnsupportedFormat, NoTerms
}

// Sets holds the parsed sets, unexported, behind ADR-001's formatting guards.
type Sets struct{ /* … */ }

func (s *Sets) Len() int
func (s *Sets) Name(i int) string     // set i's name, in file order
func (s *Sets) Line(i int) int        // the line of set i's header
func (s *Sets) Labels(i int) []string // set i's visible-to labels; never printed

// RefusesName reports whether the terms refuse a set name or client label:
// section 1.4's check 1, plain containment ignoring ASCII case and every
// set's case and match options.
func (s *Sets) RefusesName(name []byte) bool

// Match reports which sets in apply match line, as a mask in file order, and the
// byte offset where the earliest match of any set in apply begins. It never says
// which term matched.
func (s *Sets) Match(line []byte, apply Mask) (hit Mask, start int)

// Normalizer maps text to the form terms are compared in. Terms pass through the
// same normalizer at load.
type Normalizer interface {
	// Normalize appends the normalized src to dst and, for each byte appended,
	// the offset in src it came from, so a match maps back to the original line.
	Normalize(dst []byte, offs []int, src []byte) ([]byte, []int)
}
```

How the pieces fit:
- **`LoadTermSets(path)`** in package `hush` (ADR-001 section 7) runs ADR-001 section 5's checks on the file, reads it, calls `Parse`, then runs section 1.4's checks with `RefusesName` and `rule.Registry(nil)`. So `termset` does not depend on `rule`, and opens no file.
- **Redaction** calls `Match` with every loaded set. Findings call it with the sets the destination applies.
- **v0.1's normalizers** are ASCII lowering, and nothing for `case=exact` (decided item 3). Both keep offsets one for one. Each writes into `dst`, never into `src`, so the scanned line stays raw for the rules and the caller (section 2.2).
- **`Mask`** is a bit set over set indices; its representation is the implementer's choice.

#### 5.4 The identity allowance

- **On the CLI** (HSH-11): `--identities ADDR[,ADDR…]`, given at most once and accepted with every destination and with `--generic-only`. It fills ADR-001's `[ALLOWANCE]` slot.
- **The form.** The value is one or more addresses separated by commas.
  - An address holds an `@` with text on both sides, and no space, tab, `<`, `>` or `,`.
  - Addresses compare with ASCII letters lowered.
  - A malformed value, an empty one included, exits 2 with ADR-001's code `usage`, and the message cites the argument's position, never its value (ADR-001 section 6.6).
- **In package `hush`** (HSH-11): `Config.Identities`, built from a list of addresses with the same form, nil for no allowance. The type that holds it carries ADR-001 section 6.6's formatting guards, as `TermSets` does (section 6, point 6).
- **In package `rule`** (HSH-14): the allowance is the list the caller passes to the email rule, nil for none (section 5.1).
- **Hook installers** (HSH-9 and HSH-11) shell-quote the value when they write it into a hook.

#### 5.5 How v0.2 plugs in

- **The hostname rule** is one more `Rule`, appended as `hostname`.
  - Its candidates are dotted names whose last label is a top-level domain of letters. It passes the reserved names, shared with the email rule, and perhaps a caller-supplied list of public domains.
  - It checks paths and lines like the others, with no change to targets, output or the interface.
- **Secret-format rules** are one `Rule` per format family, named for the family, such as `private-key-block`.
  - A PEM private key is caught on its `BEGIN` line, and entropy checks work token by token, so one line is enough.
  - Their findings stay as free of content as every other finding. ADR-001 runs the generic tier for the `private` destination (its section 4 and its decided item 6) and says to revisit that choice when secret-format rules arrive.
- **Normalization steps** join the `Normalizer` chain (section 2.5). If sets need to choose steps, that is a new attribute key.
  - A generic rule that wants normalized text can implement a second, optional interface. The scanner then hands it the normalized line and maps its `start` back through the same offsets. `Rule` itself does not change.
- **What would force a redesign:** a rule that needs several lines at once. None is planned. PEM blocks have a `BEGIN` line, and ADR-001 already handles signature blocks in the targets.

### 6. Where this meets ADR-001

| ADR-001 asks (its section 9) | This ADR |
| --- | --- |
| A per-set visibility declaration: explicit labels, no wildcard, deny by default | `visible-to=` on the set's one header (sections 1.1 and 1.2). Without it the set applies to `public` and to every client destination. The label grammar excludes wildcards |
| Load-time checks of set names and client labels | Section 1.4 |
| No other sources: the file names no other files | Section 1.2: no includes, paths or references. The file comes only from the caller's path (section 3) |
| A rule registry with stable names, positions kept inside package `hush` | Sections 4, 5.1 and 5.2 |
| Whether the ID-prefix allowlist is built in or comes from the caller | Built in and fixed in v0.1 (section 4.1). It never comes from the scanned repository |
| The email identity allowance as explicit caller input | A flag value, `--identities ADDR[,ADDR…]`, and `Config.Identities` (sections 3.1, 4.3 and 5.4) |
| The JSON schema's set-name pattern | `^[A-Za-z0-9_.-]{1,64}$`, in `sets` and in `rule`'s `set:` branch (point 1 below) |
| `unknown-set` and `unknown-rule` | Format 1 has no references, so they cannot arise in v0.1 (section 1.2) |

**Where this ADR extends ADR-001's accepted text.** Two points change text that ADR-001 presents as complete. ADR-001 was amended to carry both when this ADR was accepted (decided item 7), and the amendment changes none of its decisions:

1. **The set-name pattern in ADR-001's schema.** ADR-001 section 6.3 gave the interim's grammar, pending this ADR. Set names are 1 to 64 characters from `[A-Za-z0-9_.-]` (section 1.3), both in the `sets` field and in the `set:` branch of a finding's `rule`: `^([a-z0-9]+(-[a-z0-9]+)*|set:[A-Za-z0-9_.-]{1,64})$`.
2. **ADR-001's output check** accepts a finding's rule when it is in the registry or is a loaded set. It also accepts ADR-001's two unscanned names, `binary-unscanned` and `unreadable` (its section 6.1), which section 5.1 keeps out of the registry.

**Notes that need no decision:**

3. **Agent range scans pass the allowance.** The `pre-push` hook, and staging CI if it scans ranges, pass `--identities` with the agent identity's commit address, or the email rule flags every agent commit. This fits ADR-001: its CLI grammar has an `[ALLOWANCE]` slot, its "Who runs what" rows end in `…`, and HSH-11 updates the hook command lines. A malformed value is a usage error under ADR-001's existing code `usage`, so its error table needs no new code.
4. **ADR-001's test 6** gives `alice@example.org` as its identity allowance "for example". That address passes on its domain alone, so HSH-11 picks an identity at a domain that is not reserved, assembled at run time, and the test then exercises the allowance.
5. **More than one built-in list.** ADR-001 section 1 calls the ID-prefix allowlist "the one built-in, loop-specific list". The documentation ranges and reserved domains are built in too. None of them is knowledge of hush's users, so the statement holds in spirit.
6. **Guards for the allowance.** ADR-001 section 6.6's formatting guards cover "an allowance", so the type that holds `Config.Identities` carries the same guards as `TermSets`.

## Alternatives considered

Each decision lists the interim scanner's choice, at least one alternative that departs from it, and why that alternative was not taken.

**The term-set format (section 1).**
- *Interim:* sections of plain terms. Kept as the base and extended with header attributes, so an interim file either keeps its meaning or is refused with a line number in one of the cases of section 1.7.
- *Departing alternative:* JSON read by `encoding/json`, such as `{"sets":[{"name":…,"visible_to":[…],"terms":[…]}]}`. It is typed and easy to version, but it has no comments, every term is quoted and escaped, and one missed comma fails the whole file. The human edits this file by hand, often. Not taken (decided item 1, option (b)).
- *Departing alternative:* TOML or YAML. Go's standard library has no parser for either, so hush would need a dependency or a hand-written parser for a richer grammar than it needs.
- *Departing alternative:* the interim format unchanged, with visibility in a second file. That makes two files to keep in step, and a missing second file needs a default (decided item 1, option (c)).
- *Departing alternative:* markers on single terms, such as a prefix for exact case. Terms would need escaping, and markers on single lines are easy to misread. Per-set options group terms instead (decided item 3, option (c)).
- *Departing alternative:* no per-term or per-set options in v0.1 (decided item 3, option (a)). Two- and three-letter abbreviations could then be listed only as substrings, at section 2.3's cost, or left out.

**Versioning (section 1.6).**
- *Interim:* none.
- *Departing alternative:* a mandatory version line in every file. Every interim file would need an edit for no gain in v0.1, because strict parsing already makes an older hush fail closed on a newer file.

**Repeated headers and empty sets (section 1.7).**
- *Interim:* a repeated header continues the set, and an empty set is accepted.
- *Taken instead:* both are refused. With attributes, a second header could disagree with the first, and an empty set reports coverage it does not give.

**Malformed headers (section 1.1).**
- *Interim:* a line is a header only if it starts with `[` and ends with `]`; any other line is a term.
- *Taken instead:* a line with either bracket is read as a header and must have both (`bad header`). With visibility on sets, a header missing a bracket, or followed by a comment, would become a term of the set above it, and the terms under it would take that set's `visible-to`. The cost is that a term cannot start with `[` or end with `]`; dropping the bracket matches at least as much.
- *Departing alternative:* report such a line as `bad set name`, under the header rules that exist. For a header with a comment after it, such as `[clients] ; main list`, that reason points the human at a name that is fine.
- *Departing alternative:* decide a set's emptiness at any line read as a header, as the draft did. A line with one bracket that was the first under its header then gave `set has no terms` on the header above it. Following that error's remedy, deleting the header, moved the lines below into the set above, under its `visible-to`.

**Characters in terms and lines (section 1.1).**
- *Interim:* a term is any bytes, kept exactly, and a comment is any line that starts with `#`.
- *Taken instead:* format 1 refuses, in terms, Unicode spaces other than space and tab, format characters other than the joiners and the prepended concatenation marks, and the shape of an inline comment; and, on every line, comments included, control characters other than tab, U+2028, U+2029 and bytes that are not valid UTF8. Each makes a term silently match nothing the human meant, or hides a term inside a comment.
- *Departing alternative:* refuse only U+200B and U+FEFF among format characters. Soft hyphens, directional marks and bidi controls, which pasting from web pages and right-to-left text leaves behind, would load and silently miss.
- *Departing alternative:* refuse every format character, the joiners included. They belong to correct spellings in some scripts, and v0.2's step 1 removes them anyway. The other format characters some scripts use, such as the Egyptian hieroglyph and shorthand format controls, are not plausible in a term.
- *Departing alternative:* refuse every default-ignorable character, variation selectors and U+034F included. Some names need variation selectors, as some need the joiners, and v0.2's step 1 removes them too.
- *Departing alternative:* check characters in terms only. A comment holding a lone CR would swallow a term written after it, which an editor may show on a line of its own.
- *Departing alternative:* strip such characters at load. The term would then differ from what the human wrote, without telling them, and a pasted no-break space would still not be a space.
- *Departing alternative:* check for valid UTF8 in terms only, as the draft did (`bad term`). Implementations could then read a comment's invalid bytes differently, as a character to refuse or as nothing.
- *Departing alternative:* an attribute that lets a set's terms hold Unicode spaces and format characters, so such variants can be listed (section 2.4). It is more parser surface for a rare case: a human lists such a variant only after seeing it slip past, and v0.2's step 1 is the lasting fix.
- *Departing alternative:* read `#` after a space as the start of a comment. That silently gives a line the interim accepts a different meaning, which needs a new format (section 1.6). Refusing the shape keeps every accepted line's meaning and tells the human.

**Set names (section 1.3).**
- *Interim:* letters, digits, `_`, `.` and `-`, of any length. Kept, with a cap of 64 characters (section 1.7).
- *Departing alternative:* lowercase only. Mixed-case interim names would need renaming for no gain, since check 1 of section 1.4 ignores case anyway.
- *Departing alternative:* 1 to 32 characters, like client labels. Names such as `clients-k7` fit either way. A cap of 64 refuses only very long interim names, and still keeps findings and statuses short.

**Load-time checks (section 1.4).**
- *Interim:* set names are not checked.
- *Departing alternative:* for a term of a `match=word` set, refuse a name only where the term stands as a word, by section 2.3's boundaries (decided item 3, answer (i) to its sub-question). Then `qvlnotes` or `clientsQVL` beside `QVL` would load and be printed in every finding, against ADR-001 section 6.6's rule that no output holds a term. Plain containment costs a rename now and then: a two-letter term refuses a name section 1.3 recommends in 31 of 676 cases.
- *Departing alternative:* also honour `case=exact`. A name in another case still reveals the term, and names are printed.
- *Departing alternative:* fold case before check 2, such as to uppercase before `id-prefix`. It adds refusals nothing asks for: the set name `notes-2026` and the client label `k-7` would be refused as keys.
- *Deferred to v0.2:* a word check, refusing a name or label with a part, split at `-`, `_` and `.`, equal to a word of any term. It would refuse `zantoph` and `clients-zantoph` beside the term `zantoph works`, and, with terms split at every character that is not a letter, mark or number of any script, beside `alice@zantoph.example` and `zantoph’s` too. The human deferred it at acceptance: content has the same gap, since `zantoph` alone in a file is no finding either, and the cure for both is to list the word as a term of its own (section 1.3), after which check 1 refuses those names. The check would also refuse names with common parts such as `com`, `https` or `works`. Adding it later only refuses more, but it can refuse a name that a v0.1 file already uses, so v0.2's release notes must say when it starts refusing names.

**Matching (section 2).**
- *Interim:* substrings, ignoring ASCII case. Kept as the default.
- *Departing alternative:* word boundaries by default. It misses forms glued to letters, and a miss at the publish gate is the worst outcome (decided item 2, option (b)).
- *Departing alternative:* word boundaries automatically for terms of three characters or fewer. The same kind of term would match differently depending on its length, which the human cannot see in the file (decided item 2, option (c)).
- *Departing alternative:* Unicode case folding now. Go's folding changes byte lengths, and without NFKC and look-alike folding it is a third of a pipeline. v0.2 does the pipeline whole.
- *Departing alternative:* one multi-pattern automaton (Aho-Corasick) instead of one search per term. It is not needed at v0.1's sizes, and `Match` allows it later without a format change.

**v0.2's normalization and word sets (section 2.5).**
- *Interim:* no normalization beyond ASCII case.
- *Departing alternative:* judge `match=word` boundaries on the normalized copy. Steps 1 and 5 would glue an abbreviation to the letters around it, so v0.2 would remove matches v0.1 gives, without a format change (section 1.6).
- *Departing alternative:* keep step 5 out of word sets' chains. Word sets would lose the dotted and separated forms of abbreviations that step 5 covers (section 2.4), and abbreviations are what word sets hold.

**Where sets live (section 3).**
- *Interim:* an explicit `--terms FILE` only, refused inside a scanned path. Kept.
- *Departing alternative:* an environment variable or a default path. ADR-001 rejects both: an implicit source can be wrong without anyone seeing it, and an agent's environment could set it.
- *Departing alternative:* the operating system's keychain or a password manager. Agents must never touch password managers, hooks would prompt, and it does not carry over to the scanner account.
- *Departing alternative:* an encrypted term file. The terms are in memory in clear during every scan anyway, and the key would sit beside the file. Against the threat that matters here, another account on the same machine, the file's permissions already do the job.
- *Departing alternative:* hashed sets on agent machines. Short abbreviations can be brute-forced from their hashes in seconds (runbook).
- *Departing alternative:* one file per client, with `--terms` repeated. ADR-001 refuses repeated options, and visibility on sets does the same job in one file.

**`id-prefix` (section 4.1).**
- *Interim:* `[A-Z]+-[0-9]+` with a built-in allowlist. The allowlist is kept. The interim pattern is the alternative rejected, because it misses keys with digits after their first letter. The cost of widening it is about 16% more flagged lines on Go's source, with the remedies in section 4.1.
- *Departing alternative:* a left token boundary, with no letter or digit allowed before the prefix. A key glued to a word would escape.
- *Departing alternative:* a fixed built-in list of standard names that pass, written with a hyphen: UTF with 8, 16 or 32; SHA with 1, 224, 256, 384 or 512; SHA3 with 224, 256, 384 or 512; ISO with 8601 or 8859 (decided item 4, option (b)). AGENTS.md calls any other token of that shape a mistake, and most standard names would stay flagged anyway, so writers keep the habit of rephrasing. A list can be added later, since it only lets more through.
- *Departing alternative:* an allowlist from the caller, of prefixes or of standard names (decided item 4, option (c)). No caller needs it in v0.1, and it can be added later without breaking anyone.

**The `reference/` exception (section 4.1).**
- *Interim:* the exception applies when the reported path starts with `reference/`. Kept, with its known limit: a tree scan rooted below the repository root gives the exception to a `reference/` folder directly under its root.
- *Departing alternative:* apply it only to paths relative to the repository root, that is, in index and range scans. The tree scan that builds the reference pack (ADR-001 section 4) would then flag the pack's own keys.
- *Departing alternative:* drop the exception, and write the pack's keys in words. The pack would no longer quote its sources as they are, and AGENTS.md already allows those two prefixes when quoting the pack.
- *Why the limit is kept:* it lets through only `FLEET` and `VMWS` keys, the two prefixes AGENTS.md allows when quoting the pack, and only in a folder named `reference` directly under a tree scan's root. The gates scan from the repository root, or scan the index or a range.

**`ip-address` (section 4.2).**
- *Interim:* no IP rule.
- *Departing alternative:* validating with regular expressions alone. `ParseAddr` is exact, part of the standard library, and refuses ambiguous forms.
- *Departing alternative:* every dotted quad, with no boundaries. Versions and object identifiers would flag constantly, with no way to write a four-part version.
- *Departing alternative:* IPv6 runs with no digit requirement. Scope operators in code, such as a bare `::` or `a::b`, parse as addresses.
- *Departing alternative:* let any `.` before a candidate stop it, as the draft did. An address inside a dotted hostname after another label, as wildcard DNS names in development and cluster documents write it, would pass whatever the allowlist, public addresses included. The cost of the narrower stop is that a four-part version after a word and a dot, such as a shared library's suffix, is flagged. Checked: every other row of section 4.2's tables keeps its result.
- *Departing alternative:* also let a `.` at the start of a line stop a candidate. The start of a line counts as neither a letter nor a digit (section 4), so a dot there would stop a candidate that the same dot after a space does not, and a miss is the worse outcome.
- *Departing alternative:* treat a token of more than four groups as no address. tcpdump and BSD netstat print an address and its port as five groups, so pasted network output, where real addresses most often appear, would pass. The cost of reading five groups as an address and a port is that five-part versions and section numbers are flagged.
- *Departing alternative:* drop only a `.PORT` suffix from an IPv6 run, not a `:PORT` one. A full IPv6 address printed with its port after a colon and no brackets, as Linux's netstat does, would be no candidate at all. Apart from the rows it adds, the `:PORT` drop changes no row of section 4.2's tables (checked), because it applies only to a run `ParseAddr` refuses.
- *Departing alternative:* drop an IPv6 run that a letter touches, with no retry. A key such as `ip6:` or `IPv6:` in a mail header or an SPF record would hide the address after it whenever the key ends in hex digits. The cost of the retry is that a documentation address with a letter straight before it is read from its second group and flagged.
- *Departing alternative:* the four documentation prefixes alone (decided item 5, option (a)). Loopback and unspecified addresses identify no machine, and documents about servers need them.
- *Departing alternative:* also pass private, unique local and link-local addresses (decided item 5, option (c)). They lay out a real network, which the public record must not show; writers use documentation addresses. Widening later is one predicate and a release note.
- *Departing alternative:* in step 2, test for `::` on the run before its dots are trimmed, or trim one dot only. Either reading lets an address or a prefix before a full stop or an ellipsis pass, public addresses included.
- *Departing alternative:* unmap only an address written as `::ffff:` and dotted IPv4. A mapped address written in hex would never lie inside an IPv4 prefix, so a mapped documentation address would be flagged.
- *Departing alternative:* also allowing the second IPv6 documentation prefix that RFC 9637 added in 2024. AGENTS.md names only `2001:db8::/32`, and the allowlist should match what writers are told to use. Adding it later is a one-line change.

**`email-address` (section 4.3).**
- *Interim:* no email rule.
- *Departing alternative:* flagging every address. AGENTS.md tells writers to use `example.com`.
- *Departing alternative:* checking the final label against the public-suffix list. That is a data file to keep current, and an unknown suffix would pass.
- *Departing alternative:* bare candidates only. They miss identities in angle brackets whose domain has no dot, such as git's fallback identity.
- *Departing alternative:* any non-ASCII character in a label, and a pass for any domain that ends in a reserved name. A private address followed directly by a no-break space, an em dash or a fullwidth comma would run on into the text after it, up to a later reserved name, and pass.
- *Departing alternative:* an ASCII final label. An address under a non-ASCII top-level domain would be no candidate at all. The cost of letters of any script is that a reserved address followed directly by such letters is flagged.
- *Departing alternative:* keep the backtick in the bare local part, as RFC 5322's atom does. A Markdown code span that puts a backtick straight before an `@` name is then a candidate, as on a line of the reference pack, which agents may not edit.
- *Departing alternative:* also leave out the apostrophe, so a single-quoted `@` name is no candidate either. An address whose local part holds an apostrophe would then be read from after it, and no longer equal its listed identity.
- *Departing alternative:* a bracketed domain that runs to the `>`. A bracketed remote on a dotless private host passed whenever its path ended in a reserved name, and bracketed URLs on a reserved host were flagged.
- *Departing alternative:* for bracketed candidates, allow no `/` before the `@`, as the bare form does. A bracketed URL with user information, or an SSH remote, on a dotless private host would then pass.

**The identity allowance (sections 3.1 and 4.3).**
- *Interim:* no email rule, so nothing to allow.
- *Taken:* the addresses as one flag value, a comma-separated list, decided at acceptance.
- *Departing alternative:* an identity file, passed as `--identities FILE`, with its own grammar, location and mode checks, an error code `identity-file` and a change to what ADR-001's `line` means, as the draft proposed. The addresses are not secret, hook scripts and shell history do not reach the public record, and on agent machines the agent can edit its hooks as easily as a file. A file form can be added later without breaking the value form. With the file went the question whether hush refuses one that group or others can write (decided item 9).
- *Departing alternative:* a section of the term file. Agent machines hold no term file, yet they must pass the agent identity in every pushed commit.
- *Departing alternative:* a built-in allowance for a hosting platform's no-reply domain. Those addresses carry account names.
- *Departing alternative:* allowing a listed address anywhere (decided item 6, option (b)). Platform no-reply addresses carry account names and would pass in any file, and a listed address in a file or a path is still worth a look.
- *Departing alternative:* any line that starts with a word and `: `, `^[A-Za-z][A-Za-z0-9-]*: `, as an identity position. It also matches every `<ID>: summary` subject line and lines such as `Note:`.
- *Departing alternative:* standard input as an identity position only when the caller marks it as a commit message. It is one more explicit input and one more extension of ADR-001, not needed while section 3.1 keeps the allowance away from the other standard-input scans.

**The rule interface (sections 5.1 and 5.2).**
- *Interim:* one awk function returns the rule names a line breaks.
- *Departing alternative:* rules as a table of regular expressions. The IP rule needs `ParseAddr`, and v0.2's secret formats need checks a pattern cannot express.
- *Departing alternative:* rules that build findings. Locations and redaction belong to the targets and package `hush`, and a rule that knew them could leak them.
- *Departing alternative:* a public rule interface in v0.1, so importers can add rules. ADR-001 keeps it internal until v0.2's rules prove it.
- *Departing alternative:* HSH-14 extends the rule interface and the targets to pass `Source` and `Part`, and its "no change to the targets" criterion is amended (decided item 8, option (a)). No scan can apply the allowance before HSH-11 adds `--identities`, HSH-11 rebuilds the targets for ADR-001's parts anyway, and in HSH-5's port it would also change `termset.Set`, which implements the same interface (HSH-5/D1).

**Recording the extensions in ADR-001 (section 6).**
- *Interim:* no ADR.
- *Taken:* ADR-001's text is amended in the same PR, so one squashed commit lands both ADRs consistent (decided item 7, option (a)).
- *Departing alternative:* this ADR's acceptance extends ADR-001, whose text stays as accepted, and HSH-11 reads both (option (b)). ADR-001 calls its error table closed and lists its fail-closed conditions, so a reader of ADR-001 alone should find what applies there.
- *Departing alternative:* this ADR lists ADR-001 under `supersedes` for those parts (option (c)). It marks ADR-001 as partly replaced, so every reader of ADR-001 must also check this ADR.

**The term loader and matcher (section 5.3).**
- *Interim:* `load_terms`, an awk function that reads the file by its path, lowercases each term and stops with a line number.
- *Departing alternative:* a loader that takes a path. File access and its errors would sit inside `termset`, apart from ADR-001's location and mode checks in package `hush`. Taking bytes keeps the parser testable, and fuzzable, without files.
- *Departing alternative:* a loader that takes an `io.Reader`. Read errors would mix with parse errors, for a file that is read whole anyway.
- *Departing alternative:* a normalizer without offset maps, which finds a match in normalized text and then searches the raw line for it again. Once a step drops or folds characters, the raw line may not hold the match in any form the search can find, and redaction would start in the wrong component or nowhere.
- *Departing alternative:* Unicode-aware normalization behind the same interface now. That is v0.2's whole pipeline, and its NFKC and look-alike steps need data the standard library does not let hush import (section 2.5).

## Consequences

- **HSH-5** is unchanged. It ports the interim format and pattern at parity. Its loader should take bytes and return line-numbered errors, so HSH-11 can extend it.
- **HSH-14** builds `ip-address` and `email-address` exactly as sections 4.2, 4.3 and 5 say, through the bridge in section 5.1. The example tables become its table tests.
  - Its criterion "through the existing rule interface, with no change to the targets" holds through that bridge (decided item 8). Its issue points to decided items 5, 6 and 8 and to the bridge before this ADR merges.
  - It extends HSH-5's leak-check helper with the tables' flagged tokens and the identity (Negative tests).
  - The tables make the criteria crisp enough for the suggested `minimax` runner.
- **Until HSH-11,** no scan can apply the identity allowance, because `--identities` does not exist yet. A range scan run with hush's own binary after HSH-14 lands flags every commit identity outside the reserved domains, the agent identity's included.
- **HSH-11** applies the rest:
  - format 1's attributes, the marker and refusals, and the load-time checks;
  - the widened ID-prefix pattern;
  - `--identities` and `Config.Identities` (section 5.4);
  - the targets' `Source`, `Path` and `Part`, `tagger` included (decided item 8);
  - the per-set options (decided item 3);
  - the migration table in its guide, and identity setup with `--identities` in the hooks and in both publish scans.

  Its comparison test against the interim scanner lists two intended differences: the wider prefix, and the new term-file refusals. Its check that hush scans its own repository clean covers the whole tree, `reference/` included.
- **HSH-9's hooks** gain `--identities` when HSH-11 updates their command lines: on agent machines with the agent identity's address, and on the review machine beside the term-file flag (section 6, point 3). The installers shell-quote the value (section 5.4).
  - **The `commit-msg` hook passes the message on standard input,** as the interim hook does, both in HSH-9 and in the command lines HSH-11 updates. Section 4.3 counts a trailer as an identity position only in an object's message or on standard input, never on a line of a file. A hook that scanned the message file as a path target would flag the human's own `Signed-off-by:` trailer on the publish commit, even with `--identities`.
- **The publish step** becomes `hush scan --destination public --terms FILE --identities ADDR …` for both scans.
- **The human:**
  - checks the term file against section 1.7, where usually nothing needs to change;
  - passes the review machine's addresses with `--identities`, and installs each agent machine's hooks with the agent identity's address.
- **Writers,** agents and the human alike, avoid the known false positives in section 4: they rephrase standard names, put `v` before four- and five-part versions, write prefix lengths instead of netmasks, use HTTPS remotes, write `@` names in code spans, and avoid `@2x` names. This repository's whole tree, `reference/` included, follows the same rules, so hush can scan itself.
- **Tests and documents** assemble every flagged token at run time, as this ADR does in its tables.
- **Known misses stay misses until v0.2,** as listed under each rule. The private sets cover client-specific forms in the meantime.
  - A client-name variant that slips past a term set by an invisible character or a Unicode space inside the term (section 2.4) is a reason to pull v0.2's step 1 forward, and, for a Unicode space, step 2's mapping of spaces, because listing cannot fix it.
- **The cost** is one pass per rule per line. The IP rule makes two pattern passes and at most two `ParseAddr` calls per candidate. Term matching is one search per term per line, as in the interim.

## Negative tests

All data is synthetic:
- invented terms: `quorvel`, `zantoph`, `mirelda`, `brindlemoor`;
- client codes `k7` and `k8`;
- addresses at `.internal`, assembled at run time.

Every test runs through HSH-5's leak-check helper, which HSH-14 and HSH-11 extend with the tables' flagged tokens, the refused set names, the client labels and the identities, assembled at run time. The helper then fails if any of these appears in standard output, standard error, a returned error or a formatted value: a term, a refused set name, a client label, an identity, a rejected token, or any matched text.

1. **A set file inside a scanned path is refused.**
   - With `--terms` naming a file inside the tree, a tree scan exits 2 with code `term-file`. The same holds for a scan of the file's directory, of an ancestor of it, of the file itself, and of a tree holding a hard link to it.
   - Index and range scans exit 2 the same way for a repository whose work tree or git directory holds the file, or that has it committed with the same blob id.
   - Standard output is empty, and nothing is scanned.
2. **No error message echoes a term or a line of the set file.**
   - For each row of section 1.5 but the last, the offending line holds a term. Examples:
     - a term line holding `quorvel` and a control character;
     - a comment holding a lone CR followed by `quorvel`;
     - a header `[quorvel` without its `]`;
     - a header `[quorvel visible-to=K7]`;
     - a set named `quorvel-notes` beside the term `quorvel`;
     - `visible-to=zan9` beside the term `zan`.
   - Standard error is exactly `hush: term file: line N: REASON`, and the JSON `error` holds `code`, `message` and `line` only.
   - The last row: a file whose only lines are blank lines and a comment holding `quorvel` gives exactly `hush: term file holds no terms`, and a JSON `error` with `code` and `message` and no `line`.
   - The leak check finds no term, set name, label, line text or file path in any output form.
3. **A documentation-range address passes and a routable one fails.**
   - Each row of section 4.2's "Passes" table, alone on a line, exits 0.
   - Each row of its "Flagged" table exits 1 with `ip-address`. These include an address after the keys `ip6:`, `IPv6:` and `node:`, addresses with a port as tcpdump and BSD netstat print them, IPv6 addresses of eight groups, or of seven and a `::`, followed by a colon and a port without brackets, an address inside a dotted hostname after another label, and private, unique local and link-local addresses.
   - The edges: `192.0.2.255` and `2001:db8:ffff:ffff:ffff:ffff:ffff:ffff` pass; `"192.0." + "3.0"` and `"2001:db9:" + ":"` fail.
4. **The human's identity passes only when configured from outside the repo.** The fixture is a commit whose author, committer and `Signed-off-by:` trailer all carry `"Alice <alice@" + "acme.internal>"`, scanned with `--range`:
   - without `--identities`, it is flagged on the author, committer and trailer lines;
   - with `--identities` listing the address, in any ASCII case and beside a second address, it is clean;
   - the `commit-msg` hook's scan, which passes the commit's message on standard input with that `--identities`, is clean for the same trailer;
   - none of these makes it pass, and the findings stay as without an allowance:
     - a file listing the address committed at the root and under `.hush/`;
     - a `.mailmap` that maps the address;
     - `git config user.email`;
     - `HUSH_IDENTITIES`, `EMAIL`, `GIT_AUTHOR_EMAIL` and `GIT_COMMITTER_EMAIL` set in the environment;
   - with the allowance, the same address on a line of a file is flagged, even on a trailer-shaped line (decided item 6), and so is a subject line `"HSH-3: write to alice@" + "acme.internal"`;
   - a malformed `--identities` value exits 2 with code `usage`, and the message cites the argument's position, never its value: an empty value, an address without an `@` or with nothing on one side of it, one holding a space, a tab, `<` or `>`, and an empty item between commas. So does `--identities` given twice.
5. **The format is strict.** Each of these exits 2 with its line and the reason given:
   - `bad character`: a control character in a term, a C1 control (U+0085) in a term, a comment line holding a lone CR, U+2028 or a vertical tab followed by a term, and a byte that is not valid UTF8 in a term and in a comment;
   - `bad header`: `[clients-k7 visible-to=k7` without its `]`, `clients-k7 visible-to=k7]` without its `[`, each between two sets, the first of them also as the first line under its header, where it gives `bad header` on its own line rather than `set has no terms` on the header above, and `[clients] ; note`;
   - `bad attribute`: an unknown key (`[clients colour=red]`) or value (`case=upper`, `match=regex`), a repeated key, a label listed twice, `visible-to=*`, `visible-to=`, `visible-to=k7,`, `[clients ]`, and `[clients] visible-to=k7]`;
   - `bad client label`: `visible-to=K7` and `visible-to=public`;
   - `bad set name`: `[ clients]` and `[clients=x]`;
   - `set declared twice` and `set has no terms`: a repeated header, and an empty set;
   - `term outside a set`: a term before any header, and a byte-order mark before a header;
   - `bad term`: a no-break space or U+3000 inside a term or at either end of it, U+200B, U+FEFF, a soft hyphen (U+00AD) inside a word, U+200E at the end of a term, a bidi isolate (U+2066 and U+2069) around a term, and `quorvel   # main client`;
   - `unsupported format`: `#hush-terms 2` on line 1.

   As controls, these load: `#hush-terms 1` on line 1; `# hush-terms 2`, which is a comment; a comment such as `# see [notes]`; `[clients case=ignore]` and `[clients match=substring]`; a file with CRLF line ends; a term holding U+200C or U+200D inside a word, or a variation selector (U+FE0F) after a letter; and `quor#vel`.
6. **Load-time refusals.**
   - Each of these exits 2 with only the fixed message:
     - a set name that contains a term in any ASCII case;
     - the set name `clients` beside the term `NT`, in a `match=substring` set and in a `case=exact match=word` set alike;
     - the set names `qvlnotes` and `clientsQVL` beside the term `QVL` in a `match=word` set;
     - a set name that breaks `id-prefix` (`"ZQX" + "-42"`) or `ip-address` (`"203.0." + "114.7"`);
     - a client label that contains a term;
     - a header whose set name and one of whose client labels both contain a term, which gives `set name refused`.
   - As controls, these load: a set named `clients` beside the term `quorvel`; the set names `notes-2026`, `zantoph`, `clients-zantoph` and `zantophclients` beside the term `zantoph works` (section 1.4, "What the checks still let through"); and the client label `k-7`.
7. **Case is ASCII only.**
   - The term `quorvel` matches `QUORVEL`.
   - A term holding `é` does not match the same word written with `É`.
   - The term `kelvo` does not match the text whose first letter is the Kelvin sign.
8. **Per-set options** (decided item 3).
   - With `[abbreviations match=word]` holding `QVL`: flagged, `QVL`, `qvl`, `QVL2`, `x-QVL`, `QVL_api`, and the paths `docs/QVL/a.md` and `docs/qvl/a.md`; not flagged, `AQVLB` and `QVLClient`.
   - With `[abbreviations-exact case=exact match=word]` holding `MOP`: flagged, `MOP` and `x-MOP`; not flagged, `mop`, `Mop` and `MOPS`.
   - The flagged rows stay flagged once v0.2's steps join the chain (section 2.5).
9. **`id-prefix` and `reference/`.** Each row of section 4.1's tables behaves as listed. `"FLEET" + "-12"`:
   - passes in `reference/notes.md`, and in a file name under `reference/`, in a tree scan rooted at the repository root and in index and range scans;
   - is flagged in a commit message of a commit that changes only `reference/`, and on standard input;
   - is flagged in `docs/reference/a.md`, in `Reference/a.md` and in a file named `reference` at the root, in a tree scan rooted at the repository root and in index and range scans;
   - passes in `docs/reference/a.md` in a tree scan rooted at `docs`, which reports it as `reference/a.md`: the known limit of section 4.1.
10. **Rules never print what they match.** Every flagged example in section 4 is scanned in every target (tree, index, standard input, range) and as a path. The leak check finds none of the matched text in any output form.
11. **Rules feed redaction.** A tree with the path `docs/` + `"203.0." + "114.7"` + `/a.md` gives `docs/<redacted>:0: ip-address in path`. A path holding `"bob@" + "acme.internal"` in its second component redacts from that component too.

## Decided at acceptance

The human accepted this ADR on 2026-10-25 (PR #10) and decided each of the nine items that were open before acceptance. For item 3's sub-question and for item 4 the human did not take the draft's recommendation, taking (ii) and (a), and item 9 lapsed with the identity file. Each answer now stands in the decision text, and the options not taken are under "Alternatives considered".

| # | Item | Answer | Decided | Now in |
| --- | --- | --- | --- | --- |
| 1 | The term-set format | (a): the interim format, extended with header attributes | 2026-10-25 | Section 1 |
| 2 | Substring or word boundary as the default | (a): substrings, as in the interim | 2026-10-25 | Section 2.3 |
| 3 | Per-term options | (b): per-set `case=exact` and `match=word`. Sub-question: (ii), plain containment for every term, as ADR-001 section 5 reads, because under (i) a printed set name could hold a `match=word` term glued to letters, against ADR-001 section 6.6. `match=word` alone is the usual pattern for short abbreviations; `case=exact` is kept for an abbreviation that spells a common word | 2026-10-25 | Sections 1.2, 1.3, 1.4, 1.8, 2.2, 2.3, 2.5 and 5.3; tests 6 and 8 |
| 4 | Standard technical names that look like IDs | (a): flag them all. AGENTS.md calls those shapes mistakes, and most standard names would stay flagged under a list of exact tokens anyway. A list can be added later | 2026-10-25 | Section 4.1 |
| 5 | Loopback and private-range addresses | (b): pass loopback and unspecified addresses only | 2026-10-25 | Section 4.2; test 3 |
| 6 | Where the identity allowance applies | (a): identity positions only, with the trailer shape narrowed to identity trailers, `^[A-Za-z][A-Za-z0-9-]*-by: ` | 2026-10-25 | Section 4.3; test 4 |
| 7 | How accepted ADR-001 records this ADR's extensions | (a): ADR-001 is amended in this PR, so one squashed commit lands both ADRs consistent. What remains to record is the set-name pattern in its schema and its output check accepting its two unscanned names | 2026-10-25 | Section 6, points 1 and 2; ADR-001's "Decided at acceptance" |
| 8 | Which unit makes the targets pass `Source` and `Part` | (b): HSH-11, with the bridge for HSH-14 written into section 5.1 | 2026-10-25 | Section 5.1; Consequences |
| 9 | Whether hush refuses an identity file that group or others can write | Not needed: the identity file is replaced by a flag value | 2026-10-25 | Sections 3.1 and 5.4 |

The review also changed three choices the draft had made itself:
- **The allowance's input.** The allowed addresses come as a flag value, `--identities ADDR[,ADDR…]`, and `Config.Identities` is built from a list, instead of an identity file (sections 3.1, 4.3 and 5.4). The identity file's grammar, its location and mode checks, the `identity-file` code and the change to what ADR-001's `line` means are gone, with their tests.
- **The word check.** Refusing a set name or label with a part equal to a word of a term is deferred to v0.2 (section 1.4 and Alternatives). Section 1.3 tells the human to list a distinctive word as a term of its own.
- **The ID-prefix pattern's cost.** The widened pattern is kept, with its measured cost and its new false positives stated (section 4.1).

## Open questions for the human

None remain.
