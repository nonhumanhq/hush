---
kind: decision
status: accepted
verified: 2026-10-25
supersedes: []
---

# ADR-001: What hush is

## Context

hush is the outbound guard for nonhumanhq: it keeps private names out of records that may become public. The bootstrap loop (`reference/bootstrap-loop.md`, "Hush in the loop") splits that job in two. A **generic tier** of rules that hold nothing secret runs everywhere. A **private tier** of term sets runs only in trusted places, because "the term sets are the secret". Hashing the sets would not change that: "short abbreviations can be brute-forced from their hashes in seconds."

Until hush ships, the loop uses the interim scanner (`reference/interim-hush/`), a POSIX shell and awk script of about 420 lines with 42 test cases.
- **Tiers.** The ID-prefix rule always runs, and term sets come only from an explicit `--terms FILE`.
- **Targets.** It scans paths, standard input and git ranges, including each commit's author, committer and message.
- **Output.** It prints `WHERE:LINE: RULE` and never the matched text, and redacts a path component that breaks a rule.
- **Exit codes.** It exits 0 when clean, 1 on findings and 2 on a usage or configuration error.

HSH-5 ports it to Go at parity now, with everything internal, and HSH-11 applies this ADR and ADR-002 to the port.

Three forces shape the decisions below.

1. **Failing closed.** The loop's gate is the publish step, which runs "Both, fail closed". A scan that checked less than it should and still exits 0 is the worst outcome, worse than any false positive. The interim scanner has several such paths:
   - Leaving out `--terms` turns a scan into a generic-only scan that exits 0.
   - Rev-list options inside `--range` can narrow the range to nothing.
   - Grafts can shorten a range.
   - `--help` exits 0 before anything is checked.
   - Special files in a tree are skipped without a report.
   - Mergetag headers and annotated tags are not scanned.
   - A repeated option silently replaces the earlier one.

   The runbook's own publish line, `hush scan --destination public .`, names no term sets at all.
2. **Importers.** swe, fleet and the orchestrator will import hush (FLT and SWE Phase 1 "also import hush"), so the Go API is a first-class surface, not an afterthought to the CLI.
3. **The clean room.** Agents never hold term sets. Their hooks, the `gh` wrapper, `dispatch.sh block` and staging CI can run only the generic tier, and that must not look like the full check the human runs at publish.

ADR-002 (HSH-3), written at the same time, decides what hush matches: the term-set format and the generic rules. This ADR decides the policy around them: scope, shape, tiers, destinations, failing closed, output and the API. Section 9 lists what this ADR asks of ADR-002.

## Decision

### 1. Scope

hush **owns**:
- **Term sets.** It loads a term-set file its caller names, holds the terms in memory and matches them. The file's format is ADR-002's.
- **Generic rules.** In v0.1 these are the ID-prefix, IP-address and email rules. Their patterns and allowlists are ADR-002's.
- **Scan targets.**
  - A buffer or stream under a caller-given stdin label.
  - Files and directory trees.
  - The git index.
  - Git ranges: each commit's added lines, the paths it adds or changes, its commit object, and every annotated tag object the range reaches.
- **Findings and output.** The finding type, the plain and JSON formats, path redaction and exit codes.
- **Hook installers and the `gh` wrapper** (HSH-9). They are hush commands, and once HSH-11 has built the public package they scan through it.
- **Scanner mode, later.** It is designed by its own ADR in v0.2.

hush **never knows** realms, repos, clients, people or hosts:
- **Realms.** A realm is the context a record belongs to: a personal project, a client engagement or a work profile (the runbook's "profile and partition"). hush never knows which realm anything belongs to. Its callers turn a realm into a destination.
- **Repos.** It holds no mapping from a repository, remote URL, path or directory name to a visibility, owner or destination.
- **Clients and people.** It holds no names of its own. The only private strings it holds are the ones its caller passes for one run:
  - the terms, as opaque bytes under opaque set names;
  - any allowance ADR-002 defines, such as the email identity allowance.
- **Hosts.** The scan path resolves no names and opens no network connections.

To "know" something here means to hold a mapping or to keep state. hush may read whatever it is asked to scan, git objects included, and may take locations as arguments. It infers nothing from where it runs and keeps nothing between runs.

**The caller contract.**
- Each of these comes from the caller, explicitly, through a flag or an API argument: every scan's destination, every term-set file and every allowance ADR-002 defines.
- hush never reads any of them from the environment, a default path, git configuration, a remote URL, the repository's name, the working directory or any file in the scanned tree.
- Set names and client labels are opaque keys: hush compares them and prints set names, but never interprets them.

**The one built-in, loop-specific list.** The ID-prefix rule's allowlist (`HSH`, `CHS`, `FLT`, `SWE` and `ADR`, plus `FLEET` and `VMWS` under `reference/`) is built into the interim scanner. These are public tracker keys, not private names, but they are knowledge of hush's first users.
- ADR-002 owns the list and decides whether it stays built in as a default or comes from the caller.
- Either way it never comes from the scanned repository, because an allowlist read from the repo would let an agent loosen its own hook.

**Outside hush:**
- consolidating, signing, tagging and publishing (the publish step, later `nh sign`);
- mapping realms to destinations and wiring hush into swe and fleet (SWE-6);
- installing anything on real machines.

### 2. Shape

hush is **one Go module that uses only the standard library**: `go.mod` has no `require` lines, and a test fails if one appears.

**Module path.** The module path is `github.com/nonhumanhq/hush`. It resolves through the default module proxy with no server to run, and staging uses the same path, so code moves to the real repo unchanged. While the repo is private, importers set `GOPRIVATE`.

**Go version.** The `go` directive names the oldest Go release still supported upstream when HSH-11 lands. `go.mod` has no `toolchain` line, and CI runs both that minimum and the newest release.

**Git.** Git targets run the `git` binary, plumbing commands only. That is a runtime requirement, not a module dependency. HSH-11 sets the minimum git version, which must support every flag section 5 relies on, and tests it in CI.

**Packages.** There is **one public package**, `hush`, at the module root, and its import path is the module path, `github.com/nonhumanhq/hush`. A thin CLI sits over it. Internal names below are indicative: HSH-5 picks them, and HSH-11 reconciles them with this section.

| Package | Visibility | Holds |
| --- | --- | --- |
| `hush` (module root) | public | Destinations and the policy for which tiers and sets apply, configuration checks, the scan entry points, path redaction, the finding, report and error types, and the JSON error document |
| `cmd/hush` | binary | Argument parsing, standard streams, signals, exit status, help and version; hosts the hook and `gh` commands |
| `internal/target` | internal | Tree walk, index, git ranges, buffers. The only package that runs git or opens scanned files |
| `internal/rule` | internal | The generic rules behind ADR-002's rule interface |
| `internal/termset` | internal | ADR-002's term-file parser and matcher. Takes bytes, never a path |
| `internal/output` | internal | The plain and JSON writers |
| `internal/hooks`, `internal/ghwrap` | internal, CLI only | HSH-9. Once HSH-11 lands, they scan only through package `hush` |
| `internal/leakcheck` | internal, tests only | HSH-5's leak-check helper |

**What the CLI may do.**
- Parse arguments into one `Config` and one scan call.
- Read standard input.
- Read the git hook environment (`GIT_INDEX_FILE`, `GIT_DIR`) in index mode, make a relative path absolute against its own working directory before applying `-C`, and pass both explicitly.
- Handle signals, choose the writer and map the exit code.
- Host `hush hooks`, `hush gh`, `--help` and `hush version`.

It never chooses a destination or a tier, and never matches, redacts, filters, reorders or rewrites findings.

**`hush gh`.**
- It scans the text a `gh` command would post, with the destination and coverage it is given.
- On a finding or an error it writes and exits exactly as `hush scan` does, and never starts `gh`.
- Only after a clean scan does it run the real `gh`, once, so that `gh` posts exactly the bytes that were scanned. HSH-9 chooses how.
- `gh`'s own output and exit status belong to `gh`, not to hush, and a failed `gh` never makes `hush gh` exit 0.
- It hands `gh` the inherited environment, which `gh` needs in order to authenticate. hush itself reads no variable from it.
- That one launch, in `internal/ghwrap`, is the only child process other than git that the architecture tests allow.
- The stream, child-process and exit-status rules of section 6 govern `hush scan`, package `hush` and the scanning half of `hush gh`.

**Enforcement.** A test parses the sources and fails in two cases:
- `cmd/hush` imports an internal package other than `internal/hooks` and `internal/ghwrap`;
- once HSH-11 lands, `internal/hooks` or `internal/ghwrap` reaches a scan mechanism other than through `hush`.

**Network and state.** The scan path makes no network calls, keeps no state between runs and writes no temporary files.

**Versions.** hush stays at v0.x until its API settles. Importers pin an exact version, and release notes list every change to the API, the output or the exit codes.

**Trust.** Whenever term sets are loaded, hush runs from a release built from the human-reviewed, signed real repository. It never runs from a staging build or with `go run` in a staging clone, because a staging build is agent-written code, and it would run next to the secrets.

### 3. Tiers

| Tier | v0.1 contents | May run | Tells whom, what |
| --- | --- | --- | --- |
| Generic | The ID-prefix rule; IP addresses outside the documentation ranges; email addresses outside the allowed domains (patterns and allowlists: ADR-002). v0.2 adds hostname patterns and secret formats | Anywhere: agent sandboxes, agent hooks, the `gh` wrapper, `dispatch.sh block`, staging CI on hosted runners, the review machine | Whoever ran the scan, agent or human: the rule and the location, at the moment of the scan, so they can fix it. Never the matched text |
| Private | The term sets in the file the caller names | Only where the human keeps a term file. In v0.1 that is the review machine: building the reference pack, publish, the full-history scan before a repo goes public, and hooks installed there with HSH-9's term-file flag. In v0.2 the scanner account joins | The human who ran it: the location and the set name. Never the term. An agent learns only what the human relays (below) |

**What an agent is told.** In v0.1 the private tier runs only on the review machine, so nothing reaches an agent automatically. These are rules of the loop, not of hush, which tells only whoever ran it:
- **A finding.** The human relays the runbook's wording: the redacted location and the set name, never more.
- **A second failure.** A second private-tier failure on the same unit blocks the unit for the human, and the agent does not retry. Otherwise an agent could bisect a reported line to learn which word matched.
- **A failure to run.** When the private tier cannot run at all (a term-file error), the agent is told nothing. It is the human's problem.
- **Later.** Scanner mode's ADR revisits this for automatic relay.

**Where it runs.** hush cannot sense where it runs and does not try: no CI variables, hostnames or user names. A tier runs where its inputs exist. Term files exist only on the human's machines (ADR-002 decides where), and every agent context says so on its command line with `--generic-only` (section 4). The term sets never reach agent machines in any form, hashed or otherwise.

### 4. Destinations

A destination says **where the scanned text may end up**, not where it is first written:
- **`public`**: anyone may eventually read the text. This includes the real repos and everything in a staging repo, because "everything in this repository may become public".
- **`client:LABEL`**: outside nonhumanhq, only the one client whose code is LABEL may read it.
- **`private`**: no one outside nonhumanhq's own machines and accounts may read it.

hush takes one destination per scan. A record that more than one client may see is therefore scanned as `public`, and a caller unsure of the audience picks the stricter destination. Mapping realms and records to destinations is the caller's (SWE-6 for swe and fleet).

| Destination | Generic tier | Term sets applied | Term file |
| --- | --- | --- | --- |
| `public` | runs | every loaded set; nothing can be exempted | required, unless `--generic-only` |
| `client:LABEL` | runs | every loaded set except those the term file declares visible to LABEL | required; `--generic-only` is refused |
| `private` | runs | none | refused |

**Rules.**
- **Every scan names exactly one destination.** There is no default on the CLI, and the zero `Destination` is invalid in the API. hush never infers one (section 1).
- **Coverage is complete unless the caller downgrades it.**
  - A complete scan runs every tier its destination calls for, so a `public` or `client:LABEL` scan without a term file exits 2. It never falls back to the generic tier alone.
  - The only downgrade is `--generic-only` (`Config.GenericOnly`). In v0.1 it is accepted only with `public`, and never together with `--terms`.
  - A clean generic-only scan exits 0. Its coverage is visible on the command line and as `"coverage": "generic-only"` in the JSON document. hush prints no notice for it.
- **A complete public or client scan applies at least one term.** A `public` or `client:LABEL` scan whose applicable sets hold no terms between them exits 2, so a private tier that checks nothing never reports complete coverage.
- **`private` runs the generic tier and no sets**, so a record mislabelled private is still checked. Because the generic tier is every tier `private` calls for, a `private` scan is complete without a term file.
- **Client labels are opaque keys.** Two kinds of label appear in this ADR: a *client label* names a client destination and is never printed; a *stdin label* names a scanned buffer and is printed as its location.
  - A client label is 1 to 32 characters from `[a-z0-9_-]`, starts with a letter or digit, and is neither `public` nor `private`. The human picks codes such as `k7`, never names.
  - The term file declares, for each set, the labels that may see it; ADR-002 picks the syntax. Visibility is denied by default: a set applies to a client destination unless it declares that client's label, and there is no wildcard.
  - Refusals. None of these echoes the label:
    - A client label that no set declares exits 2 with code `destination`.
    - A client label that contains a term from any loaded set, or that breaks a generic rule, exits 2: code `destination` when it comes from `--destination`, `term-file` when it is declared in the term file.
    - A label that leaves no term to apply exits 2 with code `coverage` (the rule above).
  - A client label never appears in any output: the JSON document says `"destination": "client"`, and `Destination` values print only their class (section 6.6).
  - Set names are printed, so a set meant for one client is named with that client's code too, for example `clients-k7`. Set names are checked against the terms at load, the same way as client labels (section 9).
- **Redaction uses every loaded set,** including sets the destination exempts. So a path that holds an exempt client's own name is still redacted.

**Who runs what.**

| Context | Command |
| --- | --- |
| Agent hooks, `dispatch.sh block`, staging CI | `hush scan --destination public --generic-only …` |
| The `gh` wrapper in agent contexts | `hush gh --destination public --generic-only -- …` |
| Publish (both tiers) | Before the commit: `hush scan --destination public --terms FILE .` After it: `hush scan --destination public --terms FILE --range origin/main..HEAD`, so the message, trailers and author are scanned too. Both add ADR-002's allowance input if it is separate from the term file |
| Building the reference pack | `hush scan --destination public --terms FILE reference/` |
| Before a repo goes public | `hush scan --destination public --terms FILE --range --all`, with the same allowance input as publish |
| Importers | their own mapping from realm to destination, passed to `hush.New` |

### 5. Failing closed

A scan exits **0 only when it completed, ran every tier its destination and coverage call for, and found nothing**. Findings never stop a scan early, so the report is complete. Errors stop it at once. Every condition below is either a finding (exit 1) or an error (exit 2), and none passes silently. The last column marks where hush departs from the interim scanner.

**Arguments**, checked before anything is read:

| Condition | Exit | Departs |
| --- | --- | --- |
| No `--destination`; an unknown destination; a malformed client label | 2 | new |
| `--generic-only` together with `--terms`, or with `client:` or `private`; `--terms` with `private` | 2 | new |
| `public` or `client:` with neither `--terms` nor `--generic-only` | 2 | yes: the interim runs generic-only |
| An unknown option, a missing value, an option given twice, an option after the first path | 2 | yes: the interim echoes unknown options, keeps the last of a repeated option and reads late options as paths |
| `--help` together with any other argument | 2 | yes: the interim exits 0 |
| Not exactly one target; `-C` without `--range` or `--index`; `--label` without `--stdin`; `--allow-empty-range` without `--range`; an unknown `--format` | 2 | no, except the last two, which are new |

An option that takes a value always takes the next argument verbatim, even one that starts with `-`. So `--range --all` passes `--all` as the range, and `--label -` is refused as a stdin label rather than read as standard input. `-` alone is an alias of `--stdin`, as in the interim.

**The term file**, read once and held in memory. The interim re-reads it for every file and commit.

| Condition | Exit | Departs |
| --- | --- | --- |
| Missing, not a regular file once symlinks are followed, or unreadable | 2 | no |
| Holds no terms, or fails ADR-002's grammar (the message gives the line number only) | 2 | no |
| Readable or writable by group or others, by the mode of the file once symlinks are followed | 2 | new: the interim does not check the mode |
| A set name or client label that contains a term or breaks a generic rule | 2 | new |
| A client label used in the destination that no set declares, or one that leaves no term to apply | 2 | new |
| Inside a scanned path: an ancestor of the file, the file itself, or the same file reached by a hard link | 2 | extends the interim's path check |
| For index and range scans: inside the scanned repository's work tree or git dir, or committed to it as a blob with the same object id | 2 | new: the interim checks paths only |

A term file that group or others can read or write is refused, not warned about. A warning that still passes is a way to fail open, and other local accounts on a shared machine, such as an agent user, must not read the sets. The cost is a one-time `chmod 600`.

**Unknown rules and sets.** Any input that names a rule or a set fails with exit 2 when hush does not know the name (`unknown-rule`, `unknown-set`).
- **In v0.1** no option selects rules or sets. The condition can arise only inside the term file, if ADR-002's syntax lets one entry refer to a set or a rule.
- **Later inputs** that name rules or sets, such as rule selection and suppressions, must fail the same way.
- **Output check.** Separately, before each finding is written, an output check confirms its rule is in the registry, is a loaded set, or is one of the two unscanned names, `binary-unscanned` and `unreadable` (section 6.1). If not, the run stops with exit 2 and the fixed `internal` message.

**Trees and files:**

| Condition | Result | Departs |
| --- | --- | --- |
| A path argument that does not exist | exit 2 | no |
| A file that cannot be read | `unreadable`, exit 1 | no |
| A directory that cannot be walked | `unreadable` on the directory, exit 1, the rest is scanned | yes: the interim exits 2 and its `find` prints the raw path |
| A FIFO, socket or device inside a walked tree | `unreadable`, exit 1 | yes: the interim skips them silently |
| A file with a NUL byte | `binary-unscanned`, exit 1 | no |
| A symlink | its link text is scanned and the link is never followed, as git stores it | no |
| An entry named `.git` | pruned; git cannot track such paths | no |
| A path component that cannot print safely: control characters, an invalid Unicode encoding, bidi or format characters | the component prints as `<redacted>`, plus `unreadable in path` at line 0, exit 1; the content is still scanned | yes: the interim splits such names |
| A file, blob or line over hush's explicit size limits (HSH-11 sets the values) | exit 2, fixed message; no limit ever skips content | new |

**Standard input and buffers:**

| Condition | Result | Departs |
| --- | --- | --- |
| A NUL byte | `binary-unscanned`, exit 1 | yes: the interim scans raw bytes |
| A read error | exit 2 | no |
| A stdin label that does not match `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`, or one that contains a term or breaks a rule | exit 2, the label is not echoed | yes: the interim prints labels as given |
| Empty input | exit 0; the JSON document shows `"lines": 0` | no |

**Git**, used as data only:

| Condition | Exit | Departs |
| --- | --- | --- |
| Not a repository; git missing or older than the minimum; a repository that holds `info/grafts` | 2 | yes for grafts: the interim lets them shorten a range |
| A revision that is empty, starts with `-` or `^` where a revision is expected, holds whitespace or a NUL, or does not resolve to a commit or an annotated tag | 2 | yes: the interim passes any rev-list option through |
| A named revision, or a ref reached through a selector, whose fully peeled target is not a commit: a tag on a tree or a blob, or a ref that names one | 2 | new: rev-list walks nothing for such targets, so their content would go unscanned |
| A range that resolves to no commits, unless the caller allows it (`--allow-empty-range`, `Range.AllowEmpty`) | 2 | yes: the interim exits 0 |
| A range that walks to a shallow boundary, a commit listed in the repository's shallow file | 2 | yes: the interim scans what is there and exits 0. Callers fetch full history first; a tree scan covers a shallow checkout's content |
| An index scan whose named index file does not exist or is not a regular file | 2 | new: git reads a missing index as empty |
| A missing or corrupt object, a failed diff, or git output the parser does not recognise | 2 | no |

**Accepted range syntax.**
- `--range` accepts only:
  - revisions;
  - `A..B`;
  - `^REV`;
  - `--not`;
  - the ref selectors `--all`, `--branches`, `--tags` and `--remotes`.
- A revision is anything `git rev-parse --verify` resolves to a commit or to an annotated tag, such as `main`, `HEAD~1`, `v0.1` or an object id.
- hush expands the selectors itself by listing refs:
  - `--all` means `HEAD`, every linked worktree's `HEAD`, and every ref under `refs/` except `refs/stash` and `refs/replace/`. That is git's own `--all` minus those two, so refs such as `refs/original/` and `refs/pull/` in a mirror are walked.
  - `--branches`, `--tags` and `--remotes` mean their one namespace.
- Every revision and ref is resolved to an object id before rev-list runs, so no other rev-list option can narrow the range.

**Annotated tags.** Every tag object in a peel chain, named or reached through a selector, is scanned as an object of its own, and the commit it finally points to is walked. The interim peels tags and skips their text.

**How git is run.**
- **Commands.** Plumbing only. Paths come from `diff-tree -r -z --raw` records, paired by output order with the same run's `-p` sections. Patch headers are never parsed for paths, so paths are git's raw bytes and never C-quoted.
  - A typechange record (`T`, for example a file that becomes a symlink) pairs with two sections: the old side's deletion, then the new side's creation.
  - Any other mismatch between records and sections exits 2.
- **Diff flags.** `--text`, `--no-ext-diff`, `--no-textconv`, `--no-color` and `--no-renames`. Because of `--text`, attributes and `core.bigFileThreshold` cannot make git hide a file's lines. hush applies its own NUL rule to each new blob in range and index scans, so `binary-unscanned` means the same thing for every target.
- **Global switches.** `--no-replace-objects`, `--no-lazy-fetch` (an older git rejects the unknown flag, which fails closed) and `-c core.fsmonitor=false`.
- **The child's environment.** It is a fixed list, and nothing is inherited: `LC_ALL=C`, `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_TERMINAL_PROMPT=0`, and the variables derived from hush's explicit inputs (`GIT_DIR`, `GIT_INDEX_FILE`).
  - `os/exec` finds the git binary through `PATH`. The child gets no `PATH` of its own.
  - Global and system configuration are ignored, so trace output, external tools and prompts cannot be switched on from them.
  - git's ownership check (`safe.directory`) applies only when git discovers a repository itself, not when hush names it through `GIT_DIR`. hush's safety does not rest on that check: the flags and the fixed environment already keep a repository's configuration from running anything.
- **The result.** A scanned repository's configuration cannot make hush run a program, reach the network or skip content.
- **Standard error.** git's standard error is captured and discarded, never relayed. The interim relayed it from two of its git calls.
- **Departure.** The interim disables only replace objects, so grafts can shorten its ranges and a partial clone can fetch.

**What a commit scan covers.**
- **Object headers.** In commit and tag objects, as `git cat-file` prints them, a header runs from its keyword line through the following lines that start with a space.
  - Skipped entirely: `tree` and `parent` in commits; `object` and `type` in tags.
  - Every other header is scanned, so mergetag content, `encoding` and a tag's `tag` and `tagger` lines are covered. The interim scans only `author` and `committer`.
  - Line numbers are as `git cat-file` prints them.
- **Messages.** The message is scanned.
- **Signature blocks.** These appear in `gpgsig` and `gpgsig-sha256` headers, inside a `mergetag` header, and at the end of a tag's message.
  - Skipped: only the `-----BEGIN` and `-----END` lines, base64 body lines and the `=` checksum line.
  - Scanned: every other line in a block, including armor header lines such as `Comment:`. Text cannot hide in a block simply by sitting between its markers.
  - Known limit: a bare word drawn from the base64 alphabet can still hide in a block's body.
- **Diffs.** A merge is diffed against its first parent.
- **Index scans.** These read each stage-0 entry's blob by object id through plumbing, never from the work tree.

**The process:**

| Condition | Exit |
| --- | --- |
| Standard output or standard error cannot be written (closed reader, full disk). The CLI ignores `SIGPIPE`, so a failed write is an error rather than a death by signal | 2 |
| `INT`, `TERM`, `HUP` or `QUIT`, handled through `os/signal` and fed to the scan's context | 2 |
| A panic, recovered with a fixed message (section 6.6) | 2 |

Exit 0 is reached by a single code path, after the output has been flushed without error. Fatal runtime errors (out of memory, stack overflow) and kills by the kernel still end non-zero, but they fall outside the one-line stderr rule of section 6.2.

**Empty scans.** An empty tree or empty input exits 0, and its counts show that nothing was scanned. An empty range exits 2 unless the caller allows it. A push that adds no new commits is ordinary, but a publish range that resolves to nothing is a mistake.

### 6. Output

Section 6 governs `hush scan`, package `hush` and the scanning half of `hush gh` (section 2).

#### 6.1 The finding

| Field (JSON) | Present | Meaning |
| --- | --- | --- |
| `kind` | always | `match` (a rule or set matched) or `unscanned` (`binary-unscanned`, `unreadable`) |
| `tier` | matches | `generic` or `private` |
| `rule` | always | `id-prefix`, ADR-002's other generic rule names, `set:NAME`, `binary-unscanned` or `unreadable`. It is the plain format's RULE without ` in path` |
| `in_path` | when true | The path itself broke the rule, not the content |
| `commit` | findings in a commit | The commit's full object id: 40 hex digits, or 64 in a sha256 repository |
| `tag` | findings in a tag object | The annotated tag object's full object id |
| `part` | findings in a commit or tag object | `author`, `committer`, `tagger`, `header` or `message` |
| `path` | file findings | Relative to the scan root (tree, index) or the repository root (range); slash-separated; already redacted |
| `path_redacted` | with `path` | `true` when `path` holds the placeholder, so it cannot be mistaken for a directory really named `<redacted>` |
| `label` | stdin and buffer findings | The stdin label, already checked, or `<stdin>` |
| `line` | always | 1-based. Added lines are numbered in the new file, and object lines as `git cat-file` prints them. 0 means the path or the whole file |
| `where` | always | The plain format's WHERE, from the same function |

A finding **never** holds:
- the matched text, the line or any part of it, or a snippet;
- a column, a length or a count of matches. v0.1 has no columns. A later version may add a column to generic findings, but never to private ones, because a column into text the reader already holds points at the term;
- which term matched: its text, its index or its position in the term file;
- any hash or fingerprint of the above. v0.1 has no fingerprints. If suppressions later need them, they are for the generic tier only and are built from content-free fields (rule, path, line), never from a hash of matched text;
- an unredacted path;
- a client label;
- the term file's path or lines.

There is one finding per location, line and rule.

#### 6.2 The plain format

The default, and the interim's format byte for byte, with one new location, `(tag)`:

```
finding = where ":" line ": " rule [" in path"] LF
where   = path / sha12 ":" path / sha12 ":(commit)" / sha12 ":(tag)" / label
```

```
docs/a.md:3: id-prefix
docs/<redacted>:0: set:clients in path
assets/logo.bin:0: binary-unscanned
9c1e5b7a2f04:docs/a.md:2: id-prefix
9c1e5b7a2f04:(commit):3: set:people
5e0b2d9c7a13:(tag):4: set:clients
issue-body:1: id-prefix
```

- **Streams.** Standard output carries findings only. Standard error is empty on exit 0 and 1, and holds exactly one fixed line, `hush: MESSAGE`, on exit 2. There are no banners, counts, progress lines or notices.
- **Order.** It is the interim's.
  - Tree files are listed in byte order. Within a file come path findings first, then `binary-unscanned` or `unreadable`, then lines in order. Within a line, generic rules come in registry order, then sets in term-file order.
  - Commits are listed oldest first. Each commit's object comes first, then its changed files in git's order. A tag object comes right after the commit it points to. A tag whose commit lies outside the range comes after all commits, in ref order.
- **Parsing.** Plain output is for people. A path that holds `:` makes it ambiguous, so programs read the JSON document.

#### 6.3 The JSON document

`--format json` writes **one JSON document**, built in memory and written once at the end of the run. It is a single line, uses no HTML escaping and keeps its keys in a fixed order.
- **When it is written.** A document is written once `--format`, the destination and the target have been parsed.
- **Earlier errors.** An error found before that (a usage error, an unknown destination or malformed client label, a wrong number of targets) leaves standard output empty, which every JSON parser rejects.
- **Later errors.** Every later outcome writes a document, including the coverage combinations, configuration errors and runtime errors.
- **The consumer contract.** A scan is clean only when the exit status is 0 **and** `result` is `"clean"`. Anything else is a stop, including empty output, an unknown schema and a missing `result`. Readers ignore fields they do not know: only `schema`, `result` and `exit` decide a pass.

| Field | Meaning |
| --- | --- |
| `schema` | The format's identifier with a major number: `hush.scan/1` in v0.1. Within a major, fields are only added. Readers ignore fields they do not know and reject a major they do not know |
| `hush` | The hush version |
| `result` | `clean`, `findings` or `error` |
| `exit` | 0, 1 or 2, equal to the process's exit status |
| `destination` | `public`, `client` or `private`; the class only, never a label |
| `coverage` | `complete` or `generic-only` |
| `tiers` | The tiers that ran; empty on `error` |
| `sets` | The names of the sets that applied; present only when the private tier ran |
| `target` | `tree`, `index`, `stdin` or `range` |
| `scanned` | `{files, commits, lines}`, so a caller can assert that something was scanned; absent on `error` |
| `findings` | Present, as an array, for `clean` (empty) and `findings` (not empty) |
| `error` | Present only for `error`: `{code, message, argument?, line?, commit?}`. `code` comes from the table in section 7, `message` is the stderr line without `hush: `, `argument` is a 1-based position, `line` a term-file line and `commit` a full object id |

The schema sketch below uses JSON Schema draft 2020-12 and is abbreviated. It describes what readers may rely on. hush's own tests check its output against a closed variant of the same schema, one that refuses unknown fields. The set-name pattern is ADR-002's grammar, 1 to 64 characters from `[A-Za-z0-9_.-]`, both in `sets` and in the `set:` branch of a finding's `rule`.

```json
{"type": "object",
 "required": ["schema", "hush", "result", "exit", "destination", "coverage", "tiers", "target"],
 "properties": {
  "schema": {"const": "hush.scan/1"},
  "hush": {"type": "string"},
  "result": {"enum": ["clean", "findings", "error"]},
  "exit": {"enum": [0, 1, 2]},
  "destination": {"enum": ["public", "client", "private"]},
  "coverage": {"enum": ["complete", "generic-only"]},
  "tiers": {"type": "array", "uniqueItems": true, "items": {"enum": ["generic", "private"]}},
  "sets": {"type": "array", "items": {"type": "string", "pattern": "^[A-Za-z0-9_.-]{1,64}$"}},
  "target": {"enum": ["tree", "index", "stdin", "range"]},
  "scanned": {"type": "object", "required": ["files", "commits", "lines"], "properties": {
   "files": {"type": "integer", "minimum": 0},
   "commits": {"type": "integer", "minimum": 0},
   "lines": {"type": "integer", "minimum": 0}}},
  "findings": {"type": "array", "items": {"$ref": "#/$defs/finding"}},
  "error": {"type": "object", "required": ["code", "message"],
   "properties": {"code": {"type": "string", "pattern": "^[a-z]+(-[a-z]+)*$"},
    "message": {"type": "string"},
    "argument": {"type": "integer", "minimum": 1},
    "line": {"type": "integer", "minimum": 1},
    "commit": {"type": "string", "pattern": "^([0-9a-f]{40}|[0-9a-f]{64})$"}}}},
 "allOf": [
  {"if": {"properties": {"result": {"const": "clean"}}},
   "then": {"required": ["findings", "scanned"], "properties": {"exit": {"const": 0}, "findings": {"maxItems": 0}}, "not": {"required": ["error"]}}},
  {"if": {"properties": {"result": {"const": "findings"}}},
   "then": {"required": ["findings", "scanned"], "properties": {"exit": {"const": 1}, "findings": {"minItems": 1}}, "not": {"required": ["error"]}}},
  {"if": {"properties": {"result": {"const": "error"}}},
   "then": {"required": ["error"], "properties": {"exit": {"const": 2}}, "not": {"anyOf": [{"required": ["findings"]}, {"required": ["scanned"]}]}}}],
 "$defs": {"finding": {"type": "object",
  "required": ["kind", "rule", "line", "where"],
  "properties": {
   "kind": {"enum": ["match", "unscanned"]},
   "tier": {"enum": ["generic", "private"]},
   "rule": {"type": "string", "pattern": "^([a-z0-9]+(-[a-z0-9]+)*|set:[A-Za-z0-9_.-]{1,64})$"},
   "in_path": {"const": true},
   "commit": {"type": "string", "pattern": "^([0-9a-f]{40}|[0-9a-f]{64})$"},
   "tag": {"type": "string", "pattern": "^([0-9a-f]{40}|[0-9a-f]{64})$"},
   "part": {"enum": ["author", "committer", "tagger", "header", "message"]},
   "path": {"type": "string", "minLength": 1},
   "path_redacted": {"type": "boolean"},
   "label": {"type": "string", "pattern": "^(<stdin>|[A-Za-z0-9][A-Za-z0-9._-]{0,63})$"},
   "line": {"type": "integer", "minimum": 0},
   "where": {"type": "string"}},
  "dependentRequired": {"path": ["path_redacted"]},
  "dependentSchemas": {"part": {"anyOf": [{"required": ["commit"]}, {"required": ["tag"]}]}},
  "if": {"properties": {"kind": {"const": "match"}}}, "then": {"required": ["tier"]}}}}
```

Synthetic examples. The term `quorvel` is in set `clients` and `zantoph` in set `people`; neither appears in any output.

A complete public scan of a tree, clean:

```json
{"schema":"hush.scan/1","hush":"0.1.0","result":"clean","exit":0,"destination":"public","coverage":"complete","tiers":["generic","private"],"sets":["clients","people"],"target":"tree","scanned":{"files":42,"commits":0,"lines":3170},"findings":[]}
```

A range with findings (wrapped here for reading):

```json
{"schema":"hush.scan/1","hush":"0.1.0","result":"findings","exit":1,"destination":"public","coverage":"complete","tiers":["generic","private"],"sets":["clients","people"],"target":"range","scanned":{"files":3,"commits":2,"lines":57},"findings":[
 {"kind":"match","tier":"private","rule":"set:people","commit":"9c1e5b7a2f04d3b6a8e1c0f9d2b7a4e6c3f1a0b9","part":"author","line":3,"where":"9c1e5b7a2f04:(commit)"},
 {"kind":"match","tier":"generic","rule":"id-prefix","commit":"9c1e5b7a2f04d3b6a8e1c0f9d2b7a4e6c3f1a0b9","path":"docs/a.md","path_redacted":false,"line":2,"where":"9c1e5b7a2f04:docs/a.md"},
 {"kind":"unscanned","rule":"binary-unscanned","commit":"4d7f0a2c9e1b5f3a8c6d2e0b7a9f1c3e5d4b2a01","path":"assets/logo.bin","path_redacted":false,"line":0,"where":"4d7f0a2c9e1b:assets/logo.bin"},
 {"kind":"match","tier":"private","rule":"set:clients","in_path":true,"commit":"4d7f0a2c9e1b5f3a8c6d2e0b7a9f1c3e5d4b2a01","path":"docs/<redacted>","path_redacted":true,"line":0,"where":"4d7f0a2c9e1b:docs/<redacted>"}]}
```

The same run in plain format:

```
9c1e5b7a2f04:(commit):3: set:people
9c1e5b7a2f04:docs/a.md:2: id-prefix
4d7f0a2c9e1b:assets/logo.bin:0: binary-unscanned
4d7f0a2c9e1b:docs/<redacted>:0: set:clients in path
```

An agent's generic-only scan of a `gh` body, clean:

```json
{"schema":"hush.scan/1","hush":"0.1.0","result":"clean","exit":0,"destination":"public","coverage":"generic-only","tiers":["generic"],"target":"stdin","scanned":{"files":0,"commits":0,"lines":4},"findings":[]}
```

A configuration error. Standard error reads `hush: term file: line 7: bad set name`:

```json
{"schema":"hush.scan/1","hush":"0.1.0","result":"error","exit":2,"destination":"public","coverage":"complete","tiers":[],"target":"tree","error":{"code":"term-file","message":"term file: line 7: bad set name","line":7}}
```

SARIF is not offered in v0.1. If code scanning is wanted later, an exporter built from the same findings can be added for the generic tier only, filling no snippet, context or fingerprint fields.

#### 6.4 Path redaction

Redaction happens when a finding is made, so `Finding.Path` is already safe in an importer's hands:

1. Normalize the path as the interim does: collapse `//` and strip a leading `./`. Range and index paths are git's raw bytes from `--raw -z` records.
2. If no active rule matches anywhere in the whole path and every component can print safely, the path prints unchanged.
3. Otherwise, find the earliest byte at which any match begins (for any active generic rule or any loaded set), or at which an unsafe character appears. Everything from the component that holds that byte onward prints as one `<redacted>`. If that is the first component, the path prints as `<redacted>` alone.

So a term that spans a `/` is redacted from the component where it starts, and no part of it prints. The interim's algorithm redacts from the component where the first breaking prefix ends. That leaks the start of a term that spans a `/`, and this ADR corrects it. Match positions are used only inside package `hush` for this step. In v0.1 they never reach a finding, an error or any exported value. A later version may expose a column on generic findings, never on private ones (section 6.1).

Redaction checks every active generic rule and **every loaded set**, including sets the destination exempts. The rules follow ADR-002's matching and its `reference/` exception.

**Never redacted.** These never hold outside text, so they are printed as they are: object ids (hex from git), rule names (constants), set names (checked at load) and fixed words.

**Never printed.** Stdin labels that break a rule are refused rather than redacted (section 5). Client labels and the term file's path are never printed at all.

There is no mode that reveals redacted text. On the review machine the human finds a location with their own tools, for example by searching for the terms in the files named.

#### 6.5 Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Clean: the scan completed with every required tier and found nothing. For a generic-only scan, clean means generic-clean |
| 1 | Findings: the scan completed and found at least one match or unscanned entry |
| 2 | Error: usage, configuration, term file, destination, label, path, git, input, output, signal or internal error. No complete scan exists |

- An error that happens after findings sets the status to 2.
- Any other status, such as a fatal runtime error or a kill by the kernel, is also a stop.
- Callers must never test for a specific non-zero value in order to proceed.
- On the scan path hush never passes a child process's status through.
- `hush scan --help` and `hush version` exit 0 only when they are the whole command.

#### 6.6 The invariant: no matched text and no term, anywhere

**The invariant.** No output, error, log line or panic message holds matched text or a term, for anyone, the human included. Every byte hush writes, whether to standard output, to standard error or to a writer it is handed, comes from one of the sources below. So does every byte it puts in a returned error or places in an exported value:
- hush's fixed vocabulary and message table;
- integers;
- git object ids;
- set names checked at load;
- stdin labels checked on input (client labels are never output);
- paths produced by redaction.

Nothing comes from scanned content, from the term file's terms, lines or path, from argument values other than checked stdin labels, from the environment, or from another process's output.

**How the Go code keeps it:**
- **Construction.** Every `Finding` hush returns is built by one constructor, from redaction and the rule registry.
- **Formatting guards.**
  - Every type that holds a term, a raw path, an allowance or a client label, directly or through unexported fields, slices or maps, implements `fmt.Formatter`, `GoString` and `slog.LogValuer` with value receivers, printing a fixed summary.
  - Its `MarshalJSON`, `MarshalText` and `GobEncode` return an error or the summary.
  - A guard protects a value only at the top level or through exported fields, because `fmt` prints unexported fields and skips the methods of values it reaches through them.
  - So `TermSets`, `Scanner`, `Destination` (whose methods print only `public`, `client` or `private`) and `Report` each carry their own guard. `Config` is covered because its `Destination` and `Terms` fields are exported.
- **One writer.** Only `cmd/hush` and `internal/output` touch standard output and standard error. The library never prints or logs.
- **Errors.** Errors come from a closed table (section 7) of fixed messages, with integer and object-id parameters only.
  - Errors from `os`, `io/fs`, `os/exec`, `strconv` and `encoding/json` are converted where they occur and dropped: never wrapped, never formatted. `*hush.Error` has no `Unwrap`.
  - The CLI prints the text only of errors it owns. Any other error prints the internal-error message.
  - `WriteErrorJSON` writes any error that is not a `*hush.Error`, including nil and `*FindingsError`, as code `internal` with the fixed message, and never formats it.
- **Arguments.** A small hand-written parser, because Go's `flag` package echoes unknown flags and keeps the last of a repeated one. Messages cite argument positions, never values.
- **Child processes.** On the scan path git is the only child process, run only with fixed argument templates, and its standard error is discarded. No term, allowance or term-file path is ever passed to it.
- **Panics.** Every exported function in `hush` and `main` recovers a panic into a fixed internal error and never formats the recovered value. Non-test code starts no goroutines of its own in v0.1. Terms never enter a regular expression's source, because compile errors print the pattern.
- **Crashes.** Before the term file is read, the CLI sets the core-dump size limit to zero on unix, so a crash cannot leave the terms in a core file.
- **No other outputs.** No `log` or `log/slog` output, no verbose or debug flag, no debug environment variable, no temporary files. Release builds use `-trimpath`. `hush version` prints only the module version and VCS revision.
- **Tests.**
  - The leak check covers every output form: plain, JSON, standard error, each returned error's text, and `%v`, `%+v` and `%#v` of every exported value.
  - Architecture tests built with `go/parser` and `reflect` fail the build when any rule above is bypassed. The `reflect` checks walk types transitively.
  - Each architecture check has a planted violation it must report.

### 7. Go API outline

This outline is concrete enough for HSH-11 to build the public package and write a doc comment for every exported identifier. HSH-11 may rename identifiers and declare the small enumerations (`Kind`, `Tier`, `Part`, `Coverage`, `Target`, `RefSelector`, `Code`, `Counts`); the behaviour is what is decided here.

```go
package hush // import path: github.com/nonhumanhq/hush (section 2)

// Destination is where the scanned text may end up. The zero value is invalid.
// Its String, Format, GoString and LogValue print only the class.
type Destination struct{ /* unexported */ }

func Public() Destination
func Private() Destination
func Client(label string) (Destination, error) // grammar only; New checks the label against the term sets
func ParseDestination(s string) (Destination, error) // "public", "private" or "client:LABEL"

// TermSets is the private tier. No method returns, prints, logs or encodes a term.
type TermSets struct{ /* set names, visibility declarations, file identity, a match function */ }

func LoadTermSets(path string) (*TermSets, error) // the only way terms enter hush
func (t *TermSets) Names() []string                // set names, in file order
// String, GoString, Format and LogValue print "hush.TermSets(N sets)";
// MarshalJSON, MarshalText and GobEncode always return an error.
// A TermSets not returned by LoadTermSets, such as new(TermSets), makes New return ErrTermFile.

type Config struct {
	Destination Destination // required
	Terms       *TermSets   // the private tier: required for public and client:LABEL unless GenericOnly
	GenericOnly bool        // the only downgrade: public only, never with Terms
	// HSH-11 adds the caller-supplied allowances ADR-002 defines here,
	// such as the email identity allowance, held like TermSets.
}

// Scanner is immutable and safe for concurrent use. All policy checks happen in New.
type Scanner struct{ /* unexported */ }

func New(cfg Config) (*Scanner, error)

func (s *Scanner) ScanBytes(ctx context.Context, label string, b []byte) (*Report, error)
func (s *Scanner) ScanReader(ctx context.Context, label string, r io.Reader) (*Report, error)
func (s *Scanner) ScanTree(ctx context.Context, root string, paths ...string) (*Report, error) // no paths: the whole root
func (s *Scanner) ScanIndex(ctx context.Context, repo Repo) (*Report, error)
func (s *Scanner) ScanRange(ctx context.Context, repo Repo, r Range) (*Report, error)

type Repo struct {
	Dir       string // a work tree or a git dir; bare mirrors included
	IndexFile string // "" is the repository's own index; set, it must exist. hush never reads GIT_INDEX_FILE itself
}

type Range struct {
	Include     []string      // revisions: a name, an object id (an annotated tag's too) or "A..B"
	IncludeRefs []RefSelector // AllRefs, Branches, Tags, Remotes (section 5)
	Exclude     []string      // revisions to subtract: ^REV, or after --not
	ExcludeRefs []RefSelector // selectors after --not; the pre-push new-branch case is {Remotes}
	AllowEmpty  bool          // otherwise a range with no commits is ErrEmptyRange
}

func ParseRange(s string) (Range, error) // the CLI's --range text; needs at least one revision or selector to include

// Report is immutable. Its methods are safe on a nil receiver, which is never clean.
// Its String, Format, GoString and LogValue print a fixed summary without the client label.
type Report struct{ /* unexported */ }

func (r *Report) Clean() bool
func (r *Report) Findings() []Finding // a copy, in output order
func (r *Report) Destination() Destination
func (r *Report) Coverage() Coverage // Complete or GenericOnly
func (r *Report) Tiers() []Tier
func (r *Report) Sets() []string
func (r *Report) Scanned() Counts // Files, Commits, Lines
func (r *Report) WritePlain(w io.Writer) error
func (r *Report) WriteJSON(w io.Writer) error

type Finding struct {
	Kind         Kind   // Match or Unscanned
	Tier         Tier   // TierGeneric or TierPrivate, for matches
	Rule         string // "id-prefix", "set:clients", "binary-unscanned", "unreadable", …
	InPath       bool
	Commit       string // full object id of the commit, for findings in a commit
	Tag          string // full object id of the annotated tag, for findings in a tag object
	Part         Part   // Author, Committer, Tagger, Header or Message, for findings in an object
	Path         string // already redacted
	PathRedacted bool
	Label        string // the stdin label
	Line         int
}

func (f Finding) Where() string
func (f Finding) String() string // the plain line, without its newline

// FindingsError is the error a scan returns when it completed and found something.
type FindingsError struct{ /* the report */ }

func (e *FindingsError) Error() string        // "hush: N findings"; no locations
func (e *FindingsError) Is(target error) bool // matches ErrFindings
func (e *FindingsError) Report() *Report      // never nil

// Error is every other failure: fixed text with integers and object ids only.
type Error struct{ /* code, argument position, term-file line, commit */ }

func (e *Error) Error() string
func (e *Error) Code() Code
func (e *Error) Argument() int // 1-based argument position, or 0
func (e *Error) Line() int     // term-file line, or 0
func (e *Error) Commit() string // full object id, or ""
func (e *Error) Is(target error) bool // matches the sentinels below; there is no Unwrap

var (
	ErrFindings, ErrUsage, ErrDestination, ErrCoverage, ErrTermFile, ErrLabel,
	ErrUnknownSet, ErrUnknownRule, ErrPath, ErrGit, ErrRange, ErrEmptyRange,
	ErrRead, ErrOutput, ErrInterrupted, ErrInternal error
)

// WriteErrorJSON writes the JSON document for a run that ended in err, through
// the same writer as Report.WriteJSON. The CLI uses it for every error after
// the destination and the target have been parsed (section 6.3). An err that
// is not a *Error, including nil and *FindingsError, is written as code
// "internal" and never formatted. A zero Destination writes nothing and
// returns ErrDestination.
func WriteErrorJSON(w io.Writer, d Destination, c Coverage, t Target, err error) error

func ExitCode(err error) int // nil 0; ErrFindings 1; anything else 2
func Version() string
```

**The scan contract.** Every scan method returns exactly one of three things:
- `(report, nil)`: the scan completed and is clean. This is the only pass.
- `(report, *FindingsError)`: the scan completed with findings, and the same report is reachable through `errors.As`.
- `(nil, *Error)`: the scan did not complete. There are no partial reports.

So the ordinary `if err != nil { return err }` fails closed, and an importer that never looks at the report cannot post text that has findings.

**Other contract points.**
- **Zero values.** A zero or nil `Scanner`, `Config`, `Destination`, `Repo` or `TermSets` returns an error and never scans.
- **Panics.** Every exported entry point recovers panics into `ErrInternal`.
- **Context.** Cancellation returns `ErrInterrupted`.

**Error codes.** Each code is shared by `Error.Code` and the JSON `error.code` field; the stderr line carries the message only. The messages are fixed text, with N standing for an integer:

| Code | Sentinel | Example message |
| --- | --- | --- |
| `usage` | ErrUsage | `argument 3: unknown option (see hush scan --help)` |
| `destination` | ErrDestination | `argument 2: unknown destination`; `argument 2: client label refused`; `the client label is not declared in the term file` |
| `coverage` | ErrCoverage | `the public destination needs --terms FILE or --generic-only`; `no term applies to this destination` |
| `term-file` | ErrTermFile | `term file: line 7: bad set name`; `term file: line 9: client label refused`; `term file: readable or writable by group or others` |
| `label` | ErrLabel | `argument 4: stdin label refused` |
| `unknown-set` | ErrUnknownSet | `term file: line 12: unknown set` |
| `unknown-rule` | ErrUnknownRule | `term file: line 12: unknown rule` |
| `path` | ErrPath | `path argument 2 does not exist` |
| `git` | ErrGit | `cannot diff commit 4d7f0a2c9e1b`; `the repository has grafts` |
| `range` | ErrRange | `range: revision 1 does not resolve to a commit`; `range: reaches a shallow boundary` |
| `empty-range` | ErrEmptyRange | `the range holds no commits` |
| `read` | ErrRead | `cannot read standard input`; `input over the size limit` |
| `output` | ErrOutput | `cannot write output` |
| `interrupted` | ErrInterrupted | `interrupted` |
| `internal` | ErrInternal | `internal error; output withheld` |

**An importer, using synthetic values:**

```go
terms, err := hush.LoadTermSets(cfg.TermFile) // a path from the importer's own trusted configuration
if err != nil {
	return err
}
s, err := hush.New(hush.Config{Destination: hush.Public(), Terms: terms})
if err != nil {
	return err // a misconfiguration fails at startup, not at the first post
}
if _, err := s.ScanBytes(ctx, "issue-body", body); err != nil {
	return err // findings or failure: do not post
}

// In an agent sandbox, where no term file exists:
agent, err := hush.New(hush.Config{Destination: hush.Public(), GenericOnly: true})
```

**The CLI over this package:**

```
hush scan --destination DEST [--terms FILE | --generic-only] [ALLOWANCE] [--format plain|json] TARGET
    DEST       public | private | client:LABEL
    ALLOWANCE  ADR-002's input for caller-supplied allowances, if it is not part of the term file
    TARGET     PATH... | --index [-C DIR] | --range REVS [-C DIR] [--allow-empty-range] | [--label NAME] (--stdin | -)
hush gh --destination DEST [--terms FILE | --generic-only] [ALLOWANCE] -- <gh arguments>    (HSH-9)
hush hooks install | uninstall …                                                         (HSH-9)
hush version
```

### 8. Departures from the runbook

The runbook (`reference/bootstrap-loop.md`) is a snapshot, and agents do not edit it. This ADR departs from it as follows:

| Runbook | This ADR |
| --- | --- |
| "Two tiers", Generic: "ID-prefix allowlist, IP addresses outside documentation ranges, email addresses, hostname patterns, secret formats" | v0.1's generic tier has the ID-prefix, IP-address and email rules only. **Hostname patterns and secret formats are v0.2.** Usernames and machine paths, which AGENTS.md also forbids, are in neither tier; they are caught only when listed as terms |
| "Two tiers", Private, "Tells the agent": "Nothing beyond 'restricted term at `file:line`, set `<name>`' on the staging PR" | In v0.1 the private tier runs only on the review machine, so nothing reaches an agent automatically; the human relays the runbook's wording. A second private-tier failure on the same unit blocks it for the human, and an agent is told nothing when the private tier cannot run (section 3) |
| "Where it runs": `pre-commit` and `commit-msg` hooks | Plus `pre-push` (HSH-9) and `dispatch.sh block`. These, the runbook's `gh` wrapper and the hooks all run `--destination public --generic-only` in agent contexts |
| "Where it runs": scanner account "once hush's scanner mode ships" | v0.2, with its own ADR |
| "Where it runs": staging CI, generic | Unchanged. Its check is named `hush/generic`, so it is never read as the publish gate |
| Publish: `hush scan --destination public .` | `--terms FILE` is added, because sets come only from explicit input. A range scan of the new commit follows, as the interim README already does, so the message, trailers and author are scanned. Both run from a release build of the real repo (section 2) |
| "Full-history scan before a repo goes public", both tiers | `--range --all` covers every ref under `refs/` except the stash and replace refs, including annotated tag objects' own text and notes. A ref whose target is not a commit, and a shallow boundary, each exit 2 |
| PR template: "hush scan clean (public destination)" | For agents this check can only be generic-only. The template under `.github/` is human-only; suggested wording: "hush generic tier clean (`--destination public --generic-only`)" |

### 9. Where this meets ADR-002

This ADR asks ADR-002 (HSH-3) for the following, without deciding the format:
- **Visibility.** A per-set declaration of the client labels that may see a set: explicit labels, no wildcard, deny by default.
- **Load-time checks.** Set names and client labels are opaque codes, checked at load against every term and generic rule. Set names stay printable and contain no `:`, because they are printed unredacted. The JSON schema's set-name pattern follows whatever grammar ADR-002 sets.
- **No other sources.** The term file names no other files, and hush reads it only from the path its caller passes.
- **Rule registry.** Stable, lowercase, hyphenated rule names, which are printed as `rule`. The matcher never exports text. Any position data stays inside package `hush`: it is used for redaction (section 6.4). v0.1 exposes none, and a later version may expose a column on generic findings only (section 6.1).
- **The ID-prefix allowlist.** Whether it stays built in or comes from the caller (section 1). It never comes from the scanned repository.
- **The email identity allowance.** It reaches hush only as explicit caller input (section 1), never from the repository, the environment or a default path. HSH-14 builds the rule; HSH-11 adds the `Config` field and the CLI input.

## Alternatives considered

Each decision lists the interim scanner's choice, at least one alternative that departs from it, and why it was not taken.

**Scope (section 1).**
- *Interim:* the loop's conventions are built into the scanner.
- *Departing alternative:* hush learns destinations itself, mapping a remote URL or repository to public, client or private. Rejected: that mapping is itself a private fact about clients and repositories, and a missing entry would need a default.
- *Departing alternative:* v0.1 also owns hostname and secret-format rules. Rejected for v0.1: they are in the interim's known limits, nothing in the pilot needs them, and the epic defers them with tripwires for pulling them forward.
- *Departing alternative:* hush also consolidates and signs. Rejected: publishing is a human step and later `nh sign`'s. hush is the scanner it calls.

**Shape (section 2).**
- *Interim:* one POSIX shell script with no library surface.
  - Rejected for v0.1: it has no API for importers and no structured output.
  - It re-parses the term file for every file and commit.
  - It is untested with macOS's awk.
- *Departing alternative:* a CLI-only Go binary that importers run as a subprocess and parse JSON from. Rejected: importers would depend on PATH and process plumbing, lose typed errors, and need the binary on every machine that imports hush.
- *Departing alternative:* several public packages (`hush/terms`, `hush/rules`, `hush/finding`). Rejected for v0.1: a larger surface to keep stable before anyone has used it. The rule interface stays internal until ADR-002's v0.2 rules prove it.
- *Departing alternative:* a pure-Go git library instead of the git binary. Rejected: it would add a dependency outside the standard library, against "standard library only".
- *Departing alternative:* a vanity module path on a nonhumanhq domain. Rejected: it needs a server of its own, while `github.com/nonhumanhq/hush` resolves through the default module proxy and is the same path in staging.
- *Departing alternative:* a `go` directive that names the newest Go release. Rejected: every importer would need the newest Go to build hush. The oldest supported release, with CI on both ends, keeps hush buildable on every release upstream still supports.

**Tiers and destinations (sections 3 and 4).**
- *Interim:* no destinations, and the private tier runs only when `--terms` is given. Rejected: forgetting `--terms` at publish gives exit 0 after a generic-only scan, the failure this ADR exists to stop.
- *Departing alternative:* an optional destination that defaults to public, with a per-call `--allow-set NAME` for client exemptions. Rejected:
  - the default can be weakened by a one-line change;
  - every caller's command line would carry the decision of which names may pass;
  - one word could exempt every client's set.
- *Departing alternative:* two commands, `hush check` (generic only) and `hush gate` (destinations). Rejected: two surfaces to keep consistent. A clean `check` still exits 0, and v0.2's per-destination generic rules would need a destination in `check` anyway.
- *Departing alternative:* an operator profile file that names term files, labels and exemptions. Rejected:
  - hush would read paths out of a file, widening the "explicit input only" rule;
  - the profile overlaps ADR-002's format;
  - a missing profile again needs a fallback.
- *Departing alternative:* a distinct exit code (3) for a clean generic-only scan. Rejected (HSH-1/D4): every hook, `dispatch.sh block` and CI step would need non-standard handling. The downgrade is already explicit on the command line and in the JSON `coverage`.
- *Departing alternative:* hashed term sets on agent machines, so agents could run the private tier. Rejected: the runbook's point stands. Short abbreviations can be brute-forced from their hashes in seconds.
- *Departing alternative:* a `private` destination that runs no tier and so always exits 2, because nothing would be checked; or one that runs only v0.2's secret-format rules, and exits 2 until they exist. Rejected: with the generic tier, a record mislabelled private is still checked. Revisit when v0.2's secret-format rules arrive.
- *Departing alternative:* tell an agent less than the runbook's wording about a private finding: the redacted location and the fixed word `restricted`, with no set name; or only that the unit failed the private tier, with no location. Rejected: the agent needs the location to fix the record, and the set name says what kind of name to remove. The stop rule (section 3), not a vaguer message, keeps an agent from bisecting a line to learn which word matched.

**Failing closed (section 5).**
- *Interim:* errors exit 2 and coverage gaps are findings, but several conditions pass silently (Context, force 1). Among them, `--range` passes any rev-list option through. Rejected: filters such as a maximum count, dates, authors or pathspecs narrow the scan silently.
- *Departing alternative:* treat `unreadable` and `binary-unscanned` as errors (exit 2). Rejected: as findings they still stop the gate, and the report also shows everything else. An error would hide the rest of the scan.
- *Departing alternative:* fail every empty input. Rejected: empty issue bodies and pushes with no new commits are ordinary. Only an empty range is an error by default, because a publish range that resolves to nothing is a mistake.
- *Departing alternative:* refuse annotated tags in ranges, leaving their text to a manual check. Rejected: the full-history scan before a repo goes public would then fail on every tagged repo, or silently skip tag text. Scanning tag objects like commit objects costs little.
- *Departing alternative:* warn about a term file that group or others can read or write, and continue. The interim does not check the mode at all. Rejected: a warning that still passes is a way to fail open, and other local accounts must not read the sets.

**Output (section 6).**
- *Interim:* plain output only, and errors may echo an option or git's own message.
- *Departing alternative:* JSON Lines. Rejected: output cut short by a dying run still parses, so a consumer that ignores the exit status would pass.
- *Departing alternative:* SARIF 2.1.0. Rejected for v0.1: it is heavy, and its snippet, context and fingerprint fields invite exactly the leaks this ADR forbids. A generic-tier exporter can come later.
- *Departing alternative:* columns and snippets for convenience.
  - Snippets are rejected outright: they are matched text.
  - Columns on private findings are rejected, because a column into text the reader already holds points at the term.
  - Columns on generic findings are left out of v0.1. They can be added later without breaking readers, who ignore unknown fields (section 6.3).
- *Departing alternative:* stable fingerprints for suppressions.
  - Rejected for v0.1. If suppressions come later, their fingerprints cover the generic tier only and are built from content-free fields (rule, path, line).
  - Hashes that include matched text are rejected outright: short terms and IPv4 addresses can be brute-forced from their hashes.
- *Departing alternative:* version the JSON document by the hush version alone. Rejected: a reader could not tell a release that adds a field from one that breaks the format.
- *Departing alternative:* a schema major plus a version the caller requests (`--format json/1`). Not in v0.1. It can be added if importers ask to pin a format.
- *Departing alternative:* separate exit codes for "scan incomplete" (3) and for each error class. Rejected: callers already treat any non-zero code as a stop, and the JSON `error.code` carries the class for programs that need it.

**Go API (section 7).**
- *Interim:* none.
- *Departing alternative:* scans return `(*Report, error)` with a nil error when findings exist, so callers must check `Report.Clean()`. Rejected: an importer that forgets the check posts text with findings. Here, findings are an error.
- *Departing alternative:* a zero `Destination` that means public. Rejected: required inputs read better at every call site, and the zero value of every hush type refuses to scan.
- *Departing alternative:* `Finding` with unexported fields and accessor methods only. Rejected for v0.1: the fields hold only values hush produced and redacted, and plain fields are easier for importers. The leak guarantee rests on how findings are built, not on hiding their fields.

## Consequences

- **Every call site of the interim scanner changes when it moves to `hush`.** This is deliberate: hush fails closed until a call site names its destination and coverage.

  | Interim | hush |
  | --- | --- |
  | `hush-interim .` | `hush scan --destination public --generic-only .` |
  | `hush-interim --terms F .` | `hush scan --destination public --terms F .` |
  | `hush-interim --range R` | `hush scan --destination public --generic-only --range R` (hooks add `--allow-empty-range`) |
  | `hush-interim --label L --stdin`, or `--label L -` | `hush scan --destination public --generic-only --stdin --label L` |

- **The comparison test.**
  - **Standard output.** HSH-11's comparison test maps the interim's arguments as in the table above. Its standard output and exit codes then match on all 42 interim cases, except where section 5 departs.
  - **Standard error.** This differs in every exit-2 case, in both the `hush:` prefix and section 7's message table. The comparison test checks it against that table instead: empty on exit 0 and 1, and exactly one `hush:` line on exit 2. HSH-11's PR lists this as an intended difference.
- **HSH-11's "Done when" command becomes `go run ./cmd/hush scan --destination public --generic-only .`.** The human updates the issue when this ADR merges.
- **Order of work.** HSH-9 and HSH-14 build on HSH-5's internal packages and the interim's arguments, because they can run before HSH-11. HSH-11 then:
  - moves `internal/hooks` and `internal/ghwrap` onto package `hush` and the new flags;
  - adds the `Config` field and the CLI input for ADR-002's allowances;
  - updates the hook command lines.

  The migration guide covers reinstalling the hooks.
- **The hooks** pass `--destination public --generic-only` by default. Hooks installed on the review machine with HSH-9's term-file flag pass `--destination public --terms FILE` instead. The `pre-push` hook also passes `--allow-empty-range`, and it scans any annotated tag it pushes.
- **`hush gh`** follows the contract in section 2. Its one launch of `gh` is the architecture tests' only allowed child process other than git, and the only place the inherited environment is passed on.
- **`dispatch.sh block` keeps calling `hush-interim`** until the migration guide moves it to `hush scan --destination public --generic-only --stdin --label question`.
- **The term-set format grows** a per-set visibility declaration and load-time checks of names and labels (section 9). ADR-002 picks the syntax and writes the migration note.
- **Client destinations need per-client sets named by code.** A set named by kind (`clients`) applies to every client. A client's own names go in a set such as `clients-k7` that declares `k7`.
- **Range scans need full, graft-free history.**
  - A range that reaches a shallow boundary exits 2, and so does any range in a repository with `info/grafts`. A tree scan covers a shallow checkout's content.
  - The full-history scan before a repo goes public scans every ref except the stash and replace refs, including tag objects and notes, and needs no manual tag check.
  - A ref that points to a tree or a blob makes it exit 2 until the human removes the ref or checks the object by hand.
- **A generic-only exit 0 is never a publish pass.** The publish procedure always passes `--terms`. Agent checks are labelled `hush/generic`, and the JSON `coverage` field says what ran.
- **Term files are private to their owner.** A term file that group or others can read or write exits 2, where the interim accepts it, until the human runs `chmod 600` on it.
- **Importers must load term sets and name a destination explicitly.** A misconfiguration fails at `hush.New`, at startup, rather than at the first scan.
- **The leak guarantee adds work in HSH-11.**
  - The architecture tests and the formatting guards.
  - The hand-written argument parser and signal handling.
  - Explicit size limits.
  - The header rules for commit and tag objects.
  - Leak checks over every output form.
- **Private-tier scans need a release build.** The human builds hush from the signed real repo before using it with term sets. Until v0.1 is tagged, the interim scanner stays the private-tier tool.

## Negative tests

All data is synthetic: invented words as terms, and rejected ID tokens assembled at run time. Every test runs through HSH-5's leak-check helper, so it also fails if any term or rejected token appears in standard output, standard error, a returned error or a formatted value.

The term file for tests 2, 7, 8 and 20 has two sets. `clients` holds `quorvel` and declares `k7`. `people` holds `zantoph` and declares `k8`.

1. **Private tier requested without a term file fails.**
   - `hush scan --destination public .`, with neither `--terms` nor `--generic-only`, exits 2. Standard output is empty, and standard error holds the fixed `coverage` message.
   - `--format json` gives `result: "error"`, `error.code: "coverage"`.
   - `hush.New(Config{Destination: Public()})` returns `ErrCoverage`.
   - The same holds for `client:k7`.
2. **A public destination with any private-set match fails.**
   - A tree file holds `QuorVel` on line 1, and a commit message holds it on line 6.
   - For `public`, the tree scan exits 1 with `docs/a.md:1: set:clients`, and the range scan exits 1 with `<sha12>:(commit):6: set:clients`. This holds even though `clients` declares `k7`.
   - For `client:k8`, the tree scan also exits 1 with `docs/a.md:1: set:clients`.
   - For `client:k7`, it exits 0, because `clients` is visible to k7 and `people` has no match.
3. **Term sets in the environment are ignored.**
   - `HUSH_TERMS`, and every other variable whose name starts with `HUSH`, are set to a valid term file whose term appears in the scanned tree.
   - `--destination public --generic-only` exits 0 with no `set:` finding.
   - `--destination public` without `--terms` exits 2.
   - An architecture test finds no environment read or pass-through outside two places: `cmd/hush`'s git-hook handling, and `internal/ghwrap` handing the inherited environment to `gh`.
4. **Term sets at a default path are ignored.** `HOME` and `XDG_CONFIG_HOME` point at a temporary directory, which holds valid term files at plausible default places such as `.config/hush/terms`, `.hush/terms` and `hush.terms`. The scans in test 3 behave the same.
5. **Term sets in the scanned repo are ignored.**
   - A valid term file committed at the repository root and under `.hush/` is never loaded: the scans in test 3 behave the same.
   - Naming it with `--terms` exits 2 (`term-file`) for a tree scan of the repository, and for an index or range scan of it.
   - A hard link to the term file inside a scanned tree exits 2.
   - A committed copy with the same blob id, met in a range, exits 2.
6. **Matched text is absent from every output form.**
   - Each target is covered (tree, index, stdin, range), in each format (plain, JSON). There are matches in content, paths, commit messages, author lines and an annotated tag's message.
   - Nothing printed or returned holds a term, a rejected token or the synthetic identity allowance (for example `alice@example.org`): not standard output, not standard error, not `err.Error()`, and not `%v`, `%+v` or `%#v` of any returned `Report`, `Finding`, `Error`, `*FindingsError`, `TermSets`, `Scanner` or `Config`.
   - The same holds for these failure cases:
     - a term-file syntax error on a line that holds a term;
     - an unknown option whose text is a term;
     - a refused stdin label that holds a term;
     - a git failure in a repository whose ref names hold a term;
     - a panic injected in a test build;
     - `WriteErrorJSON` given a foreign error whose text is a term.
7. **A path component holding a term is redacted.**
   - **Basic case.** `docs/quorvel/plan.md`, with a rejected ID token on line 2, gives `docs/<redacted>:0: set:clients in path` and `docs/<redacted>:2: id-prefix`. In JSON its `path_redacted` is true.
   - **First component.** When the first component holds the term, the path prints as `<redacted>`.
   - **A term that spans `/`.**
     - With `quor/vel` added to `clients`, the path `docs/quor/vel/plan.md` gives `docs/<redacted>:0: set:clients in path`.
     - It gives the same result when `vel` is added to `clients` too.
   - **In a range.** The basic case gives `<sha12>:docs/<redacted>:0: set:clients in path`.
   - **Exempt sets still redact.** In a `client:k7` scan, the basic case gives only `docs/<redacted>:2: id-prefix` and no `set:clients` finding. Redaction uses every loaded set.
8. **Client labels.**
   - A client label that no set declares exits 2.
   - A label that contains a term exits 2, and the label is not echoed.
   - With a separate term file in which both `clients` and `people` declare `k7`, `client:k7` leaves no term to apply and exits 2 with code `coverage`.
   - In a `client:k7` scan, `k7` is a forbidden string in every output form: plain, JSON, standard error, and `%v`, `%+v` and `%#v` of `Config`, `Destination` and `Report`.
9. **Coverage combinations.**
   - `--generic-only` with `--terms`, with `client:k7` or with `private`, and `--terms` with `private`, each exit 2.
   - A `private` scan of a file that holds a rejected ID token exits 1 with an `id-prefix` finding, because the generic tier runs.
10. **Unknown destination.** `--destination publc` exits 2, and the message does not echo the value. With `--format json`, standard output is empty.
11. **Ranges.**
    - **Empty.** A range that resolves to no commits exits 2, and exits 0 with `--allow-empty-range`.
    - **Rev-list options.** A range text that holds a rev-list option (a maximum count, a date filter, a pathspec after `--`) exits 2.
    - **Annotated tags.** `--range --all` in a repository with an annotated tag scans the tag's message and tagger and walks its commit. A term in the tag message gives `<sha12>:(tag):N: set:clients`.
    - **Commits reachable only from a tag.** A commit reachable only from that tag is scanned.
    - **Other refs.** A commit holding a term that is reachable only from `refs/original/refs/heads/main` gives a finding.
    - **Stash.** The stash is not scanned.
    - **Notes.** A note holding a term gives a finding.
    - **Tags on blobs.** An annotated tag on a blob that holds a term makes `--range --all` exit 2, never 0.
    - **Shallow clones.** `--range --all` in a depth-1 clone exits 2.
    - **Grafts.** A repository with `info/grafts` exits 2.
    - **Typechanges.** A commit turns a file into a symlink and also changes a second file whose added line holds a term. The term is reported at the second file's own path and line.
12. **git cannot run code or reach the network.**
    - **Programs.** The scanned repository configures a textconv driver, an external diff and an fsmonitor hook. Each would create a marker file when run. A range scan and an index scan complete, and no marker file exists.
    - **Attributes.** A committed `.gitattributes` with `* -diff`, together with `core.bigFileThreshold=1`, does not hide an added line that holds a term.
    - **Network.** A partial clone with a missing blob exits 2 without any network access.
13. **git's standard error never reaches output.** A missing object exits 2. Standard error holds only `hush: cannot read commit <sha12>` or `hush: cannot diff commit <sha12>`.
14. **Arguments.**
    - `scan --terms F --help .` exits 2.
    - `--range A --range B` exits 2.
    - `--allow-empty-range` with a tree target exits 2.
15. **Special files and names.**
    - A FIFO inside a walked tree gives `unreadable`, exit 1.
    - A directory that cannot be read gives `unreadable` on it, and the rest of the tree is still scanned.
    - A file name with a newline or a bidi control prints as `<redacted>` with `unreadable in path`, and its content is still scanned, in both a tree scan and a range scan.
16. **Write failures.** A scan that would be clean exits 2 with the `output` message when standard output is `/dev/full`, and again when standard output is a pipe whose reader has already exited.
17. **Mergetag and signature blocks.** Fixtures are built offline, with an SSH signing key made by `ssh-keygen` or with objects written by `git hash-object`.
    - A merge commit whose embedded tag message holds a term gives a `set:` finding with part `header`.
    - A tag signed with that key, scanned with `--range --all`, gives no finding from its signature's base64 body.
    - An unsigned tag whose message ends in a fake signature block holding free text with a term gives a `(tag)` finding.
    - A hand-built commit whose `gpgsig` header holds a `Comment:` line with a term gives a `header` finding.
18. **Index scans.** `--index` with `GIT_INDEX_FILE` naming a missing file exits 2.
19. **The API's zero values and nil receivers.**
    - `New(Config{})` fails.
    - `New` with `Terms: new(TermSets)` fails.
    - `(*Report)(nil).Clean()` is false.
    - A scan on a nil `*Scanner` returns an error and no report.
    - `ExitCode(err)` is 0 only for a nil error.
20. **Term-file permissions.**
    - With the term file at mode 0640, `hush scan --destination public --terms FILE .` exits 2 with code `term-file` and the fixed message. So does each of modes 0604, 0620 and 0602.
    - `LoadTermSets` returns `ErrTermFile` for each of those modes.
    - Neither standard error nor the JSON document names the file's path.
    - At mode 0600 the same file loads, and so does a symlink to it, whatever the link's own mode.

## Decided at acceptance

The human accepted this ADR on 2026-10-24 and took the recommended option for each of the eight items that were open before acceptance. Each answer now stands in the decision text, and the options not taken are under "Alternatives considered".

| # | Item | Answer | Decided | Now in |
| --- | --- | --- | --- | --- |
| 1 | The module path | `github.com/nonhumanhq/hush` | 2026-10-24 | Sections 2 and 7 |
| 2 | The minimum Go version (the `go` directive) | The oldest Go release still supported upstream when HSH-11 lands. No `toolchain` line, and CI runs both the minimum and the newest release | 2026-10-24 | Section 2 |
| 3 | Column numbers in findings | None in v0.1. Columns on generic findings may be added later; never on private findings | 2026-10-24 | Sections 6.1, 6.4 and 9 |
| 4 | Stable fingerprints for suppressions | None in v0.1. If they come later: generic tier only, built from content-free fields (rule, path, line), and never a hash of matched text | 2026-10-24 | Section 6.1 |
| 5 | How the JSON schema is versioned | A `schema` identifier with a major number (`hush.scan/1`). Fields are only added within a major; readers ignore unknown fields and reject an unknown major | 2026-10-24 | Section 6.3 |
| 6 | Whether the `private` destination runs the generic tier | Yes | 2026-10-24 | Section 4; test 9 |
| 7 | What an agent sees when the private tier fails | The redacted location and the set name, relayed by the human. A second private-tier failure on the same unit blocks the unit for the human, and the agent does not retry. When the private tier cannot run at all (a term-file error), the agent is told nothing | 2026-10-24 | Sections 3 and 8 |
| 8 | Whether hush refuses a term file that is readable or writable by group or others | Yes: exit 2 | 2026-10-24 | Sections 5 and 7; Consequences; test 20 |

**Amended on 2026-10-25,** with ADR-002's acceptance (PR #10, ADR-002's decided item 7). The amendment records the two places where ADR-002 extends this ADR's text, and changes none of the decisions above:
- **Section 6.3's schema** takes ADR-002's set-name grammar, 1 to 64 characters from `[A-Za-z0-9_.-]`, in `sets` and in the `set:` branch of a finding's `rule`. It had the interim's grammar, pending ADR-002.
- **Section 5's output check** also accepts the two unscanned names of section 6.1, `binary-unscanned` and `unreadable`, which ADR-002 keeps out of its rule registry.

## Open questions for the human

None remain.
