# hush

hush keeps private names out of public records. It scans files, standard input and git
ranges (lines, paths, authors and messages) for two kinds of match:

- the **generic tier**, always on: tracker-style IDs outside an allowlist, IP addresses other than
  documentation, loopback and unspecified addresses, and email addresses outside the reserved
  domains (ADR-002, sections 4.2 and 4.3);
- the **private tier**, with `--terms FILE`: term sets the caller supplies.

Findings name the place and the rule, never the matched text.

**hush is pre-release** (ADR-001 and ADR-002, toward v0.1). Every scan names its destination,
and a public or client scan needs a term file unless it says `--generic-only`:

```sh
go run ./cmd/hush scan --destination public --generic-only .                          # the working tree
go run ./cmd/hush scan --destination public --generic-only --range origin/main..HEAD  # new commits
go run ./cmd/hush scan --destination public --generic-only --label issue-body --stdin < body.md
go run ./cmd/hush scan --destination public --generic-only --format json --index  # the git index
```

With term sets, hush runs only from a release build of the reviewed repository, never with
`go run` in a staging clone (ADR-001 section 2): `hush scan --destination public --terms FILE .`.

`--identities ADDR[,ADDR...]` lets those addresses pass where they stand as a commit's author,
committer or tagger, or in a trailer. `--format json` writes one JSON document (`hush.scan/1`).
`hush scan --help` lists every option.

Two more commands bring the generic tier to agents:

```sh
hush hooks install [--terms FILE] [--identities ADDR]  # pre-commit, commit-msg and pre-push hooks
hush gh -- pr create -t TITLE -F body.md              # scan what gh would post, then run gh
```

The hooks' git conditions arrive in HSH-11's part d; do not install them on a clone before v0.1.

Exit status: 0 clean, 1 findings, 2 an error, with one line on standard error.

The public Go package, `github.com/nonhumanhq/hush` at the module root, is the API of ADR-001
section 7: destinations, the term-file checks, path redaction, typed errors and the JSON writers.
`go doc github.com/nonhumanhq/hush` describes it, with runnable examples. `hush scan` is a thin
layer over it.
