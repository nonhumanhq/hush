# hush

hush keeps private names out of public records. It scans files, standard input and git
ranges (lines, paths, authors and messages) for two kinds of match:

- the **generic tier**, always on: tracker-style IDs outside an allowlist;
- the **private tier**, only with `--terms FILE`: term sets the caller supplies.

Findings name the place and the rule, never the matched text.

**hush is pre-release.** It is a Go port of the interim scanner in `reference/interim-hush/`,
with the same arguments, output and exit codes:

```sh
go run ./cmd/hush scan .                          # the working tree
go run ./cmd/hush scan --range origin/main..HEAD  # new commits
go run ./cmd/hush scan --label issue-body --stdin < body.md
```

Exit status: 0 clean, 1 findings, 2 usage or configuration error. The public Go package,
destinations and machine-readable output arrive with v0.1 (ADR-001, ADR-002).
