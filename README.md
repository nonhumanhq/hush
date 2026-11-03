# hush

hush keeps private names out of public records. It scans files, standard input and git
ranges (lines, paths, authors and messages) for two kinds of match:

- the **generic tier**, always on: tracker-style IDs outside an allowlist, IP addresses other than
  documentation, loopback and unspecified addresses, and email addresses outside the reserved
  domains (ADR-002, sections 4.2 and 4.3);
- the **private tier**, only with `--terms FILE`: term sets the caller supplies.

Findings name the place and the rule, never the matched text.

**hush is pre-release.** It is a Go port of the interim scanner in `reference/interim-hush/`,
with the same arguments, output and exit codes, plus the `ip-address` and `email-address` rules
(the interim has neither, and `hush scan --help` still lists only its rules). No scan applies an
identity allowance yet, so a commit identity outside the reserved domains is flagged:

```sh
go run ./cmd/hush scan .                          # the working tree
go run ./cmd/hush scan --range origin/main..HEAD  # new commits
go run ./cmd/hush scan --label issue-body --stdin < body.md
```

Exit status: 0 clean, 1 findings, 2 usage or configuration error. The public Go package,
destinations and machine-readable output arrive with v0.1 (ADR-001, ADR-002).
