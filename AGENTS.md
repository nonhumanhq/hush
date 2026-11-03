# Rules for agents (shared across nonhumanhq/hush, chassis, fleet, swe)

## Scope
- You work in this repository only. Do not clone, read or reference any other repository
  except the pinned dependencies declared in this repo and the `reference/` folder.
- If a task needs information that is not in the issue, this repo or `reference/`, stop:
  post your question with `dispatch.sh block <repo> <number>`, which labels the issue
  `agent:blocked`, and end the run. Never guess about real systems, people, hosts or
  organizations.

## The public record
Everything in this repository may become public. Therefore:
- Never write the name, abbreviation, ticket key or domain of any employer or client, or of
  any other organization you work for or with, except nonhumanhq. Public products, projects,
  vendors and standards may be named where the work needs them.
- Never write real hostnames, IP addresses, usernames, people's names or paths from a
  real machine.
- In examples use `acme`, `example.com`, `example.org`, `192.0.2.0/24`, `2001:db8::/32`,
  `alice`, `bob`.
- The only ID prefixes you may write are `HSH-`, `CHS-`, `FLT-` and `SWE-`, plus `ADR-` for
  ADR numbers (write `chassis ADR-002` for another repo's). When quoting the reference pack
  you may also write `FLEET-` and `VMWS-`. Any other token of that shape (capital letters, a
  hyphen, digits) is a mistake; remove it.
- Test data is synthetic. Never copy data from `reference/` into fixtures.

## Safety
- Never run anything against real machines, real overlays, password managers, SSH agents,
  tailnets or cloud accounts. Tests use fakes.
- Network use is limited to package registries and the model API.
- Do not add dependencies outside the language's standard library without listing them in
  your PLAN.md with a reason.

## Naming
- New names are only for new repositories, binaries or wire identifiers. Inside a module,
  name things for what they are (`plugintest`, `browser`, `lock`), never with a new coined term.

## How to work an issue
1. Read the issue, its linked ADRs and its dependencies. Create `.work/<ID>/PLAN.md`
   (template in `.github/plan_template.md`) and commit it first.
2. Work on branch `<ID>-<short-slug>`. Commit subjects are `<ID>: <summary>`.
3. Keep `.work/<ID>/PROGRESS.md` current by task number (T1, T2…): done, next, blockers.
   Add each new decision to PLAN.md as the next D#. Elsewhere, write them as `<ID>/T3` and
   `<ID>/D2`; they never become issues.
4. Tests must pass. Do not mark anything done that is stubbed; say so in PROGRESS.md.
   When you write that something was checked, commit the program that checks it under
   `.work/<ID>/checks/` with the command that runs it, or call the claim unchecked.
5. Before opening the PR, do a self-review into `.work/<ID>/REVIEW.md`: bugs,
   readability, maintainability, anything outside the issue's scope.
6. Open a draft PR with the PR template, then run `dispatch.sh review <repo> <number>`,
   which labels the issue `agent:review`. Stop.

## Design work
- ADRs live in `docs/adr/NNN-title.md` with front matter: `kind: decision`, `status:
  proposed`, `verified: <date>`, `supersedes: []`.
- Each ADR states context, decision, alternatives considered, consequences, negative tests
  and open questions for the human. Keep decisions the human must make in an
  "Open before acceptance" table; never decide them yourself.

# hush: repo-specific

hush keeps private names out of public records. v0.1 implements the accepted ADR-001 and
ADR-002 (HSH-11); `docs/release-notes/v0.1.md` lists its known limits and `docs/migration.md`
the move from `reference/interim-hush/`.

## Build and test
- Go, standard library only: `go.mod` has no `require` lines, and a test fails if one appears.
- `go vet ./...` and `go test ./...`. The comparison test in `cmd/hush` builds hush, runs
  it and `sh reference/interim-hush/hush-interim` over the same synthetic fixtures, and
  needs `git`, `sh`, `awk` and `find`. It skips where `reference/` is absent, as in the
  public repository. Without network access, set
  `GOTOOLCHAIN=local GOPROXY=off`.
- `go run ./cmd/hush scan --destination public --generic-only .` scans the tree with the generic tier.

## Packages
| Package | Holds |
| --- | --- |
| `hush` (module root) | The public package of ADR-001 section 7: destinations, `LoadTermSets`, `Config` and `New`, the scan entry points, findings with path redaction, the report, the JSON writers and the closed error table |
| `cmd/hush` | `hush scan` (ADR-001 section 7's grammar, over package `hush`), `hush hooks`, `hush gh` (the same options, over package `hush`), `hush --help`, `hush version`; signals and the one result written per run. Imports no internal package but `internal/hooks` and `internal/ghwrap` |
| `internal/target` | Tree, standard input, git range and git index targets; the only package that runs git for a scan or opens scanned files. Reports raw findings to package `hush` through a sink; its older printing path serves only its own tests |
| `internal/rule` | The `Rule` interface, the `id-prefix`, `ip-address` and `email-address` rules and their registry, and the checks and path redaction a rule list gives |
| `internal/termset` | The term-file parser and matcher; takes bytes, never a path |
| `internal/output` | The plain finding line, shared with package `hush` |
| `internal/hooks` | The git hooks `hush hooks` writes and removes, and the installer's own git, with the caller's configuration; CLI only, imports only `hush` |
| `internal/ghwrap` | What `hush gh` covers, reading a `gh` command line, the scan of each text through package `hush`, and the one launch of `gh`; CLI only, imports only `hush` |
| `internal/leakcheck` | Synthetic terms and tokens, and the leak check every test uses |
| `internal/schema` | The closed check of ADR-001 section 6.3's JSON document; tests only |

## Tests
- Every test passes what it prints and every error it gets through `leakcheck.Check`.
- Package `hush`'s tests run under a `TestMain` that turns off git's user and system
  configuration and points `HOME` at a temporary directory; `go doc` shows its runnable examples.
- Synthetic strings come from `internal/leakcheck`, assembled at run time, so sources scan clean.
- A change to scanning behaviour keeps `TestParity` passing, or lists the intended difference
  in the PR. `TestParity` maps the interim's arguments as ADR-001's Consequences table says and
  compares exit status and standard output; standard error is checked against the message table.
- A JSON document a test prints passes `schema.CheckLine`.
- `TestArchitecture` (`arch_test.go`) holds ADR-001 sections 2 and 6.6: imports, environment
  reads, child processes, output, panic recovery, foreign errors and the formatting guards, each
  with a planted violation. A file behind the `hushpanic` build tag injects a panic for
  `TestNegative6InjectedPanic`; no other build holds it.
- The release notes and the migration guide have tests (`docs_test.go`); a limit the notes
  list is pinned there.
