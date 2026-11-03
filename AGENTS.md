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

hush keeps private names out of public records. Until ADR-001 and ADR-002 are accepted it
is a port of `reference/interim-hush/` at parity, and everything is internal.

## Build and test
- Go, standard library only: `go.mod` has no `require` lines, and a test fails if one appears.
- `go vet ./...` and `go test ./...`. The comparison test in `cmd/hush` builds hush, runs
  it and `sh reference/interim-hush/hush-interim` over the same synthetic fixtures, and
  needs `git`, `sh`, `awk` and `find`. Without network access, set
  `GOTOOLCHAIN=local GOPROXY=off`.
- `go run ./cmd/hush scan .` scans the tree with the generic tier.

## Packages
| Package | Holds |
| --- | --- |
| `cmd/hush` | `hush scan` (the interim scanner's arguments), `hush hooks`, `hush gh`, `hush --help`, `hush version` |
| `internal/target` | Tree, standard input, git range and git index targets; the only package that runs git or opens scanned files |
| `internal/rule` | The `Rule` interface, the `id-prefix`, `ip-address` and `email-address` rules and their registry, and the checks and path redaction a rule list gives |
| `internal/termset` | The term-file parser and matcher; takes bytes, never a path |
| `internal/output` | The plain finding line and the error line |
| `internal/hooks` | The git hooks `hush hooks` writes and removes, and the `GIT_INDEX_FILE` check; CLI only |
| `internal/ghwrap` | What `hush gh` covers, reading a `gh` command line, and the one launch of `gh`; CLI only |
| `internal/leakcheck` | Synthetic terms and tokens, and the leak check every test uses |

## Tests
- Every test passes what it prints and every error it gets through `leakcheck.Check`.
- Synthetic strings come from `internal/leakcheck`, assembled at run time, so sources scan clean.
- A change to scanning behaviour keeps `TestParity` passing, or lists the intended difference
  in the PR.
