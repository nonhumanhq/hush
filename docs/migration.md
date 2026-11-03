# Moving from the interim scanner to hush v0.1

This guide takes the human from `reference/interim-hush/hush-interim` to hush v0.1, in order. The checklist at the end repeats every step. The release notes, `docs/release-notes/v0.1.md`, list what changed and v0.1's known limits.

Two rules hold throughout:
- **A scan that loads term sets runs a release build** of hush, built from the signed real repository with `-trimpath`, never a staging build or `go run` in a staging clone (ADR-001 section 2, "Trust"). Until v0.1 is tagged and built, the interim scanner stays the private-tier tool.
- **A generic-only exit 0 is never a publish pass.** The publish scans always pass `--terms`.

## 1. Command mapping

Every call site names its destination and its coverage, or hush exits 2 (ADR-001, Consequences).

| Where | Interim | hush |
| --- | --- | --- |
| Tree, generic | `hush-interim .` | `hush scan --destination public --generic-only .` |
| Tree, both tiers | `hush-interim --terms F .` | `hush scan --destination public --terms F .` |
| Range | `hush-interim --range R` | `hush scan --destination public --generic-only --range R` (hooks add `--allow-empty-range`) |
| Standard input | `hush-interim --label L --stdin`, or `--label L -` | `hush scan --destination public --generic-only --stdin --label L` |
| Publish, the tree | `hush-interim --terms F .` | `hush scan --destination public --terms F --identities ADDRS .` |
| Publish, the new commit | `hush-interim --terms F --range origin/main..HEAD` | `hush scan --destination public --terms F --identities ADDRS --range origin/main..HEAD` |
| Scanner account, a mirror's new commits | `hush-interim --terms F -C M.git --range "OLD..NEW"` | `hush scan --destination public --terms F --identities ADDRS -C M.git --range "OLD..NEW"`, until scanner mode (v0.2) |
| Agent hooks | the interim `commit-msg` and `pre-push` hooks of `reference/interim-hush/README.md` | `hush hooks install --identities ADDR` (section 4) |
| The `gh` wrapper | each body piped through `hush-interim --label issue-body --stdin` | `hush gh --destination public --generic-only -- GH-ARGUMENTS` |
| `dispatch.sh block` | `hush-interim` | `hush scan --destination public --generic-only --stdin --label question` |

Notes:
- **A range takes no `rev-list` options.** It takes revisions, `A..B`, `^REV`, `--not` and the selectors `--all`, `--branches`, `--tags` and `--remotes`.
- **`--range` needs full, graft-free history.** A shallow boundary, `info/grafts` and a ref whose target is not a commit each exit 2.
- **`--index` replaces the interim's tree scan in `pre-commit`,** and reads `GIT_INDEX_FILE` when git sets it.
- **Standard error** is one `hush: ` line on exit 2. Scripts that matched the interim's wording match the exit status instead.

## 2. Check the term file

hush reads ADR-002's term-file format 1. An interim file loads unchanged unless one of these applies; in each case hush exits 2 and names the line (ADR-002 section 1.7):

| Interim | Format 1 | What the human does |
| --- | --- | --- |
| A repeated `[name]` continues the set | `set declared twice` | Merge the sections |
| A set may hold no terms | `set has no terms` | Delete the header, or add terms |
| A set name may be any length | 1 to 64 characters | Shorten it |
| A term may hold any bytes, and a `#` after a term is part of it | `bad term` for a term that holds a Unicode space other than space and tab, a format character other than those section 1.1 allows (such as U+200B, U+FEFF, a soft hyphen or a bidi mark), or a space or tab followed by `#` | Fix the term; move a trailing comment to a line of its own. A term that holds such a character on purpose, as a variant, cannot be kept: that variant stays a miss until v0.2 (section 2.4) |
| A term or a comment may hold control characters, so a comment may hold a lone CR with text after it, and any line may hold bytes that are not valid UTF8 | `bad character` for a control character (tab excepted), U+2028, U+2029, or bytes that are not valid UTF8, on any line, comments included | Remove the character, and put any text after it on a line of its own; save the file as UTF8 |
| A line that starts with `[` or ends with `]`, but not both, is a term | `bad header` | Fix the header. A term that starts with `[` or ends with `]` drops that bracket, which matches at least as much |
| Set names are not checked | `set name refused` when section 1.4 refuses a name | Rename the set |
| Line 1 may be any comment | A line 1 that starts with `#hush-terms` must be `#hush-terms 1` (`unsupported format`) | Reword the comment |

ADR-001 adds two more changes:
- **Permissions.** A term file that group or others can read or write exits 2. Run `chmod 600` on it, and keep it in a directory of mode 0700 that you own, outside every repository, clone and worktree, and outside any synced or shared folder.
- **Client destinations.** A set named by kind, such as `clients`, applies to every client. For `--destination client:LABEL`, move each client's own names into a set named by the client's code that declares it, such as `[clients-k7 visible-to=k7]`.

There is no converter. To check the file, run any scan with it, such as `hush scan --destination public --terms F --stdin < /dev/null` from a release build; exit 0 means it loads. A refusal names only the line and the reason, never the line's text.

## 3. Set up the identities

The email rule flags every address outside the reserved domains, commit identities included, unless the caller lists them with `--identities ADDR[,ADDR...]`. A listed address passes only where it stands as an identity: an author, committer or tagger line, or a trailer such as `Signed-off-by:`. The addresses are not secret, and they come only from the command line, never from the repository (ADR-002 section 3.1):

| Machine | It lists | Passed with `--identities` by |
| --- | --- | --- |
| The review machine | Your commit address, plus any platform address the full-history scan meets, plus each agent address when the scanned refs include agent commits (a clone holding the staging refs) | The publish scans, the full-history scan and the review machine's hooks |
| Each agent machine | The agent identity's commit address, and nothing else | The hooks `hush hooks install --identities` writes |
| Staging CI, if it scans ranges | The agent identity's commit address | The workflow, which takes it from the repository variable `HUSH_IDENTITIES` (`.work/HSH-11/workflows/`) |

The public repository's squashed history carries only your address, so its scans need only yours; a scan of refs that hold agent commits, such as the staging refs, flags every agent commit's author, committer and trailer lines unless each agent address is in `--identities` too.

Changing an address means changing the commands that pass it and reinstalling the hooks.

## 4. Replace the hooks

Until this step, **install no hook from `hush hooks install`** on any clone: a hook installed without `--identities` refuses every push whose commits carry an identity outside the reserved domains, which is every agent commit. So none is installed before v0.1.

On each clone:
1. Remove the interim hooks from the hooks directory (`git rev-parse --git-path hooks`), or let `hush hooks install --force` replace them. A hook hush did not write is replaced only with `--force`.
2. Install the hooks with `--identities` in every one, running `hush hooks install` from the release binary of section 6 kept at a stable path: a hook runs the binary by the absolute path it was installed from, so if the binary moves, every commit is blocked (`exec: ... not found`, which fails closed) until you reinstall the hooks from its new path:
   - **an agent machine:** `hush hooks install --identities AGENT-ADDR`, which scans with `--generic-only`;
   - **the review machine:** `hush hooks install --terms F --identities ADDRS`, which scans with the term file. The hooks hold the term file's path and the addresses, shell-quoted, never the terms.
3. Check with a commit: `pre-commit` runs `hush scan --index`, `commit-msg` scans the message on standard input labelled `commit-message`, and `pre-push` scans each pushed ref's name and its new commits, and refuses a pushed ref that does not point to a commit.

**With an editor,** `commit-msg` also scans git's comment lines, which name the branch and the staged paths (`git commit -v` adds the diff), so a token in a branch name blocks the commit (HSH-9's REVIEW.md, finding 3). Commit with `-m` or `-F`, as agents do, or rename the branch.

Hooks are per repository: install hush in each submodule you push with `--recurse-submodules`.

## 5. Pass `--identities` in both publish scans

The publish step becomes, in a clean clone of the reviewed branch:

```sh
hush scan --destination public --terms F --identities ADDRS .                          # the consolidated tree
git commit -S ...                                                                      # as before
hush scan --destination public --terms F --identities ADDRS --range origin/main..HEAD  # the new commit: lines, message, author
git push origin BRANCH
```

`ADDRS` is the review machine's list from section 3. Without it, the range scan flags your own `Signed-off-by:` trailer and author line.

## 6. Tag v0.1

Tag `v0.1.0` on the signed real repository, then build the release binary from that tag with `-trimpath` (the release draft in `.work/HSH-11/workflows/` builds and checksums it). Importers pin that exact version. Tagging, signing and publishing are yours.

## 7. Run the full-history scan

Before a repository goes public, scan every ref with both tiers and the publish scans' `--identities` value (ADR-001 section 4). When the refs include agent commits (a clone holding the staging refs), add each agent address to `ADDRS` too; the public repository's squashed history needs only yours:

```sh
hush scan --destination public --terms F --identities ADDRS --range --all
hush scan --destination public --generic-only --identities ADDRS --range --all
```

`--all` covers every ref under `refs/` but the stash and replace refs, annotated tag objects' own text and notes included. A shallow clone, grafts and a ref whose target is not a commit each exit 2: fetch the full history, remove the grafts, or remove the ref after checking its object by hand.

## 8. Retire the interim scanner

Once the hooks, the publish step, `hush gh`, `dispatch.sh block` and CI all run hush, remove the interim scanner from every call site and from your `PATH`. `reference/interim-hush/` stays in the reference pack as a record.

## Checklist

- [ ] Every interim call site mapped to its `hush` command (section 1): publish scans, scanner account, hooks, the `gh` wrapper, `dispatch.sh block`, CI
- [ ] The term file checked against ADR-002 section 1.7's table, at mode 0600, outside every repository, with per-client sets for client destinations (section 2)
- [ ] Identities set up: the review machine's addresses, each agent machine's agent address, and staging CI's `HUSH_IDENTITIES` if it scans ranges (section 3)
- [ ] The interim hooks replaced by `hush hooks install` with `--identities` in every hook, on every clone, and none installed before v0.1 (section 4)
- [ ] Noted: with an editor, `commit-msg` also scans git's comment lines; commit with `-m` (section 4)
- [ ] `--identities` passed in both publish scans (section 5)
- [ ] `v0.1.0` tagged and a release build made from it (section 6)
- [ ] The full-history scan run with both tiers and the publish scans' `--identities` value, before the repository goes public (section 7)
- [ ] The interim scanner retired (section 8)
