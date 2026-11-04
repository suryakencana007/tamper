---
description: Run one slice of a tamper phase — sketch first, then code, then review rounds with mutation proofs, stopping at the merge gate
argument-hint: <slice-id, e.g. 12c> [--plan] [--sketch-only]
allowed-tools: Read, Grep, Glob, Edit, Write, Bash(go:*), Bash(git:*), Bash(gh:*), Bash(golangci-lint:*)
---

Run slice **$ARGUMENTS** of the current tamper phase under this repo's working
discipline. `/phase7` remains the mechanics for Phase 7 slices specifically; this
command is the loop around any phase, and it is the loop that has caught the most
defects.

If `--plan` is passed, produce the plan and stop before writing code. If
`--sketch-only` is passed, do Steps 0–2 and stop.

## Step 0 — load what governs the slice

Read, and do not skip:

1. `CLAUDE.md` — the standing rules. Rule 6 (an optional upgrade ships a guard **and**
   a test that the guard fires) and rule 7 (improvements spotted en route are separate
   changes) bite most often.
2. The phase sketch named by the slice (`PHASE*-SKETCH.md`), and `tech-debt.md` for
   the item it closes.
3. `PHASE7-AGENT-MANIFEST.md` for the shape a slice spec takes, even when the slice is
   not Phase 7.

**Anything touching `identity`, `crypto`, `oidc`, `saml`, `scim`, `espresso`,
`tenant`, or `audit` needs the sketch amended FIRST** — a docs-only change, merged,
before a line of code. That is not ceremony: in this repo the sketch has been wrong
about its own design every single time it was checked against the tree (§"What the
sketch usually gets wrong", below).

## Step 1 — re-verify the item against the code

Do not plan from the tech-debt prose. Grep for the symbols it names and enumerate the
real surface:

- `tech-debt.md` items have been **incomplete** (TD-28's list was eight methods short,
  and had been short when it was written). Enumerate the whole type, then diff.
- Confirm the line numbers it cites still point where it says — a phase's own slices
  move them.

## Step 2 — amendment or plan

State, before touching code:

- the exact files created or modified, and why each
- new exported symbols with full signatures
- which invariants constrain each change, and where each invariant is **enforced in
  one place** rather than duplicated
- the tests, and for each one the **mutant** that must turn it red
- what the slice does **not** do

## Step 3 — implement, then prove

Code, then tests, then the mutants. For each mutant:

1. Apply it, `go build ./...` (a mutant that does not compile proves nothing).
2. Run the named test and confirm it goes **red**.
3. Revert, confirm the suite is green.

A mutant that stays green is a **lost proof**, not a pass: either the test is wrong or
the property is untested. Say which, in the PR.

## Step 4 — the drift grep, before opening the PR

Any invariant this slice changes is probably stated in more places than the sketch
lists. Grep the tree for its own words — not for the concept:

```
grep -rn "the sentence the old invariant used" --include="*.md" --include="*.go" .
```

Phase 12's tree held **ten** documents stating the invariant, where the sketch named
three, two of them user-facing — and the slice's own summary then miscounted it twice. Current-state documents get reworded; decisions and manifests get an
in-place `AMENDED <date>` note (the house style `PHASE7-*` already uses).

Also grep for the numbers you are about to claim: PR ranges, test counts, method
counts. `#91–#96` once claimed the release PR and an amendment PR as fix PRs; a
"17 tests" became "22" from memory.

## Step 5 — PR, then STOP

Open the PR with: what changed, why, the review rounds, the mutant table, and what
the slice does not do.

Then **stop and report the URL and CI status.** Do not merge on your own initiative,
ever — the merge is the owner's decision, and it is given as `merge #N`.

## Step 6 — review rounds (only when asked)

Each round starts from the tree, not from the diff's prose. What has actually been
found this way:

- a signature that undid a type's reason to exist (`Ancestors(ctx, store, id string)`
  vs `tenant.ID`, whose whole point is that `""` said deliberately and `""` forgotten
  are different facts)
- a return type handing back the wrong tenant (`DomainRecord.TenantID` was the
  ANCESTOR's, and the login path reads exactly that field)
- a rule that was wrong for the commonest case (12b: the zero entitlement record
  means "unlimited", so every child of a capped group got an uncapped plan)
- security logic duplicated between two files, byte-identical except comments — the
  cue to hoist it, not to sync it
- a **real hole** found only by trying it: a verified `gmail.com` claim granted
  authority over `x.gmail.com`

Report findings, fix them, repeat. Three rounds is normal; the last round is usually
consistency (headings, counts, cross-references).

## Step 7 — after the merge

Verify the tag, not the intention:

```
git show vX.Y.Z:README.md | grep -m1 "go get"
git show vX.Y.Z:CHANGELOG.md | grep -m1 "^## \[X.Y.Z\]"
git show vX.Y.Z:<file the release claims> | head -3
```

Then tag, release, and check the release notes against the tag's contents.

## What the sketch usually gets wrong

Phase 12's four code slices each found one of these, and not one of them was visible
from the sketch — a better record than "a phase, once". Phase 13 then produced a fifth
kind, in the item rather than the design: the list of what to change was incomplete and
had been incomplete when it was written. Assume your sketch has one of these:

1. **The design does not survive the code.** 12a: "resolve before the lock" turned out
   to be a restructure of four call paths, and it breaks one documented promise.
2. **The rule is wrong for the most common input.** 12b.
3. **Two consumers are byte-identical**, so the logic is already duplicated before it
   ships.
4. **A security check checks the input but not the stored value.** 12d.

And a fifth, from the item rather than the sketch: **the inventory is short.** TD-28
named six methods and there were fourteen. Enumerating a type's whole surface takes one
grep, and it is the cheapest step in the list.

So: pre-flight the riskiest assumption with two greps before writing code, and put
the finding in the amendment.

## Non-negotiables

- `tenantID == ""` and `tenant.Single` are not wildcards and not "unset".
- Cross-tenant misses are 404/`ErrNotFound`, never 403 and never distinguishable from
  a miss.
- Misconfiguration fails at `New`, never as a per-request denial.
- tamper names no table; ports and neutral records only.
- A release that breaks something gets `MIGRATION-vX.Y.md`; an additive one says so in
  the entry instead, and does not open a guide nobody needs.
