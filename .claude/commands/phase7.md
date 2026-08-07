---
description: Execute one Phase 7 multi-tenancy slice from the agent manifest
argument-hint: <slice-id, e.g. 7a-1> [--plan]
allowed-tools: Read, Grep, Glob, Edit, Write, Bash(go:*), Bash(git:*), Bash(golangci-lint:*), Bash(moon:*)
---

Execute Phase 7 slice **$ARGUMENTS** of the tamper pooled-multi-tenancy roadmap.

If `--plan` is passed, produce the plan and stop before writing any code.

## Step 0 — load the contract

Read, in this order, and do not skip any:

1. `PHASE7-AGENT-MANIFEST.md` — find the slice block whose `id` matches the
   argument. **That block is your specification.** If no block matches, list the
   available slice ids and stop.
2. The sketch section named in that block's `design_ref`, in
   `PHASE7-MULTITENANCY-SKETCH.md`.
3. `TAMPER-DESIGN.md` §"The extraction playbook" — especially step 5, on tests
   that stay green while guarding nothing.
4. Every path in the slice's `reads` list.

## Step 1 — check the gate

The slice's `depends_on` is a **hard gate**. For each dependency, confirm the
work actually landed (grep for the symbols it was supposed to introduce — do
not trust a checkbox or a commit message). If a dependency is missing, say
which one and stop.

If the block carries `blocked_by_decision`, stop and state the decision that
must be made first. Do not proceed on an assumption.

## Step 2 — plan

State, before touching code:

- the exact files you will create or modify, and why each one
- the new exported symbols, with their full signatures
- which invariants from the slice block constrain each change
- the tests you will add, named
- the mutation you will apply to prove the guard bites

Stop here if `--plan` was passed.

## Step 3 — implement

Honour the slice block's `invariants` — **they outrank the task description
and they outrank your own judgement about what would be cleaner.**

Global rules that apply to every slice:

- `tenantID == ""` must stay **byte-identical** to pre-slice behavior: same
  bytes, headers, status codes, error envelopes, audit-row payloads.
- tamper names no table, column or migration outside `audit/`. Ports and
  neutral records only. If you find yourself defining a schema, the seam is in
  the wrong place — stop and say so.
- Every tenant-scoped port method carries the isolation-contract doc clause
  from sketch §4.3, verbatim.
- Any optional-interface upgrade ships a boot guard **and** a test that the
  guard fires, in the same change.
- Deny-by-default extends to tenancy: absent, empty or mismatched tenant
  resolves to deny. No error return may be read as allow.
- Cross-tenant misses are **404, never 403**. A deny and a miss must be
  indistinguishable.
- If you spot a genuine improvement while implementing, **do not include it**.
  Note it for a separate change. This is the 4e rule and it exists because an
  adapter written one slice early carried an intentional deviation that stayed
  invisible until a later slice wired it into the request path.

## Step 4 — prove it

Run every command in the slice's `verify` block. Then run each `mutation`:

1. Apply the mutation to the **production** path, not the test.
2. **Confirm it compiles.** A mutant that fails to compile proves nothing —
   it is measuring your typo.
3. Run the named test and confirm it goes **red**.
4. Revert the mutation and confirm green again.

Report each mutation as: the diff applied, that it compiled, the test that
failed. If a mutation stays green, the guard is pointed at the wrong thing —
fix the test, not the report.

## Step 5 — report

Walk the slice's `dod` list item by item and mark each one. Do not claim a
slice done with an unchecked line; say what is outstanding instead.

Finish with a PR-body-ready summary containing:

- what changed and why, in the repo's own voice
- the mutation-proof results
- any invariant you found yourself under pressure to bend, and how you didn't
- anything you deliberately left out for a separate change

## When to stop and ask

Stop and ask a human if the slice cannot be completed without violating an
invariant. That is a design bug in the manifest, not a licence to deviate —
and saying so is more useful than a green build that quietly widened a tenant
boundary.
