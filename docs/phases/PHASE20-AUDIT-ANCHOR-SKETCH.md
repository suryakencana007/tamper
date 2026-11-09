# Phase 20 — an anchored chain, so a prune is provable

**Slice 20a — the design freeze.** Code lands in 20b; `audit` is a frozen package.

## 1. The gap, restated from the M5 revisit

`Verify` takes the first surviving row's `PrevHash` as the chain baseline — deliberately, and
documented, because a retention prune leaves that row pointing at a deleted predecessor. The
consequence is documented nowhere:

> **A deleted prefix is invisible.** Pruning by policy and excising the oldest rows by hand produce
> the same verdict, so `Verify` cannot answer "was the beginning of this chain removed by us, and
> when".

That is the question an auditor asks of a compacted log, and it is what ISO 27001 A.5.33 (protection
of records from destruction) is about. The M5 revisit (#154) scoped this as the engineering gap, with
no legal dependency: uniform retention and the anchor are inside the decision; per-tenant
segmentation stays reserved.

## 2. The decision: the anchor must be IN the chain

Two shapes were considered, and the choice is forced by the threat model:

- **A separate anchor table** — easy to query, and worthless: an attacker who can delete chain rows
  can delete or forge the anchor row with the same access. An anchor that the chain does not protect
  is decoration, and this repository has spent the whole roadmap removing decoration.
- **A checkpoint EVENT** (chosen). The anchor is an ordinary event appended to the chain in the same
  transaction as the prune, so it is covered by the hash chain like everything else: editing or
  removing it breaks the chain, and its own `PrevHash` names the row the prune removed.

## 3. The shape, with the parts that could go wrong decided

**One event, existing machinery, no canonical-version bump.** The checkpoint is a normal event whose
`Action` is `system.audit.chain_pruned` — app-visible like any other — and whose `ResourceID` carries
the hash of the last row the prune removed. `ResourceID` is already opaque and app-defined
(`audit.Event` documents no format), so no new field enters the hashed payload and `canonical_version`
stays 4 for every row. Adding a field would mean a v5 and a second encoder for no gain: the anchor's
only payload is one hash.

**Prune becomes one transaction**, honouring the single-writer rule from Phase 7:

```
BEGIN IMMEDIATE
  read the newest row  -> tail hash
  insert checkpoint(action=system.audit.chain_pruned, resource_id=<hash of last row to prune>,
                     prev_hash=tail hash)              -- appended FIRST, so it is not pruned
  delete rows with timestamp <= cutoff
COMMIT
```

The checkpoint is inserted **before** the delete and is itself newer than the cutoff — so it survives
its own prune and becomes the new baseline.

**The verification rule, which is the whole point:**

| First surviving row | Verdict |
|---|---|
| `PrevHash` is `HashSize` zero bytes | **genesis** — chain never pruned. Clean |
| `PrevHash` equals the `ResourceID` of a `system.audit.chain_pruned` row that IS present | **anchored prune** — clean, and the result reports where the chain now begins |
| anything else | **tampered**: a prefix was removed and nothing in the chain says so |

So a row with a non-genesis `PrevHash` is legitimate only when that row is a checkpoint whose
recorded hash equals its own `PrevHash`. Nothing else excuses a dangling link.

`VerifyResult` gains `Pruned bool` and `AnchoredAt string` (the hash the chain now starts from), so a
clean walk can still say "this chain has been compacted, here is the boundary" instead of silently
resembling an unpruned one.

## 4. The breaking consequence, and the remedy

**A chain pruned before this feature has no checkpoint, so it now verifies as TAMPERED.** That is the
safe direction — an unanchored prefix is exactly what the feature exists to catch — but it is a
behaviour change for an existing deployment, and it must not be discovered at boot without a path
forward.

- **Boot guard**: the existing boot verification surfaces `ChainMismatchError` naming the first bad
  row; the sketch requires it to name this specific condition ("prefix removed with no checkpoint")
  rather than reporting it as an ordinary hash mismatch, and a test that the guard fires (standing
  rule 6).
- **The remedy is an administrative act, not a flag**: `Log.AnchorCurrentChain(ctx)` records a
  checkpoint for the CURRENT first row, in the chain, with the caller's actor. An operator who knows
  the prefix was pruned says so, once, and the statement is itself auditable — which is the opposite
  of a "skip verification" switch, and the reason this is the chosen remedy.

## 5. What it does not do

- **No per-tenant anything.** Uniform cutoff only; per-tenant retention is the reserved M5 variant.
- **No scheduled pruning.** `PruneOlderThan` remains a tool the application calls.
- **No signing of the anchor.** The chain's own hash coverage is the integrity mechanism; a signature
  would be a second mechanism answering the same question, and the repo's rule is that a second
  answer is a second thing to disagree with the first.
- **No rewriting of history.** Pruned rows are gone; the anchor proves *that* they were pruned and
  where the boundary is, not what they said.
- **No change to what is hashed for existing rows** — `canonical_version` stays 4, so an old row
  verifies exactly as it did.

## 6. Tests and mutation proofs (slice 20b)

- Prune then verify: clean, `Pruned=true`, `AnchoredAt` equal to the recorded hash.
- **Delete the oldest rows by hand (no checkpoint): TAMPERED** — the test the feature exists for.
- **Delete the checkpoint row**: TAMPERED — an anchor that can be removed is not an anchor.
- Edit the checkpoint's `ResourceID`: TAMPERED (its hash changes → chain break).
- Unpruned chain: unchanged verdict, `Pruned=false` — the additive case.
- `AnchorCurrentChain` on a hand-pruned chain: clean afterwards, and the checkpoint carries the
  caller's actor.
- Mutants: `PrevHash` always accepted (the pre-slice behaviour — must fail the hand-prune test);
  the checkpoint inserted after the delete (must fail the prune test); verification ignoring the
  checkpoint's recorded hash (must fail the forged-boundary test).

## 7. The rule this slice is written under

Compaction must not become a way to hide an edit. Every test above is chosen so that the failure
direction is "tampered", never "clean" — and the one case that must stay CLEAN (a real prune, by
policy, with its anchor) is asserted explicitly, because a guard that refuses legitimate compaction
would be bypassed rather than fixed.
