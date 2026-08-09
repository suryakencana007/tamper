# CLAUDE.md

<!-- PHASE7:BEGIN -->
## Phase 7 — pooled multi-tenancy (M1-M5 complete)

Phase 7 makes tamper serve N tenants from one process. **M1-M5 have landed**;
only M6 (`7l-1`, the v0.4.0 default flip) remains, and it is a release
decision rather than a queued slice.

Two DoD lines are still open and are **not** to be marked done from this
machine: `7i-1`'s boot-verify on a real Barista audit DB, and the Docker
deploy-artifact walk. Barista CI has been deferred for the whole phase with a
documented local proxy. All three, with the exact commands, are in
**`PHASE7-HANDOFF.md`** — read it before claiming any of them.

Three documents govern the phase. Read them before touching `identity`,
`crypto/jwt.go`, `oidc`, `saml`, `scim`, `espresso` or `audit`:

- **`PHASE7-MULTITENANCY-SKETCH.md`** — the design freeze. Why the tenant axis
  is absent, the five library-owned blockers, the three forks as decided, and
  the seven invariants. Status is DESIGN FREEZE: no code lands that contradicts
  it without amending it first.
- **`PHASE7-AGENT-MANIFEST.md`** — the executable spec, one block per slice:
  `reads` / `writes` / signatures / invariants / tests / mutation proof / DoD.

- **`PHASE7-HANDOFF.md`** — what could not be verified here, what stood in for
  it, and the exact commands to close it on a machine with Barista + Docker.
  Also the sharp edges the phase hit (sqlc truncating SQL around non-ASCII;
  `DEFAULT` not applying when sqlc names every column; `-run` quoting through
  a non-POSIX shell silently matching zero tests).

Run a slice with `/phase7 <slice-id>` (e.g. `/phase7 7a-1`). Add `--plan` to
stop before writing code.

### Decisions already taken — do not relitigate in passing

- **Pooled**, not silo. One process, N tenants.
- **Additive first, break later.** An empty `TenantID` means today's behavior,
  the same escape hatch already used for `acr` and `purpose`. The breaking flip
  is its own milestone (M6, v0.4.0).
- **`examples/multitenant` is the proving ground, not Barista.** Barista is
  single-tenant and structurally cannot prove the tenant path — a Barista
  façade would pass `tenantID=""` everywhere and prove only the compat half.
  This is a bounded, documented exception to the phase rule (sketch §3), not
  its abandonment. Barista still gates the `""` path on every slice.

### Standing rules while Phase 7 is open

1. `tenantID == ""` is byte-identical to pre-Phase-7 behavior. Same bytes,
   headers, status codes, error envelopes, audit-row payloads.
2. Deny-by-default extends to tenancy. Absent, empty or mismatched tenant
   resolves to deny; no error return may be read as allow.
3. Cross-tenant misses are **404, never 403** — a deny and a miss must be
   indistinguishable (the discipline `espresso/decision.go` already documents).
4. Tenancy misconfiguration fails at `New`, never as a per-request denial.
5. tamper still names no table. Ports and neutral records only.
6. Optional-interface upgrades ship a boot guard **and** a test that the guard
   fires. This is the mechanism that silently disabled the exit-3 chain guard
   in Phase 0c; it is not allowed to fail quietly again.
7. Improvements spotted en route are separate changes, never smuggled into a
   slice (the 4e rule).

### The one that fails silently

`identity.Store.CountUsers(ctx)` drives the `firstUser` bootstrap signal. Every
other blocker fails to compile the moment a consumer tries pooled tenancy —
this one compiles, passes, ships, and surfaces months later as "the new
customer's admin has no permissions." Slice `7b-2` carries two mandatory
mutation proofs because of it. Do not weaken them.

### The M5 decision, settled

**One chain**, tenant in the canonical row at `canonical_version=4`, with
commitment-based redaction shipped inside v4. Full reasoning in sketch §8
item 1, including the two original premises that were checked against the code
and found wrong.

Its revisit condition — a DPA demanding physical per-tenant removal on a
divergent cadence, with counsel refusing redaction as discharge — was answered
against **ISO/IEC 27001** and found **not triggered**. It stays recorded rather
than deleted: A.5.34 defers to applicable PII law, so a GDPR-covered market
under DPAs can revive it. If that happens, re-run the analysis already written.

Two ISO obligations came out of it. One is closed (the chain-append
single-writer fix — `Log` was a read-modify-write behind an in-process mutex,
so two replicas forked the chain; now a `BEGIN IMMEDIATE` transaction). The
other is the A.8.17 clock note, recorded in
`TestMultiWriter_AtStaysStrictlyIncreasing`: `Event.At` is not a pure
synchronised clock reading, it is the caller's timestamp bumped forward on
collision to preserve chain order.
<!-- PHASE7:END -->
