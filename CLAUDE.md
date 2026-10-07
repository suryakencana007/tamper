# CLAUDE.md

<!-- PHASE7:BEGIN -->
## Phase 7 — pooled multi-tenancy (COMPLETE, 2026-08-09)

Phase 7 made tamper serve N tenants from one process. **All six milestones
are done**, including M6 — the v0.4.0 default flip (`7l-1`). The tenant is a
type (`tenant.ID`, zero value invalid; sketch §8 item 7), the *InTenant
surface is folded into the base ports, and Barista is migrated with CI green.

The three deferred verifications were all closed on a machine with Barista
and Docker (`PHASE7-HANDOFF.md` §0): boot-verify on the real audit DB, the
Docker deploy-artifact walk, and Barista CI — which was RED on first contact
and caught a real invariant-1 regression (#20, fixed at the shared boundary
with `sqltypes.Blob`, then made structurally impossible by moving the
generated layer under `audit/internal/`).

Releases: `MIGRATION-v0.4.md` + `CHANGELOG.md` govern the upgrade. v0.3.0
tags the last additive commit; v0.4.0 is the flip.

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
- **Additive first, break later** was the rule through Phase 7. It ended on
  2026-10-05; see standing rule 1.
- **`examples/multitenant` is the proving ground, not Barista.** Barista is
  single-tenant and structurally cannot prove the tenant path — a Barista
  façade would pass `tenant.Single` everywhere and prove only that half.
  Since 2026-10-05 Barista is not kept compiling against `main` either
  (standing rule 1, TD-27).

### Standing rules

1. **No compatibility code. Decided by the repo owner on 2026-10-05.** Do not
   keep an old function, an old signature or an old behaviour alive beside
   the new one, and do not add a fallback so that old callers keep working.
   Nothing is in production. Change the API, change every caller in this
   repo, and write the breaking change in `CHANGELOG.md`.

   This replaces the Phase 7 rule that `tenantID == ""` must be
   byte-identical to pre-Phase-7 behavior. That rule and rule 2 could not
   both hold in one place (the `""` path had to keep working, and a missing
   tenant had to deny), and code written to satisfy both guessed tenants.

   **Single-tenant is still a supported deployment.** It is said out loud:
   the application passes `tenant.Single`, or a resolver that returns `""`.
   What is gone is the idea that leaving the tenant out means single-tenant.
   A user in a single-tenant deployment is stored in `tenant.Single` and
   needs no membership.

   Barista is not kept compiling against `main`. Moving it is separate work
   (TD-27).

   Shims that still exist from before this rule are listed in TD-28 of
   `tech-debt.md`. Remove them one package per change (rule 7).
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

### Phase 8 — platform admin (started 2026-10-05)

`PHASE8-PLATFORM-ADMIN-SKETCH.md` governs "a user of one tenant acts inside
another": `identity.MembershipStore`, `Core.EnterTenant`, the `htid` claim.
Read it before touching them. Two things are decided and not to be loosened in
passing: entering gives an access token only (no refresh session), and no
token is ever valid for more than one tenant. `RequireTenant` refuses an
entered token; a route takes guests only through `RequireTenantAllowEntered`.

`PHASE8B-AUTHZ-TENANT-SKETCH.md` governs tenants in `authz`: every port takes
a `tenant.ID` (the scope), and `Subject` carries its home tenant. Decided and
not to be loosened: no binding spans tenants, so a guest needs a binding in
the tenant entered. Every `BindingStore` and `PermissionStore` must pass
`authz/tenanttest` (the one exception, the RBAC-backed store, is explained in
the sketch).

### The M5 decision, settled

**One chain**, tenant in the canonical row at `canonical_version=4`, with
commitment-based redaction shipped inside v4. Full reasoning in sketch §8
item 1, including the two original premises that were checked against the code
and found wrong.

Since 2026-10-04 v4 is the **only** version. The v1–v3 encoders, the
chain-restart anchors, `VerifyLegacy`, the in-place migration helpers and the
`Tenancy` logger option are gone: every row is v4, for every deployment. Do not
bring a second version or an anchor back to solve a problem; a chain that could
hold two versions was the cause of TD-16, TD-24 and TD-25 in `tech-debt.md`.

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
