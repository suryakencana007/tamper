# CLAUDE.md

<!-- PHASE7:BEGIN -->
## Phase 7 — pooled multi-tenancy (in progress)

The current milestone is Phase 7: making tamper serve N tenants from one
process. Two documents govern it. Read them before touching `identity`,
`crypto/jwt.go`, `oidc`, `saml`, `scim` or `espresso`:

- **`PHASE7-MULTITENANCY-SKETCH.md`** — the design freeze. Why the tenant axis
  is absent, the five library-owned blockers, the three forks as decided, and
  the seven invariants. Status is DESIGN FREEZE: no code lands that contradicts
  it without amending it first.
- **`PHASE7-AGENT-MANIFEST.md`** — the executable spec, one block per slice:
  `reads` / `writes` / signatures / invariants / tests / mutation proof / DoD.

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

### Open decision blocking M5

`7i-1` (audit canonical v4) is blocked until this is settled: **one chain with
tenant in the canonical row, or one chain per tenant?** Every other Phase 7
choice can be revised additively; this one cannot. Do not start `7i-1` on an
assumption.
<!-- PHASE7:END -->
