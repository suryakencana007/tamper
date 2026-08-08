# Phase 7 — Pooled Multi-Tenancy

> Status: **DESIGN FREEZE (Slice 0)**. Decision provenance: an architecture
> alignment review on 2026-08-07 mapped tamper @ `20fa206` onto a 7-layer
> enterprise multi-tenant reference model and found the tenant axis absent from
> library-owned state. The three load-bearing forks were answered the same day
> (§2). This doc gates the implementation the way
> `PHASE4D-BOUNDARY-DECISION.md` / `PHASE5-CUSTOM-ROLE-RBAC-SKETCH.md` gated
> theirs. **No code lands until this is reviewed.**

Companion documents:

- [`PHASE7-AGENT-MANIFEST.md`](PHASE7-AGENT-MANIFEST.md) — the per-slice
  machine-actionable manifest (files, signatures, invariants, mutation proofs).
- [`phase7-issues.json`](phase7-issues.json) + `create-phase7-issues.sh` — the
  GitHub milestone/issue projection of §5.

## 1. What this is

Today one tamper process serves exactly one tenant. That is not a stated
design position — it is an unexamined consequence of Barista, the flagship,
being a single-instance self-hosted PaaS. The evidence at `20fa206`:

```
$ grep -ric tenant --include=*.go .   # 150 files, ~19.7k production LOC
1                                     # a comment in espresso/decision.go
```

Everything the reference model needs *inside* a tenant is built, and layers 5
(authz) and 7 (audit) exceed what the model asked for. What is missing is the
tenant axis itself, in five places that are **library-owned** — meaning no
adapter, façade or app-side seam can supply it:

| # | Where | Consequence today |
|---|---|---|
| B1 | `identity.Store.UserByEmail(ctx, email)` | Email is globally unique. Two customers cannot both have `bob@acme.com`. |
| B2 | `identity.Store.CountUsers(ctx)` → `firstUser` | The bootstrap signal fires **once ever**. Tenant #2's first admin silently gets `firstUser=false`. |
| B3 | `crypto.AccessClaims` | No `tid`. One HS256 secret per process. Nothing in a token says which tenant it is for. |
| B4 | `oidc.Manager` / `saml.Manager` | One process-wide `ProviderRegistry` + one `cachedAt`. No per-tenant view, no domain→IdP routing. |
| B5 | `SCIMConfig` + `RequireServiceAccount` | One prefix, one `ServiceAccountValidator`, `Principal` with no tenant. |

`authz` is deliberately excluded from that list: `Subject`/`Resource` are
opaque `{Type,ID}` pairs, so `Resource{Type:"tenant", ID:"acme"}` already
works. **Phase 7 changes nothing in `authz`.** That package is the proof the
seam-first thesis pays off — it needed no rework to become tenant-ready, and
the rest of this document is about earning the same property elsewhere.

**B2 is the one that deserves fear.** Every other blocker fails to compile the
moment a consumer tries pooled tenancy. B2 compiles, passes, ships, and then
looks like "the new customer's admin has no permissions" three months later.
It is the archetype of the failure mode `TAMPER-DESIGN.md` §playbook-step-5
already warns about: the guard exists, it is green, and it is pointed at the
wrong thing.

## 2. Scope — the three forks, as decided

| Fork | Decision | Consequence |
|---|---|---|
| **Tenancy model** | **Pooled** — one process, N tenants | The reference-architecture target. Silo (one tamper per tenant) needs zero code and stays valid as a deployment choice; §7 records how to say so. |
| **Compatibility** | **Additive first, break later** | Empty `TenantID` means today's behavior, the same escape hatch already used for `acr` (`WithDefaultACR`) and `purpose` (legacy-tolerant read). Barista compiles unchanged through M1–M5. The flip is its own milestone (M6, v0.4.0). |
| **Proving ground** | **`examples/multitenant`, not Barista** | See §3. This is a documented, bounded exception to the phase rule — not its abandonment. |

Explicitly **out of scope** for Phase 7:

- A tenant *table*. tamper never names a table (`PHASE4E` §ColumnMapping, and
  every Store port since Phase 2a). Phase 7 ships the **ports** and the
  **neutral records**; the app owns the schema.
- An admin UI for tenant management. Non-goal #1 since inception.
- Tenant-scoped authz. Already expressible; adding a tenant concept to `authz`
  would hard-code a taxonomy the package exists to avoid.
- Data-layer isolation (RLS, schema-per-tenant, DB-per-tenant). That is the
  app's Store implementation, and tamper must not have an opinion — the port
  contract in §4.3 is the entire surface tamper needs.

## 3. Why Barista cannot be the proving ground

`TAMPER-DESIGN.md` states the phase rule plainly:

> Phases land in order — each depends on the one before. **No phase begins
> until the previous one has a Barista façade in production.**

Phase 7 cannot satisfy it. Barista is single-tenant by construction; a Barista
façade over tenancy would pass `tenantID=""` everywhere and prove only that
the compatibility escape hatch works — which is the *least* interesting half.
Adopting the rule unmodified would mean either never shipping tenancy or
shipping it with a proof that structurally cannot bite.

The bounded exception, and what replaces the rule's guarantee:

1. **Barista still gates every slice** for the `tenantID=""` path. Byte-parity
   is unchanged as a hard contract: `moon run barista:ci` green, and for
   anything touching auth or audit, the Docker deploy-artifact walk with the
   chain self-test OK. If a slice breaks Barista, the slice is wrong.
2. **`examples/multitenant` is the pooled proving ground.** A runnable
   two-tenant example — two verified domains, two OIDC providers on the
   embedded fake IdP, two SCIM tokens, one process — driven end to end by a
   test, in the shape `examples/federation` already established. It is not a
   demo; it is the consumer that makes the tenant path real, and **it lands in
   M1, not at the end.**
3. **A cross-tenant leak suite is a first-class artifact.** For every
   tenant-scoped port method: seed tenant A and tenant B, ask as A for B's
   object, assert not-found — never "denied" (the 404-vs-403 discipline
   `espresso/decision.go` already documents). This suite is the instrument
   that replaces "Barista runs it in production".

The deeper form of playbook step 5 applies to the exception itself: *what was
guarding this, and is it still pointed at where the code went?* The answer for
Phase 7 is "Barista guards the compatibility path; the leak suite and the
multitenant example guard the tenant path". Both must exist before M2 opens.

## 4. The additive mechanism

Three devices carry every slice. They are what make "additive first" real
rather than aspirational.

### 4.1 `TenantID` is an opaque string, `""` is single-tenant

Same shape as ACR: an app-defined value tamper never interprets, persisted by
the app, with a zero value that selects today's behavior.

```go
// identity/identity.go
type User struct {
    ID       string
    TenantID string // opaque, app-defined. "" = single-tenant deployment.
    Email    string
    ...
}
```

tamper does **not** validate, parse, namespace or canonicalize a `TenantID`.
It compares it for equality and passes it through. A UUID, a slug, a
`realm/sub-realm` path — all fine, all the app's problem.

### 4.2 Ports upgrade by optional interface, and the upgrade is checked at boot

Existing `Store` ports stay byte-identical. Tenant-aware methods land on a
**separate, additively-satisfied interface**:

```go
// identity/store.go
type TenantScopedStore interface {
    Store
    UserByEmailInTenant(ctx context.Context, tenantID, email string) (User, error)
    IdentityByProviderSubjectInTenant(ctx context.Context, tenantID, provider, subject string) (Identity, error)
    CountUsersInTenant(ctx context.Context, tenantID string) (int64, error)
    RevokeAllRefreshSessionsForTenant(ctx context.Context, tenantID string, at time.Time) error
}
```

`identity.Core` type-asserts once at construction, not per request.

**This is the exact mechanism that bit you in Phase 0c** — a type assertion
(`logger.(*audit.SQLiteLogger)`) that compiled fine and silently disabled the
exit-3 chain-integrity guard when the re-export became a defined type. So the
assertion is not allowed to fail quietly:

```go
// provider.go — New() fails at BOOT, never per-request.
if cfg.Tenancy != nil && cfg.Tenancy.Enabled {
    if _, ok := cfg.Identity.Store.(identity.TenantScopedStore); !ok {
        return nil, fmt.Errorf(
            "tamper: Tenancy.Enabled requires an identity.Store that implements " +
            "identity.TenantScopedStore; %T does not", cfg.Identity.Store)
    }
}
```

Consistent with the standing contract that misconfiguration fails at
`NewRBAC`/`New` — at boot — and never as a silent per-request deny. Every
slice that adds an optional-interface upgrade adds the matching boot guard
**and a test that the guard fires**, in the same PR.

### 4.3 The port contract carries the isolation obligation

tamper cannot enforce tenant isolation — the query lives in the adapter. What
it *can* do is state the obligation where the implementer reads it, in terms
that are testable. Every tenant-scoped port method's doc comment carries this
clause verbatim:

> **Isolation contract.** The implementation MUST constrain the query to
> `tenantID` and MUST return `ErrNotFound` — never a permission error and
> never another tenant's row — when the addressed object belongs to a
> different tenant. A `""` tenantID selects the single-tenant table shape.
> tamper cannot verify this; the cross-tenant leak suite (§3.3) is the proof
> obligation that comes with implementing this interface.

The leak suite ships as an exported conformance harness
(`identity/tenanttest`), so an adapter author runs it against their own store
the way `identity.MemStore` + the existing suite already work.

## 5. Milestones and slices

Six milestones, 19 slices, ascending risk within each. Every slice is
independently shippable and leaves Barista green.

### M1 — Tenancy foundation

The only milestone that must land whole; everything else composes on it.

| Slice | What | Risk |
|---|---|---|
| **7a-1** | `tamper/tenant` package: `Descriptor{ID, Slug, ParentID, Status}` neutral record, `Store` + `Resolver` ports, `MemStore` reference impl, `WithTenant`/`FromContext` propagation, `ErrNotFound`/`ErrSuspended` sentinels. No consumer yet. | LOW — pure addition, nothing imports it. |
| **7a-2** | `identity/tenanttest`: the exported cross-tenant leak conformance harness, plus the `identity.TenantScopedStore` **declaration** it is written against. Self-tested against in-package fixtures — one deliberately-leaky fixture per leak shape — because `MemStore` cannot satisfy the interface until 7b-2. **Runs after 7b-1** (amended 2026-08-07, see below). | LOW |
| **7b-1** | `TenantID` field on `User`, `NewUser`, `RefreshSession`, `Identity`, `NewIdentity`. Zero behavior change — the core reads and writes it, nothing branches on it yet. Parity: every existing test passes UNCHANGED. | LOW — the parity proof is the point. |
| **7b-2** | `identity.TenantScopedStore` + `Core` upgrade assertion + `WithTenancy(enabled)` option. Core routes `Register`/`Login`/`ResolveByIdentity`/`ProvisionUserWithIdentity` through the scoped methods when tenancy is on. **Fixes B1 and B2.** | **HIGH** — the semantic change. Needs both mutation proofs in §6. |
| **7b-3** | `examples/multitenant`: two tenants, two domains, two OIDC providers on the fake IdP, one process, driven by a test that asserts a cross-tenant login is rejected. | MED |

**M1 exit criteria:** the leak suite is green against a two-tenant store; the
multitenant example's test asserts a genuine cross-tenant denial; Barista CI
green with zero diff in its adapter.

> **Amendment, 2026-08-07 — M1 slice order.** M1 now runs
> `7a-1 → 7b-1 → 7a-2 → 7b-2`, not with 7a-2 parallel to 7b-1. Two defects
> forced it, both found when 7a-2 was opened and both compile-verified:
>
> 1. `RunLeakSuite`'s signature named `identity.TenantScopedStore`, which 7b-2
>    introduced, while 7b-2 gates on 7a-2 — a literal cycle. The
>    **declaration** moves to 7a-2 (7b-2 keeps the implementation, the routing,
>    the boot guard and both mutation proofs, and keeps its gate on 7a-2, so
>    the suite still exists before the change it proves). This mirrors how
>    §4 already treats a port: 7a-1 shipped `tenant.Resolver` with no
>    implementation, consumed four slices later.
> 2. The suite must SEED tenants, and every write path on the port is
>    inherited from `Store` — no slice defines a `CreateUserInTenant`. So the
>    tenant can only arrive on the record, via 7b-1's `TenantID` fields.
>    7a-2 was under-gated independently of the cycle.
>
> The `""`-mode case is **removed**, not deferred. Nothing the suite can
> observe distinguishes a single-tenant store from a leaky pooled one, so any
> "detect and skip" is a heuristic that goes quiet exactly when it finds the
> bug it exists to find. §6.2 governs: ambiguous means deny, and in a harness
> deny means FAIL. A single-tenant adapter has no isolation to prove and does
> not run the suite. At 7l-1 the question dissolves — `""` becomes an explicit
> single-tenant value and every store is tenant-scoped.

### M2 — Token and key binding

| Slice | What | Risk |
|---|---|---|
| **7c-1** | `AccessClaims.TenantID string \`json:"tid,omitempty"\``. `IssueAccess` takes it via an issuer option; `VerifyAccess` unchanged. Legacy tolerance mirrors `purpose`: a missing `tid` reads `""`. | LOW |
| **7c-2** | `VerifyAccessInTenant(token, tenantID)` + `RequireTenant` middleware that cross-checks the routed tenant against the token's `tid`. **When tenancy is enabled, an empty `tid` REJECTS** — the tolerance in 7c-1 buys a graceful rollout for single-tenant deployments only. **Fixes B3 (claim half).** | MED |
| **7d-1** | `crypto.Signer` seam: an interface over sign/verify with `alg` + `kid`, HS256 as the default implementation so nothing changes. Unblocks RS256/ES256 and per-tenant keys without committing to either. **Fixes B3 (key half), partially.** | MED |

**M2 exit criteria:** a token minted for tenant A is rejected on a tenant-B
route with a 401 that does not disclose whether B exists; HS256 output is
byte-identical to pre-7d-1.

### M3 — Tenant-scoped federation

| Slice | What | Risk |
|---|---|---|
| **7e-1** | `oidc.ProviderStore.ListEnabledProvidersForTenant` (optional interface) + registry cache keyed by tenant (`map[string]*cachedRegistry`, per-key `cachedAt`, same double-checked locking and nil-sentinel symmetry as today). `WithRedirectURLForTenant(func(tenantID, id string) string)`. **Fixes B4 for OIDC.** | **HIGH** — the cache is load-bearing and multi-replica convergence semantics must survive. |
| **7e-2** | The same for `saml.Manager`, mirroring 7e-1's contract exactly the way `3d-core` mirrored `3c-core`. **Fixes B4 for SAML.** | MED |
| **7f-1** | Home-realm discovery: `tenant.Resolver.ResolveByDomain(ctx, emailDomain)`, a `DomainStore` port, a verification-token generator, and a public-domain blocklist as data. DNS `TXT` checking is an optional `DNSVerifier` port — tamper ships the interface and a `net.Resolver` impl, the app decides when to run it. | MED |
| **7f-2** | `espresso.StartLogin(email)` — resolve domain → tenant → provider → redirect, falling back to the password/invite path on no match. The fallback must be **timing-indistinguishable** from a match, or the endpoint becomes a tenant-enumeration oracle. | MED |

**M3 exit criteria:** two tenants with different IdPs both log in through one
process; an unverified domain cannot bind an IdP; `StartLogin` timing does not
leak domain membership.

### M4 — Tenant-scoped provisioning and entitlements

| Slice | What | Risk |
|---|---|---|
| **7g-1** | `Principal.TenantID`. `RequireServiceAccount` stashes it; SCIM handlers read tenant from the **validated principal**, never from the path. **Fixes B5.** | MED |
| **7g-2** | Per-tenant SCIM base URL derivation (`meta.location`, `$ref`) from the principal's tenant, preserving the no-drift invariant that `MaxResults`/`MaxPayloadBytes` established. | LOW |
| **7h-1** | `Entitlements` port: `ForTenant(ctx, tenantID) (Entitlements, error)` with `SSOEnabled`, `SCIMEnabled`, `MaxIdPConnections`. Gated at the route surface, **not** at boot — boot-time nil-encoding is per-process and cannot express per-tenant tiers. | LOW |

**M4 exit criteria:** tenant A's SCIM token cannot read or write tenant B's
users (leak suite covers it); an SSO-disabled tenant gets a clean 403 at the
route, not a boot failure.

### M5 — Governance and hardening

| Slice | What | Risk |
|---|---|---|
| **7i-1** | Tenant in the audit canonical row → `canonical_version` v4, dispatched per row exactly as v2/v3 already are. **One chain, not one chain per tenant** (§8, open item 1) — plus a tenant-filtered export path. | **HIGH** — chain semantics. Requires the byte-parity diff the Phase 0c lift used. |
| **7j-1** | Invitations: `Invitation` record, `InvitationStore` port, single-use token with TTL, accept → membership. The non-SSO onboarding path has no home today. | LOW |
| **7k-1** | Rate limiting: a `Throttle` port + an in-process token-bucket default, wired on login, TOTP-verify and SCIM. Zero hits for this today; timing-parity rejections are not throttling. | LOW |

**M5 exit criteria:** `VerifyChainPostMigration` green across a v3→v4
migration on a real Barista audit DB; a tenant-scoped export contains no
other tenant's rows.

### M6 — Default flip (v0.4.0)

| Slice | What | Risk |
|---|---|---|
| **7l-1** | Fold `TenantScopedStore` into `Store`; delete the fallback path and the boot assertion; `TenantID` becomes required (`""` still legal, but as an explicit single-tenant value, not an unset one). Migration note + `CHANGELOG`. | **HIGH** — the breaking change, done once, in the open. |

**M6 exit criteria:** one migration guide, one major-version note, and every
`in-tenant`-suffixed method name collapsed back to its plain form.

## 6. Invariants — what must not break

Non-negotiable across every slice. A PR that trades one of these for
convenience is rejected regardless of test colour.

1. **`tenantID == ""` is byte-identical to today.** Same wire bytes, headers,
   status codes, error envelopes, audit-row payloads. This is the Phase 0
   byte-parity contract, re-scoped.
2. **Deny-by-default extends to tenancy.** An absent, empty or mismatched
   tenant in a tenancy-enabled deployment resolves to deny. There is no
   "unknown tenant means all tenants" path, and no error return may be read as
   allow.
3. **Cross-tenant misses are 404, never 403.** A deny and a miss must look
   identical, exactly as `espresso/decision.go`'s `VisibilityAction` flow
   already establishes for the org case.
4. **Boot, not request.** Every tenancy misconfiguration — a store that does
   not implement the scoped interface, a resolver with no domain source, a
   signer with no key for a tenant — fails at `New`.
5. **tamper still names no table.** Ports and neutral records only. If a slice
   is tempted to define a schema, the seam is in the wrong place.
6. **No new global mutable state.** The per-tenant registry cache replaces a
   single-value field with a keyed map; it does not add a second lock or a
   package-level var. (`saml.SetMaxClockSkew` remains the app's boot call and
   remains process-global — crewjam's constraint, unchanged and re-documented,
   not silently inherited.)
7. **Improvements are separate changes.** The 4e rule holds: a tenancy slice
   reproduces behavior for the `""` path. A genuine fix spotted en route is its
   own tested, documented PR — never smuggled in. Watch specifically for an
   adapter written one slice early carrying an intentional deviation that goes
   live when a later slice wires it into the request path (4e-2's 500-vs-400).

### The two mutation proofs 7b-2 must produce

Per playbook step 5, a green suite proves nothing until a mutation in the
**production** path goes red — and a mutant that fails to compile proves
nothing at all, so build it first.

- **M-B1:** in `Core.Login`, replace `UserByEmailInTenant(ctx, tenantID, email)`
  with `UserByEmail(ctx, email)`. The leak suite must go red. If it stays
  green, the suite is testing the store's method rather than the core's choice
  of method.
- **M-B2:** in the `firstUser` path, replace `CountUsersInTenant(ctx, tenantID)`
  with `CountUsers(ctx)`. A test asserting that tenant B's first user receives
  `firstUser=true` must go red. This is the B2 blocker's only real guard.

## 7. If the answer changes to silo

Recorded so the decision stays reversible and legible. If pooled tenancy is
abandoned, tamper needs **zero code changes** — the tenant boundary becomes
the deployment boundary, which is the purest form of isolation and fits the
embeddable-single-binary thesis exactly. The whole obligation is one paragraph
in `README.md` under "What your app supplies":

> **Tenancy.** tamper is single-tenant per process. Multi-tenant deployments
> run one tamper instance per tenant (its own binary, its own store, its own
> audit chain) — the tenant boundary is the deployment boundary. Pooled
> multi-tenancy, where one process serves many tenants, is not supported:
> `identity.Store` resolves users by email globally, provider registries are
> process-wide, and access tokens carry no tenant claim.

Saying it costs nothing and closes a question every evaluator will ask.

## 8. Open items

1. **One audit chain or one per tenant? — DECIDED 2026-08-08: ONE CHAIN**,
   tenant in the canonical row at `canonical_version=4`, **with
   commitment-based redaction shipped inside v4**. Recorded here because §8
   says the reasoning must be written down, and because this is the one Phase 7
   choice that cannot be revised additively.

   **Both premises the original assumption rested on are wrong.** They were
   checked against the code and should stop being reasons for anything:

   - *"per-tenant chains multiply the boot-verify cost by tenant count"* —
     **false**. `verifyChainPostMigrationStore` hashes every row once;
     bucketing the same sorted result set by tenant is the same SHA-256 count.
     Per-tenant chains multiply QUERIES, not hashes.
   - *"global ordering is the property that makes the chain worth having"* —
     **overstated**. The ordering is `Event.At`, which `Log` FABRICATES by
     bumping 1ns on collision under an in-process mutex. It is also additively
     recoverable under per-tenant chains, via checkpoint rows. Neither premise
     carries the decision.

   **The reason that does carry it, which the original text never made.** A
   hash chain exists to detect DELETION, not merely edits. Under per-tenant
   chains, deleting the whole of tenant X's chain leaves nothing behind: no
   global row references it, enumeration finds T−1 chains and reports success,
   and "tenant X was wiped" is byte-identical to "tenant X never emitted an
   event". Per-tenant chains buy the ability to drop a tenant's log without
   breaking anything by surrendering the ability to DETECT that a tenant's log
   was dropped — and for a log whose adversary model includes the operator
   (the model `RehashChainInPlace`'s own warning already assumes), that is a
   bad trade at any price. The proposed fix — checkpoint rows committing each
   tenant's tip hash — is a global chain with less in it.

   Secondary: per-tenant chains force `audit` to ENUMERATE TENANTS to emit
   genesis rows and run boot verification, so `audit` would depend on
   `tenant.Store`. Today it depends on nothing but its own store. That breaks
   §6.5 and the opaque-pass-through discipline `Actor.TenantID` already
   follows.

   **Per-tenant erasure is NOT a reason to pick per-tenant chains.** Erasing
   one data subject is a middle-of-chain deletion under BOTH topologies, and
   it is the commoner demand by an order of magnitude. It is solved by
   redaction, which is available under either — so it cannot discriminate
   between them.

   **What was checked and found unavailable.** A mid-table genesis row is
   UNCONSTRUCTIBLE through the port: `Log` sets `e.PrevHash = latestHash()`
   unconditionally. So "segment per tenant-era" is not an escape hatch. The
   only real ones are commitment redaction, whole-row tombstones, and
   export-then-anchor-then-prefix-prune — the last of which costs EVERY
   tenant's pre-anchor walkable proof, so it is offered last.

   Also corrected while checking: prefix-prune tolerance does NOT come from
   the chain-restart anchor. `walkChain` seeds `prev = e.PrevHash` at row 0 —
   it TRUSTS the first surviving row. The anchor selects the walk root and the
   encoder version. (A consequence worth its own issue: deleting the oldest N
   rows is undetectable without head-hash notarisation.)

   **The honest residual.** Rows written before the v4 anchor hash plaintext
   and are permanently un-redactable; they can only age out through
   `PruneOlderThan`. That window closes the day v4 ships and grows every month
   it slips.

   **Reserved, named but not built** (rule 7): a per-tenant rolling accumulator
   carried as a hashed v4 field plus a periodic
   `system.audit.tenant_checkpoint`, which would give tenant-scoped
   completeness with no cross-tenant leakage.

   **REVISIT before 7i-1 opens if** a signed or in-pipeline DPA requires
   physical removal of one tenant's audit rows on a cadence differing from the
   pool's longest retention, AND counsel will not accept irreversible
   redaction-in-place as discharge. That is this decision's one structurally
   unfixable gap; it arrives on the second enterprise contract, not in an
   exotic edge case, and no engineering closes it. The question is for legal
   with the contract text in hand — it is not answerable from the codebase.

   **ANSWERED 2026-08-09: NOT TRIGGERED. The compliance target is ISO/IEC
   27001, as the provider.** 7i-1 is clear to open.

   The condition needed both halves and ISO 27001 supplies neither. It is an
   ISMS standard, not a data-subject-rights regime: it requires that a
   retention policy be DEFINED and that records be protected, not that any
   particular customer's rows be destroyed on that customer's own schedule.
   There is no DPA-style physical-removal clause to satisfy, so the question of
   whether redaction discharges one does not arise.

   It argues the same way the decision already did:

   - **A.5.33 protection of records** — protect from loss, destruction and
     falsification. Per-tenant chains surrender exactly that: a wiped tenant
     chain is byte-indistinguishable from a tenant that never logged. This is
     the reason the decision turned on, restated in the auditor's vocabulary.
   - **A.8.15 logging** — logs protected against tampering and unauthorised
     deletion. One chain is the stronger control and the one demonstrable in a
     single walk.
   - **A.5.33 / A.8.10 retention and deletion-when-no-longer-required** —
     `PruneOlderThan` is a uniform, tenant-blind cutoff, which is CORRECT under
     a provider-defined uniform ISMS retention policy. It breaks only under
     per-customer contractual variance, which is the DPA case and not this one.

   **The condition stays recorded rather than deleted.** ISO 27001 A.5.34
   defers to applicable PII law. Selling into a GDPR-covered market under DPAs
   can revive it, and if it does, the analysis above is the analysis to re-run
   — not a new one.

   **Two obligations ISO does add.**

   - The single-writer defect below stops being merely a bug. Under A.8.15 the
     chain IS the tamper-protection control, and a control that fails under the
     deployment's own topology is a reproducible nonconformity. It wants its
     own slice, AHEAD of 7i-1 if certification is near — it is not in 7i-1's
     scope and must not be smuggled into it (rule 7).
   - **A.8.17 clock synchronisation** needs a written answer. `Event.At` is not
     purely a synchronised clock reading: `Log` bumps it by 1ns on collision
     against a process-local watermark. That is defensible — it is a
     sequence-preserving adjustment, and it is what makes `ORDER BY at` follow
     chain order — but it should be documented before it is asked about live,
     not improvised in the room.

   Scope and the Statement of Applicability are the certifying auditor's call,
   not this document's.

   **Separate blocker, independent of this fork, and arguably more urgent.**
   `Log` is SELECT-latest-hash then INSERT, under an IN-PROCESS mutex with an
   IN-PROCESS `lastAt` watermark. Two replicas writing one audit DB race on
   both and break the chain — under either topology. Pooled deployments are
   usually multi-replica. Confirm the deployment's writer topology before M5
   lands.
2. **Does `identity.User.Email` stay globally unique in `""` mode?** Yes, by
   the parity contract. But an app migrating from `""` to real tenants needs a
   backfill story: assign every existing row a tenant, then flip. That guide is
   part of M6, not M1 — but if it turns out to be impossible for some schema
   shape, that is a M1 finding, not a M6 one.
3. **Nested tenants.** `Descriptor.ParentID` is reserved in 7a-1 and used by
   nothing. Resolving whether a parent's IdP serves a child tenant is a real
   product question (enterprises with business units will ask) and is
   deliberately deferred — but the field exists so the answer is additive.
4. **`RequireTenant` placement.** Whether the tenant cross-check belongs in
   `RequireAuth` (one gate, always on) or as a separate composable middleware
   (explicit, skippable, therefore forgettable). The sketch assumes separate;
   revisit at 7c-2 with the same lens `4b` used for the step-up gate.
5. **Rate limiting is in M5 but is arguably M1.** It is independent of tenancy
   and currently absent entirely. If Phase 7 slips, 7k-1 should be pulled out
   and shipped on its own — a pooled deployment without per-tenant throttling
   turns one abusive customer into everyone's outage.
