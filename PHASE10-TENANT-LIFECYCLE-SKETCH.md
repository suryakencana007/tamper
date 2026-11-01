# Phase 10 — tenant lifecycle: a write port and one `Suspend`

Status: **draft, for review. Not decided, no code.** This sketch covers TD-05
from `tech-debt.md`, the second half of the pair Phase 9 (`TD-06`) opened.

It follows `PHASE9-TENANT-STATUS-SKETCH.md`, which added the enforcement half:
`RequireActiveTenant` refuses a tenant that is not `StatusActive`. This sketch
adds the half that was still missing — a supported way to *set* that status, and
one operation that pairs a suspension with the session revocation it needs.

---

## 1. The problem

`tenant.Store` is read-only: `ByID` and `BySlug`, nothing else
(`tenant/store.go:51-59`). There is no create, no list, no status change, and no
delete. So every application writes its whole platform console — list tenants,
provision one, suspend one, offboard one — with **no contract at all** from the
framework that is supposed to be its tenancy substrate.

Two useful pieces already exist and are not the answer:

- `identity.Core.RevokeAllSessionsForTenant(ctx, tenantID)` revokes a tenant's
  refresh sessions (`identity/core.go:502`).
- `tenant.DomainStore.ListForTenant` is the admin-shaped read for domains.

Phase 9 made the gap sharper. Before it, suspension was advisory. After it,
`RequireActiveTenant` refuses a non-active tenant on every request — so the
status now *matters*, while the only way to set it is a write from application
code that tampers' own tests cannot see. The one operation that must never be
half-done, **set the status and revoke the sessions**, is left to each app to
remember:

```
suspend a tenant  =  tenant row: status = suspended
                    identity:   revoke every refresh session
                    ---------
                    forget the second line?  the tenant keeps serving until
                    its access tokens expire, silently.
```

That is a control an auditor asks about, implemented differently per
deployment, or not at all.

---

## 2. Decisions

Proposals for review, each stated with what it protects.

1. **A separate opt-in port, `tenant.AdminStore`.** `tenant.Store` stays
   read-only. Every consumer of the framework reads a tenant; only a console
   writes one. Adding writes to `Store` would force every read-only adapter to
   implement or stub them, and would put "change a tenant" behind an interface
   that anonymous routing code already holds. Same shape as
   `identity.MembershipStore` and `tenant.DomainStore`: an admin concern gets its
   own port.

2. **tamper still names no table.** `AdminStore` is implemented by the
   application over its own tenants table, exactly as `Store` and `DomainStore`
   are. The framework adds no schema and no migration.

3. **`Suspend` is one operation with a defined order, and its partial failure is
   named.** The status write comes **first** — so the Phase 9 gate stops serving
   immediately — and the revocation second, which closes the token window. If
   revocation fails, the operation returns an error that says the tenant **is**
   suspended and N sessions may survive. A loud partial state, never a silent
   one.

4. **Why one operation and not two calls.** The two writes live in different
   stores — the application's tenant table and `identity.Store`'s session rows —
   possibly in different databases. The framework cannot promise cross-store
   atomicity, so it promises the **order** and the **reporting** instead of
   pretending to a transaction it does not have. Reverse the order and a crash
   leaves a tenant that still serves; that is why the order is part of the
   contract and not an implementation detail.

5. **No `Delete`.** Offboarding is a status change plus a retention policy. A
   deleted tenant row orphans audit rows, bindings, identities and MACs, and the
   audit chain is precisely the record that the tenant existed (the M5 decision
   keeps one chain for all tenants). The framework will not offer a call that
   makes its own record incoherent.

6. **Writes fail closed on the values this version does not know.** An empty id,
   the single tenant, or a `Status` the library has never seen is refused and
   nothing is written — the write-side sibling of `authz`'s "unset scope denies"
   and of Phase 9's "any status but active refuses".

7. **A duplicate id or slug is `ErrConflict`, not a silent overwrite.** Provisioning
   the same tenant twice must not quietly reset a suspended tenant to pending, or
   re-point a slug another tenant holds.

8. **The single tenant is not administrable.** `tenant.Single` is the empty id
   and, as Phase 9 records, the deployment with no tenant row to find. There is
   nothing to create, and no row to change.

9. **Misconfiguration fails when the composer is built**, per standing rule 4,
   and the guard ships with a test that fires (rule 6). `NewAdmin` is the thing
   that can be wired wrong — a plain function cannot fail at build time, which is
   why the composer is a type with a constructor rather than one exported func.

10. **A suspension is audited, and the row's scope is the tenant it suspends.**
    A lifecycle write is exactly the action an auditor asks about, and the
    console is an UNTENANTED surface: `espresso.Auditor.For` there derives the
    scope from the pinned tenant (`espresso/audit.go`, `eventScope`), so it would
    write `Event.TenantID = ""` and the row would be **absent from the suspended
    tenant's per-tenant export**, because that export filters on `Event.TenantID`.

    `Admin.Suspend` therefore emits its own event:

    | Field | Value |
    |---|---|
    | `Event.TenantID` (the row's scope) | the **target** tenant |
    | `Actor.TenantID` (the actor's home) | the operator's, from the claims in the context |
    | `Action` / `ResourceType` / `ResourceID` | `tenant.suspend` / `tenant` / the target id |

    That keeps the two facts apart exactly as Phase 8 §3 requires, and puts the
    row where a customer's own export can see it. The logger is a required
    argument to `NewAdmin`: a deployment that does not want audit says so with
    `audit.NewNoopLogger()`, which is a decision rather than an omission.

---

## 3. The model

```
console (platform admin)
  │
  ▼
admin.Suspend(ctx, acme)
  │
  ├── 1. AdminStore.SetStatus(acme, suspended)
  │        └── error -> return; nothing else happened
  │
  ├── 2. Core.RevokeAllSessionsForTenant(acme)
  │        ├── ok    -> nil
  │        └── error -> error naming BOTH: tenant suspended, sessions may remain
  │
  ▼
Phase 9's RequireActiveTenant now refuses acme on every request.
```

Reads do not change: `tenant.Store.ByID`/`BySlug` still answer, and the gate
still reads whatever the row says. Nothing in Phase 9 needs to change for this
phase to land, which is the point of having split them.

**Resuming is the easy direction.** `SetStatus(ctx, id, tenant.StatusActive)`
needs no composer and revokes nothing: the gate stops refusing on the next
request, and the sessions that were revoked at suspension are simply gone. There
is therefore no `Unsuspend`, and there is nothing to get out of order.

**What a suspension does and does not close.** The status write takes effect on
the next request; the revocation takes effect on the next refresh. An access
token already minted stays valid until it expires — the same window Phase 9
names. `Suspend` shortens it from "one token lifetime, unknowable" to "one
refresh cycle, at a known moment".

---

## 4. API

```go
package tenant

// AdminStore is the opt-in write port. It is the application's adapter over its
// own table, the write-shaped sibling of Store; tamper names no table.
type AdminStore interface {
    // List returns every tenant. The admin surface legitimately needs them
    // all, which is why it is not scoped by tenant.
    List(ctx context.Context) ([]Descriptor, error)

    // Create provisions one tenant. ErrConflict for an existing id or slug;
    // ErrSingleTenant when the id is empty — which IS the single tenant, its
    // string form — and ErrInvalidDescriptor for an unknown Status. Nothing is
    // written on any error.
    //
    // A non-empty ParentID is stored as given and nothing more: tamper does not
    // resolve it, inherit through it, or branch on it. This is where a hierarchy
    // deployment writes the parentage ADR-0001 reads through its own port.
    Create(ctx context.Context, d Descriptor) error

    // SetStatus moves one tenant to status. ErrNotFound for an unknown id;
    // ErrInvalidDescriptor for an unknown Status; ErrSingleTenant for
    // tenant.Single. Nothing is written on any error.
    //
    // Idempotent: setting the status a tenant already has succeeds and writes
    // nothing new. A retried suspension must not fail — see Suspend below.
    SetStatus(ctx context.Context, id tenant.ID, status Status) error
}
```

The composer, because it needs both stores:

```go
package tamper

// Admin holds what a lifecycle write needs: the tenant table, the identity side,
// and the audit chain. All three are required.
type Admin struct { /* admin tenant.AdminStore; core *identity.Core; log audit.Logger */ }

// NewAdmin returns an Admin.
//
// It panics on a nil AdminStore, a nil *identity.Core, or a nil audit.Logger: a
// composer missing a store would either set a status and revoke nothing, or
// revoke sessions for a tenant it never suspended, and one missing the logger
// would suspend a tenant silently. That is a wiring bug, so it fails when the
// composer is built (standing rule 4), and the guard ships with a test that
// fires (rule 6). A deployment that wants no audit passes audit.NewNoopLogger().
func NewAdmin(admin tenant.AdminStore, core *identity.Core, log audit.Logger) *Admin

// Suspend suspends a tenant and revokes its refresh sessions, IN THAT ORDER. It
// is the one supported way to do both: the status write stops the tenant serving
// (espresso.RequireActiveTenant), and the revocation closes the token window.
//
// Two stores per call, deliberately: admin is the tenant table, core is the
// identity side. A framework cannot atomically write both, so it reports a
// partial failure instead of pretending to prevent one.
//
// Refusals come from the status write, before anything else happens:
// ErrNotFound for an unknown tenant, ErrSingleTenant for tenant.Single,
// ErrInvalidDescriptor for a status this version does not know, and the store's
// own error otherwise. None of them revoke a session.
//
// The audit row (decision 10) is written after the status change. A failure to
// log it is reported with the partial-state wording, not swallowed: the tenant
// is suspended and the record is missing, which an operator must know.
func (a *Admin) Suspend(ctx context.Context, id tenant.ID) error
```

New sentinels, so a caller can tell the cases apart on its own surface:

```go
var (
    ErrConflict          = errors.New("tenant: tenant already exists")
    ErrInvalidDescriptor = errors.New("tenant: invalid tenant descriptor")
    ErrSingleTenant      = errors.New("tenant: the single tenant is not administrable")
)
```

**Shapes considered and rejected.**

- **Writes on `tenant.Store`**: forces every read-only adapter to implement or
  stub them, and hands mutation to code that only ever read (see decision 1).
- **`Suspend` as an `AdminStore` method**: the two writes are in different
  stores, so an `AdminStore` implementation could not keep the order without
  owning `identity.Store` too. The composer owns the order where both stores are
  in scope.
- **`Delete`**: decision 5.
- **A single `SetStatus` with the revocation inside it**: same problem as the
  second point, and it hides the partial-failure contract inside an adapter the
  framework cannot test.

---

## 5. Invariants

1. **Nothing is written on an error.** `Create`/`SetStatus` validate before the
   write, and a refusal leaves the table as it was.
2. **An unknown status is never stored**, and neither is an empty id or the
   single tenant.
3. **A duplicate is `ErrConflict`**, never an overwrite.
4. **`Suspend` writes the status before it revokes.** After any failure,
   the tenant is not serving; at worst its sessions outlive the call.
5. **A partial `Suspend` is reported**, with both facts in the error.
6. **There is no `Delete`**, and offboarding removes no row.
7. **Reads are unaffected**: `tenant.Store` is unchanged and Phase 9's gate
   needs no change.
8. **tamper adds no table and no migration.**

---

## 6. What this does not do

- **Domain lifecycle.** Claiming, verifying and removing a domain stays
  `DomainStore` + `DNSVerifier`. `AdminStore` does not touch it.
- **IdP / OIDC / SAML configuration.** Provider registries are their own ports.
- **Entitlements.** `EntitlementStore` is per tenant and unchanged; provisioning
  a new tenant does not copy a parent's entitlements (TD-04 is per axis).
- **Deletion, retention, GDPR erasure.** Decision 5. Erasure of PII inside the
  audit chain is the M5 redaction path, a separate operation on a separate port.
- **Authorization of the console itself.** Who may suspend a tenant is the
  application's decision — the same posture as the audit-log read surface.
  For a hierarchy deployment, ADR-0001's decision 6 covers who may grant.
- **The audit row is not the console's job** (decision 10). `Suspend` emits its
  own, scoped to the suspended tenant, because the console's own scope would place
  it outside that tenant's export. The console owns the authorization above, not
  the record.
- **Impersonation.** TD-07.

---

## 7. Proof obligations

Mutation proofs, each failing a named test.

| Mutant | Test that must go red |
|---|---|
| `Create` accepts an empty id, `tenant.Single`, or an unknown status | the per-case refusal tests |
| `Create` overwrites an existing id or slug instead of `ErrConflict` | the duplicate test |
| `SetStatus` accepts an unknown status | the unknown-status test |
| `SetStatus` returns nil for an unknown tenant | the not-found test |
| `Suspend` revokes before it sets the status | the ordering test (a failing status write must leave sessions untouched; a failing revoke must leave the tenant suspended) |
| `Suspend` swallows the revocation error | the partial-failure test |
| `NewAdmin` accepts a nil store, a nil core, or a nil logger | the panic test (rule 6: the guard ships with a test that fires) |
| `Suspend` emits its audit row with the console's empty scope instead of the target tenant | the per-tenant export test (the row must be in the suspended tenant's export) |
| `Suspend` swallows an audit failure | the partial-state test |

Plus, not mutation-based:

- `ErrConflict` is returned for a duplicate slug even when the id is new, and the
  reverse.
- `Suspend` on an already-suspended tenant succeeds and still revokes (an
  idempotent suspension is a normal retry).
- A refused `SetStatus` leaves the previous status readable through `ByID`.

---

## 8. Relationship to Phase 9 (TD-06), and open questions

**Phase 9 is a prerequisite, and it is already in `main`.** The gate is what
makes a status change mean anything on the request path. This phase adds no
enforcement; it adds the write and the pairing.

When this lands, one sentence in Phase 9 changes and nothing else: the
"accepted window" moves from *"a suspension still leaves valid access tokens
until they expire"* to *"until the next refresh cycle, at the moment of
`Suspend`"*.

**Open questions for the owner:**

- **A fourth status for offboarding, or reuse `StatusSuspended`?** Suspension
  reads as reversible; offboarding does not. Phase 9's gate refuses *any*
  non-active status, so a `StatusDisabled` would be additive and needs no gate
  change. Proposal: add it when offboarding gets a real retention policy, not
  before.
- **Who may call `Suspend`?** The framework cannot answer this; the
  console's own authorization does. For a tenant-hierarchy deployment, ADR-0001
  decision 6 (only a platform admin grants) is the nearest recorded answer.
- **Does `List` need pagination?** A platform console with thousands of tenants
  says yes; the signature above says not yet. Proposal: `List(ctx)` now, and a
  `ListPage` added later without breaking it — a separate method, not a changed
  one.
- **Does `Create` allocate the id, or accept one?** The descriptor carries an
  opaque app-defined id and tamper never derives it, so `Create` accepts it.
  A deployment that wants UUIDs generates them in the adapter.
