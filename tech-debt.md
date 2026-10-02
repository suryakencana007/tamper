# Tech debt — cross-tenant platform admin and organization hierarchy

This document lists what is missing in Tamper for two needs:

- a **super admin / platform admin / console admin** user who can access many
  tenants;
- an **organization hierarchy** (parent and child tenants).

It was written from the code at `v0.6.0` (commit `c1af24e`). The flows that
exist today are described in [`flow.md`](flow.md).

## Summary

Tamper does not support these needs out of the box. Its model is "one user =
one tenant" and "one token = one tenant", on purpose. The tenant hierarchy is
only a reserved field today.

Most items below are **gaps against a new requirement**, not bugs. Phase 7
chose these limits deliberately. Three items are **sharp edges that exist
today** in a pooled deployment, with or without a platform admin: TD-08,
TD-09, and TD-10. These three come from reading the code. They are not yet
proven by a failing test.

| ID | Title | Kind | Priority | Change in |
|---|---|---|---|---|
| TD-01 | A user can belong to only one tenant | gap | P0 | Tamper + application |
| TD-02 | A token is locked to one tenant; no "enter tenant" flow | gap | P0 | Tamper |
| TD-03 | `authz` does not know about tenants | gap | P0 | Tamper |
| TD-04 | No tenant hierarchy | gap | P1 | Tamper + application |
| TD-05 | No tenant lifecycle | gap | P1 | Tamper |
| TD-06 | Tenant suspension is not enforced on authenticated requests | gap | P1 | Tamper |
| TD-07 | No impersonation | gap | P1 | Tamper |
| TD-08 | `Auditor` and `RequireAuth` do not set the tenant | sharp edge | P1 | Tamper |
| TD-09 | `tamper.New` cannot turn on audit v4 | sharp edge | P1 | Tamper |
| TD-10 | The TOTP path mints a token without a tenant | sharp edge | P1 | Tamper |
| TD-11 | The audit log cannot be queried per tenant | gap | P2 | Tamper |
| TD-12 | A service account has only one tenant | gap | P2 | Tamper |
| TD-13 | Second-factor policy cannot be set per role | gap | P2 | Tamper |
| TD-14 | The per-tenant route mounting pattern is static | gap | P2 | example + docs |

P0 = the feature cannot be built safely without this. P1 = the application can
work around it, but mistakes are easy. P2 = convenience and completeness.

## P0

### TD-01 — A user can belong to only one tenant

**Evidence.** `identity.User.TenantID` is a single string
(`identity/identity.go:40`). `MIGRATION-v0.4.md:156` says it directly: a user
who really belongs to more than one tenant ("a support engineer who is a real
user in every tenant") cannot be expressed. The suggested shape is one user row
per (person, tenant), with a membership table owned by the application.

**Impact.** A platform admin has no place in the identity model. There is no
membership port and no idea of a "cross-tenant identity". Also,
`tenanttest.RunLeakSuite` has no test case for cross-tenant access that is
*allowed*.

**Workaround in the application.** Create a special tenant (for example
`platform`) and register console admins as users there. Keep the cross-tenant
rights in your own table.

**Proposal for Tamper.** An optional port `identity.MembershipStore`
(`MembershipsFor(userID)`, `IsMember(userID, tenant)`), opt-in like
`InvitationStore`. Standing rule 6 applies: ship a boot guard and a test that
proves the guard fires.

### TD-02 — A token is locked to one tenant; no "enter tenant" flow

**Evidence.** The `tid` claim holds one tenant (`crypto/jwt.go:296`).
`VerifyAccess` requires an exact match (`crypto/jwt.go:438`). `RequireTenant`
rejects every mismatch with a 401 (`espresso/tenantgate.go:112`). There is no
platform scope and no function to exchange a token for another tenant.

`Core.IssueTokensForUserInTenant` (`identity/core.go:331`) can mint a token for
any user in any tenant. It only rejects an unset tenant. It does **not** check
that the user has a right to that tenant.

**Impact.** The building block for "enter tenant X" exists, but the caller
must do the whole rights check. One call without the check is a cross-tenant
grant.

**What not to do.** A wildcard token (an empty `tid`, or `*`, accepted in every
tenant). It breaks standing rule 2 (deny by default). It also brings back the
ambiguity that `tenant.ID` was created to remove.

**Proposal for Tamper.** An explicit exchange function, for example
`Core.EnterTenant(ctx, actorUserID, homeTenant, targetTenant, authTime, acr)`.
It should:

- call `MembershipStore` or `authz.Check` before minting;
- produce a token with the target tenant in `tid`, a short TTL, and **no**
  refresh session (or a session that records where the actor came from);
- add an origin claim, for example `htid` (home tenant), so that `RequireAuth`
  can set `Actor.TenantID` correctly (see TD-07, TD-08).

### TD-03 — `authz` does not know about tenants

**Evidence.** `authz.Subject` and `authz.Resource` are only `{Type, ID}`
(`authz/authz.go:26`, `:36`). `BindingStore` and `PermissionStore` take no
`tenant.ID` (`authz/store.go:29`, `authz/permissionset.go:58`). The word
"tenant" does not appear in the `authz` package. `RequireDecision` builds the
subject from the user id only (`espresso/decision.go:101`).

**What already works.** A platform admin can be modelled with an application
convention:

- RBAC: add `Requirement{Type: "platform", Min: "admin"}` as a global
  alternative on every action, plus a binding on
  `Resource{Type: "platform", ID: ""}`.
- PermissionSet: the store returns `Superuser: true`.
- Tenant admin: `Resource{Type: "tenant", ID: "<tenant>"}`.

**Impact.** No contract protects tenant isolation in the authorization layer.
A store that forgets to filter by tenant still compiles and still passes every
Tamper test. There is no `RunLeakSuite` for `authz`. Also, a user id is only
guaranteed to be unique inside one store, so cross-tenant bindings depend fully
on the application's discipline.

**Proposal for Tamper.** Two options. Choose one through a sketch amendment:

1. Add `tenant.ID` to `CheckRequest` and to the port methods. This is a
   breaking change, like what v0.4.0 did to `identity.Store`.
2. Keep the ports as they are, but publish `authz/tenanttest` with a leak suite
   for the "tenant as a resource type" convention, and document that convention
   as a contract.

## P1

### TD-04 — No tenant hierarchy

**Evidence.** `Descriptor.ParentID` is marked RESERVED: "Nothing in tamper
resolves it, inherits through it, or branches on it" (`tenant/tenant.go:19-25`).
`PHASE7-MULTITENANCY-SKETCH.md:510` (§8 item 3) defers it on purpose.
`tenant.Store` has only `ByID` and `BySlug` (`tenant/store.go:51`). The RBAC
engine has no containment graph (`authz/policy.go:38`), and it cannot express
AND-gates (`authz/policy.go:49`).

**Impact.** Nothing is inherited from parent to child:

- roles: an admin of the parent organization is not an admin of its units;
- IdP: `Manager.GetRegistry(ctx, tenant)` (`oidc/manager.go:366`,
  `saml/manager.go:385`) looks up the exact tenant, so the parent's SSO does
  not serve a child;
- entitlements: `EntitlementStore.ForTenant` (`tenant/entitlements.go:68`) is
  also exact;
- domains: a parent's domain claim does not apply to a child.

**Workaround in the application.** The engine leaves all indirection to the
store. So the application's `BindingStore` may return bindings that come from
ancestors. Entitlements and the IdP registry can be wrapped by an adapter that
walks up to the parent. Decide inheritance for each axis separately. Do not
assume the answer is the same for all of them.

**Proposal for Tamper.** First answer the product question the sketch deferred
(does the parent's IdP serve a child?). Then add `tenant.Store.Ancestors(id)`
and `Children(id)`. Make inheritance opt-in per axis, with cycle detection like
`scim.DetectCycle`.

### TD-05 — No tenant lifecycle

**Evidence.** The `tenant.Store` port is read-only (`tenant/store.go:51-59`).
There is no create, list, status update, or delete.

**Impact.** The application must write the whole platform console (list
tenants, create, suspend, offboard) with no contract from Tamper. Two useful
pieces already exist: `Core.RevokeAllSessionsForTenant`
(`identity/core.go:463`) and `DomainStore.ListForTenant`.

**Proposal for Tamper.** A separate opt-in port `tenant.AdminStore` with
`List`, `Create`, `SetStatus`, plus one `Suspend` operation that changes the
status and revokes the sessions together.

### TD-06 — Tenant suspension is not enforced on authenticated requests

**Evidence.** `Descriptor.Status` is checked only in `StartLogin`
(`espresso/startlogin.go:264`), and only when `WithStartLoginTenants` is set.
`RequireTenant` takes no `tenant.Store` and does not check the status
(`espresso/tenantgate.go:94`).

**Impact.** A suspended tenant is still served for access tokens that are still
valid, and for password login, unless the application adds its own gate.

**Proposal for Tamper.** A middleware `RequireActiveTenant(store)` that runs
after `RequireTenant` / `PinTenant`. On unauthenticated routes its response
must look the same as for an unknown tenant (standing rule 3).

### TD-07 — No impersonation

**Evidence.** `AccessClaims` has no "acting on behalf of" claim
(`crypto/jwt.go:258-299`). `audit.ActorType` knows only user, service account,
and system (`audit/audit.go:78-`).

**Impact.** When a platform admin works inside a customer tenant, the log
cannot separate "platform admin as themself" from "platform admin as user X".
For ISO 27001 A.8.15, auditors usually ask for exactly this difference.

**Proposal for Tamper.** An `act` claim (the real actor) next to `sub`, a field
`Actor.ImpersonatorID`, and special audit actions when impersonation starts and
ends. `Actor` is part of the canonical payload, so this change touches
`canonical_version` and needs a sketch amendment.

### TD-08 — `Auditor` and `RequireAuth` do not set the tenant *(sharp edge)*

**Evidence.** `decorateAuthed` sets `audit.Actor{Type, UserID}` without
`TenantID`, even though `claims.TenantID` is available
(`espresso/auth.go:168-176`). `Auditor.For` builds the `audit.Event` without
`TenantID` (`espresso/audit.go:111`). The file `espresso/audit.go` does not
mention tenants at all.

**Impact.** In a pooled deployment, audit rows written by the `Auditor`
middleware have an empty `Event.TenantID`. `ExportForTenant` filters on that
field (`audit/export.go:99`). So these rows do not appear in the export of any
tenant except `tenant.Single`. The audit design already separates
`Event.TenantID` from `Actor.TenantID` for the cross-tenant admin case, but the
HTTP adapter does not fill them in.

**Proposal for Tamper.** `decorateAuthed` sets `Actor.TenantID` from the claim.
`Auditor.For` sets `Event.TenantID` from `TenantFromContext`. This changes the
content of audit rows, so it must be proven that the bytes on the
`tenant.Single` path do not change (standing rule 1).

### TD-09 — `tamper.New` cannot turn on audit v4 *(sharp edge)*

**Evidence.** `AuditConfig` has only `DBPath` and `EmailLookup`
(`provider.go:65`). `New` calls `audit.NewSQLiteLogger` without `Tenancy`
(`provider.go:167`). The option exists in `SQLiteLoggerOptions`
(`audit/audit_sqlite.go:91`).

**Impact.** Through the root facade, the logger always writes
`canonical_version=3`. The tenant is not in the hash, and PII cannot be
redacted. A pooled application must build its own logger outside `tamper.New`.

**Proposal for Tamper.** A field `AuditConfig.Tenancy` that is passed through
as-is. The default is `false`, so current behaviour does not change.

### TD-10 — The TOTP path mints a token without a tenant *(sharp edge)*

**Evidence.** The `espresso.IdentityService` port has only
`IssueTokensForUser(ctx, userID)` (`espresso/authroutes.go:50`), and
`AuthRoutes.VerifyTOTP` calls it (`espresso/authroutes.go:267`).
`Core.IssueTokensForUser` mints with `tenant.Single` (`identity/core.go:295`).

**Impact.** An adapter that passes this call straight to `Core` produces a
token with no `tid` after TOTP verification. `RequireTenant` then rejects that
token on a tenant route. It fails closed (deny), so nothing leaks. But a user
with 2FA cannot sign in until the adapter uses `IssueTokensForUserInTenant`.

**Proposal for Tamper.** Document this duty on the port. Or change the port
signature to carry the tenant, so the mistake fails at compile time.

## P2

### TD-11 — The audit log cannot be queried per tenant

**Evidence.** `audit.Filter` has no tenant field (`audit/audit.go:364`).
`ListScoped` filters on `clusterIDs`, a concept inherited from Barista
(`audit/audit.go:419`). The only per-tenant path is `ExportForTenant`, which
returns every row with no paging.

**Impact.** A platform console cannot show "activity of tenant X this week" or
"all platform-admin actions in any tenant" without pulling the full export.

**Proposal for Tamper.** `Filter.TenantID` and `Filter.ActorTenantID`, both of
type `tenant.ID`, so that an unset value means "no filter" only when the caller
says so explicitly.

### TD-12 — A service account has only one tenant

**Evidence.** `Principal.TenantID` is a single value
(`espresso/sagate.go:43`). `scimTenant` reads it directly
(`espresso/scimroutes.go:158`).

**Impact.** Platform-level automation (tenant provisioning, cross-tenant sync)
has no matching principal.

**Proposal for Tamper.** Keep SCIM at one tenant per token. For platform
automation, add a separate principal that is valid only on platform routes.

### TD-13 — Second-factor policy cannot be set per role

**Evidence.** `identity.WithTOTPRequired` applies to the whole process
(`identity/core.go:54`).

**Impact.** You cannot say "platform admins must use 2FA, normal users need
not".

**Workaround in the application.** Put `RequireFreshAuth` with strict
`acrValues` on every platform route. The local-password ACR does not satisfy
step-up by design, so platform admins must sign in through an IdP with MFA.

### TD-14 — The per-tenant route mounting pattern is static

**Evidence.** `examples/multitenant/main.go:122` mounts one auth surface per
tenant in a loop at boot, with an adapter that closes over the tenant id. The
port method `IdentityService.Login(ctx, email, password)` takes no tenant
(`espresso/authroutes.go:39-41`).

**Impact.** If an application copies the example, a tenant created at runtime
by the platform console gets no routes until the process restarts.

**Proposal.** Add an example adapter that reads `TenantFromContext` after
`PinTenant`, so one surface serves dynamic tenants.

## What is ready to use

These are not debt, but they matter when you design the workarounds:

- `Event.TenantID` is separate from `Actor.TenantID`. The code comment names
  the cross-tenant support engineer case explicitly.
- Global bindings in RBAC, and the `Superuser` flag in PermissionSet.
- `RequireDecision` with the two-check flow: 404 for not visible, 403 for tier.
- `RequireFreshAuth` for step-up on sensitive actions.
- `IssueTokensForUserInTenant` as the tenant-bound mint primitive.
- `RevokeAllSessionsForTenant` for offboarding and incident response.
- `Signer` and `WithVerifiers` in `crypto`, if platform tokens need a key
  separate from tenant tokens.

## Recommended order

Without changing Tamper, an application can already run with three things: a
special `platform` tenant, its own membership table, and a per-tenant token
exchange through `IssueTokensForUserInTenant` after an `authz.Check`. This is
enough for a console prototype. Note that TD-08 means cross-tenant actions are
not recorded with the right scope unless the application writes those events
by hand.

Suggested slice order if this work moves into Tamper:

1. **TD-09, TD-08, TD-10** — the sharp edges that exist today. They are small,
   and TD-08 is required for a correct audit trail in every other item.
2. **TD-01 + TD-02** — the membership port and `EnterTenant`. They are one
   design decision and must be designed together.
3. **TD-03** — the tenant contract for `authz`, with its leak suite.
4. **TD-07 + TD-11** — impersonation and per-tenant audit queries.
5. **TD-05 + TD-06** — tenant lifecycle and suspension enforcement.
6. **TD-04** — hierarchy, after the product question in sketch §8 item 3 is
   answered.
7. **TD-12, TD-13, TD-14** — the rest.

## Process limits

`CLAUDE.md` says Phase 7 is complete, and `PHASE7-MULTITENANCY-SKETCH.md` is a
design freeze. Any item that touches `identity`, `crypto/jwt.go`, `oidc`,
`saml`, `scim`, `espresso`, or `audit` needs a sketch amendment (or a new
phase sketch) before any code. Two earlier decisions are affected. They must be
reopened explicitly, not bypassed:

- "one row, one tenant" (`MIGRATION-v0.4.md`), by TD-01;
- "nested tenants are deferred" (sketch §8 item 3), by TD-04.

Standing rule 7 still applies: each item is a separate change.
