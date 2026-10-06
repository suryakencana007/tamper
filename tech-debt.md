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
chose these limits deliberately. Six items were found as **sharp edges that
exist today**, with or without a platform admin: TD-08, TD-09, TD-10, TD-15,
TD-16, and TD-17. All six are fixed or resolved; see the fix status below.

**Fix status (2026-10-05).**

| Item | Pull request | State |
|---|---|---|
| TD-15 | #39 | Merged. Guard with an explicit opt-out. |
| TD-10 | #40 | Merged. Contains behaviour changes. |
| TD-08 | #43 | Merged. |
| TD-09, TD-16, TD-21, TD-24, TD-25 | #46 | Merged. The audit log is v4-only; these five items cannot occur any more. |
| TD-19 | #47 | Merged. |
| TD-22 | #48 | Merged. |
| TD-17 | #49 | Merged. |
| TD-18 | #50 | Merged. |
| TD-20 | #51 | Merged. |
| TD-23 | #52 | Merged. |
| TD-26 | #54 | Merged. |

Ten more items (TD-18 to TD-27) were found while the fixes were written and
reviewed. They are listed after TD-17. Of all the sharp edges found, only
TD-27 is still open: Barista must move to the v4-only audit API (and, since
#56, to the tenant-scoped `authz` API).

Every fix had a code review, and the reviews changed the fixes:

- #39 and #40: see the **Fix** paragraphs of TD-15 and TD-10. The findings
  that were not fixed are recorded in TD-18, TD-20 and TD-23.
- The audit fixes went through three designs. #41 (repair a late anchor) and
  #42 (a `Tenancy` flag on `tamper.New`) worked around one root cause. #45
  (hash each row under its own version) fixed that cause but left a v3 row
  inside a v4 deployment unflagged. The owner then decided that v4 is the only
  version: #46 deletes everything before it, and #41, #42 and #45 are closed.

All six sharp edges, and the refresh-session problem in TD-02, were
**reproduced with tests on 2026-10-02**. The test sources and their output are
in [`tech-debt-proofs.md`](tech-debt-proofs.md). The tests are not in the Go
packages, because they fail until the problems are fixed. The other items are
gaps: something does not exist, so there is nothing to reproduce.

| ID | Title | Kind | Priority | Change in |
|---|---|---|---|---|
| TD-01 | A user can belong to only one tenant | fixed by #55 | — | — |
| TD-02 | A token is locked to one tenant; no "enter tenant" flow | fixed by #55 | — | — |
| TD-03 | `authz` does not know about tenants | fixed by #56 | — | — |
| TD-04 | No tenant hierarchy | gap | P1 | Tamper + application |
| TD-05 | No tenant lifecycle | gap | P1 | Tamper |
| TD-06 | Tenant suspension is not enforced on authenticated requests | gap | P1 | Tamper |
| TD-07 | No impersonation | gap | P1 | Tamper |
| TD-08 | `Auditor` and `RequireAuth` do not set the tenant | sharp edge | P1 | Tamper |
| TD-09 | `tamper.New` cannot turn on audit v4 | resolved by #46 | — | — |
| TD-10 | The TOTP path mints a token without a tenant | sharp edge | P1 | Tamper |
| TD-11 | The audit log cannot be queried per tenant | gap | P2 | Tamper |
| TD-12 | A service account has only one tenant | gap | P2 | Tamper |
| TD-13 | Second-factor policy cannot be set per role | gap | P2 | Tamper |
| TD-14 | The per-tenant route mounting pattern is static | gap | P2 | example + docs |
| TD-15 | SCIM tenant scoping is off by default | sharp edge | P1 | Tamper |
| TD-16 | `Verify` reports tamper on a mixed-version chain | resolved by #46 | — | — |
| TD-17 | `audit.Filter` fields are ignored by `List` | fixed by #49 | — | — |
| TD-18 | A not-found from the TOTP mint is a 500 on the wire | fixed by #50 | — | — |
| TD-19 | `Refresh` does not re-check the session's tenant | fixed by #47 | — | — |
| TD-20 | Step-up-denied audit rows carry no tenant | fixed by #51 | — | — |
| TD-21 | `HasChainRestartV2` / `V3` / `V4` count rows, not anchors | resolved by #46 | — | — |
| TD-22 | The multitenant example is out of date | fixed by #48 | — | — |
| TD-23 | A wrong-tenant token error has its own text | fixed by #52 | — | — |
| TD-24 | A v3 row in a v4 deployment is not flagged | resolved by #46 | — | — |
| TD-25 | `VerifyLegacy` reports tamper on a mixed-version chain | resolved by #46 | — | — |
| TD-26 | Generated SQL queries that nothing calls | fixed by #54 | — | — |
| TD-27 | Barista must move to the v4-only audit API and the tenant-scoped `authz` API | gap | P1 | Barista |
| TD-28 | Compatibility shims from before 2026-10-05 | gap | P1 | Tamper |

P0 = the feature cannot be built safely without this. P1 = the application can
work around it, but mistakes are easy. P2 = convenience and completeness.

## P0

### TD-01 — A user can belong to only one tenant *(fixed by #55)*

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

**Fix: #55.** Designed in `PHASE8-PLATFORM-ADMIN-SKETCH.md`, together with
TD-02. `identity.MembershipStore` is the port, enabled with
`WithMemberships`. A user still has one home tenant and one row; a membership
is a right to act inside another tenant. "One row, one tenant" is kept, not
reopened. `WithMemberships(nil)` panics, and a `Core` without the store
returns `ErrNoMembershipStore`; both are tested.

Not done: `tenanttest.RunLeakSuite` has no case for a `MembershipStore`. The
port has two methods and the `Core` treats every answer but `true` as a deny,
so the suite was left alone.

### TD-02 — A token is locked to one tenant; no "enter tenant" flow *(fixed by #55)*

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

There is a second problem. When the refresh TTL is above zero,
`IssueTokensForUserInTenant` also stores a refresh session with the target
tenant (`issueTokens`, `identity/core.go:481`). `Core.Refresh` then rotates
that session and checks only `user.Active` (`identity/core.go:347`). It does
not check the right again. So an admin whose cross-tenant right was removed can
keep getting new tokens for tenant X until the session expires.

**Proof.** `TestTD10_PendingTokenCannotMintIntoAnotherTenant`. For a user
stored in tenant `globex`, `IssueTokensForUserInTenant(…, acme, …)` returned no
error. The token had `tid="acme"`, passed `VerifyAccess(acme)`, and came with a
refresh token. `Refresh` then succeeded and returned a new token with
`tid="acme"`.

**Workaround in the application.** To enter a tenant, do not use
`IssueTokensForUserInTenant`. After the rights check, call
`Provider.JWT.IssueAccess(userID, tenant, authTime, acr)` directly. It mints
only a short-lived access token and stores no refresh session. When the token
expires, the admin enters the tenant again and the right is checked again.

**Partly fixed by #40.** `IssueTokensForUserInTenant` now refuses a tenant
that differs from the user's stored tenant, so it can no longer create a
cross-tenant session. Use `Provider.JWT.IssueAccess` for the workaround above.
The refresh part is still open; see TD-19.

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

**Fix: #55.** `Core.EnterTenant(session, target)` is the supported
cross-tenant mint. `session` is the verified claims of the user's home access
token.

- It asks `MembershipStore.IsMember` before it mints. A non-member, a missing
  user, and the single tenant on either side get the same `ErrNotFound`.
- The session must be a home session of the tenant the user is stored in. An
  entered token cannot be used to enter again.
- The token has `tid` = the tenant entered and a new claim `htid` = the
  user's home tenant. It works in the tenant entered and nowhere else, not
  even at home.
- **`RequireTenant` refuses an entered token.** Only a route mounted with
  `RequireTenantAllowEntered` accepts one. Existing routes assume the subject
  is a user of the routed tenant ("my account" handlers, `RequireDecision`),
  so they stay closed to guests until the application opts them in.
- There is **no refresh session**. When the token expires the caller enters
  again and the membership is checked again. `WithEnterTenantTTL` makes the
  token shorter. This answers the "second problem" above by design.
- `auth_time` and `acr` are copied from the session, so entering never renews
  a step-up.
- `Hooks.OnTenantEntered` runs after a successful entry. The application
  writes the audit row for the entry there.
- The audit actor carries the home tenant. A row written while entered has
  scope = the tenant entered and actor tenant = the home tenant.
- `IssueTokensForUserInTenant` is unchanged: only the user's own tenant.

`examples/multitenant` shows the flow over HTTP with a `platform` tenant.

Known limits, also in the sketch:

- A removed membership, or a deactivated admin, keeps working until the
  entered token expires.
- The home session is not checked for liveness: a home access token that has
  not expired can still enter after a logout.
- Entering is not throttled, and a refused entry is not recorded.
- On a route that accepts guests, what the guest may do was still the
  application's problem when #55 merged. #56 (TD-03) closes it.

### TD-03 — `authz` does not know about tenants *(fixed by #56)*

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

**Fix: #56.** Option 1 was chosen by the repo owner, with one more decision:
a guest needs a binding in the tenant they entered. Design:
`PHASE8B-AUTHZ-TENANT-SKETCH.md`.

- Every `Authorizer`, `BindingStore` and `PermissionStore` method takes a
  `tenant.ID` after `ctx`: the **scope**, the tenant whose resources are
  being acted on. A store that ignores tenants does not compile.
- `Subject` has a `Tenant` field, the subject's **home tenant**. The same id
  in two tenants is two subjects.
- `Binding` has a `Tenant` field, the scope it lives in. The RBAC engine
  drops a binding of another scope, or of another tenant's subject, even when
  the store returns it.
- An unset scope, or a subject with no home tenant, is `ErrTenantRequired`.
- No binding spans tenants. A platform admin who entered `acme` is the
  subject `{platform, user, id}` in scope `acme`, and gets only what `acme`
  granted to that subject. Roles held at home are never checked.
- `espresso.DecisionGate` has a required `Tenant` resolver. The gate asks in
  that tenant, requires the token to be for it, and takes the subject's
  tenant from the token. It never guesses a tenant. Its ghost probe
  (`UserExists`) is given the subject's home tenant.
- `authz/tenanttest` has a leak suite for each store port, and tests that
  prove the suites fail on stores that leak.

Left open:

- There is no cross-tenant role. An admin who works in ten tenants needs a
  binding in each. This follows from the decision above.
- The `PermissionSet` engine cannot filter by tenant itself, because a
  `PermissionSetResult` carries no tenant. Only the leak suite guards its
  store.
- Barista must move to this API (TD-27).

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

**Proposal for Tamper.** Three changes are needed together:

1. `decorateAuthed` sets `Actor.TenantID` from the claim.
2. `captureActor` keeps that value. Today it does not: for a user actor it
   ignores the actor in the context and builds a new
   `audit.Actor{Type, UserID, Email, IP}` (`espresso/audit.go:174-190`). So
   change 1 alone has no effect on rows written by `Auditor`.
3. `Auditor.For` sets `Event.TenantID` from `TenantFromContext`.

This changes the content of audit rows, so it must be proven that the bytes on
the `tenant.Single` path do not change (standing rule 1).

**Fix: #43.** All three changes, as proposed. The row's scope is the routed
tenant; there is no fallback to the actor's tenant. The single-tenant event is
unchanged. Rows written before the fix are not migrated.

**Proof.** `TestTD08_AuditorStampsTenant`. A request with an `acme` token went
through `RequireAuth` → `RequireTenant` → `Auditor.Mutation` into a v4 logger.
The row was written with `canonical_version=4`, `Event.TenantID=""`, and
`Actor.TenantID=""`. `ExportForTenant(acme)` returned 0 rows for that action.

### TD-09 — `tamper.New` cannot turn on audit v4 *(resolved by #46)*

**The problem.** A logger built by `tamper.New` always wrote
`canonical_version=3`, because `AuditConfig` had no way to pass the `Tenancy`
option. The tenant was not in the hash and PII could not be redacted.

**Resolved by #46.** There is no option any more. Every logger writes v4, so a
logger built by `tamper.New` does too. `tamper.Config` did not change.

**Proof of the original problem.** `TestTD09_NewCanWriteAuditV4`: a row logged
through `tamper.New` had `canonical_version=3`, and `RedactEvent` returned
`redacted=false`.

### TD-10 — The TOTP path mints a token without a tenant *(sharp edge)*

**Evidence.** The `espresso.IdentityService` port has only
`IssueTokensForUser(ctx, userID)` (`espresso/authroutes.go:50`), and
`AuthRoutes.VerifyTOTP` calls it (`espresso/authroutes.go:267`).
`Core.IssueTokensForUser` mints with `tenant.Single` (`identity/core.go:295`).

The TOTP-pending token carries no tenant (`IssueTOTPPending(userID)`,
`crypto/jwt.go:482`), and `Core.VerifyTOTP(userID, code)` is not tenant-scoped
(`identity/totp.go:158`).

**Impact.** There are two ways to get this wrong, and they fail in opposite
directions:

- *Fails closed.* An adapter that passes the call straight to `Core` produces
  a token with no `tid`. `RequireTenant` rejects that token on a tenant route.
  Nothing leaks, but a user with 2FA cannot sign in.
- *Fails open.* An adapter that "fixes" this by minting with the **routed**
  tenant, without checking the user, gives a cross-tenant token. A user of
  tenant B sends their pending token to tenant A's `/totp/verify`. Nothing in
  the pending token or in `VerifyTOTP` stops it, and the user receives an
  access and refresh pair with `tid=A`.

**Workaround in the application.** The tenant must come from the user's
**stored row**, not from the route alone. Load the user, compare
`user.TenantID` with the routed tenant, return not-found on a mismatch, and
only then call `IssueTokensForUserInTenant`. The example adapter does this
comparison (`examples/multitenant/identity_adapter.go:105`), but it then mints
through `IssueTokensForUser`, so its token still has no `tid`.

**Proposal for Tamper.** Put the tenant in the pending token (a `tid` claim)
and check it in `VerifyTOTPPending`. Also change the port signature to carry
the tenant, so a missing tenant fails at compile time.

**Fix: #40.** `IssueTokensForUserInTenant` refuses a tenant that differs from
the user's stored tenant, with the same `ErrNotFound` as a missing user. It
also refuses a deactivated user with `ErrUserInactive`, after the tenant check.
Because the check reads the row from `UserByID`, that method must return the
user's tenant; the leak suite now has a `UserByID` case for it. New
`IssueTOTPPendingInTenant` / `VerifyTOTPPendingInTenant` put the tenant in the
pending token. The example adapter uses both. The port signature is not
changed, so an adapter that forwards `IssueTokensForUser` straight to `Core`
still gets a token with no `tid`; the port's doc comments now say so.

**Proof.** Two tests.

- *Fails closed:* `TestTD10_PostTOTPMintCarriesTheUsersTenant`. For a user in
  `globex`, `Core.IssueTokensForUser` gave a token with `tid=""`.
  `VerifyAccess(globex)` rejected it with "invalid token".
- *Fails open:* `TestTD10_PendingTokenCannotMintIntoAnotherTenant`. The pending
  token of a `globex` user was accepted by `VerifyTOTPPending`, and
  `IssueTokensForUserInTenant(…, acme, …)` then gave a session with
  `tid="acme"`.

### TD-15 — SCIM tenant scoping is off by default *(sharp edge)*

**Evidence.** `SCIMConfig.Tenancy` is `false` by default
(`espresso/scimroutes.go:72-80`). With the default, every SCIM handler calls
the unscoped store methods, for example `s.users.Get(ctx, id)`
(`espresso/scimroutes.go:200-240`), and nothing reads `Principal.TenantID`.
v0.4.0 folded the tenant-scoped methods into `identity.Store`,
`oidc.ProviderStore`, and `saml.ProviderStore`. SCIM was not folded: it still
has the optional `TenantScopedUserStore` / `TenantScopedGroupStore` and a
flag.

**Impact.** A pooled deployment that forgets the flag still compiles and
boots. Tenant A's service account can then list and change tenant B's users
and groups. Unlike the identity and federation ports, a forgotten setting
here fails open.

**Workaround in the application.** Set `SCIMConfig.Tenancy: true` in every
pooled deployment. With the flag on, `NewSCIMRoutes` fails at boot if a store
does not implement the scoped interface.

**Proposal for Tamper.** Fold the scoped methods into `scim.UserStore` and
`scim.GroupStore`, the same way v0.4.0 did for the other ports. A
single-tenant deployment then passes `tenant.Single` explicitly.

**Fix: #39.** Not the fold. A guard: with `Tenancy` off, a principal that
carries a tenant is refused with a 500 `CONFIG_ERROR` before any store call. A
single-tenant principal is unchanged.

- The guard is one wrapper around each unscoped store, built in
  `NewSCIMRoutes`. No code in the package can reach an unscoped store method
  without passing it.
- There is an explicit opt-out, `SCIMConfig.TenantBoundStores`, for a
  deployment whose unscoped stores are already confined to one tenant (one
  `SCIMRoutes` per tenant, or stores that scope themselves). Tamper cannot
  verify that claim. `Tenancy` and `TenantBoundStores` together fail at
  `NewSCIMRoutes`.
- The guard fails per request, not at `New`, because `NewSCIMRoutes` never
  sees the validator.

The fold stays the long-term fix.

**Proof.** `TestTD15_SCIMDefaultConfigIsTenantScoped`. With the default
config, a principal of tenant A got `200` on `GET` of tenant B's user, `204` on
`DELETE` of tenant B's group, and `200` on the user list. Every store call was
the unscoped method. The principal's tenant never reached the store. (The test
store returns fixed data from its unscoped methods, so the proof is about which
method was called, not about the data returned.)

### TD-16 — `Verify` reports tamper on a mixed-version chain *(resolved by #46)*

**The problem.** `Verify` took the `canonical_version` of the newest
chain-restart anchor and applied it to every later row. A chain that mixed
versions behind one anchor then read as tamper although no row had been
changed: a v4 row behind a v3 anchor, a v3 row behind a v4 anchor, or an older
anchor written after the v4 one. It was first noticed because
`BootstrapChainV4` was skipped once any v4 row existed, so the missing anchor
could never be written.

**Resolved by #46.** There is one version and no anchor. `Verify` walks every
row from the first one. A row whose stored version is not 4 is reported at
that row, and a DB that already holds such a row is refused at open.

**Proof of the original problem.** `TestTD09_TenancyWithoutBootstrap`: on a
DB with a v3 anchor, switching `Tenancy` on and logging one row gave
`Verify -> tamper=true firstBad=2`, and a late `BootstrapChainV4` returned
`emitted=false`.

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
`PinTenant`, so one surface serves dynamic tenants. That adapter must still
check the user's stored tenant on the TOTP path (see TD-10).

### TD-17 — `audit.Filter` fields are ignored by `List` *(fixed by #49)*

**Evidence.** `audit.Filter` declares `Since`, `Until`, `ActorEmail`, and
`Action` (`audit/audit.go:364`), and its comment says zero-valued fields mean
"any". `SQLiteLogger.List` and `ListScoped` never read these four fields
(`audit/audit_sqlite.go:447`, `:573`). `List` picks exactly one query, in this
order: `RequestID`; `ResourceType` together with `ResourceID`; `ActorUserID`;
`Cursor`; otherwise all rows. `ResourceType` alone is also ignored.

**Impact.** A caller that asks for "only this action" or "only this time
range" gets unfiltered rows and no error. A console page built on these
fields shows unrelated events.

**Fix: #49.** `List` and `ListScoped` share one query. Every field that is set
is one condition, and the conditions are ANDed. `Since` is inclusive and
`Until` is exclusive. `ResourceType` alone and `ResourceID` alone now filter
too, and the cursor pages within the filter. The query is assembled in the
`audit` package; only fixed fragments and placeholders are concatenated, and
every value is bound.

A caller that relied on a field being ignored gets fewer rows now. A tenant
filter is still TD-11.

**Proof.** In `TestTD08_AuditorStampsTenant`,
`List(Filter{Action: "td.proof.mutation"})` returned 2 rows. Only 1 had that
action; the other was the chain anchor.

### TD-18 — A not-found from the TOTP mint is a 500 on the wire *(fixed by #50)*

**Evidence.** `mapAuthWireError` has no case for `identity.ErrNotFound`
(`espresso/wire.go:142`). The error falls to the default branch, which is a
500. After #40, `IssueTokensForUserInTenant` returns `ErrNotFound` for a
missing user and for a tenant mismatch.

**Impact.** With tenant-bound pending tokens the cross-tenant case stops
earlier, at `VerifyTOTPPending`, with a 401. The 500 remains for a user deleted
in the middle of the ceremony, and for an adapter that does not bind the
pending token. Standing rule 3 wants a deny and a miss to look the same.

The refusal also comes late. `AuthRoutes.VerifyTOTP` checks the code first and
mints after (`espresso/authroutes.go`). So when the mint is refused, a
single-use recovery code has already been spent.

**Fix: #50.** `AuthRoutes.VerifyTOTP` answers `ErrNotFound` from the mint
exactly as it answers a dead pending token: `401 UNAUTHENTICATED`, the same
bytes. The mapping is at that call site only, so no other route changes. On
the single-tenant path, a user deleted during the ceremony now gets 401 where
it got 500.

Still true after the fix: the refusal comes after the code check, so a
single-use recovery code is spent by then. The port has no way to ask first.
With tenant-bound pending tokens (#40) a cross-tenant attempt stops earlier,
before any code is read.

### TD-19 — `Refresh` does not re-check the session's tenant *(fixed by #47)*

**Evidence.** `Core.Refresh` rotates a session after checking only
`user.Active` (`identity/core.go:347`). It does not compare
`session.TenantID` with the user's stored tenant.

**Impact.** This is the rest of TD-02. After #40 the library no longer creates
a session whose tenant differs from the user's. But a row that already exists,
or one written by the application, keeps rotating.

**Fix: #47.** `Refresh` compares the session's tenant with the user's stored
tenant. On a mismatch it revokes the session and returns `ErrInvalidSession`.
The check runs before the `Active` check, so `ErrUserInactive` is never
reported through a session bound to another tenant.

One consequence to know: `IssueTokensForUser` and `IssueTokensForUserWithACR`
write a session with no tenant. For a user stored in a tenant, that session
can no longer be refreshed. A pooled adapter must mint with
`IssueTokensForUserInTenant`.

### TD-20 — Two kinds of audit rows still carry no scope *(fixed by #51)*

**Evidence.** #43 fills the tenant for user requests that pass `RequireTenant`
or `PinTenant`. Two emitters are not covered:

- `emitStepUpDenied` builds its own `audit.Actor` and `audit.Event`
  (`espresso/stepup.go:232`, `:256`). Neither gets a tenant. It does not go
  through `captureActor`, although its comment says it does.
- An `Auditor` route behind `RequireServiceAccount`. The actor carries the
  service account's tenant, but no tenant is pinned in the context, so
  `Event.TenantID` stays empty.

**Impact.** The same as TD-08 for those rows: they are missing from
`ExportForTenant` of the real tenant.

**Fix: #51.** One function, `eventScope`, decides the scope for both
emitters:

- The scope is the routed tenant, the one `RequireTenant` or `PinTenant`
  pinned.
- For a user actor there is no fallback, as in #43.
- A service account is the exception. Its tenant comes from the validated
  credential and it acts in no other tenant, so with nothing pinned its tenant
  is the scope. A pinned tenant still wins.

The step-up denial's actor also carries its home tenant from the token. A
step-up gate must be mounted inside `RequireTenant` for its denial to be
scoped.

The service-account rule is a decision the owner may want to revisit: the
alternative is for `RequireServiceAccount` to pin the tenant in the context.

### TD-21 — `HasChainRestartV2` / `V3` / `V4` count rows, not anchors *(resolved by #46)*

**The problem.** The three methods counted every row at a version, not anchor
rows, so their answer was wrong in both directions.

**Resolved by #46.** The methods and the anchors are deleted.

### TD-22 — The multitenant example is out of date *(fixed by #48)*

**Evidence.** In `examples/multitenant`, the `/me` route uses `RequireAuth`
without `RequireTenant` (`main.go:143`). The cross-tenant check for that route
lives in the adapter instead: `tenantIdentity.Me` compares the user's stored
tenant with its own (`identity_adapter.go:68`). Comments in
`identity_adapter.go` and `main.go` still describe `tid` and `RequireTenant`
as future work, and mention `Tenancy.Enabled`, which no longer exists.

**Impact.** `/me` itself is protected, by the adapter. But the example is the
proving ground for pooled tenancy, and people copy it. An authenticated route
added next to `/me` gets no tenant check at all, because the pattern shown
puts the check in one handler's adapter and not in a gate on the route.

**Fix: #48.** The `/me` route is now `RequireAuth` → `RequireTenant` →
handler, with a comment that every authenticated route beside it needs both.
The adapter's stored-tenant check stays as a second fence. The stale comments
are rewritten.

A test shows why the gate is needed and not only tidy: a token signed with the
deployment's key, for a user stored in `globex`, but with `tid=acme`, was
served on the `globex` route when only the adapter checked. The adapter
compares the user row, not the token. With the gate it gets a 401 that is
byte-identical to an invalid token's.

### TD-23 — A wrong-tenant token error has its own text *(fixed by #52)*

**Evidence.** `VerifyAccess` and `VerifyTOTPPendingInTenant` return
`ErrInvalidToken` with the text "token not valid" on a tenant mismatch
(`crypto/jwt.go`). Other failures on the default HS256 path include the JWT
library's own text, for example for an expired token. `errors.Is` cannot tell
them apart, but `err.Error()` can.

**Impact.** The comments say a mismatch is indistinguishable from an ordinary
invalid token. That holds on the wire, because the built-in routes answer with
a generic 401. It does not hold for an adapter or a log line that shows the
error text: "token not valid" then means "a real token, aimed at the wrong
tenant".

**Fix: #52.** Every verification failure returns one error whose text is
always `auth: invalid token: token not valid`. The reason is kept in the error
chain (`errors.Is(err, jwt.ErrTokenExpired)` still works), and it is never
part of the text. The errors the `Issue*` methods return for a bad argument
keep their text; they are caller bugs.

### TD-24 — A v3 row in a v4 deployment is not flagged *(resolved by #46)*

**The problem.** A v3 hash does not cover the tenant. A v3 row written after
`Tenancy` was switched on (by a replica on the old config, or by an explicit
older version on an event) could have its tenant changed without `Verify`
noticing.

**Resolved by #46.** No v3 row can be written: `Log` refuses every version but
4. Every row's tenant is inside its hash.

### TD-25 — `VerifyLegacy` reports tamper on a mixed-version chain *(resolved by #46)*

**The problem.** `VerifyLegacy(N, "")` linked only the rows at version N, so
it reported tamper on a chain where versions were interleaved.

**Resolved by #46.** `VerifyLegacy` is deleted. There is one version.

### TD-26 — Generated SQL queries that nothing calls *(fixed by #54)*

**Evidence.** #46 deletes the code that used these generated queries in
`audit/internal/sqlitestore`: `CountChainRestartV2`, `GetLatestChainRestart`,
`GetLatestChainRestartAtVersion`, `ListEventsForVerifyFromChainRestart`,
`ListEventsByCanonicalVersion`, `UpdateEventHash`. The generated layer was
left alone, because CI regenerates it with sqlc and compares, and sqlc was not
available where #46 was written.

#49 replaces the per-filter list queries with one assembled query, so these
are unused as well: `ListEventsAll`, `ListEventsBefore`, `ListEventsByActor`,
`ListEventsByRequest`, `ListEventsByResource`, `ListEventsNonClusterScoped`,
`ListEventsNonClusterScopedBefore`.

**Impact.** Dead code only. `UpdateEventHash` is worth removing for its own
sake: nothing in a tamper-evident log should be able to rewrite a stored hash.

Two more things wait for the same regeneration:

- `NewSQLiteLogger` checks for rows before v4 with the existing
  count-by-version query. That scans the whole table on every open, with no
  context. A query that stops at the first such row would be cheaper.
- `sqlitestore.Open` runs its migrations before that check, so a file that is
  then refused has already been migrated.

**Fix: #54.** Sixteen queries are deleted from `queries/events.sql` and the
layer is regenerated with sqlc v1.30.0, the pinned version. The thirteen named
above, plus `CountEvents` and `CountEventsByAction`, which nothing called
before either, plus `CountEventsByCanonicalVersion`, which the new check
replaces. Eleven queries remain and each has a caller. `UpdateEventHash` is
gone: nothing in the package can rewrite a stored hash.

The open-time check is also fixed, with a schema migration:

- Migration 006 adds a partial index over the rows that are not v4. On a
  healthy DB the index is empty, so the check reads nothing. A test asserts
  that the query plan uses the index.
- The refusal lists how many rows there are at each version, lowest first.
  The count matters: one stray row in a v4 file is a row that was changed; a
  file of older rows is an old file.
- A `canonical_version` that is not an integer cannot be read. That open also
  fails, and its error also says to keep the file.

Left as it is:

- `sqlitestore.Open` still runs its migrations before the check, so a refused
  file has already been migrated (and now also gets the index).
- `NewSQLiteLogger` takes no context, so the check cannot be cancelled. With
  the index it has nothing to wait for on a healthy DB.

### TD-27 — Barista must move to the v4-only audit API and the tenant-scoped `authz` API

**Evidence.** #46 removes API that Barista uses in its audit CLI and its boot
path: `VerifyLegacy`, `MigrateLegacyV2Hashes`, `RehashChainInPlace`,
`HasChainRestartV2` / `V3`, the chain-restart actions, `IsReservedAction`,
`CountByCanonicalVersion`, `ListByCanonicalVersion`, and
`VerifyBootResult.Segments`.

**Impact.** Barista does not compile against #46 until it is changed. Its
existing audit DB cannot be opened either: `NewSQLiteLogger` refuses a DB with
rows before v4, so Barista needs a fresh audit file. This was decided knowing
that nothing is in production. It was not done or tested where #46 was written.

**Proposal.** In Barista: drop the legacy boot bootstraps and the `--legacy`
and migrate commands, keep the boot call to `VerifyChainPostMigration`, and
start a fresh audit DB.

**Added by #56 (TD-03).** The `authz` ports now take a `tenant.ID`, and
`Subject` and `Binding` have a `Tenant` field. Barista's binding store and
permission store do not compile against #56 until they take the new argument.
Barista is single-tenant, so the change is mechanical: pass `tenant.Single`
as the scope, set `Tenant: tenant.Single` on every subject and binding,
ignore the argument in the queries, add the tenant argument to its
`UserExists` probes, give every `DecisionGate` a `Tenant` resolver that
returns `(tenant.Single, true)`, and handle the error its binding store's
writes now return. It was not done or tested where #56 was
written.

### TD-28 — Compatibility shims from before 2026-10-05

**Background.** Through Phase 7 the rule was that an empty tenant must behave
exactly as before tenants existed. On 2026-10-05 the repo owner replaced it:
no compatibility code (`CLAUDE.md` standing rule 1). Single-tenant stays
supported, but the application says `tenant.Single` out loud.

**Evidence.** These exist only so that old callers keep working. The list
comes from a read of the code and each line must be checked again when its
change is made.

| Where | What |
|---|---|
| `crypto` | **Done in #57.** `Issue`, `Verify`, and the tenant-less `IssueTOTPPending` / `VerifyTOTPPending` are removed. A token with no `purpose`, no `auth_time` or no `acr` is refused. |
| `identity` | **Done in #58.** `IssueTokensForUser` and `…WithACR` are removed; `…InTenant` is now `IssueTokensForUser(user, tenant, authTime, acr)`. The fallbacks to "now" and the default ACR, and the rotation of a session row with no `auth_time`, are gone. |
| `espresso.IdentityService` (port) | `IssueTokensForUser(ctx, userID)` and the TOTP-pending methods take no tenant. This is the root of TD-10, which was patched in the adapter, not in the port. |
| `espresso` SCIM | `SCIMConfig.TenantBoundStores` and the unscoped store path. |
| `espresso` | `ContextWithUserID` and `SetUserID` put a user id in the context with no token. |
| `espresso` | The resolvers of `RequireTenant`, `RequireTenantAllowEntered` and `PinTenant` return a `string`, and `""` becomes `tenant.Single`. A route pattern with no tenant segment is then served as a single-tenant route. `DecisionGate.Tenant` already returns `(tenant.ID, bool)`; these should too. |
| `identity` throttling | A `Core` built without `WithThrottling` permits unlimited password and second-factor attempts. The doc says this is allowed "because it is the pre-7k-1 behavior". Whether `New` should require a throttle is a product decision, not a shim removal; it was not changed in #58. |
| `identity/legacy_adapter_test.go` | A hand-written `Store` that stands in for a pre-Phase-7 adapter. It is still a useful second implementation of the port; its framing as "the compatibility path" is not. |
| tests and comments | "byte-identical" tests, and history comments about Barista. A stale line in this file: the slice list still says TD-03 is "Open as #56"; it merged. |

**Impact.** Each shim is a second way to do something, and the second way is
the one without a tenant. #56 showed the cost: a gate that had to serve both
ways guessed a tenant, and three reviews could not make the guess safe.

**Proposal.** One change per package (standing rule 7), from the bottom up:

1. `crypto`: one set of functions, all taking a tenant; `purpose` required.
   **Done, #57.**
2. `identity`: one mint function that always reads the user and checks the
   tenant. **Done, #58.**
3. `espresso.IdentityService` and `AuthRoutes`: every method takes the
   tenant, so the TOTP second leg is bound to a tenant by the library.
4. SCIM: the scoped path only.
5. The examples and docs follow in each change. History comments are cleaned
   in a last, docs-only change.

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

Since #55 an application can build a console on Tamper's own API: a special
`platform` tenant for the admins, a membership table behind
`identity.MembershipStore`, and `Core.EnterTenant` for the token. See
`PHASE8-PLATFORM-ADMIN-SKETCH.md` and `examples/multitenant`.

What the admin may do inside the tenant is decided by `authz` since #56: the
admin needs a binding in that tenant, granted to the subject
`{home tenant, type, id}`. See `PHASE8B-AUTHZ-TENANT-SKETCH.md`.

Suggested slice order if this work moves into Tamper:

1. **TD-15, TD-10, TD-08** — merged (#39, #40, #43). **TD-16, TD-09, TD-21,
   TD-24, TD-25** — resolved by #46, which is open. **TD-27** goes with #46:
   Barista must be changed before it can use that release.
   TD-15 and TD-10 can leak across tenants, so they come first. TD-16 must be
   fixed before or together with TD-09: turning on v4 through `tamper.New`
   without a safe bootstrap would produce false tamper reports. TD-08 is
   required for a correct audit trail in every other item.
2. **TD-19 and TD-22** — small. TD-19 closes the cross-tenant refresh path
   that the five fixes leave open, and TD-22 makes the example show the gate
   that pooled routes need.
3. **TD-01 + TD-02** — the membership port and `EnterTenant`. Merged (#55).
4. **TD-03** — the tenant contract for `authz`, with its leak suite. Open as
   #56.
5. **TD-07 + TD-11** — impersonation and per-tenant audit queries.
6. **TD-05 + TD-06** — tenant lifecycle and suspension enforcement.
7. **TD-04** — hierarchy, after the product question in sketch §8 item 3 is
   answered.
8. **TD-17, TD-18, TD-20, TD-23, TD-26** — merged (#49 to #52, #54).
9. **TD-12, TD-13, TD-14** — the rest.

## Process limits

`CLAUDE.md` says Phase 7 is complete, and `PHASE7-MULTITENANCY-SKETCH.md` is a
design freeze. Any item that touches `identity`, `crypto/jwt.go`, `oidc`,
`saml`, `scim`, `espresso`, or `audit` needs a sketch amendment (or a new
phase sketch) before any code. Two earlier decisions are affected. They must be
reopened explicitly, not bypassed:

- "one row, one tenant" (`MIGRATION-v0.4.md`), by TD-01. Phase 8 (#55) did
  not reopen it: the row stays in one tenant and a membership is added beside
  it;
- "nested tenants are deferred" (sketch §8 item 3), by TD-04.

Standing rule 7 still applies: each item is a separate change.
