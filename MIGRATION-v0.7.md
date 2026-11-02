# Migrating to tamper v0.7.0

> **v0.7.0, cut 2026-11-02.** Everything below is taken from the `0.7.0` section
> of `CHANGELOG.md`, which remains the authoritative list — this document only
> puts it in upgrade order.

This release finishes the pooled-tenancy **upgrade** — the breaking changes that tenancy needed, and the phases that carried them. Three things break code:

1. **TD-28 — no compatibility code.** Every package had each API twice, once
   with a tenant and once without, so that pre-tenancy callers kept working.
   The unscoped forms are gone. `CLAUDE.md` standing rule 1 removed the
   fallback: nothing is in production, so the old name is deleted rather than
   deprecated.
2. **TD-03 — the tenant reaches `authz`.** `authz` was the last package that
   did not know about tenants. Every port now takes the scope, `Subject` and
   `Binding` carry a tenant, and an unset scope is an error.
3. **The audit log is `canonical_version=4` only** (#46). An audit DB written by
   an earlier version cannot be opened, and there is no workaround: archive it and
   start a new file. §2a.

Plus four additive features, none of which does anything unless you wire it:
**entering another tenant** (Phase 8, TD-01/TD-02), the **tenant lifecycle write
port** (TD-05), **impersonation** (TD-07), and **plan inheritance** (Phase 12).
The last is partial in this release — `tenant.Ancestors` and
`tenant.InheritingEntitlements` ship here, and the IdP and domain axes land in
0.8.0. §4.

**Read §1 first.** Almost every compile error below is the compiler asking you
the same question — *which tenant is this?* — and answering it once, up front,
is cheaper than answering it at forty call sites.

---

## 1. The one idea

The previous release introduced `tenant.ID`, whose zero value is invalid, and
threaded it through `identity`, `crypto`, `oidc`, `saml` and the transport.
This release asks the same of everything left:

| Package | Before | Now |
|---|---|---|
| `authz` | `Check(ctx, sub, act, res)` | `Check(ctx, tenant.ID, sub, act, res)` |
| `scim` | `UserStore.Get(ctx, id)` | `UserStore.Get(ctx, tenant.ID, id)` |
| `espresso` | `RequireTenant(func(*http.Request) string)` | `…func(*http.Request) (tenant.ID, bool)` |
| `identity` / `crypto` | a scoped form **and** an unscoped form | only the scoped form |

The one value that replaces every "no tenant" needs a name, and it is the same
name as before: `tenant.Single`. Three constructors, as in v0.4:

| Call | Meaning | On `""` |
|---|---|---|
| `tenant.Single` | "this deployment has one tenant" | — |
| `tenant.New(s)` | untrusted input: a `tid` claim, header, path segment | **invalid, denies** |
| `tenant.FromStored(s)` | a value read back out of your own storage | `Single` |

**Rule:** `FromStored` only on values out of your database, `New` on everything
else. `New("")` is not `Single`; it is "the lookup produced nothing", which must
deny.

---

## 2. Do you need a data migration?

Two things need your attention, and only one of them is a schema change.

### 2a. The audit database must be new (breaking, no workaround)

Every audit row is now written and read at `canonical_version=4`; the older
encoders, the chain-restart anchors, `VerifyLegacy` and the in-place migration
helpers are removed. **An audit DB written by an earlier version cannot be
opened** — `NewSQLiteLogger` returns an error naming the file and counting the
rows it found at each other version.

```sh
# archive, do not delete: the error also fires on a row whose version was
# changed after it was written, and you want to know which case you have
mv audit.db audit-v3-archive.db
```

Then let the application create a new file.

### 2b. Your `authz` tables need the tenant column (if you are pooled)

An `authz` binding row is now `(scope tenant, subject home tenant, type, id,
resource, role)`. If you keep bindings in SQL:

- add the two columns (the row's scope and the subject's home tenant);
- **backfill every existing row** — `ListSubjects` returns
  `ErrTenantRequired` when a store hands back a subject with no home tenant, so
  a `NULL` column surfaces as a runtime error rather than a quiet gap;
- for a single-tenant deployment every existing row gets `tenant.Single`,
  whose stored form is the empty string.

`scim` and `identity` already had their tenant columns from the previous
release; nothing to add there.

---

## 3. Signature changes

Mechanical, and the compiler finds all of them. That is the point of changing
the *type* rather than only the name.

### `authz`

```go
Check(ctx, sub, act, res)                            -> Check(ctx, tenant.ID, sub, act, res)
CheckBulk(ctx, reqs)                                 -> CheckBulk(ctx, tenant.ID, reqs)
ListResources(ctx, sub, act, type)                   -> ListResources(ctx, tenant.ID, sub, act, type)
ListSubjects(ctx, act, res)                          -> ListSubjects(ctx, tenant.ID, act, res)

BindingsFor(ctx, sub, res)                           -> BindingsFor(ctx, tenant.ID, sub, res)
BindingsForSubject(ctx, sub, type)                   -> BindingsForSubject(ctx, tenant.ID, sub, type)
BindingsOnResource(ctx, res)                         -> BindingsOnResource(ctx, tenant.ID, res)

PermissionsFor(ctx, sub, res)                        -> PermissionsFor(ctx, tenant.ID, sub, res)
ResourcesWithPermission(ctx, sub, key, resourceType) -> ResourcesWithPermission(ctx, tenant.ID, sub, key, resourceType)
SubjectsWithPermission(ctx, key, res)                -> SubjectsWithPermission(ctx, tenant.ID, key, res)
MemPermissionStore.Grant(sub, res, keys...)          -> Grant(tenant.ID, sub, res, keys...)
MemPermissionStore.GrantSuperuser(sub)               -> GrantSuperuser(tenant.ID, sub)
```

- `authz.Subject` gains `Tenant` (the subject's **home** tenant);
  `authz.Binding` gains `Tenant` (the **scope** the binding lives in). Unkeyed
  literals such as `Subject{"user", "u-1"}` stop compiling.
- An unset scope, or a subject with no home tenant, is `authz.ErrTenantRequired`.
  **Treat every error as deny**, as before.
- `MemStore.Grant`/`Revoke` and `MemPermissionStore.Grant`/`GrantSuperuser`
  now **return an error** and store nothing for those two cases.
  `NewMemStore` panics on a broken seed binding — a keyed literal written
  before the upgrade still compiles, so the panic is the only place it can be
  caught.
- `espresso.DecisionGate` gains a **required** `Tenant`
  `func(*http.Request) (tenant.ID, bool)` (`RequireDecision` panics without
  it) and `AllowEntered`; `UserExists` becomes
  `func(ctx, home tenant.ID, userID string)`.

**Single-tenant:** pass `tenant.Single` as the scope, set `Tenant:
tenant.Single` on every `Subject` and `Binding`, and give every gate
`Tenant: FixedRequestTenant(tenant.Single)`. Decisions are unchanged.

**Pooled:** filter by scope in every query, match subjects with their home
tenant, and run the leak suite (§5).

### `scim`

```go
UserStore.Get(ctx, id)                      -> Get(ctx, tenant.ID, id)
UserStore.Create(ctx, w, meta)              -> Create(ctx, tenant.ID, w, meta)
UserStore.Replace(ctx, id, w, meta)         -> Replace(ctx, tenant.ID, id, w, meta)
UserStore.Delete(ctx, id, meta)             -> Delete(ctx, tenant.ID, id, meta)
UserStore.SavePatch(ctx, id, w, ops)        -> SavePatch(ctx, tenant.ID, id, w, ops)
UserStore.ListFiltered(ctx, start, n, f)    -> ListFiltered(ctx, tenant.ID, start, n, f)
GroupStore (same six)                       -> …tenant.ID after ctx
UserStore.List(ctx) / GroupStore.List(ctx)  -> removed; use ListFiltered ("" is no filter)
type TenantScopedUserStore / …GroupStore     -> folded into the base ports
SCIMConfig.Tenancy, .TenantBoundStores      -> removed; there is one scoped path
```

A single-tenant deployment is handed `tenant.Single` and its store refuses any
other tenant with `scim.ErrNotFound`.

### `espresso`

```go
RequireTenant(func(*http.Request) string)   -> func(*http.Request) (tenant.ID, bool)
PinTenant(func(*http.Request) string)       -> func(*http.Request) (tenant.ID, bool)
RequireTenantAllowEntered(…)                -> same resolver shape   // NEW
TenantFromContext(ctx) (string, bool)       -> (tenant.ID, bool)
TenantFromRoutedContext(r) (string, bool)   -> (tenant.ID, bool)
TenantFromServiceAccount(r) (string, bool)  -> (tenant.ID, bool)
                                            + FixedRequestTenant(tenant.Single)  // NEW
```

**This is the change most likely to be silently lost.** An empty string used to
become `tenant.Single`, so a route pattern with no tenant segment was served as
a single-tenant route. Now a tenant that does not resolve (`false`, or the zero
`tenant.ID`) is refused: `RequireTenant` with the 401 a wrong-tenant token
gets, `PinTenant` with a 404. If you have a genuinely single-tenant router, say
so:

```go
r.Use(tamperespresso.PinTenant(tamperespresso.FixedRequestTenant(tenant.Single)))
```

`espresso.IdentityService`: every method takes `tenant.ID` after `ctx`, and
`AuthRoutesConfig.Tenant` is **required** — `func(context.Context) (tenant.ID,
bool)`; behind a tenant gate pass `TenantFromContext`, single-tenant pass
`FixedTenant(tenant.Single)`. `NewAuthRoutes` refuses a config without it.

### `identity`

```go
Register(ctx, email, pw)                    -> Register(ctx, tenant.ID, email, pw)
Login(ctx, email, pw)                       -> Login(ctx, tenant.ID, email, pw)
IssueTokensForUser(ctx, userID)             -> removed
IssueTokensForUserWithACR(ctx, userID, acr) -> removed
IssueTokensForUserInTenant(ctx, tid, …)     -> IssueTokensForUser(ctx, userID, tenant.ID, authTime, acr)
                                             +  DefaultACR()   // the ACR Login stamps
```

- `authTime` and `acr` are **required**; a non-positive `authTime` or empty
  `acr` is the new `ErrAuthContextRequired` — a caller bug, not a 400.
- `Refresh` refuses (and revokes) a session row whose `auth_time` is not
  positive or whose `acr` is empty.

### `crypto`

```go
Issue(userID)                               -> removed
Verify(token)                               -> removed
IssueAccess(userID, authTime, acr)          -> IssueAccess(userID, tenant.ID, authTime, acr)
VerifyAccess(token)                         -> VerifyAccess(token, tenant.ID)
IssueTOTPPendingInTenant(userID, tid)       -> IssueTOTPPending(userID, tenant.ID)
VerifyTOTPPendingInTenant(token, tid)       -> VerifyTOTPPending(token, tenant.ID)
```

- `IssueAccess` returns `ErrTenantRequired` for an unset tenant; it used to
  mint, and the zero `tenant.ID` has the same string form as `tenant.Single`.
- A token must carry `purpose`, `auth_time` and `acr`; `ParseAccess` and
  `VerifyAccess` refuse one missing any of them. Tokens this version mints
  always have all three.
- A single-tenant deployment's tokens are the same bytes: `tenant.Single` is
  still spelled as no `tid` claim.

---

## 4. The additive features: nothing here happens unless you wire it

A user is stored in one home tenant. A **membership** is the right to act
inside another. Nothing happens unless you wire it.

```go
core, _ := identity.New(store, jwt,
    identity.WithMemberships(membershipStore), // your table
    identity.WithEnterTenantTTL(15*time.Minute),
)

tok, err := core.EnterTenant(ctx, sessionClaims, tenant.New("acme"))
// tok.Access carries tid=acme, htid=<home>. No refresh session.
```

- `identity.MembershipStore` is the port: `IsMember`, `MembershipsFor`.
  `EnterableTenants` is what your tenant switcher lists.
- An entered token is a guest pass: it cannot enter again, it has no refresh
  session, and **`RequireTenant` refuses it**. A route that invites guests
  mounts `RequireTenantAllowEntered` and sets `AllowEntered: true` on its
  `DecisionGate`.
- The gate builds the subject with the token's **home** tenant
  (`EnteredFromContext`), so the guest gets only what was granted to them
  inside that tenant. Roles held at home never apply.
- `Hooks.OnTenantEntered` is where you record the entry — tamper has no audit
  log of its own.
- A removed membership keeps working until the entered token expires. That is
  the whole revocation window; keep the TTL short.

**Tenant lifecycle (TD-05).** `tenant.AdminStore` (`List`, `Create`,
`SetStatus`) is the write port for a console, and `tamper.NewAdmin(admin, core,
log)` composes it with the identity side. `Admin.Suspend` sets the status and
revokes the tenant's refresh sessions **in that order**, and reports a partial
state rather than swallowing it. Also opt-in: a deployment that does not
implement the port is unchanged. Nothing here is breaking.

**Impersonation (TD-07).** `identity.Core.Impersonate` mints a token that is
another user, with a new `act` claim naming the human behind it — **every audit
row is attributed to that human**, never to the impersonated user. It is opt-in
twice over: a Core without `WithImpersonation` cannot impersonate, and
`RequireTenant` / `RequireTenantAllowEntered` refuse the token until a route
mounts `RequireTenantAllowImpersonated` (or the combined
`RequireTenantAllowEnteredOrImpersonated`) and sets
`DecisionGate.AllowImpersonated`. Tokens minted before this release are
unchanged: `AccessClaims.Entered()` still means what it meant, because only an
impersonated token carries `act`. Nothing here is breaking.

**Plan inheritance (TD-04, decision D2).** A tenant's **effective** plan can be
its own widened by what its ancestors bought. `tenant.InheritingEntitlements(plans,
hierarchy)` is a decorator over `tenant.EntitlementStore`, so
`espresso.RequireEntitlement` is untouched — pass your plain store and nothing
changes. `tenant.Entitlements.Union` is the widening: capabilities OR'd, the IdP
cap at the larger value, and a record that bought *something* keeping `0` as
unlimited. A **record that bought nothing widens nothing** — `Entitlements.IsZero`
is that question — otherwise a child with no plan row would inherit an *uncapped*
IdP allowance from a capped parent. Two things to know before wiring it: it is
**uncached** (1+depth store reads per gated request, so wrap it in your own
cache), and it reports the **effect**, while your own `ForTenant` remains the
**purchase** — an admin screen showing "your plan" must read the inner store.

---

## 5. The isolation contract you now owe

`authz` cannot enforce tenant isolation — the query is in your adapter. What it
can do is state the obligation and ship the instrument that checks it:

```go
// import authztest "github.com/suryakencana007/tamper/authz/tenanttest"
func TestMyBindingStoreIsolation(t *testing.T) {
    authztest.RunBindingStoreLeakSuite(t, func() authztest.BindingHarness {
        s := newMyStore(t) // fresh and empty on every call
        return authztest.BindingHarness{
            Store: s,
            Grant: func(b authz.Binding) error { return s.Grant(context.Background(), b) },
        }
    })
}
```

`RunPermissionStoreLeakSuite` is its sibling. The RBAC engine drops a binding
of the wrong scope when a store hands one over, but that is defence in depth —
only the suite proves the query never produced it. `identity/tenanttest` is the
same instrument for `identity.Store`.

---

## 6. Upgrade order

1. **Archive the audit DB** and point the application at a new file (§2a).
2. **Backfill the `authz` tenant columns** if you keep bindings in SQL (§2b).
3. `go get …@v0.7.0` and build. The compiler lists every call site.
4. Fix `crypto` and `identity` first — they are the leaves.
5. Fix the `authz` scopes and subjects. Decide the scope **per route**, once:
   pooled routes use `TenantFromRoutedContext`; a console route of one tenant
   is a route of that tenant.
6. Fix the tenant resolvers to return `(tenant.ID, bool)`. Add
   `FixedRequestTenant(tenant.Single)` where the route really is single-tenant.
7. Give every `DecisionGate` its `Tenant`; add `AllowEntered: true` only on the
   routes that invite guests.
8. Run the leak suites against your stores (§5) and watch them pass.
9. If you use scim: thread the principal's tenant through both ports and delete
   the `Tenancy` config.
10. Optional: wire `WithMemberships` + `EnterTenant` (§4).

### If you are single-tenant

Steps 1, 3, 6 (`FixedRequestTenant(tenant.Single)`), 7 and 8. Every scope is
`tenant.Single`, every subject and binding says `Tenant: tenant.Single`,
decisions are the same as before, and tokens are the same bytes. The
`identity`/`crypto` signature changes still apply — TD-28 removed the unscoped
forms for everyone.

---

## 7. What this release does **not** change

- **No tenant hierarchy is inherited.** `tenant.Descriptor.ParentID` is no longer
  "reserved, read by nobody": `tenant.Ancestors` walks it, and the inheritance axes
  land in later slices. Nothing calls the walk today, no axis inherits, and no
  authorization scope is derived from parentage. A deployment that sets nothing
  sees no change.
- **No tenant hierarchy in the library.** A three-level model
  (platform → tenant-group → organization) is shown in
  [`examples/tenanthierarchy`](./examples/tenanthierarchy), decided in
  [`ADR-0001`](./ADR-0001-tenant-hierarchy-platform-tenantgroup-org.md). It is
  application code: zero tamper-core change. If you want it, vendor the
  pattern; there is no API to import.
- **IdP, entitlement and domain inheritance remain open** (TD-04, per axis).
- **Impersonation, tenant lifecycle, suspension enforcement** (TD-05/06/07).

---

## 8. Known limits carried into this release

- An entered token has no refresh session and no revocation list: a removed
  membership or a deactivated admin keeps working until the token expires.
- `RevokeAllSessionsForTenant` does not touch entered tokens — they have no
  session row.
- The home access token is not checked for liveness at `EnterTenant`; the
  exposure ends at its expiry plus the entered TTL.
- Entering is not throttled, and a refused entry is not recorded by tamper
  (the hook runs on success only).

**Limits this release adds**, all of them deliberate:

- **Impersonation has no revocation list.** The token is valid until it expires,
  which is the whole window, the impersonated user is not notified, a token cannot
  be re-impersonated (no chaining) and same-tenant impersonation is refused. Give
  `WithImpersonation` a TTL in minutes.
- **Plan inheritance is uncached.** `tenant.InheritingEntitlements` costs 1+depth
  store reads on every gated request, so wrap it in your own cache, and read the
  inner store when you show a customer *their* plan rather than their effect.
- **An ancestor that bought only an uncapped plan reads as having bought nothing**,
  because `Entitlements` cannot distinguish that from an empty record. Grant a
  capability alongside a cap.
- **Corrupt parentage denies.** A cycle, a chain deeper than 32, or a parent id
  that does not resolve makes every gated request for that tenant fail closed
  rather than inherit a partial answer. The sentinels are the log line to look for.
