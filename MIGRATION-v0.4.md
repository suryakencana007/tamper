# Migrating to tamper v0.4.0

v0.4.0 is the one deliberate breaking release of Phase 7. Everything from
v0.2.x to v0.3.x was additive: an empty tenant meant "today's behavior" and
nothing you had written needed to change. This release ends that, on purpose,
and folds the tenant into the base ports.

Read §1 first even if you are single-tenant. **Especially** if you are
single-tenant — the whole point of the change is that "I have one tenant" is
now something you say rather than something tamper assumes.

---

## 1. The one idea

Before v0.4.0 a tenant was a `string`, and `""` meant two different things:

```go
core.Login(ctx, "", email, password)   // "I am single-tenant"
core.Login(ctx, "", email, password)   // "I forgot to thread the tenant"
```

Those are the same line. Nothing downstream could tell them apart, so a
forgotten tenant silently read the single-tenant bucket — which in a pooled
deployment is a cross-tenant read.

v0.4.0 threads `tenant.ID`, whose **zero value is invalid**:

```go
core.Login(ctx, tenant.Single, email, password)      // legal, explicit
core.Login(ctx, tenant.New("acme"), email, password) // legal, explicit
core.Login(ctx, tenant.ID{}, email, password)        // ErrTenantRequired
```

Three constructors, and the difference between them is the migration:

| Call | Meaning | On `""` |
|---|---|---|
| `tenant.Single` | "this deployment has one tenant" | — |
| `tenant.New(s)` | untrusted input: a `tid` claim, a header, a path segment | **invalid, denies** |
| `tenant.FromStored(s)` | a value read back out of your own storage | `Single` |

`New("")` is deliberately NOT `Single`. An empty string out of a claim or a
config lookup means the lookup produced nothing, and that is exactly the case
that must deny. `FromStored("")` IS `Single`, because a row could only have
been written by a call that already passed the gate.

**If you take one rule from this document:** use `FromStored` only on values
that came out of your database, and `New` on everything else.

---

## 2. Do you need a database backfill?

**Single-tenant deployments: no.** This is the common case and it is worth
being explicit about, because "backfill" sounds alarming.

tamper's records have carried a `TenantID string` field since v0.3.0 (slice
7b-1), and your rows have been writing `""` into it ever since. `""` is
exactly what `tenant.Single` stores. **Your data is already correct.** The
v0.4.0 change is in the Go signatures, not in your tables.

Verify with one query per table rather than trusting this paragraph:

```sql
SELECT COUNT(*) FROM users            WHERE tenant_id IS NULL;  -- expect 0
SELECT COUNT(*) FROM user_identities  WHERE tenant_id IS NULL;  -- expect 0
SELECT COUNT(*) FROM refresh_tokens   WHERE tenant_id IS NULL;  -- expect 0
```

If any return non-zero you have rows written before 7b-1 added the column.
`NULL` is not `''`, and `FromStored` will read a `NULL`-scanned empty string
as `Single` — which is right for a single-tenant deployment and wrong for a
pooled one. Normalise before upgrading:

```sql
UPDATE users           SET tenant_id = '' WHERE tenant_id IS NULL;
UPDATE user_identities SET tenant_id = '' WHERE tenant_id IS NULL;
UPDATE refresh_tokens  SET tenant_id = '' WHERE tenant_id IS NULL;
```

**Going pooled at the same time: yes, and it is your decision, not tamper's.**
See §3.

---

## 3. Worked backfill — single-tenant to pooled

The order matters: **assign every row a tenant, then upgrade the library.**
Doing it the other way means running a pooled binary against rows whose tenant
is `''`, and every one of them will resolve to `tenant.Single`.

Worked example. An installation that has been serving one customer, `acme`,
and now wants to onboard `globex`:

```sql
-- 1. Give the existing estate a real tenant. One statement per table, run in
--    ONE transaction: a half-backfilled estate has rows in two tenants that
--    were never two tenants.
BEGIN;
UPDATE users           SET tenant_id = 'acme' WHERE tenant_id = '';
UPDATE user_identities SET tenant_id = 'acme' WHERE tenant_id = '';
UPDATE refresh_tokens  SET tenant_id = 'acme' WHERE tenant_id = '';
COMMIT;

-- 2. Prove it. Both must return zero rows before you deploy.
SELECT COUNT(*) FROM users WHERE tenant_id = '';
SELECT COUNT(*) FROM users WHERE tenant_id NOT IN ('acme');
```

```sql
-- 3. The uniqueness constraint moves WITH the tenant. This is the step that
--    is easy to miss and expensive to miss: a global unique index on email
--    makes it impossible for globex to have its own bob@example.com, which
--    is the entire feature.
DROP INDEX users_email_key;
CREATE UNIQUE INDEX users_tenant_email_key ON users (tenant_id, email);

-- Same shape for federated identities: (provider, subject) is unique PER
-- TENANT, so two customers can federate the same IdP.
DROP INDEX user_identities_provider_subject_key;
CREATE UNIQUE INDEX user_identities_tenant_provider_subject_key
    ON user_identities (tenant_id, provider, subject);
```

```go
// 4. Your Store's queries constrain on the tenant. This is the isolation
//    contract, and tamper cannot verify it for you — see §6.
func (s *Store) UserByEmail(ctx context.Context, tid tenant.ID, email string) (identity.User, error) {
	row, err := s.q.UserByTenantAndEmail(ctx, db.UserByTenantAndEmailParams{
		TenantID: tid.String(),
		Email:    email,
	})
	if errors.Is(err, sql.ErrNoRows) {
		// ErrNotFound, never a permission error: a miss and a wrong-tenant
		// hit must be indistinguishable.
		return identity.User{}, identity.ErrNotFound
	}
	...
}
```

```go
// 5. Resolve the tenant per request and pin it.
r.Use(espresso.PinTenant(func(r *http.Request) string {
	return subdomain(r.Host)   // or a path segment, or a header
}))
```

### When the backfill is impossible — record it, do not paper over it

tamper's model is **one row, one tenant**. There is one schema shape where
step 1 has no correct answer, and if you are in it you should stop rather
than pick a tenant and hope:

> **A user who legitimately belongs to more than one tenant.** A consultant
> with access to two customers, or a support engineer who is a real user in
> every tenant. `UPDATE users SET tenant_id = ?` cannot express that row.

This is not a bug in the backfill, it is tamper's identity model showing its
edge: the `users` row IS the tenant-scoped object. The shape that works is one
user row per (person, tenant) with your application owning the membership
table that links them, and the person's cross-tenant identity living in your
domain rather than in tamper's.

If that is your shape, do not upgrade until you have modelled it. A
`tenant_id` picked to make the `UPDATE` succeed is a cross-tenant grant with a
migration script in front of it.

---

## 4. Signature changes

Mechanical. The compiler finds all of them — there is no silent failure mode
in this list, which is the deliberate consequence of changing the *type*
rather than only the name.

### identity

```go
// Store — TenantScopedStore is folded in and gone
UserByEmail(ctx, email)                          -> UserByEmail(ctx, tenant.ID, email)
CountUsers(ctx)                                  -> CountUsers(ctx, tenant.ID)
IdentityByProviderSubject(ctx, provider, subject)-> IdentityByProviderSubject(ctx, tenant.ID, provider, subject)
                                                 +  RevokeAllRefreshSessionsForTenant(ctx, tenant.ID, at)

// Core — the *InTenant suffix collapses onto the plain name
Register(ctx, email, pw)                         -> Register(ctx, tenant.ID, email, pw)
RegisterInTenant(ctx, tid, email, pw)            -> Register(ctx, tenant.ID, email, pw)
Login(ctx, email, pw)                            -> Login(ctx, tenant.ID, email, pw)
LoginInTenant(ctx, tid, email, pw)               -> Login(ctx, tenant.ID, email, pw)
ResolveByIdentityInTenant(...)                   -> ResolveByIdentity(ctx, tenant.ID, provider, subject)
ProvisionUserWithIdentityInTenant(...)           -> ProvisionUserWithIdentity(ctx, tenant.ID, email, provider, subject)
RevokeAllSessionsForTenant(ctx, tid string)      -> RevokeAllSessionsForTenant(ctx, tenant.ID)
Invite(ctx, tid string, ...)                     -> Invite(ctx, tenant.ID, ...)
AcceptInvitation(ctx, tid string, ...)           -> AcceptInvitation(ctx, tenant.ID, ...)

// removed
type TenantScopedStore                           -> folded into Store
identity.WithTenancy(bool)                       -> removed; every Core is tenant-scoped
identity.ErrTenancyDisabled                      -> removed; there is no disabled mode
```

### crypto

```go
IssueAccess(userID, authTime, acr)               -> IssueAccess(userID, tenant.ID, authTime, acr)
IssueAccessForTenant(userID, tid, authTime, acr) -> IssueAccess(userID, tenant.ID, authTime, acr)
VerifyAccess(token)                              -> VerifyAccess(token, tenant.ID)   // now CHECKS the tenant
VerifyAccessInTenant(token, tid)                 -> VerifyAccess(token, tenant.ID)
                                                 +  ParseAccess(token)               // parse only, tenant NOT checked
```

> **Read this one twice.** `VerifyAccess` used to be the unpinned form and
> the pinned one carried the suffix, so the safe call was the longer name and
> the foot-gun was the default. That is now inverted: `VerifyAccess` checks
> the tenant, and skipping the check requires saying `ParseAccess`. If you
> mechanically kept your `VerifyAccess` calls you got the stronger behavior,
> which is the intended direction of the accident.

### oidc / saml

```go
GetRegistry(ctx)                                 -> GetRegistry(ctx, tenant.ID)
GetRegistryForTenant(ctx, tid)                   -> GetRegistry(ctx, tenant.ID)
Reload(ctx) / ReloadForTenant(ctx, tid)          -> Reload(ctx, tenant.ID)
PinRegistry(reg) / PinRegistryForTenant(tid,reg) -> PinRegistry(tenant.ID, reg)
InvalidateTenant(tid string)                     -> InvalidateTenant(tenant.ID)
ProviderStore.ListEnabledProviders(ctx)          -> ListEnabledProviders(ctx, tenant.ID)
WithRedirectURLForTenant / WithSPMetadataURLForTenant
                                                 -> callbacks now receive tenant.ID
type TenantScopedProviderStore                   -> folded into ProviderStore
```

### espresso

```go
TenantFromContext(ctx) (string, bool)            -> (tenant.ID, bool)
TenantFromRoutedContext(r) (string, bool)        -> (tenant.ID, bool)
RequireEntitlement(store, cap, resolve, ...)     -> resolve is now func(*http.Request) (tenant.ID, bool)
                                                 +  PinTenant(resolve)  // NEW, see §5
FederationHooks.Registry                         -> func(ctx, tenant.ID) (*oidc.ProviderRegistry, error)
SAMLHooks.Registry                               -> func(ctx, tenant.ID) (*saml.ProviderRegistry, error)
```

### audit

```go
ActorService(saID, saName)                       -> ActorService(saID, saName, tenant.ID)
ActorServiceInTenant(saID, saName, tid)          -> ActorService(saID, saName, tenant.ID)
EntitlementStore.ForTenant(ctx, tid string)      -> ForTenant(ctx, tenant.ID)
ExportForTenant(ctx, tid string)                 -> ExportForTenant(ctx, tenant.ID)
                                                    // unset ERRORS (was: "" exported nothing);
                                                    // tenant.Single exports rows stamped "", never the pool

// audit/sqlitestore is now audit/internal/sqlitestore — see §7
sqlitestore.IsUniqueViolation(err)               -> audit.IsUniqueViolation(err)
SQLiteAuditQueriesForTest(l)                     -> audit.InsertEventDirectForTest(ctx, l, Event)
StoreForDebug() / FromRowForDebug(row)           -> l.ListByCanonicalVersion(ctx, v) ([]Event, error)
```

Unchanged, and deliberately: `RevokeAllSessionsForTenant`,
`RevokeAllRefreshSessionsForTenant` and `audit.ExportForTenant` keep their
suffix. `ForTenant` there names the **subject** of the operation, not a scope
— routing a single user's "log out everywhere" onto the first two would sign
out an entire customer.

---

## 5. Middleware: `PinTenant` vs `RequireTenant`

New in v0.4.0, and the split is load-bearing:

- **`RequireTenant(resolve)`** — for **authenticated** routes. It cross-checks
  the token's `tid` against the routed tenant and rejects a mismatch. It must
  run INSIDE `RequireAuth`, because it needs the verified claims.
- **`PinTenant(resolve)`** — for **pre-authentication** routes. It pins the
  tenant and makes no claim about a credential, because there is none yet.

You need `PinTenant` if you serve OIDC/SAML start legs, which you almost
certainly do: the provider registry is keyed by tenant now, so a start leg has
to know whose IdP to look up. Before v0.4.0 it read an unscoped registry.

```go
r := espresso.Portafilter()

// Single-tenant: say so once, globally.
r.Use(espresso.PinTenant(func(*http.Request) string { return "" }))

// Pooled: resolve however your routing says.
r.Use(espresso.PinTenant(func(r *http.Request) string { return subdomain(r.Host) }))

// Authenticated routes additionally cross-check the token.
r.Get("/api/me", surfaces.RequireAuth(
	espresso.RequireTenant(resolveTenant)(handler),
))
```

Using `PinTenant` on an authenticated route compiles and skips the token
cross-check. That is why they are two names and not one boolean.

### It is one line per ROUTER, not one line per application

This is the part of the upgrade that costs real time, and it is the one thing
the compiler cannot tell you — a missing pin is a run-time 404, not a build
error.

Every router you construct needs the pin, and that includes **test harnesses
that build their own**. Barista's production wiring took a single line; its
test suite needed the same line in **nine** more places, because the
federation handler tests assemble a router directly rather than going through
the application's. Until they were pinned, every OIDC and SAML start leg
returned:

```json
{"error":{"code":"OIDC_PROVIDER_NOT_FOUND","message":"provider not found"}}
```

That is the deliberate deny doing its job — a request with no tenant cannot
resolve a provider, and the response is deliberately indistinguishable from a
genuine miss so it discloses nothing. It reads correctly to a caller and
confusingly to an upgrader, which is worth knowing in advance.

Find them before you start:

```sh
grep -rn 'Portafilter()\|chi.NewRouter()\|http.NewServeMux()' --include='*_test.go' .
```

A harness that does not pin is testing a router your application never
builds, so the pin belongs there for correctness, not just to make the suite
pass.

---

## 6. The isolation contract you now owe

Folding `TenantScopedStore` into `Store` means the compiler now requires the
tenant-scoped methods — but it cannot check that you *honour* the tenant
inside them. A `UserByEmail` that accepts a `tenant.ID` and ignores it
compiles perfectly and leaks every row.

Run the conformance suite against your store. It is the instrument built for
exactly this and it is one call:

```go
func TestStore_NoCrossTenantLeaks(t *testing.T) {
	tenanttest.RunLeakSuite(t, func() identity.Store { return newTestStore(t) })
}
```

It seeds two tenants, addresses one tenant's objects as the other, and
requires `ErrNotFound` every time — not a permission error, not a zero value
with a nil error, and obviously not the other tenant's row. The first two fail
because they disclose existence; the third is the leak itself.

---

## 7. `audit/sqlitestore` is internal

`audit/sqlitestore` moved to `audit/internal/sqlitestore`. If you imported it,
you cannot any more, and that is the point: tamper's SQLite schema was public
API, so every migration that added a `NOT NULL` column could break an outside
caller's struct literal at run time while still compiling. It did exactly that
once (see the CHANGELOG's `row_salt` entry).

The three things consumers actually used have neutral replacements, listed in
§4 under audit. If you were using something else from that package, open an
issue rather than working around it — the replacement probably belongs in the
public API.

---

## 8. Upgrade checklist

1. `SELECT COUNT(*) ... WHERE tenant_id IS NULL` on all three tables → 0.
2. Going pooled? Do the §3 backfill and move the unique indexes, in one
   transaction, **before** deploying.
3. `go get github.com/suryakencana007/tamper@v0.4.0` and build. The compiler
   lists every call site.
4. At each one, pick the right constructor: `Single` for a single-tenant
   deployment, `New` for untrusted input, `FromStored` for values out of your
   own tables.
5. Add `PinTenant` to **every** router you construct — production and each
   test harness that builds its own (`grep -rn 'Portafilter()' --include='*_test.go'`).
   Without it, pre-auth federation routes 404 and authenticated routes 401,
   both deliberately indistinguishable from an ordinary miss. Barista needed
   one line in production and nine in its tests.
6. Wire `tenanttest.RunLeakSuite` against your store and watch it pass.
7. Grep your own code for `FromStored` and confirm every call sits on a value
   that came out of storage.
