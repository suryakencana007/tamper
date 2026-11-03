# Migrating to tamper v0.9.0

> **v0.9.0, cut 2026-11-03.** Everything below is taken from the `0.9.0` section of
> `CHANGELOG.md`, which remains the authoritative list — this document only puts it in
> upgrade order.

This release finishes **TD-28**: the compatibility shims from before 2026-10-05 are
gone. Every one of them was *a second way to do something, and the second way was the
one without a tenant*. There is no shim and no deprecation: the weaker way is deleted
(standing rule 1), and this document says what to call instead.

Nothing here changes the tenant model, the audit format, or any database.

---

## 1. The one idea

The previous releases put the tenant into **every signature that names a user or a
session**. What was left was the places where a caller had to supply the check
themselves, and where an adapter that forgot **still compiled**.

So the rule for this upgrade is: **if a method takes a user id or a refresh token,
it now also takes a `tenant.ID`, and you pass the tenant the request was routed to.**

```go
// before
user, tokens, err := core.Refresh(ctx, refreshToken)

// after
user, tokens, err := core.Refresh(ctx, tenantID, refreshToken)
```

The parameter goes **immediately after `ctx`**, which is where `Store` and
`espresso.IdentityService` already put it — so an adapter that implements that port
is a straight pass-through.

---

## 2. `identity` — eleven signatures, two deletions

| Before | After |
|---|---|
| `Refresh(ctx, token)` | `Refresh(ctx, tenantID, token)` |
| `Logout(ctx, token)` | `Logout(ctx, tenantID, token)` |
| `VerifyTOTP(ctx, userID, code)` | `VerifyTOTP(ctx, tenantID, userID, code)` |
| `VerifyRecoveryCode(ctx, userID, code)` | `VerifyRecoveryCode(ctx, tenantID, userID, code)` |
| `DisableTOTP(ctx, userID, code)` | `DisableTOTP(ctx, tenantID, userID, code)` |
| `StartTOTPEnrollment(ctx, userID)` | `StartTOTPEnrollment(ctx, tenantID, userID)` |
| `CompleteTOTPEnrollment(ctx, userID, code)` | `CompleteTOTPEnrollment(ctx, tenantID, userID, code)` |
| `RevokeAllSessions(ctx, userID)` | `RevokeAllSessions(ctx, tenantID, userID)` |
| `Link(ctx, userID, provider, subject)` | `Link(ctx, tenantID, userID, provider, subject)` |
| `Unlink(ctx, userID, identityID)` | `Unlink(ctx, tenantID, userID, identityID)` |
| `ListIdentities(ctx, userID)` | `ListIdentities(ctx, tenantID, userID)` |

**Deleted:**

- **`Core.ClearTOTP(ctx, userID)`** — it removed a second factor with **no proof**.
  The capability still exists on the `Store` (`ClearTOTP(ctx, userID)`), where
  removing someone's 2FA is the application's own authorization decision on its own
  table; `DisableTOTP` is a live caller of it. Call `store.ClearTOTP` from your admin
  path, behind whatever check your console already applies.
- **`Core.EnrollTOTP(ctx, userID)`** — it enabled a secret the user had never
  demonstrated, so a mistyped authenticator could lock them out. Use the staged pair
  that proves a code: `StartTOTPEnrollment` → `CompleteTOTPEnrollment`.

**Unchanged on purpose:** `EnterableTenants(ctx, userID)`. *"Which tenants may this
user enter"* is a question about the user **across** tenants; scoping it would
re-break the platform admin that Phase 8 solved.

### What replaces the check you had

Nothing — you delete it. Inside the library, a user or a session stored in another
tenant is refused with `identity.ErrNotFound` (or `ErrInvalidSession` for a token),
**the same answer a thing that does not exist gets**, so neither is an existence
oracle. Two properties are now guaranteed and tested:

- a miss and a mismatch are one branch, so they cannot be told apart;
- the comparison is on the **stored** tenant (`tenant.FromStored`), so a
  single-tenant row stored as `""` equals `tenant.Single`, and `Single` is not a
  wildcard.

### Two things that are still yours

The compiler cannot enforce either:

- **`Me`** has no `Core` equivalent that takes a user id and a tenant in one call —
  load the user and compare `User.TenantID` yourself.
- **A store failure must surface as itself.** Never fold it onto
  `ErrNotFound`/`ErrInvalidSession`: an outage must not read as "that user does not
  exist", or a database blip signs everyone out of every tenant.

### One behaviour change in `Logout`

`Logout` of another tenant's token now answers `identity.ErrInvalidSession`
(previously an adapter could report success). An **unknown** token still answers
`nil` — a stale cookie must not produce an error the client cannot act on.

And a refused rotation is **not** revoked: that is deliberate. A session whose tenant
differs from its *user's* is corrupt data and is revoked (TD-19); a session whose
tenant differs from the *route's* is a caller error, and revoking there would let a
misconfigured route — or anyone holding a leaked token — destroy valid sessions.

---

## 3. `espresso` — one helper gone, three renamed, one hook changed

| Before | After |
|---|---|
| `espresso.ContextWithUserID(ctx, userID)` | **removed** — use `RequireAuth` / `RequireAuthWS`, whose `decorateAuthed` installs the user id **and** the claims |
| `espresso.SetUserID(ctx, userID)` | `espresso.SetAuditActor(ctx, audit.Actor{UserID: …, TenantID: …})` |
| `espresso.WithUserIDCapture(ctx)` | `espresso.WithAuditActorCapture(ctx)` |
| `espresso.UserIDFromContext(ctx)` | `espresso.AuditActorFromContext(ctx)` |
| `AuthRoutesConfig.OnAuthenticated: func(ctx, userID string)` | `func(ctx context.Context, actor audit.Actor)` |

**Why `ContextWithUserID` could go:** it asserted an identity with no token, and the
gate refused it anyway (`RequireDecision` asks the token which tenant the subject is
from). Its one legitimate use was an integration that verifies tokens **outside**
espresso; if that is you, the answer is a tenant-aware path, not a tenant-less
helper — `decorateAuthed` is what `RequireAuth` installs, and it is unexported, so
mount the gate.

**Why the audit slot grew a tenant:** a public-route audit row (login, TOTP second
leg) has no token, so nothing could name the actor's tenant, and `Actor.TenantID` was
empty on exactly the rows a reviewer asks about first. `SetAuditActor` lets the
handler say it. The `Type` is forced to `ActorTypeUser` — the slot exists for routes
where a *human* authenticated mid-request, and a caller able to claim another type
there could mint a non-user actor with no verified principal behind it.

**`OnAuthenticated`** now receives the actor with the **routed tenant** filled in at
every call site, so the framework's own auth routes produce a complete actor and the
application does nothing.

---

## 4. Upgrade order

1. `go get …@v0.9.0` and build. The compiler lists every call site.
2. **Fix `identity` first** — it is the leaf. Most of the work is inserting the
   tenant, and in an adapter implementing `espresso.IdentityService` the value is
   already a parameter: pass it through.
3. **Delete the guards you wrote.** If you implemented a `sessionIn`/`userIn` check
   before calling `Refresh`/`Logout`/the TOTP verbs, it is now redundant — and its
   comment ("Core takes no tenant, so without this…") is now false.
4. **Replace `EnrollTOTP`** with `StartTOTPEnrollment` + `CompleteTOTPEnrollment`,
   and `ClearTOTP` with your own store call behind your own authorization.
5. **Replace `SetUserID`** with `SetAuditActor`, and decide what tenant to name. On a
   login route it is the tenant the route is mounted for.
6. **Replace `ContextWithUserID`** by mounting `RequireAuth` (or `RequireAuthWS`).
7. Rebuild; a leftover `... is unused` from your linter is the signal that a guard or
   helper of yours is now dead code — that is the shape of this whole release.

### If you are single-tenant

The same changes apply, and the answer is `tenant.Single`, said out loud:

```go
core.Refresh(ctx, tenant.Single, refreshToken)
```

`tenant.Single` is **not** a wildcard: it equals a user or session stored with an
empty tenant, and nothing else.

---

## 5. What this release does **not** change

- The tenant model, `tenant.Descriptor`, or the hierarchy: nothing here touches
  inheritance or authorization.
- The audit format (`canonical_version=4`), or any database. No migration is needed.
- The `Store` port. It never carried the fix; the fix is that the library now does the
  comparison its doc asked callers to do.
- SCIM and the federation route surfaces, which have taken the tenant since #59/#61.

---

## 6. Why there is no shim

The shorthand for the alternative is that a deprecation would have been kind. It would
not: a deprecated tenant-less `Refresh` is exactly the thing this release exists to
delete, and it would keep compiling — in adapters that never learn the tenant exists.
Standing rule 1 says the old name is deleted rather than kept, and the compiler is the
migration guide.
