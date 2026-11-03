# Phase 13 — Drop the compatibility shims (TD-28)

Status: **accepted 2026-11-03; D1–D5 decided as recommended.** Slice 13b
(`identity`) lands with this line; 13c (`espresso`) and 13d (docs, release) follow.

TD-28 is the last P1 in the platform-admin line, and it is the only item in
`tech-debt.md` that is not a gap in a feature but a **rule** that was applied
incompletely. This sketch re-inventories it, because the item's own evidence table
says "the list comes from a read of the code and each line must be checked again
when its change is made" — and the re-read found the list is **eight methods short**
(§2.2).

---

## 1. The rule, and why the work exists

Through Phase 7 the rule was: *an empty tenant must behave exactly as it did before
tenants existed.* So every API grew **two forms** — one with a tenant, one without —
so that pre-tenancy callers kept working.

On 2026-10-05 that rule was replaced: **no compatibility code** (`CLAUDE.md`
standing rule 1). Single-tenant stays supported, but the application says
`tenant.Single` out loud.

`tech-debt.md` states the cost in one sentence, and it is worth keeping in view for
the whole phase:

> Each shim is a second way to do something, and the second way is the one without a
> tenant. #56 showed the cost: a gate that had to serve both ways **guessed a
> tenant**, and three reviews could not make the guess safe.

Two decisions are already taken and are **not** reopened here:

- **Throttling stays optional** (decided 2026-10-06). `New` does not require
  `WithThrottling`; the docs recommend it for any deployment that serves a login
  form. That row is closed.
- **`identity/handwritten_adapter_test.go`** is a second implementation of the
  `Store` port, not "the compatibility path", and it stays (§2.1, #62).

---

## 2. The inventory, per row, against the code today

### 2.1 Rows that are done

| Where | Verified how |
|---|---|
| `crypto` — one set of functions, `purpose` required (#57) | `JWTService` has no tenant-less mint or verify: `IssueAccess`, `IssueAccessEntered`, `IssueAccessImpersonated`, `IssueTOTPPending` and `VerifyAccess`/`VerifyTOTPPending` all take a `tenant.ID`; `ParseAccess` reads claims rather than minting |
| `identity` — one mint function that always reads the user and checks the tenant (#58) | `IssueTokensForUser(ctx, userID, tenantID, authTime, acr)` loads the user, compares `FromStored(user.TenantID) != tenantID` in ONE branch with the miss, and answers `ErrNotFound` |
| `espresso.IdentityService` port (#59) | every method takes the routed tenant, resolved by the required `AuthRoutesConfig.Tenant` |
| SCIM (#61) | no `SCIMConfig.Tenancy`, no `TenantBoundStores`, no unscoped store form; the gate resolvers are `(tenant.ID, bool)` (#60) |
| Tests, comments, names (#62) | `identity/legacy_adapter_test.go` is `handwritten_adapter_test.go` |

### 2.2 The row that is **eight methods short**

TD-28 names six: `Refresh`, `Logout`, `VerifyTOTP`, `VerifyRecoveryCode`,
`EnrollTOTP`, `DisableTOTP`. Enumerating `Core`'s exported surface finds **eight
more** that take a bare `userID` and belong to the same class:

| Method | Takes | Added |
|---|---|---|
| `StartTOTPEnrollment(ctx, userID)` | bare user id | 2026-07-10 |
| `CompleteTOTPEnrollment(ctx, userID, code)` | bare user id — and **mints tokens** | 2026-07-10 |
| `ClearTOTP(ctx, userID)` | bare user id — **removes a second factor with no proof** | 2026-07-10 |
| `RevokeAllSessions(ctx, userID)` | bare user id | 2026-07-09 |
| `Link(ctx, userID, provider, subject)` | bare user id — attaches an identity | 2026-07-10 |
| `Unlink(ctx, userID, identityID)` | bare user id — detaches one | 2026-07-10 |
| `ListIdentities(ctx, userID)` | bare user id (read) | 2026-07-10 |
| `EnterableTenants(ctx, userID)` | bare user id (read, and **legitimately** cross-tenant — it lists where a user may enter) | 2026-07-10 |

The dates are checked, not assumed: those methods landed **2026-07-09/10**, and
TD-28 was written **2026-10-05**. The list was therefore incomplete *when it was
written*, not overtaken by later work. That matters for the phase's shape: the
homework is not "the six we knew about" but "every bare-key method `Core` exposes",
and the re-read is the reason this sketch exists.

`EnterableTenants` is the one that should stay unscoped: asking "which tenants may
this user enter" is a question *about* the user across tenants, and scoping it would
reintroduce the platform-admin problem Phase 8 solved. It is listed here so that the
slice does not quietly "fix" it.

### 2.3 Two look like shims and are not

- **`Impersonate(ctx, session *crypto.AccessClaims, targetUserID)`** takes verified
  claims, so the tenant comes from the token, and the target's tenant is compared to
  it (Phase 11). Not a shim.
- **`IssueTokensForUser`** already checks the tenant (§2.1). It is the pattern the
  rest of §3 copies.

### 2.4 The `Store` port, and why this phase does not change it

The port has the matching bare-key methods — `ClearTOTP`, `EnableTOTP`,
`SetTOTPPending`, `SetRecoveryCodeHashes`, `TOTPState`,
`RevokeAllRefreshSessionsForUser`, `IdentitiesByUserID`, `CountIdentitiesByUserID` —
and its own doc already assigns the comparison to its callers:

> `UserByID` … **the callers that need a tenant check compare `User.TenantID`** …
> That comparison is why the returned row MUST carry its `TenantID`
> (`identity/store.go:35-40`)

So the fix in §3.2 needs **no port change**: `UserByID` already returns the field,
and moving the comparison from every adapter into `Core` is a change in one package.

---

## 3. The two open items

### 3.1 `espresso`: two ways to declare an identity, one without a token

| Symbol | Where | What it is |
|---|---|---|
| `WithUserIDCapture`, `SetUserID`, `UserIDFromContext` | `espresso/auth.go:90,110,124` | the **audit attribution** slot: a handler that completes authentication mid-request (login, TOTP verify) records the user id so the row's `actor.user_id` is populated. `Auditor` installs the slot (`audit.go:98`) and reads it (`:108`) |
| `ContextWithUserID` | `espresso/auth.go:244` | puts a user id straight into `userIDKey{}` — an identity asserted **without a verified token** |

**What is NOT wrong with them**, verified so this section does not overstate:

- **They cannot bypass the gate.** `RequireDecision` reads the claims and refuses
  when `tokenFitsTenant(nil, …)` is false (`espresso/decision.go:150-170`), so a
  token-less identity is a 401 on any route with a decision gate. That is Phase 9
  and 11's work holding.
- **The audit row is scoped correctly anyway.** `eventScope` uses the **pinned**
  routed tenant (`TenantFromContext`), and `PinTenant` pins one. On a public route
  `actor.TenantID` is empty — correct, because no token exists yet and the user's
  home tenant is genuinely unknown at that moment. The row's scope is `Event.TenantID`.

**So what is the defect?** The same one TD-28 names: it is a **second way to say who
this request is**, and that way carries no token and no tenant. The decision is
therefore not "is it exploitable" but **"is it still needed, and may it stay
tenant-less?"** — four answers are open in §5, and they are the point of this slice.

### 3.2 `identity`: every bare-key method becomes tenant-keyed

The failure mode, precisely. Take a route on tenant A that receives a refresh token
belonging to a session in tenant B:

- `Core.Refresh` **does** check that the session's tenant equals the **user's** tenant
  and revokes on mismatch (`identity/core.go:405-417`, TD-19/#47). It does **not**
  know which tenant the *route* resolved, because nothing passes it.
- So the call succeeds, rotates the session, and returns tokens for **B** on a route
  that is A's.
- Today, the check that catches this lives in the **application**: the port doc says
  so in as many words (§2.4). Six call sites per application, and **an adapter that
  forgets still compiles** — which is TD-28's own definition of the debt.

For the `userID`-keyed methods the shape is the same with one fewer guard: there is
no session row to compare against, so the library cannot tell that the user id
belongs to another tenant at all.

**The fix has a precedent in this repo**, and it is worth copying exactly
(`identity/core.go:338-360`):

```go
if err := c.mintGate(tenantID, authTime, acr); err != nil { … }   // wiring first
user, err := c.store.UserByID(ctx, userID)
// ONE branch for the miss and the mismatch: two returns could drift into two
// distinguishable errors.
if err != nil || tenant.FromStored(user.TenantID) != tenantID {
    return Tokens{}, fmt.Errorf("%w: user %s", ErrNotFound, userID)
}
if !user.Active { return Tokens{}, ErrUserInactive }              // AFTER the tenant check
```

Three properties are load-bearing and each gets a test: **deny is a miss** (one
error, not two), **`FromStored` not `New`** (the value came out of storage), and
**`Active` after the tenant** (the order is deliberate — `ErrUserInactive` is a
deliberate disclosure and must not be made about a user through a key bound to
another tenant).

For `Refresh` and `Logout` the comparison is **`session.TenantID` against the
requested tenant** — more direct than going through the user, and `Refresh` already
loads both.

---

## 4. A second category the inventory turned up: twin operations

Not tenant shims, but the same disease — a second way to do something where the
second way is weaker. They are recorded here because two of them are decided by the
same slice, and one is a security question:

| Twin | The other way | Question |
|---|---|---|
| `DisableTOTP(ctx, userID, currentCode)` — requires the current code | `ClearTOTP(ctx, userID)` — **requires nothing** | Which callers legitimately hold only a user id? An admin console holds a *routed tenant*, which is what §3.2 would give it |
| `StartTOTPEnrollment` + `CompleteTOTPEnrollment` — staged, and the second step proves the user can produce a code | `EnrollTOTP(ctx, userID)` — enables the secret immediately | Keep the one-shot form? It is the one that can lock a user out of an account with a half-configured authenticator |
| `RevokeAllSessionsForTenant(ctx, tenantID)` | `RevokeAllSessions(ctx, userID)` | The scoped one exists; is the unscoped one used by anything that is not a user acting on themselves? |

---

## 5. Decisions this sketch needs

All five are **decided** (2026-11-03), as recommended:

| # | Decision | Consequence |
|---|---|---|
| **D1** | Add `tenant.ID` to the bare-key `Core` methods — all of §2.2, not the six TD-28 named | **Breaking**, and per rule 1 there is no shim: the next release is `0.9.0` with a `MIGRATION-v0.9.md`. The parameter goes **immediately after `ctx`**, which is where `Store` and `espresso.IdentityService` already put it, so an adapter's call is a straight pass-through |
| **D2** | **Delete** `ContextWithUserID`; the tenant-aware path is `RequireAuth` / `RequireAuthWS` → `decorateAuthed` | Breaking for an integration that verifies tokens OUTSIDE espresso, and the decision carries that condition: if such a caller turns out to exist, the answer is a tenant-aware replacement, not a tenant-less helper. `espresso`'s own tests move to the token path |
| **D3** | `SetUserID` / `WithUserIDCapture` **carry the tenant**, so a public-route row can name `actor.TenantID` instead of leaving it empty | The shape is `SetAuditActor(ctx, audit.Actor)`, which is additive; pairs with TD-08 (closed) |
| **D4** | **`ClearTOTP` and `EnrollTOTP` are deleted**; `RevokeAllSessions` takes a tenant like the rest | One way per operation. The `Store` port keeps `EnableTOTP` and `ClearTOTP` — the staged flow and `DisableTOTP` still use them |
| **D5** | **`EnterableTenants` stays unscoped**, and is the only one | Recorded so a future reader does not "fix" it |

Two consequences worth stating because they change the shape of the work:

- **13b is `identity`-only and needs no port change.** `Store.EnableTOTP` and
  `Store.ClearTOTP` remain used by the staged enrollment and by `DisableTOTP`, and
  `UserByID` already returns the tenant (§2.4).
- **Deleting `Core.EnrollTOTP` does not break `espresso`'s code**, because
  `IdentityService` is an interface the APPLICATION implements. Its own twin — the
  port exposes both `EnrollTOTP` and `EnrollTOTPViaSession` — is an `espresso`-side
  question and belongs to 13c, which is also where the port's doc comment ("the
  adapter checks first that the user … is stored in that tenant") becomes only
  partly true and must be split into pass-through and still-the-adapter's-job.

**`Refresh` and `Logout` need one more decision, taken while implementing: a routing
mismatch is refused WITHOUT revoking the session.** TD-19 revokes when a session's
tenant differs from its *user's* — that is corrupt data and must not be retryable.
A session whose tenant differs from the *route's* is a caller error: revoking there
would let a misconfigured route (or anyone holding a leaked token) destroy valid
sessions. The two mismatches therefore get different treatment, and the code says
why.

---

## 6. Invariants

1. A tenant-scoped operation reads the tenant from its argument — never from the
   context, never guessed, never defaulted to `tenant.Single`.
2. A store row's tenant is compared with `tenant.FromStored`, because the value came
   out of storage; a request's tenant goes through `tenant.New`, where `""` denies.
3. Deny is a miss: a cross-tenant key and an unknown key produce the **same** error,
   so neither is an existence oracle.
4. `ErrUserInactive` is decided **after** the tenant check, never before.
5. A method that mutates a credential (`ClearTOTP`, `DisableTOTP`, `Unlink`, …)
   requires a tenant, like every other mutation.
6. A token-less identity never satisfies a decision gate (already true; this phase
   must not weaken it) and never becomes the actor of a row scoped to another tenant.
7. One way per operation: where two methods do the same thing, the weaker one is
   deleted rather than deprecated (rule 1).

---

## 7. Tests and mutation proofs

Per package, and every test ships with a mutant that must go red — verified to
compile before it is counted.

**`identity`** (the bulk):

| Test | Mutant |
|---|---|
| a user id from another tenant → `ErrNotFound`, the same as an unknown id | return distinct errors for the miss and the mismatch |
| a refresh session from another tenant → `ErrInvalidSession`, and the session is revoked | drop the routed-tenant comparison (TD-19's check alone stays green — that is the point) |
| `Active` is decided after the tenant: an inactive user in the wrong tenant → the generic error | check `Active` first |
| the comparison uses `FromStored`: a session stored as `""` equals `tenant.Single` | use `New` |
| each of the eight §2.2 methods refuses a foreign user | drop the tenant parameter from one |
| `EnterableTenants` still answers across tenants | scope it |

**`espresso`**: a public-route audit row carries the actor's tenant when the handler
supplies one (D3); `ContextWithUserID` is gone and its tests use a verified token
(D2); a token-less identity is still a 401 at every decision gate (the invariant this
phase must not lose).

---

## 8. Slices

1. **13a — the rule and the inventory.** This sketch, accepted, with the corrected
   eight-method list and the five decisions.
2. **13b — `identity`.** `tenant.ID` on the bare-key methods; the comparison moved
   out of the adapters into `Core`; the twins in §4 deleted. Breaking, so it carries
   the `MIGRATION-v0.9.md` entry.
3. **13c — `espresso`.** D2 and D3: the helpers either carry a tenant or are gone,
   and the audit-actor path is the tenant-aware one.
4. **13d — docs and the release.** `tech-debt.md` TD-28 closed, with the eight
   methods it missed recorded so the next reader knows the list was wrong; the
   `[Unreleased]` entry; `MIGRATION-v0.9.md`; the version cut.

`13b` before `13c` because the espresso helpers are meaningless until the library
can say what a tenant-less call means, and because rule 7 asks for one package per
change.

---

## 9. What this phase does not do

- It does not add a tenant to `EnterableTenants` (§2.2, D5).
- It does not change the `Store` port: `UserByID` already returns the tenant, and the
  comparison moves to the caller side *inside* the library.
- It does not reopen "one row, one tenant" or the hierarchy decisions; nothing here
  touches inheritance or authorization.
- It does not deprecate anything. Per rule 1 the weaker method is deleted, and the
  migration guide says so.
