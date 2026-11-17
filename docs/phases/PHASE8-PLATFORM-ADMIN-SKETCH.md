# Phase 8 — platform admin: entering a tenant

Status: **design, decided 2026-10-05**. This sketch covers TD-01 and TD-02
from `../tasks/tech-debt.md`. It is the document to amend before changing the code it
describes.

## 1. The problem

Tamper's model is "one user row, one tenant" and "one token, one tenant".
That is right for a customer's users. It leaves no place for a **platform
admin**: a person who works for the operator and must act inside many
customers' tenants (support, a console, incident response).

Before this phase the only building block was
`Core.IssueTokensForUserInTenant`, and since #40 it refuses a tenant that is
not the user's own. So there was no supported way at all.

## 2. Decisions

Two were taken by the repo owner on 2026-10-05:

1. **The rights check lives in tamper, behind a port.** A new optional port,
   `identity.MembershipStore`, answers "may this user enter this tenant".
   `Core.EnterTenant` calls it before it mints, so the check cannot be
   forgotten by a caller. The application owns the table.
2. **Entering gives an access token only.** No refresh session. When the
   token expires the console enters again with its home session, and the
   membership is checked again. A removed right stops working within one
   token lifetime.

The rest follows from decisions already recorded:

3. **No wildcard token.** A token is still for exactly one tenant. An entered
   token has the target tenant in `tid`.
4. **A user still has one home tenant.** The user row is not duplicated. A
   platform admin is a user stored in a tenant of the operator's choosing (for
   example `platform`). "One row, one tenant" (`../migrations/MIGRATION-v0.4.md`) stays
   true; membership is additive.
5. **`IssueTokensForUserInTenant` stays strict.** It mints only for the
   user's home tenant. Entering is a different method with a different check.
6. **Guests are refused by default** (added after review of #55, standing
   rule 2). `RequireTenant` refuses an entered token. A route accepts one only
   if it is mounted with `RequireTenantAllowEntered`. See section 4.

## 3. The model

```
user row          home tenant = platform            (identity.Store, unchanged)
membership        (user, acme), (user, globex)      (identity.MembershipStore, new)

home session      access {sub, tid=platform} + refresh        (Login, unchanged)
entered token     access {sub, tid=acme, htid=platform}       (EnterTenant, new)
                  no refresh session
```

An entered token says two things, and they are different facts:

- `tid` — the tenant the token is **for**. This is what the tenant gates
  compare with the route.
- `htid` — the tenant the subject is **from**. It is present only on an
  entered token.

The audit log already separates the same two facts: `Event.TenantID` is the
row's scope and `Actor.TenantID` is the actor's home tenant. With `htid`, a
row written while a platform admin acts in `acme` has scope `acme` and actor
tenant `platform`. `acme`'s export contains it, and it shows who acted.

## 4. API

### `crypto`

```go
// AccessClaims gains:
HomeTenantID string `json:"htid,omitempty"`

// The tenant the subject is from: htid when present, tid otherwise.
func (c *AccessClaims) ActorTenantID() string

// Mints an entered token. ttl <= 0 means the service TTL; a ttl longer
// than the service TTL is cut to it.
func (j *JWTService) IssueAccessEntered(userID string, tenantID, homeTenantID tenant.ID,
    authTime int64, acr string, ttl time.Duration) (string, error)
```

`IssueAccess` is unchanged and never writes `htid`. `VerifyAccess` and
`ParseAccess` still compare `tid` only. They also refuse a token whose `htid`
is not beside a different, non-empty `tid`: no mint here produces one.
`AccessClaims.Entered()` reports whether a token is an entered one.

`IssueAccessEntered` refuses an unset tenant (`ErrTenantRequired`), the
single tenant on either side, and a target equal to the home tenant. An
entered token always names two different real tenants.

### `identity`

```go
type MembershipStore interface {
    // IsMember reports whether userID may enter tenantID.
    IsMember(ctx context.Context, userID string, tenantID tenant.ID) (bool, error)
    // MembershipsFor lists the tenants userID may enter.
    MembershipsFor(ctx context.Context, userID string) ([]tenant.ID, error)
}

func WithMemberships(s MembershipStore) Option      // panics on nil
func WithEnterTenantTTL(d time.Duration) Option     // optional, shorter entered tokens

func (c *Core) EnterTenant(ctx context.Context, session *crypto.AccessClaims,
    target tenant.ID) (Tokens, error)
func (c *Core) EnterableTenants(ctx context.Context, userID string) ([]tenant.ID, error)

// Hooks gains:
OnTenantEntered func(ctx context.Context, user User, target tenant.ID)
```

`session` is the verified claims of the access token the user is entering
from. The first draft took a user id, `authTime` and `acr`. Review showed what
that left to the caller: the `Core` could not tell a home session from an
entered one, and could not know the caller passed the session's real
`auth_time`. With the claims it can.

`EnterTenant`, in order:

1. No membership store → `ErrNoMembershipStore`. No JWT service →
   `ErrNoTokenService`. Both are wiring errors, said plainly.
2. Unset target → `ErrTenantRequired`. Nil session, or one with no subject,
   `auth_time` or `acr` → `ErrInvalidInput`.
3. Everything else that is a "no" → `ErrNotFound`, **one error built in one
   place**:
   - the session is an entered one (no chained entry);
   - the user does not exist;
   - the session's `tid` is not the tenant the user is stored in;
   - the single tenant is on either side;
   - the target is the user's own tenant;
   - `IsMember` is false.

   The user's own tenant was `ErrInvalidInput` in the first draft. That told
   a caller which tenant a user id is stored in, so it is now the same deny.
4. An `IsMember` error is returned as an error, never read as a yes.
5. User inactive → `ErrUserInactive`. Checked after membership, so it is
   never reported about a tenant the user may not enter.
6. Mint with `IssueAccessEntered`, with the session's `auth_time` and `acr`.
   Return `Tokens{Access: ...}` with no refresh token. No session row is
   written.
7. Call `Hooks.OnTenantEntered`. The `Core` has no audit log; this hook is
   where the application records the entry in the entered tenant's log.

`auth_time` and `acr` are copied, so step-up state carries over and is never
raised by entering. The `IssueTokensFor*` methods fall back to "now" and the
default ACR when these are missing. `EnterTenant` does not.

`WithEnterTenantTTL` longer than the access token TTL fails `New` (standing
rule 4).

`EnterableTenants` reports `ErrUserInactive` only when the list would not be
empty, for the same reason as step 5.

### `espresso`

```go
func RequireTenantAllowEntered(resolve func(*http.Request) string) func(http.Handler) http.Handler
func EnteredFromContext(ctx context.Context) (home tenant.ID, entered bool)
```

**`RequireTenant` refuses an entered token**, with the refusal a wrong-tenant
token gets. `RequireTenantAllowEntered` is the same gate that also accepts a
token entered into the routed tenant.

This is the most important thing review changed. In the first draft
`RequireTenant` accepted an entered token like any other. But every route
written before Phase 8 assumes the subject is a user of the routed tenant:

- "My account" handlers are keyed by the bare user id. `AuthRoutes.EnrollTOTP`
  and `DisableTOTP`, and identity linking, would have acted on the admin's
  **home** account from a customer's route.
- `RequireDecision` builds the `authz` subject from the bare user id. The
  roles the admin holds at home would have been checked against the entered
  tenant's resources.

So a guest is refused unless the route invites guests. Opting a route in is a
statement about its handler: it does not treat the subject as a user of this
tenant, and its authorization knows the subject may be a guest
(`EnteredFromContext`).

`RequireAuth` stashes the audit actor with `Actor.TenantID` set to
`claims.ActorTenantID()`: the home tenant for an entered token, `tid`
otherwise. The step-up denial row uses the same value.

There is no built-in "enter" route: the handler is a few lines in the
application, and the route shape is the application's.

## 5. Invariants

1. An entered token is accepted only on routes of its `tid` tenant, and only
   on those mounted with `RequireTenantAllowEntered`.
2. No path mints an entered token without a `true` from `IsMember`.
3. A deny and a miss are the same error (standing rule 3).
4. Entering writes no refresh session. `Refresh` (TD-19) still refuses a
   session whose tenant is not the user's home tenant.
5. `htid` is never the audit scope. The scope is the routed tenant.
6. A deployment that does not use memberships is unchanged, byte for byte:
   no new claim, no new store read.

## 6. What this phase does not do

- **Impersonation** (TD-07). An entered admin acts as themself. Acting as
  another user is a separate design.
- **Tenant hierarchy** (TD-04). A membership names one tenant. It does not
  flow to child tenants.
- **Authorization inside the tenant** (TD-03). Entering says the admin may
  be in the tenant. What they may do there is still the application's
  `authz` decision. A common shape: a global `platform` role in the RBAC
  policy.
- **Suspension** (TD-06) and **tenant lifecycle** (TD-05).
- **A transport route**. See section 4.

## 7. Proof obligations

- Mutation proofs: `EnterTenant` without the `IsMember` call must fail a
  test; a refusal that differs from the missing-user refusal must fail a
  test; an entered mint that writes a refresh session must fail a test;
  `RequireTenant` letting an entered token through must fail a test.
- `examples/multitenant` gains a `platform` tenant and shows the whole flow
  through HTTP: a platform admin with a membership enters `acme`; the token
  works on an `acme` route and is refused on a `globex` route and on a
  `platform` route; an admin without a membership is refused.
- The audit proof is in `espresso/entered_test.go`, not in the example,
  because the example has no audit log: a row written while entered has scope
  `acme` and actor tenant `platform`, and is in `acme`'s export only.

## 8. Known limits

- **The home session is not checked for liveness.** `EnterTenant` sees
  claims, and an access token is stateless. After a logout or a
  `RevokeAllSessions`, a home access token that has not expired yet can still
  enter. The exposure ends at the home token's expiry plus the entered TTL.
- **Entering is not throttled** and a refused entry is not recorded by
  tamper. The hook runs on success only.
- **Authorization for guests** was the application's problem when this phase
  merged. Phase 8b (`./PHASE8B-AUTHZ-TENANT-SKETCH.md`) closes it: the subject
  carries its home tenant, and a guest needs a binding in the tenant entered.
- **A removed membership keeps working until the token expires.** There is no
  revocation list. Keep `WithEnterTenantTTL` short.
- **Deactivating the admin** has the same window, for the same reason.
- **`RevokeAllSessionsForTenant(acme)` does not touch entered tokens.** They
  have no session row.
- **`/me`-style routes** that load "my account in this tenant" do not answer
  for an entered admin, who has no account there. That is correct, and an
  application's console must not depend on them.
- **SCIM and service accounts** are not part of this. They authenticate with
  their own credentials.

> **Amendment, 2026-11-16 — entered tokens carry a required member/guest
> mode; the store, not the caller, chooses it (#169, for `kubuskotak/aio`
> #61).**
>
> Phase 8 gave every entered token one lifetime (`WithEnterTenantTTL`). That
> is no longer enough: ADR-0007 §3–4 in `kubuskotak/aio` separates a direct
> **member** of the tenant from a Console **guest**. A member's token must live
> as long as an ordinary access token, a guest's must keep the shorter
> `WithEnterTenantTTL`, and a route must be able to tell the two apart without
> reading the application's bindings table on every request.
>
> The first draft of #169 added the mode as a caller argument and kept the old
> shapes beside the new ones. Review rejected that under standing rule 1. This
> amendment is the decision the code follows; no compatibility mode survives
> v0.15.0.
>
> **1. `em` is mandatory on every entered token.** `crypto.AccessClaims` gains
>
> ```go
> EnterMode EnterMode `json:"em"`
> ```
>
> with `EnterMode` values `member` and `guest`. `Purpose` still says `access`;
> `em` refines an entered token, it does not create a second token shape for
> `RequireAuth`. `AccessClaims.Member()` is true only for an entered token
> with `em=member`; `Guest()` only for `em=guest`. There is no `""` fallback:
> an entered token without `em`, with an empty mode, or with an unknown mode
> is refused by `ParseAccess`/`VerifyAccess`. The only tokens that become
> invalid are outstanding entered tokens at upgrade time; they are short-lived
> and have no refresh session, so re-entering is the recovery.
>
> **2. One mint, and it always writes `em`.**
>
> ```go
> func (j *JWTService) IssueAccessEntered(userID string, tenantID, homeTenantID tenant.ID,
>     authTime int64, acr string, ttl time.Duration, mode crypto.EnterMode) (string, error)
> ```
>
> `IssueAccessEnteredMode` is gone. `IssueAccessEntered` refuses an invalid
> mode (`ErrInvalidToken`), and writes `em` (never omitted) on every token it
> returns. `IssueAccess` and `IssueAccessImpersonated` are unchanged and never
> write `em`.
>
> **3. The mode comes from `MembershipStore`, never from the caller.**
>
> ```go
> type Membership struct {
>     Tenant tenant.ID
>     Mode   crypto.EnterMode
> }
>
> type MembershipStore interface {
>     // Membership reports the subject's mode in tenantID. (`false, nil`)
>     // is the deny-by-default miss; an error is a failed lookup, never a
>     // yes. The mode must be member or guest.
>     Membership(ctx context.Context, userID string, tenantID tenant.ID) (crypto.EnterMode, bool, error)
>     // MembershipsFor lists the subject's memberships (tenant + mode).
>     MembershipsFor(ctx context.Context, userID string) ([]Membership, error)
> }
> ```
>
> `IsMember` is replaced by `Membership`; `MembershipsFor` keeps its name but
> returns modes. `Core.EnterTenant` has **no mode parameter** and no way for a
> caller to choose one:
>
> - `Membership` returns `false` → the existing collapsed `ErrNotFound`.
> - `Membership` returns an error → returned wrapped, never a yes.
> - mode is empty or not `member`/`guest` → `ErrInvalidInput`, no token. This
>   is a store bug, not a caller preference; it must fail closed.
> - otherwise mint with that mode.
>
> A caller that wants a long member token cannot ask for one: it must hold a
> membership row whose store-returned mode is `member`.
>
> `EnterableTenants` reads `MembershipsFor`, returns the tenant ids, and
> fails closed on an empty/unknown mode rather than listing a tenant whose
> rights it cannot classify.
>
> **4. TTL follows the store's mode.**
>
> - `member`: the ordinary access-token TTL (`JWTService.AccessTTL()`), the
>   same lifetime as the home session.
> - `guest`: `WithEnterTenantTTL`, or the service TTL when the option is not
>   configured. `WithEnterTenantTTL` remains the guest knob and is still
>   refused by `New` when longer than the access TTL.
>
> There is one `EnterTenant`; the old entered-token bytes are not preserved.
>
> **5. Phase 8's decisions that do not move.**
>
> - Entering gives an **access token only**: no refresh session, no session
>   row. When it expires, the caller enters again with the home session and
>   the membership (and mode) are checked again.
> - **One token, one tenant.** `tid` is the tenant the token is for, `htid`
>   the subject's home; no token is valid for two tenants, and `RequireTenant`
>   still refuses entered tokens unless a route opts in.
> - `auth_time` and `acr` are copied from the home session; entering never
>   makes an old login look fresh.
> - A deny and a missing membership remain the same error.
>
> **6. Migration and tests.**
>
> This is a **breaking** change, recorded under `### Changed` for **v0.15.0**:
> every `MembershipStore` implementation, `MemStore`, the
> `examples/multitenant` store, and every caller of `IssueAccessEntered` must
> change in the same release. Tests must prove:
>
> - a store returning `guest` yields `em=guest` and the enter TTL, even if a
>   caller tried to ask for member (there is no caller mode);
> - a store returning `member` yields `em=member` and the access TTL;
> - an empty/unknown mode from the store yields `ErrInvalidInput` and no token;
> - `ParseAccess` refuses an entered token with no `em`, empty `em`, or an
>   unknown `em`, and refuses `em` on a non-entered/impersonated token;
> - the legacy "no `em` means guest" behaviour is gone.
