# Identity and factors

`identity` is credentials and sessions: register, log in, refresh, log out, TOTP
enrolment, and linking several external identities to one user. It sits behind a single
`identity.Store` port, and it mints tokens through `crypto`.

```go ignore
core, err := identity.New(store, jwtService,
    identity.WithRefreshTTL(30*24*time.Hour),
    identity.WithDefaultACR(crypto.ACRLocalPassword),
)
```

## Sessions carry three facts about how they were established

| Claim | Meaning |
|---|---|
| `auth_time` | When the user actually authenticated — not when the token was issued |
| `acr` | The **policy class** the deployment accepted (`crypto.ACRLocalPassword`, `crypto.ACRIncommonSilver`, …) |
| `amr` | The **methods** the session proved: `crypto.AMRPassword` (`"pwd"`), `crypto.AMROTP` (`"otp"`), `crypto.AMRSAML` |

`acr` and `amr` answer different questions, and neither answers the other. That separation
is what makes step-up expressible: a locally-enrolled TOTP session is
`acr=local-password` **and** `amr=["pwd","otp"]`.

## Step-up: ask for a fresh session, and for a method

```go ignore
// Fresh in the last 15 minutes, and this deployment's accepted policy class.
mux.Handle("/admin", espresso.RequireFreshAuth(15*time.Minute,
    []string{crypto.ACRLocalPassword})(adminHandler))

// The same gate, plus: this session must have PROVED a second factor.
mux.Handle("/billing", espresso.RequireFreshAuth(15*time.Minute,
    []string{crypto.ACRLocalPassword},
    espresso.StepUpRequireMethods(crypto.AMROTP))(billingHandler))
```

The two axes stay independent, in both directions:

- A method does **not** lift a class requirement (an `otp` session under a silver-only gate
  is still refused).
- A class does **not** supply a method (a silver session with no `amr` is refused by a
  method gate).

A refusal says which axis failed: `StepUpDenyMissingMethod` for the method, the existing
stale-ACR reason otherwise. A token minted before `amr` existed simply has no methods, and
is refused by a method gate — the safe direction.

## Second factors per role, not just globally

`WithTOTPRequired(true)` is process-wide: everybody, or nobody. When the policy is a role
mapping — *platform admins must use 2FA, a read-only viewer need not* — implement the port:

```go ignore
type SecondFactorPolicy interface {
    RequiredFor(ctx context.Context, tenantID tenant.ID, userID string) (SecondFactorRequirement, error)
}

type SecondFactorRequirement struct {
    AtLogin    bool        // block the password leg until the user enrols (model A)
    ForActions bool        // let the routes demand a step-up (model B)
    GraceUntil time.Time   // postpone AtLogin until this instant (model C)
}
```

```go ignore
core, err := identity.New(store, jwtService,
    identity.WithSecondFactorPolicy(myPolicy),
)
```

Three rules carry the security here:

1. **An error denies.** A policy that cannot be read never opens a login — it is not
   "not required".
2. **`WithTOTPRequired` is a floor.** A policy may add requirements, but it cannot exempt a
   user from one the deployment already made for everyone. Both directions are tested.
3. **A requirement is not a permission.** Asking for a second factor can never satisfy an
   authorization decision.

`identity` never learns what a role is: the mapping is yours, through the port. (This is the
same shape as the impersonation policy, and for the same reason.)

## Adapters: say which leg you served

`identity` cannot tell from a call alone whether it is serving the password leg or the
second leg. The adapter must say so, because a method gate depends on it:

```go ignore
// password leg
tok, err := core.IssueTokensForUser(ctx, user, tenantID, authTime, acr, crypto.AMRPassword)

// second leg
tok, err := core.IssueTokensForUser(ctx, user, tenantID, authTime, acr,
    crypto.AMRPassword, crypto.AMROTP)
```

The methods are variadic, so an existing call compiles and produces the same token bytes: a
session with no methods carries no `amr` key at all.

::: warning Interface compatibility
A variadic method does not satisfy an interface declared with the old (non-variadic)
signature. If you keep mints behind an interface — a common shape for test doubles — that
declaration needs updating. Direct calls are unaffected.
:::

## Session lifecycle

| Operation | What it does |
|---|---|
| `Login` | Password verification with equal timing and throttling; returns `ErrTOTPRequired` when a second factor is owed |
| `Refresh` | Rotates the session. Tenant, `auth_time`, `acr` and `amr` are copied unchanged — a rotation is not a new authentication and never adds a method |
| `Logout` / `RevokeAllSessions` / `RevokeAllSessionsForTenant` | Revokes one, a user's, or a whole tenant's sessions |
| `StartTOTPEnrollment` / `CompleteTOTPEnrollment` | The enrolment ceremony. A user who owes a second factor must still reach enrolment — the failure mode there is a support ticket, not an error log |

Access tokens are purpose-bound: a `purpose=access` token, an entered token, and an
impersonated token are not interchangeable, and every gate checks the purpose before
anything else.

---

Looking a name up? The [API reference](../api/) lists every exported package.
