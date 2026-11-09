# Phase 18 — `PasswordPolicy` as a port (TD-12's sibling)

**Slice 18a — the port, and the ordering that makes it safe.**

## 1. The gap, checked before designing for it

`identity.Register` already enforces a floor: `validatePassword` refuses anything outside
`MinPasswordLen`..`MaxPasswordLen` (`identity/core.go:627`). What tamper cannot express is
everything else a deployment needs — a breach list, a length by role, a rotation cadence, a refusal
of the user's own email — and it should not try: that list has no end, and every item on it is a
product decision.

The item's own text claimed the SCIM path was "easy to miss". **Checked, and corrected here:**
`espresso`'s SCIM surface declares `changePassword: not supported`, and no SCIM write in this
repository sets a password. The SCIM path is not a path. That is the third time an item's evidence
was stale in this way (TD-14's, TD-13's, this), and the reason the rule is to check rather than
trust an item's prose.

## 2. The decision

A port, `identity.PasswordPolicy`, the same shape as `SecondFactorPolicy` (#120) and
`ImpersonationPolicy` (#88) — those three now share one construction: *policy lives in the
application, the library owns the mechanism*.

```go
type PasswordPolicy interface {
    Accept(ctx context.Context, tenantID tenant.ID, userID, email, password string) error
}
```

Wired with `WithPasswordPolicy`. A `Core` without one behaves exactly as before — additive, so
0.14.0 needs no migration guide.

## 3. The ordering is the security property

`checkPassword` runs **the floor first, then the policy**. Two consequences, both tested:

- a policy can never be asked to approve something tamper already refuses, and
- **a permissive policy cannot relax the library's own minimum.** A port whose zero value made the
  floor optional would be a way to ship a weaker system than the library's minimum, silently. That
  is not a choice an application should be able to make by accident.

## 4. An error denies

`Accept` returning an error refuses the registration, wrapped in `ErrPasswordPolicy` so a caller
catches every refusal the same way. A policy that cannot reach its breach list, or cannot read the
user's role, must not let the password through — the same rule `SecondFactorPolicy` carries, for
the same reason: an unreadable policy must never open a door.

`userID` is empty on this path because the user does not exist yet. The doc comment says so, and
says what a policy should do about it: treat `""` as unknown, and remember that refusing is always
available and always safe.

## 5. What this does not do

- **No policy implementation ships.** Not even a length check: shipping one would make tamper's
  opinion the default, and the port exists so that it is not.
- **No breach-list integration.** It is a network call on a credential path; whether that belongs
  in a request is the application's call, and the port is what lets it be.
- **No change to password verification or hashing.** This slice is about what may be *set*.

## 6. Tests and mutation proofs

Six subtests: the floor alone with no policy; a policy refusing; **a policy error denying and
leaving no user row**; a permissive policy unable to relax the floor; the policy receiving the
tenant and email with an empty user id; and `WithPasswordPolicy(nil)` panicking at construction
rather than reading as "no rules" forever.

Four mutants, all red: the floor replaced by the policy (M1, the pre-slice behaviour); a policy
error read as acceptable (M2); the floor skipped when a policy exists (M3); `nil` accepted (M4).
