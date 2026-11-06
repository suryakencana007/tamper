# Phase 16 — Second-factor policy, per role (TD-13)

Status: **reviewed 2026-11-06, D3 replaced by D3′ (§1.1), no code yet.**

This document reached `main` without a PR review of its own — it was swept into a security PR
by a branch-base mistake (see the closing comment on #116). It has now been read as a review,
and §1.1's decision was changed as a result.

TD-13 is the last P2 that is tamper's own work. It is a **policy** gap, not a mechanism gap:
both enforcement points already exist, and the product question — *block at login, or block
the privileged action?* — has been answered below as a decision.

---

## 1. Re-verification, per `/slice` step 1

| The item says | Verified |
|---|---|
| *"`identity.WithTOTPRequired` applies to the whole process (`identity/core.go:54`)"* | **True.** It sets `c.totpRequired`, and `Login` answers `ErrTOTPRequired` for every user: `if user.TOTPEnrolled \|\| c.totpRequired` (`identity/core.go:286`) |
| *"You cannot say 'platform admins must use 2FA, normal users need not'"* | **True** — the switch is process-wide by construction |
| *"workaround: `RequireFreshAuth` with strict `acrValues` on platform routes … platform admins must sign in through an IdP with MFA"* | **True, and it hides the real blocker** — see §1.1 |

The enforcement primitives that DO exist:

- **Login gate.** `ErrTOTPRequired` + a **pending token** (`IssueTOTPPending`), then
  `POST …/auth/totp/enroll` → `EnrollSession` → `EnrollTOTPViaSession(tid, sessionToken, …)`.
  Verified end to end: a blocked user can enrol **without** a session, so model A (§2) has
  no lockout dead end.
- **Action gate.** `RequireFreshAuth(maxAge, acrValues)` / `RequireFreshAuthWithAudit`
  (`espresso/stepup.go:89, 132`): fails closed when `auth_time` is too old or `acr` is not in
  the list.

### 1.1 The finding: a TOTP session still carries the password ACR

`CompleteTOTPEnrollment` mints with `c.defaultACR` (`identity/totp.go:104`), and the second
leg of a TOTP login mints through the application adapter with `DefaultACR()`
(`examples/multitenant/identity_adapter.go:133`). The default is
`crypto.ACRLocalPassword` (`identity/core.go:91`).

**Consequence: there is no ACR that means "this session proved a second factor".** A user
who typed a password and a TOTP code is indistinguishable, by ACR, from one who typed only a
password. That is why TD-13's workaround says "sign in through an IdP with MFA": the only
ACR that satisfied step-up was somebody else's.

So **model B cannot be expressed today**, and something has to make "a second factor was
proved" askable.

**The first draft of this section answered with `ACRLocalTOTP`, stamped over
`ACRLocalPassword`. That is withdrawn.** It was the wrong category, and the cost proves it:
every existing `acrValues` matcher that lists `ACRLocalPassword` would silently stop matching
TOTP sessions, which is a breaking change for a question that has a standard shape.

`acr` and `amr` are different claims in OIDC/SAML, and this repository only has the first
(`crypto/jwt.go:306-307`; there is no `amr` anywhere in the tree):

| Claim | Answers | Example |
|---|---|---|
| `acr` | which **policy class** was satisfied | `urn:mace:incommon:iap:silver` |
| `amr` | which **methods** were actually proved | `["pwd","otp"]` |

Folding "methods" into `acr` would make one claim carry two meanings — the same shape of
mistake as a bare `string` standing in for `tenant.ID`, which this repo already paid for. So:

**D3′ — add `amr []string` to `AccessClaims`; leave `acr` exactly as it is.**

- filled at the minting site, never by a client: it is inside the signed token, like `acr`;
- `["pwd"]` for a password-only session, `["pwd","otp"]` after `VerifyTOTP` or
  `VerifyRecoveryCode`, `["sso"]` for a federated login, and `"hwk"`/`"swk"` become available
  the day a second factor other than TOTP exists;
- `RequireFreshAuth` gains an **additive** option (`StepUpRequireMethods("otp")`), so a gate
  can ask for the method instead of borrowing another IdP's `acr`;
- **nothing breaks**: no `acr` value changes, no `acrValues` matcher changes meaning, and no
  migration guide is needed. 0.12.0 is additive.

What that does *not* do, stated plainly: a local TOTP session still does not satisfy a gate
that demands `ACRIncommonSilver`, because it is not in that policy class — the fix is a gate
that asks about methods, not a stamp that lies about the class.

---

## 2. The three models, and the decision

Each model is a place to enforce, and they compose:

| Model | Enforced at | A user who has not enrolled… |
|---|---|---|
| **A. At login** | `Login` → `ErrTOTPRequired` + pending token | is blocked from everything except enrolment (existing behaviour, made conditional) |
| **B. At the action** | `RequireFreshAuth(acrValues: […], StepUpRequireMethods("otp"))` on privileged routes | keeps using the app, and is refused at the action that needs a second factor |
| **C. Grace** | A deadline in the policy | keeps everything until the deadline, then falls into A |

**Decision: A for privileged roles, B for the rest, with C as the rollout knob.** That
follows from what the two models cost the user: a platform admin who can browse a console
without a second factor is not really an admin gate, and a customer's viewer who must enrol
before seeing their own dashboard is an onboarding wall for a role that changes nothing.

What is explicitly **not decided here**: which roles are "privileged". That mapping belongs
to the application (§3), not to tamper.

---

## 3. The policy is a port the application implements

`identity` must not learn what a role is, and must not depend on `authz`. Precedent: Phase
11's `ImpersonationPolicy` is an interface the application implements, exactly because
tamper names no table and reads no foreign model.

```go
// identity
type SecondFactorRequirement struct {
	AtLogin    bool          // model A
	ForActions bool          // model B — the routes decide via RequireFreshAuth
	Grace      time.Duration // 0 = in force now; >0 = model C
}

type SecondFactorPolicy interface {
	// RequiredFor answers for one user. An error denies: no error return may be
	// read as "not required".
	RequiredFor(ctx context.Context, tenantID tenant.ID, userID string) (SecondFactorRequirement, error)
}
```

Wired like impersonation: `identity.WithSecondFactorPolicy(p)`. A `Core` without one keeps
today's semantics exactly — `WithTOTPRequired` continues to mean "everyone", so an existing
deployment is unchanged.

Two rules in the port's doc, both of which are the whole point:

- **Deny is a miss.** A policy that errors, or that cannot decide, denies; it never means
  "not required". The application's console keeps working only if the policy says so.
- **The policy is a *requirement*, not a permission.** It says a second factor is owed; it
  grants nothing. Authorization stays in `authz`, and a requirement never widens access.

---

## 4. Invariants

1. A `Core` with no policy behaves exactly as before — `WithTOTPRequired` is unchanged, and
   the process-wide switch keeps its meaning.
2. Policy errors deny. There is no path where an unreadable policy becomes "allowed".
3. **No user can be locked out of enrolment.** Any requirement that blocks login must leave
   the pending-token enrolment path reachable — asserted with a test, because the failure
   mode is a support ticket, not an error log.
4. A requirement never grants. `RequiredFor` cannot satisfy a `RequireDecision`, and the
   gate that enforces it fails closed on its own claims.
5. The policy is asked **once per login** and its answer is not cached by tamper: the
   application owns freshness, and a stale "not required" is a security decision tamper
   must not make for it.
6. `acr` is the session's claim about *what was proved*, so a TOTP session's ACR must say
   so — otherwise every `acrValues` gate is asking the wrong question (§1.1).
7. Grace is a **deadline**, not a warning: when it lapses, the same login gate applies. A
   grace window that never closes is model "none" with extra steps, and the audit row must
   say when it closes.

---

## 5. Decisions this sketch needs

| # | Question | Recommendation |
|---|---|---|
| **D1** | Three models, applied per role | **A for privileged, B for the rest, C as the rollout knob** (§2) |
| **D2** | Where the role mapping lives | **A port the application implements** (§3) — tamper must not learn roles |
| **D3′** | How "a second factor was proved" becomes askable | **Add `amr []string`; leave `acr` alone** (§1.1). Additive, no `MIGRATION` guide, and it survives the arrival of WebAuthn as a new `amr` value rather than a new `acr`. The withdrawn D3 stamped `ACRLocalTOTP` over `ACRLocalPassword` — correct question, wrong claim |
| **D4** | Is `WithTOTPRequired` kept beside the policy? | **Kept**, as "everyone" — deleting it would break single-policy deployments for no gain. When both are set the stricter answer wins |
| **D5** | Escape hatch for a lost device | **The application's**, behind an audit row: `identity` exposes no bypass, and a requirement with no reset path is a lockout the product must own |

---

## 6. Tests and mutation proofs

| Test | Mutant |
|---|---|
| no policy: login behaves exactly as `WithTOTPRequired` did | make the default "require nothing" |
| policy says `AtLogin` for admin, nothing for viewer: admin gets `ErrTOTPRequired`, viewer gets a session | ignore the answer and use the process switch |
| a blocked user can still reach enrolment with the pending token | drop the pending token from the error path |
| policy error → `ErrTOTPRequired` (deny), not a session | read an error as "not required" |
| `Grace` in the future → session issued; after it lapses → `ErrTOTPRequired` | treat any non-zero grace as unlimited |
| a session that passed TOTP carries `amr` containing `otp`, and satisfies `StepUpRequireMethods("otp")` | stamp today's ACR and no `amr` |
| a password-only session does NOT satisfy that gate | accept any `amr` |
| `acr` is unchanged for a TOTP session (`ACRLocalPassword`, as today) | change the `acr` value too |
| a password-only session does NOT satisfy that gate | accept any ACR |
| `RequiredFor` cannot satisfy a `RequireDecision` | wire the requirement as a permission |
| a requirement never applies to a user of another tenant | key the policy on the user id only |

---

## 7. Slices

1. **16a — this sketch**, accepted, with D1–D5.
2. **16b — `identity`**: `SecondFactorPolicy`, `WithSecondFactorPolicy`, the login gate asks
   it; `amr` in `AccessClaims` + filling it on every minting path (D3′).
3. **16c — `espresso`**: `StepUpRequireMethods`, the port doc gains "which `amr` values the
   adapter must set on each leg", and the auth routes surface the enrolment path for a
   policy-blocked user.
4. **16d — docs and release**: TD-13 closed, `MIGRATION-v0.12.md` (D3 is a behaviour change),
   `flow.md`, `CHANGELOG`, the version cut.

`16b` before `16c` because the ACR has to exist before a route can require it.

---

## 8. What this does not do

- It does not make `authz` know about 2FA, or `identity` know about roles. The mapping stays
  with the application, and that is the point of the port.
- It does not add WebAuthn or any second factor other than TOTP; the port is shaped so
  "which factor" is a later question, not a rewrite.
- It does not change `RequireFreshAuth`'s semantics (age + ACR list), which stay as they are
  and become usable for this purpose once §1.1 is fixed.
- It does not decide the grace default. A deployment that wants C sets it; a deployment that
  wants A leaves it zero.
