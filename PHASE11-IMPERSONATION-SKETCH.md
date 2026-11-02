# Phase 11 — impersonation: a human acting as another user

Status: **draft, for review. Not decided, no code.** This sketch covers TD-07
from `tech-debt.md`, the last P1 in the platform-admin line.

It follows `PHASE8-PLATFORM-ADMIN-SKETCH.md` (entering a tenant) and
`PHASE8B-AUTHZ-TENANT-SKETCH.md` (the tenant in every port). Phase 8 named this
gap and deliberately left it alone: *"Impersonation (TD-07). An entered admin
acts as themself. Acting as another user is a separate design."* This is that
design.

**One decision in here needs your explicit sign-off before any code: §2 decision
3 (how the impersonated user is recorded). It is the difference between staying
on `canonical_version=4` and cutting a v5.**

---

## 1. The problem

An entered platform admin acts **as themself** inside a customer's tenant: their
`sub` is their own user id, and Phase 8's audit split already records the scope
they are in and the tenant they came from.

Support work also needs the other thing: acting **as the customer's user**, so
the console shows that user's screens and the handlers act on that user's data.
Today the framework cannot express it, and the log cannot tell the two apart:

- `crypto.AccessClaims` has no "acting on behalf of" claim
  (`crypto/jwt.go:304-338`): `sub` is the only identity a token carries.
- `audit.ActorType` knows `user`, `service_account` and `system`
  (`audit/audit.go:76-87`): there is no "this is a human wearing someone else's
  identity".
- `espresso.RequireAuth` builds the audit actor from `claims.Subject`, so a
  handler that acted as a customer's user would write a row that says the
  **customer** did it.

For ISO/IEC 27001 A.8.15 auditors ask exactly this difference — *who really
performed the action* — and a log attributed to the impersonated user answers it
wrongly while looking complete. Attribution that is merely implied by a session
record outside the chain is not evidence in the chain.

## 2. Decisions

Proposals for review. Decision 3 is the one that needs a decision, not a review.

1. **Impersonation is a token shape, not a mode.** A token minted by
   impersonation carries **two** identities: `sub` (the user being impersonated,
   so handlers and `GetUserID` act as that user) and a new `act` claim (the real
   actor). No ambient "impersonation enabled" flag exists, so nothing can turn it
   on by mistake.

2. **Attribution is never the impersonated user.** `espresso.RequireAuth` puts
   the **real actor** in the audit actor: `act` when present, `sub` otherwise.
   Every row written during an impersonation says a human did it, and the human
   is named. This is the single most important property here, because it is the
   one an auditor checks and the one a convenient implementation gets wrong.

3. **The row does not gain a field; the impersonation is bracketed** — *this is
   the sign-off item.* `audit` is a hash chain with a fixed field order
   (`audit/canonical_v4.go`): *"The field order is fixed forever: changing it is
   a v5, not an edit."* Adding `actor.impersonator_id` is therefore a **new
   canonical version**, and `v4` is the only version this package reads or writes
   — a v5 means every deployment archives its audit DB and starts a new file,
   the cutover #46 forced, for a feature that benefits a support console.

   So this phase keeps v4 and records impersonation the way the chain already
   supports:

   - `impersonation.start` and `impersonation.end` rows, both fully hashed, with
     `action` = those names, `resource_type` = `user`, `resource_id` = the
     **impersonated** user, `tenant_id` = the tenant the impersonation happens
     in, and the actor = the human;
   - the rows in between keep their normal action and resource, and their actor
     is the human.

   What that buys: accountability is per-row and hashed, and the impersonated
   user is hashed too. What it costs: **a single row does not say "as whom"**. You
   learn it by correlating the row's time with the bracket for that tenant, which
   `ListScoped` can already filter by.

   The revisit condition is recorded in §8: if counsel requires per-row "as whom",
   that is a v5 and its own decision with its own migration.

4. **How, not who.** Like `Admin.Suspend` (TD-05) and `RequireActiveTenant`
   (TD-06), the framework ships the mechanism and the application decides the
   right to use it — but following Phase 8's lesson, the check is a **port the
   caller cannot forget**, not a convention: `Core.Impersonate` asks an
   `ImpersonationPolicy` before it mints, the way `EnterTenant` asks
   `MembershipStore`. A nil policy is a wiring error, not an open door.

5. **An impersonated token is refused by default.** `RequireTenant` and
   `DecisionGate` refuse it exactly as they refuse an entered token unless the
   route opts in (`AllowImpersonated`). Every existing route stays closed to
   impersonation without a line being changed.

6. **No chaining, no refresh, short life.** An impersonated token cannot
   impersonate again; it has no refresh session, so ending it is a TTL, not a
   revocation list. The TTL is the exposure, as with entered tokens.

7. **The impersonated user must exist in the tenant being acted in**, and the
   impersonator must be able to enter that tenant in the first place. Refusals are
   one `ErrNotFound`, the shape Phase 8 uses: "not a user", "not your tenant",
   "not allowed" are indistinguishable.

8. **No unhashed columns.** The impulse to add `actor_impersonator` as a
   query-only column is the `cluster_id` precedent v4 explicitly rejected for
   `tenant_id`: an unhashed column can be re-attributed without breaking the
   chain, and re-attribution is the attack a pooled audit log exists to refute.

9. **Misconfiguration fails at construction** (rule 4), and every guard ships with
   a test that fires (rule 6).

## 3. The model

```
home session            {sub: ops,    tid: platform}
enter acme              {sub: ops,    tid: acme, htid: platform}
impersonate bob in acme {sub: bob,    tid: acme, htid: platform, act: ops}
                          │
                          ├── GetUserID / handlers ......... bob   (act as bob)
                          ├── audit Actor.UserID ........... ops   (attribute to the human)
                          ├── DecisionGate subject ........ {acme, user, bob}
                          └── reached only where a route sets AllowImpersonated
```

Two identities, two purposes, and they never swap: the request **is** bob for
everything the application does, and it **is** ops for everything the record says.

**What an operator sees.** In the customer's export: `impersonation.start`
(opened by ops), the actions attributed to ops, `impersonation.end`. In ops's own
tenant export: the same bracket, because the actor's home tenant is hashed too.
The customer can always answer "who touched my data", which is the point.

**What this does not give you.** A row that says "ops, acting as bob, deleted
cluster c-1" in one line. That needs a new field, and a new field needs a v5
(decision 3, §8).

## 4. API

Sketch-level, to make the shape reviewable — not final signatures.

```go
package crypto

// AccessClaims gains: ActorID string `json:"act,omitempty"` — the real actor
// behind an impersonated token. Empty on every other token, so existing tokens
// are byte-identical (the htid precedent).
func (c *AccessClaims) Impersonated() bool

// IssueAccessImpersonated mints an impersonated access token: sub = target,
// tid = tenant, htid = the impersonator's home tenant, act = impersonator.
// Refuses an unset tenant, an empty target or actor, actor == target, and a TTL
// that exceeds the service TTL.
func (j *JWTService) IssueAccessImpersonated(target, actor string, tenantID, homeTenantID tenant.ID,
    authTime int64, acr string, ttl time.Duration) (string, error)

package identity

// ImpersonationPolicy answers whether actorID may act as targetUserID in
// tenantID. The application owns the table; nil disables the feature and makes
// Impersonate an error, never an open door.
type ImpersonationPolicy interface {
    MayImpersonate(ctx context.Context, actorID string, tenantID tenant.ID, targetUserID string) (bool, error)
}

func WithImpersonation(p ImpersonationPolicy, ttl time.Duration) Option
func (c *Core) Impersonate(ctx context.Context, session *crypto.AccessClaims, targetUserID string) (Tokens, error)

package espresso

// RequireTenantAllowImpersonated mirrors RequireTenantAllowEntered.
// DecisionGate gains AllowImpersonated, defaulting to false.
func RequireTenantAllowImpersonated(resolve func(*http.Request) (tenant.ID, bool)) func(http.Handler) http.Handler
func ImpersonatedFromContext(ctx context.Context) (actor tenant.ID /* home */, actorID string, ok bool)
```

Audit vocabulary, owned by the application's routes (the `Auditor.For` precedent):

```go
audit.Action("impersonation.start")
audit.Action("impersonation.end")
// resource_type "user", resource_id = the impersonated user, tenant = the target tenant
```

**Shapes considered and rejected.**

- **A boolean `Impersonated` claim with no actor id.** It says someone
  impersonated, never who — the opposite of what A.8.15 asks.
- **`sub` = the impersonator, with the target in a separate claim.** Handlers and
  `GetUserID` would act as the admin, so "acting as the user" would have to be
  re-derived at every call site, and a forgotten one silently acts as the wrong
  person. The token that reaches a handler should be the token of the user the
  request *is*.
- **Reusing the entered-token mechanism.** Entering answers "which tenant"; it
  keeps `sub` as the human on purpose. Impersonation changes who the request is.
  One token cannot serve both meanings without making every gate guess.
- **An unhashed `actor_impersonator` column.** Decision 8.

## 5. Invariants

1. **Every row written during an impersonation is attributed to the real actor**,
   never to the impersonated user.
2. **An impersonated token is refused by every existing gate** unless the route
   opts in.
3. **No chaining**: an impersonated token cannot mint another.
4. **No refresh session**: ending an impersonation is its TTL expiring.
5. **One refusal**: unusable policy, unknown target, wrong tenant and inactive
   target are `ErrNotFound`, indistinguishable.
6. **The token says two things plainly**: `sub` is who the request is, `act` is
   who is responsible. Nothing downstream infers either from a session record.
7. **The chain stays v4**, and no impersonation fact lives outside the hash.
8. **A nil policy is a wiring error**, never a permission.

## 6. What this does not do

- **Per-row "as whom"** in the chain (decision 3, §8).
- **Consent or notification.** Whether the customer is told, and how, is the
  application's product decision; the framework records, it does not notify.
- **Reading the impersonated user's secrets.** Their password hash, TOTP state and
  sessions are untouched and unreachable through this path.
- **Impersonating a suspended tenant's user** — `RequireActiveTenant` (TD-06)
  refuses the request before any of this matters.
- **Chained or multi-hop impersonation.** Explicitly no.
- **The right to impersonate.** The application's policy port decides.

## 7. Proof obligations

Mutation proofs, each failing a named test.

| Mutant | Test that must go red |
|---|---|
| `RequireAuth` attributes the row to `sub` instead of `act` | the "row names the human" test |
| `RequireTenant` accepts an impersonated token without opting in | the default-refusal test |
| `Impersonate` mints without asking the policy | the policy test |
| `Impersonate` allows chaining from an impersonated session | the no-chaining test |
| `Impersonate` mints a refresh session | the access-only test |
| A refusal distinguishes "not found" from "not allowed" | the single-refusal test |
| `IssueAccessImpersonated` accepts actor == target | the self-impersonation test |
| Remove a construction guard | the panic test (rule 6) |

## 8. The v5 question, and open questions

**When this design should be revisited as a v5.** If counsel or a customer
contract requires a single row that states both identities, the answer is
`actor.impersonator_id` in the canonical payload, which is
`canonical_version=5` — a new version, a new file for every deployment, and its
own decision (the M5 precedent: v4 was cut over because the tenancy evidence
required it; a support-console convenience does not carry the same weight).

**Open questions for the owner:**

- **Is bracketing enough for A.8.15 here?** The row says who acted; the bracket
  says what they were wearing. My reading is yes, and it is why decision 3 keeps
  v4.
- **Should the impersonated user be told?** Out of scope above; the product
  answer may be "yes, an audit row is visible in their export", which the design
  already gives them.
- **What TTL?** Proposal: much shorter than an entered token — minutes, not hours.
- **Does `RequireDecision` need `AllowImpersonated` at all?** If an impersonated
  token is only ever used on console routes, the answer may be "no route opts in,
  keep it closed until one does".
