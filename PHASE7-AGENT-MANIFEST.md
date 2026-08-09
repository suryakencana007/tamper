# Phase 7 — Agent Task Manifest

> Machine-actionable companion to [`PHASE7-MULTITENANCY-SKETCH.md`](PHASE7-MULTITENANCY-SKETCH.md).
> The sketch holds the *why*; this file holds the *what*, in a fixed schema an
> agent can execute one slice at a time.
>
> Baseline: `20fa206` (2026-07-25). Module `github.com/suryakencana007/tamper`.

## Status — 2026-08-09 (phase COMPLETE)

**M1-M6 complete.** Every slice has landed, one branch per slice, in manifest
order; `7l-1` shipped as the v0.4.0 flip with `tenant.ID` threading (sketch
§8 item 7 — the manifest block implied a string, which could not express the
"" invariant; the amendment is recorded there).

| Milestone | Slices | State |
|---|---|---|
| M1 | 7a-1, 7b-1, 7a-2, 7b-2, 7b-3 | done |
| M2 | 7c-1, 7c-2, 7d-1 | done |
| M3 | 7e-1, 7e-2, 7f-1, 7f-2 | done |
| M4 | 7g-1, 7g-2, 7h-1 | done |
| M5 | 7i-1, 7j-1, 7k-1 | done — the two deferred `7i-1` DoD lines verified 2026-08-09 |
| M6 | 7l-1 | done (breaking; v0.4.0) |

**Nothing outstanding.** The three deferred verifications were closed on a
machine with Barista and Docker on 2026-08-09 (`PHASE7-HANDOFF.md` §0). The
Barista CI deferral ended the way deferrals should: the first real run was
RED and found an invariant-1 regression the local proxy was structurally
blind to (#20 — migration 005 vs external `sqlitestore` callers).

**Decisions taken since the freeze**, all recorded in sketch §8 item 1:
one audit chain at `canonical_version=4` with commitment redaction; the
revisit condition answered against ISO/IEC 27001 and found not triggered.

**Landed outside this manifest** (rule 7 — separate change, not a slice):
the chain-append single-writer fix. `Log` was a read-modify-write guarded only
by an in-process mutex, so two replicas forked the chain. Reproduced, then
closed with a `BEGIN IMMEDIATE` transaction. Under ISO 27001 A.8.15 the chain
IS the tamper-protection control, so this was a reproducible nonconformity.

## How to use this file

**One slice per PR. Never batch slices.** Work strictly in the order given —
`depends_on` is a hard gate, not a suggestion.

For every slice, in this order:

1. Read the sketch section named in `design_ref`.
2. Read every path in `reads` before writing anything in `writes`.
3. Implement. Honour `invariants` — they outrank the task description.
4. Write the tests in `tests`. Run the `mutation` proofs: break the property in
   the **production** path, confirm the test goes red, revert. **A mutant that
   fails to compile proves nothing — verify it builds first.**
5. Run `verify`. All commands must pass.
6. Check every line of `dod`. A slice with an unchecked DoD line is not done.

**Global rules, every slice:**

- `tenantID == ""` MUST be byte-identical to the pre-slice behavior. Same
  bytes, headers, status codes, error envelopes, audit-row payloads.
- Never define a table, column or migration in tamper outside `audit/`. Ports
  and neutral records only.
- Every tenant-scoped port method carries the isolation-contract doc clause
  (sketch §4.3) verbatim.
- New optional-interface upgrades get a boot guard **and** a test that the
  guard fires, in the same PR.
- If you spot a genuine improvement while implementing, **do not include it**.
  Open a separate issue. (Sketch §6.7 — the 4e rule.)
- Stop and ask a human if a slice cannot be done without violating an
  invariant. That is a design bug in this manifest, not a licence to deviate.

---

## Slice 7a-1 — `tamper/tenant` package

```yaml
id: 7a-1
milestone: M1
risk: LOW
depends_on: []
design_ref: "§4.1, §4.3"
```

**Goal.** Ship the tenancy vocabulary with zero consumers. Nothing in the
module imports it when this slice lands.

**reads**
- `identity/store.go` — port style, sentinel style, doc-comment conventions
- `identity/memstore.go` — reference-impl conventions
- `oidc/store.go` — `ProviderRecord` as the neutral-record precedent

**writes**
- `tenant/doc.go`
- `tenant/tenant.go` — `Descriptor`, `Status`
- `tenant/store.go` — `Store`, `Resolver`, `DomainRecord`, sentinels
- `tenant/context.go` — `WithTenant`, `FromContext`
- `tenant/memstore.go` — `MemStore`
- `tenant/*_test.go`

**new symbols**

```go
package tenant

// Descriptor is the identity core's projection of a tenant. Applications
// carry more columns on the same row (billing, branding, plan); the Store
// maps between its wide row and this struct.
type Descriptor struct {
    ID       string // opaque, app-defined. Never parsed by tamper.
    Slug     string
    ParentID string // "" = root. Reserved; no behavior depends on it yet.
    Status   Status
}

type Status string
const (
    StatusActive    Status = "active"
    StatusSuspended Status = "suspended"
    StatusPending   Status = "pending"
)

var (
    ErrNotFound  = errors.New("tenant: not found")
    ErrSuspended = errors.New("tenant: suspended")
)

// Store is the tenant persistence port.
type Store interface {
    ByID(ctx context.Context, id string) (Descriptor, error)
    BySlug(ctx context.Context, slug string) (Descriptor, error)
}

// Resolver answers home-realm discovery: which tenant owns this email
// domain? Implemented over the app's verified-domain table. Consumed in
// 7f-1; defined here so the vocabulary lands in one slice.
type Resolver interface {
    ResolveByDomain(ctx context.Context, emailDomain string) (Descriptor, error)
}

// WithTenant/FromContext propagate the ACTIVE tenant. Propagation only —
// never authorization. A tenant in the context is a routing fact, not a
// grant; the caller still passes tenantID explicitly to every port method.
func WithTenant(ctx context.Context, id string) context.Context
func FromContext(ctx context.Context) (string, bool)
```

**invariants**
- `ParentID` is reserved and unused. Do not add resolution logic for it.
- `FromContext` must never be read by a port method to *derive* a tenant. An
  implicit tenant is a silent cross-tenant leak waiting for one missing
  `WithTenant` call. Ports take `tenantID` as an explicit argument, always.
- No package in the module imports `tenant` when this slice lands.

**tests**
- `MemStore` round-trips; `ErrNotFound` on miss.
- `FromContext` on a bare context returns `("", false)`.
- Nested `WithTenant` calls: innermost wins.

**mutation** — none (no production consumer yet).

**verify**
```sh
go build ./... && go test -race ./tenant/...
go vet ./... && golangci-lint run
grep -rn '"github.com/suryakencana007/tamper/tenant"' --include=*.go . | grep -v '^./tenant/'   # must be EMPTY
```

**dod**
- [ ] `tenant` package builds, tests green with `-race`
- [ ] Zero importers outside the package itself
- [ ] Every exported symbol has a doc comment; `Descriptor.ID` says "opaque, never parsed"
- [ ] `golangci-lint` clean

---

## Slice 7a-2 — `identity/tenanttest` conformance harness

```yaml
id: 7a-2
milestone: M1
risk: LOW
depends_on: [7a-1, 7b-1]
design_ref: "§3.3, §4.2, §4.3"
```

> **Amended 2026-08-07.** As frozen, this slice could not be built. Its
> `RunLeakSuite` signature names `identity.TenantScopedStore`, which 7b-2
> introduced — and 7b-2 is `depends_on: [7a-2, 7b-1]`. A true 2-cycle,
> compile-verified (`undefined: identity.TenantScopedStore`). Independently,
> the suite has to SEED tenants, and the only write paths on the port are the
> ones inherited from `Store`; no slice defines a `CreateUserInTenant`, so the
> tenant can only arrive on the record via `NewUser.TenantID` — which is 7b-1.
> So `depends_on: [7a-1]` was wrong on its own terms, cycle or no cycle.
>
> The fix moves the **declaration** of `TenantScopedStore` here and re-gates
> the slice on 7b-1. 7b-2 keeps every semantic obligation and keeps its gate
> on 7a-2, so the leak suite still exists before the change it has to prove —
> which is the whole point of sketch §3.3. Order becomes
> `7a-1 → 7b-1 → 7a-2 → 7b-2`; 7a-2 leaves the parallel track and joins the
> critical path. Precedent: 7a-1 shipped `tenant.Resolver` the same way — a
> port declared one slice before its first implementation, on purpose.

**Goal.** The cross-tenant leak suite, exported so adapter authors run it
against their own store. This is the instrument that replaces "Barista runs it
in production" (sketch §3).

**reads**
- `identity/store.go`, `identity/memstore.go`
- `crypto/testing.go`, `audit/testing_export.go` — how this repo exports test helpers

**writes**
- `identity/store.go` — the `TenantScopedStore` **DECLARATION ONLY**. No
  implementation, no `MemStore` methods, no `Core` routing, no boot guard:
  all four are 7b-2. A diff that touches `core.go`, `linking.go`,
  `memstore.go` or `provider.go` means this slice has quietly become 7b-2
  without 7b-2's mutation proofs — stop.
- `identity/tenanttest/tenanttest.go`
- `identity/tenanttest/tenanttest_test.go` (self-test against in-package
  fixtures; `MemStore` cannot satisfy the interface until 7b-2)

**new symbols**

```go
// identity/store.go — declaration only; 7b-2 implements and routes it.
type TenantScopedStore interface {
    Store
    UserByEmailInTenant(ctx context.Context, tenantID, email string) (User, error)
    IdentityByProviderSubjectInTenant(ctx context.Context, tenantID, provider, subject string) (Identity, error)
    CountUsersInTenant(ctx context.Context, tenantID string) (int64, error)
    RevokeAllRefreshSessionsForTenant(ctx context.Context, tenantID string, at time.Time) error
}
```

```go
package tenanttest

// RunLeakSuite asserts the isolation contract on a TenantScopedStore.
// newStore must return a FRESH, empty store on each call.
//
// Every assertion is of the form: seed tenant A and tenant B, address B's
// object as A, require errors.Is(err, identity.ErrNotFound). A permission
// error, a zero value with a nil error, or B's row are all failures — the
// first two because they disclose existence, the third because it is the leak.
func RunLeakSuite(t *testing.T, newStore func() identity.TenantScopedStore)
```

**cases** (each in its own `t.Run`)
- `UserByEmailInTenant`: same email in A and B resolves to different users; A cannot see B's.
- `IdentityByProviderSubjectInTenant`: same `(provider, subject)` in A and B stays separate.
- `CountUsersInTenant`: A's count excludes B's users.
- `RefreshSessionByHash`: a session minted in B is not usable from A.
- `RevokeAllRefreshSessionsForTenant`: revoking A leaves B's sessions live.

> **The `""` mode case was REMOVED in the 2026-08-07 amendment.** It read:
> "with a single-tenant store, every case is vacuous and skips cleanly." It is
> unimplementable, and dangerously so. Nothing the suite can observe separates
> a single-tenant store from a leaky pooled one — seed A and B, ask as A for
> B's row, and a store that ignores `tenantID` returns B's row exactly like a
> store that has only ever had one tenant. Any auto-detection is therefore a
> heuristic that resolves the ambiguity in the store's favour: it goes quiet
> precisely when it finds the bug it exists to find. That is playbook step 5's
> failure mode inside the instrument §3.3 built to replace it, and §6.2
> settles it — ambiguous means deny, and in a harness deny means FAIL, never
> SKIP. A single-tenant adapter has no isolation to prove and simply does not
> run this suite. At 7l-1 the question dissolves: `""` becomes an explicit
> single-tenant value and every store is tenant-scoped.

**invariants**
- The suite fails on a permission-shaped error, not just on a returned row.
  404-not-403 is the property under test (sketch §6.3).
- **The suite never skips.** No case may resolve to `t.Skip` on any input. A
  skipped case reports as green and guards nothing.
- `TenantScopedStore` lands as a bare declaration. Implementing it anywhere in
  this slice — even on `MemStore` — is 7b-2's work and moves 7b-2's mutation
  proofs out from under it.
- No `time.Sleep`. No wall-clock dependence.

**tests** — self-test: `RunLeakSuite` green against a compliant two-tenant
in-package fixture, and RED against a deliberately-broken one. `MemStore`
cannot be the target until 7b-2 implements the interface. Ship one broken
fixture PER LEAK SHAPE, unexported, so the proof is per-case rather than
"something went red".

Proving a test suite FAILS needs a seam: `RunLeakSuite` keeps its
`*testing.T` signature and delegates to an unexported `runLeakSuite(t
harnessT, …)` over a minimal `Helper/Errorf/Fatalf/Run` interface, which the
self-test drives with a recorder. Without it, "a leaky fixture fails the
suite" is an unverifiable claim.

**mutation** — the fixtures ARE the mutation; confirm each one fails. Then one
mutation on the suite itself: relax the assertion from
`errors.Is(err, identity.ErrNotFound)` to "any non-nil error" and confirm the
permission-shaped-error test goes green, proving the 404-not-403 check is
load-bearing rather than decorative.

**verify**
```sh
go test -race ./identity/...
```

**dod**
- [ ] Suite is exported and runnable from an external module
- [ ] A deliberately-leaky fixture fails the suite (proof it bites), one per leak shape
- [ ] A permission-shaped error fails the suite, not just a returned row
- [ ] No sleeps, no clock dependence, no shared state between `t.Run`s
- [ ] No `t.Skip` reachable on any input
- [ ] `identity/store.go` gains the declaration and NOTHING else; `core.go`,
      `linking.go`, `memstore.go`, `provider.go` are untouched

---

## Slice 7b-1 — `TenantID` fields, zero behavior change

```yaml
id: 7b-1
milestone: M1
risk: LOW
depends_on: [7a-1]
design_ref: "§4.1, §6.1"
```

**Goal.** Add the field everywhere it belongs and carry it through
unread. The value of this slice is the parity proof: **every existing test
passes UNCHANGED**. If any test needed editing, you changed behavior.

**reads**
- `identity/identity.go`, `identity/core.go`, `identity/linking.go`, `identity/memstore.go`

**writes**
- `identity/identity.go` — `TenantID` on `User`, `NewUser`, `RefreshSession`, `Identity`, `NewIdentity`
- `identity/memstore.go` — store and return it
- `identity/core.go`, `identity/linking.go` — carry it through mint/rotate/link

**invariants**
- No branch anywhere reads `TenantID` in this slice. Carry only.
- Refresh rotation copies `TenantID` onto the successor row **unchanged**, the
  same discipline `AuthTime`/`ACR` already have. A rotation that drops the
  tenant would silently widen a session.
- Zero edits to existing `_test.go` files. If one needs an edit, stop.

**tests**
- Rotation preserves `TenantID` across `Refresh`.
- `ProvisionUserWithIdentity` writes the same `TenantID` to user and identity.

**mutation** — in `Core.issueTokens`, drop `TenantID` from the successor
`RefreshSession`. The rotation-preservation test must go red.

**verify**
```sh
go test -race ./...
git diff --stat -- '*_test.go'   # must show ONLY NEW test files
```

**dod**
- [ ] `git diff` touches no existing test file
- [ ] Full suite green with `-race`
- [ ] Rotation-preservation test exists and its mutation goes red

---

## Slice 7b-2 — `TenantScopedStore` + Core upgrade (fixes B1, B2)

```yaml
id: 7b-2
milestone: M1
risk: HIGH
depends_on: [7a-2, 7b-1]
design_ref: "§4.2, §6 (both mutation proofs)"
```

**Goal.** The semantic change. `Core` resolves users and counts within a
tenant when tenancy is on, and fails at boot when the store cannot.

**reads**
- `identity/store.go`, `identity/core.go`, `identity/linking.go`
- `provider.go` — `Config`, `New`, existing boot validation style
- `TAMPER-DESIGN.md` §playbook step 3 — the type-assertion failure mode

**writes**
- `identity/store.go` — **nothing.** `TenantScopedStore` is DECLARED in 7a-2
  (2026-08-07 amendment). If this slice needs to edit that declaration, then
  7a-2's harness was written against a different contract: reconcile it
  deliberately and re-run the leak suite, do not let the two drift. That drift
  is the 4e-2 trap — a contract written one slice early, quietly adjusted when
  a later slice wires it into the request path.
- `identity/core.go` — `WithTenancy` option, construction-time assertion, routing
- `identity/linking.go` — tenant-scoped resolve/provision
- `identity/memstore.go` — implement the scoped interface
- `provider.go` — `Config.Tenancy`, boot guard

**new symbols**

```go
// identity/store.go — DECLARED IN 7a-2, repeated here for reference only.
// This slice implements it (on MemStore) and routes through it; it does not
// author it. See the note in **writes** above.
type TenantScopedStore interface {
    Store
    UserByEmailInTenant(ctx context.Context, tenantID, email string) (User, error)
    IdentityByProviderSubjectInTenant(ctx context.Context, tenantID, provider, subject string) (Identity, error)
    CountUsersInTenant(ctx context.Context, tenantID string) (int64, error)
    RevokeAllRefreshSessionsForTenant(ctx context.Context, tenantID string, at time.Time) error
}

// identity/core.go
func WithTenancy(enabled bool) Option

// provider.go
type TenancyConfig struct {
    Enabled bool
    Store   tenant.Store    // optional; nil = the app resolves tenants itself
}
// Config gains:  Tenancy *TenancyConfig
```

**routing rules**
- Tenancy OFF → every call path is byte-identical to 7b-1. No new branches
  execute.
- Tenancy ON → `Register`, `Login`, `ResolveByIdentity`,
  `ProvisionUserWithIdentity`, `RevokeAllSessions` use the `*InTenant`
  methods. An empty `tenantID` with tenancy ON is an **error**, not a wildcard.
- `firstUser` derives from `CountUsersInTenant`, so it is per-tenant. **This is
  B2 and it is the reason this slice is HIGH risk.**

**invariants**
- The construction assertion fails at `New`, with a message naming the concrete
  type that failed to satisfy the interface. Never a per-request denial.
- `Login` keeps its timing-parity rejection property: a wrong tenant must cost
  the same as a wrong password. Do not early-return before the hash comparison.
- `ProvisionUserWithIdentity` stays atomic. The tenant does not introduce a
  second round trip between resolve and provision — that is where the app's
  email-collision veto wedges (Phase 2d), and widening the window reopens the
  lost-first-sign-in race.

**tests**
- `RunLeakSuite` green against a two-tenant `MemStore`.
- Boot guard: a `Store` that is not `TenantScopedStore` + `Tenancy.Enabled` →
  `New` returns an error naming the type.
- Tenancy ON + empty `tenantID` → error, not a cross-tenant match.
- Same email in two tenants → two distinct users, both able to log in.
- Tenant B's first user gets `firstUser=true` even though tenant A has users.
- Timing-parity: wrong-tenant and wrong-password rejections are
  indistinguishable (same code path, assert structurally not statistically).

**mutation** — both are mandatory; a PR without both is incomplete.
- **M-B1** — in `Core.Login`, swap `UserByEmailInTenant(ctx, tenantID, email)`
  for `UserByEmail(ctx, email)`. A **Core-level** cross-tenant login test must
  go RED.

  > **CORRECTION, 2026-08-09 — as originally written this mutation could not
  > bite, and it was demonstrated rather than argued.** The spec named
  > `RunLeakSuite` as the witness. `RunLeakSuite` exercises a `Store`
  > implementation directly and never constructs a `Core`, so a mutation
  > inside `Core.Login` is invisible to it: the mutant was applied, it
  > compiled, and the suite stayed GREEN. The proof was moved to Core-level
  > tests, which do go red. Left as a caution rather than a quiet edit: this
  > is exactly the playbook step-5 failure the manifest warns about — a guard
  > that is green and pointed at the wrong thing — and it appeared in the
  > spec, not in the code.

- **M-B2** — in the `firstUser` path, swap `CountUsersInTenant(ctx, tenantID)`
  for `CountUsers(ctx)`. The tenant-B-bootstrap test must go RED.

Record both in the PR body: the diff applied, that it compiled, and the test
that failed.

**verify**
```sh
go test -race ./...
# Barista, unchanged, must still be green:
moon run barista:ci
```

**dod**
- [ ] Both mutation proofs recorded in the PR body with the failing test named
- [ ] Boot guard test asserts the error message names the concrete type
- [ ] Barista CI green with **zero** diff in its identity adapter
- [ ] Leak suite green against a two-tenant `MemStore`
- [ ] Timing-parity property preserved and tested

---

## Slice 7b-3 — `examples/multitenant`

```yaml
id: 7b-3
milestone: M1
risk: MED
depends_on: [7b-2]
design_ref: "§3.2"
```

**Goal.** The pooled proving ground. Not a demo — the consumer that makes the
tenant path real, in the shape `examples/federation` established.

**reads**
- `examples/federation/*` — the fake-IdP harness and test shape
- `examples/quickstart/main.go` — the `coreIdentity` adapter shape

**writes**
- `examples/multitenant/main.go`, `store.go`, `identity_adapter.go`, `main_test.go`

**shape**
- One process, two tenants (`acme`, `globex`), each with its own verified
  domain and its own OIDC provider on the embedded fake IdP.
- A two-tenant in-memory store implementing `identity.TenantScopedStore`.
- `go run ./examples/multitenant` serves on `:8080`;
  `go test ./examples/multitenant/...` drives both tenants end to end.

**test must assert**
- Both tenants log in through one process, landing on distinct users.
- `bob@acme.com` and `bob@globex.com` coexist as separate users.
- A token minted for `acme` is **rejected** on a `globex` route.
- `globex`'s first user got the bootstrap signal despite `acme` having users.

**invariants**
- Zero external dependencies — embedded fake IdP, like `examples/federation`.
- No `time.Sleep` in the test.

**verify**
```sh
go run ./examples/multitenant &   # must boot
go test -race ./examples/multitenant/...
```

**dod**
- [ ] Runs with no external services
- [ ] All four assertions above present and passing
- [ ] `README.md` gains a multi-tenant section pointing at it

---

## Slice 7c-1 — `tid` claim

```yaml
id: 7c-1
milestone: M2
risk: LOW
depends_on: [7b-2]
design_ref: "§5 M2"
```

**reads** — `crypto/jwt.go` (the `purpose` claim's legacy-tolerance comment is the template)

**writes** — `crypto/jwt.go`, `crypto/jwt_test.go`

**new symbols**
```go
type AccessClaims struct {
    AuthTime int64  `json:"auth_time"`
    ACR      string `json:"acr"`
    Purpose  string `json:"purpose,omitempty"`
    TenantID string `json:"tid,omitempty"`   // NEW
    jwt.RegisteredClaims
}

func (s *JWTService) IssueAccessForTenant(subject, tenantID string, authTime int64, acr string) (string, error)
```

**invariants**
- A token minted without a tenant is **byte-identical** to today's — `omitempty`
  must actually omit. Assert on the raw base64 payload, not the parsed struct.
- `VerifyAccess` is unchanged in this slice. A missing `tid` reads `""`.

**tests**
- Byte-identical payload for the no-tenant case (pin the encoded string).
- Round-trip with a tenant.
- A pre-7c token parses with `TenantID == ""`.

**mutation** — remove `omitempty`. The byte-identity test must go red.

**dod**
- [ ] Encoded-payload byte-identity test present and pinned
- [ ] Legacy-tolerance comment written in the `purpose`-claim style

---

## Slice 7c-2 — tenant pinning + `RequireTenant` (fixes B3, claim half)

```yaml
id: 7c-2
milestone: M2
risk: MED
depends_on: [7c-1, 7b-3]
design_ref: "§5 M2, §6.2, §6.3, §8 open item 4"
```

**reads** — `espresso/auth.go`, `espresso/decision.go` (the 404-vs-403 flow), `espresso/stepup.go` (gate shape)

**writes** — `crypto/jwt.go`, `espresso/tenantgate.go`, tests

**new symbols**
```go
func (s *JWTService) VerifyAccessInTenant(token, tenantID string) (*AccessClaims, error)

// espresso
func RequireTenant(resolve func(*http.Request) string) func(http.Handler) http.Handler
func TenantFromContext(ctx context.Context) (string, bool)
```

**invariants**
- Tenancy ON + empty `tid` → **reject**. The 7c-1 tolerance is for
  single-tenant deployments only. State this in the doc comment.
- A tenant mismatch collapses onto `ErrInvalidToken` — the same one-status-code
  discipline the package already applies to every JWT failure mode. Do not add
  a distinguishable "wrong tenant" error; it is a tenant-existence oracle.
- The deny response must not disclose whether the target tenant exists.

**tests**
- Token for A on a B route → 401, identical body to an expired-token 401.
- Tenancy OFF + no `tid` → allowed (the compat path).
- Tenancy ON + no `tid` → rejected.

**mutation** — make the mismatch return a distinct error string. The
identical-body test must go red.

**dod**
- [ ] Deny body byte-identical between wrong-tenant and invalid-token
- [ ] Open item 4 (gate placement) resolved in the PR description with a reason

---

## Slice 7d-1 — `crypto.Signer` seam

```yaml
id: 7d-1
milestone: M2
risk: MED
depends_on: [7c-1]
design_ref: "§5 M2"
```

**Goal.** Make asymmetric signing and per-tenant keys *possible*, without
committing to either now. HS256 stays the default and its output must not
move by a byte.

**writes** — `crypto/signer.go`, `crypto/jwt.go`, tests

**new symbols**
```go
// Signer abstracts the JWT signing method so a deployment can move to
// asymmetric keys (and per-tenant kid) without touching call sites.
type Signer interface {
    Alg() string
    KeyID() string            // "" = no kid header
    Sign(signingString string) ([]byte, error)
    Verify(signingString string, sig []byte) error
}

func NewHS256Signer(secret []byte) Signer
func WithSigner(s Signer) JWTOption
// Multi-key verification (rotation / per-tenant kid) resolves by kid:
func WithVerifiers(byKID map[string]Signer) JWTOption
```

**invariants**
- Default construction (`NewJWTService(cfg)`) produces byte-identical tokens to
  pre-slice. Pin an encoded token in a test.
- No JWKS endpoint in this slice. Seam only. (JWKS is a later, separate slice —
  do not smuggle it in.)
- The `panic` on empty secret stays for the default path; a supplied `Signer`
  bypasses the secret requirement.

**tests** — byte-identity for HS256; a stub asymmetric signer round-trips; an
unknown `kid` fails closed.

**mutation** — reorder the header fields in the HS256 path. The byte-identity
test must go red.

**dod**
- [ ] Pinned encoded-token test proves HS256 did not move
- [ ] `kid` resolution fails closed on unknown key
- [ ] No JWKS route added

---

## Slice 7e-1 — tenant-keyed OIDC registry (fixes B4, OIDC)

```yaml
id: 7e-1
milestone: M3
risk: HIGH
depends_on: [7b-2]
design_ref: "§5 M3, §6.6"
```

**Goal.** Replace one process-wide registry with a per-tenant keyed cache,
preserving every existing caching semantic exactly.

**reads** — `oidc/manager.go` (all of it — the cache is load-bearing), `oidc/store.go`, `oidc/provider.go`

**writes** — `oidc/manager.go`, `oidc/store.go`, tests

**new symbols**
```go
// oidc/store.go — optional upgrade, same mechanism as TenantScopedStore
type TenantScopedProviderStore interface {
    ProviderStore
    ListEnabledProvidersForTenant(ctx context.Context, tenantID string) ([]ProviderRecord, error)
}

// oidc/manager.go
func (m *Manager) GetRegistryForTenant(ctx context.Context, tenantID string) (*ProviderRegistry, error)
func WithRedirectURLForTenant(fn func(tenantID, providerID string) string) Option
```

**invariants — these are the reason this slice is HIGH**
- **Double-checked locking preserved.** The read path dominates; do not
  degrade `RWMutex` to `Mutex` for convenience.
- **Nil-sentinel caching stays symmetric.** A tenant with no providers caches a
  nil sentinel for the same TTL as a populated one, or multi-replica
  convergence breaks. This property is already documented in `manager.go` —
  keep the comment and extend it.
- **Eager invalidation on same-process mutation** applies to the mutated
  tenant's key only, never the whole map.
- `PinRegistry` (the Year-9999 test seam) still works, per tenant.
- Tenancy OFF → the `""` key holds exactly one registry and every existing
  test passes unchanged.
- **No unbounded map growth.** A cache keyed by an attacker-influenced tenant
  id is a memory-exhaustion vector. Either bound the map or key it only on
  tenants that resolved through `tenant.Store`. State which, in a comment.

**tests**
- Two tenants, disjoint provider sets, no cross-visibility.
- TTL expiry per tenant is independent.
- Mutating tenant A's providers does not invalidate tenant B's cache.
- Nil-sentinel: a provider-less tenant does not re-query the store within TTL.
- Concurrent `GetRegistryForTenant` across tenants under `-race`.

**mutation** — make invalidation clear the whole map. The
"B's cache survives A's mutation" test must go red.

**dod**
- [ ] All five caching invariants have a named test
- [ ] `-race` green under concurrent multi-tenant load
- [ ] Map-growth decision documented in a comment
- [ ] Existing `oidc` tests pass unchanged

---

## Slice 7e-2 — tenant-keyed SAML registry (fixes B4, SAML)

```yaml
id: 7e-2
milestone: M3
risk: MED
depends_on: [7e-1]
design_ref: "§5 M3"
```

**Goal.** Mirror 7e-1's contract exactly, the way `3d-core` mirrored
`3c-core`. Any deviation is a bug in one of the two.

**writes** — `saml/manager.go`, `saml/store.go`, tests

**invariants**
- Contract parity with 7e-1: same method names modulo package, same caching
  semantics, same option shape. A reviewer must be able to diff the two files
  and see only SAML-specific differences.
- The log-and-omit-per-provider rebuild resilience is preserved **per tenant**:
  one mis-provisioned IdP takes down neither its own tenant's other providers
  nor any other tenant.
- `SetMaxClockSkew` stays the app's process-global boot call. Do not attempt to
  make it per-tenant — crewjam v0.5.x makes it impossible, and a per-tenant API
  over a process-global is a lie. Re-document the constraint here.

**tests** — 7e-1's suite, transposed, plus: a broken cert in tenant A's
provider does not affect tenant B.

**mutation** — same as 7e-1.

**dod**
- [ ] Side-by-side contract parity with 7e-1 noted in the PR body
- [ ] Per-tenant rebuild resilience tested
- [ ] `SetMaxClockSkew` constraint re-documented, not worked around

---

## Slice 7f-1 — home-realm discovery ports

```yaml
id: 7f-1
milestone: M3
risk: MED
depends_on: [7e-1]
design_ref: "§5 M3"
```

**writes** — `tenant/domain.go`, `tenant/verify.go`, tests

**new symbols**
```go
type DomainRecord struct {
    TenantID   string
    Domain     string // lowercased, punycode-normalised by the CALLER
    Verified   bool
    ProviderID string // "" = no IdP bound; falls back to password/invite
}

type DomainStore interface {
    ByDomain(ctx context.Context, domain string) (DomainRecord, error)
    ListForTenant(ctx context.Context, tenantID string) ([]DomainRecord, error)
}

// DNSVerifier checks the TXT proof. tamper ships a net.Resolver impl; the
// app decides when to run it (registration, a cron, an admin action).
type DNSVerifier interface {
    VerifyTXT(ctx context.Context, domain, expectedToken string) error
}

func NewVerificationToken() string   // crypto/rand, URL-safe
func IsPublicEmailDomain(domain string) bool
```

**invariants**
- **An unverified domain must never bind an IdP.** This is the tenant-takeover
  vector; the check belongs in the resolver path, not only in the admin path.
- `IsPublicEmailDomain` blocks `gmail.com`, `outlook.com`, `yahoo.com`, etc. as
  **data**, in a file that is easy to extend. A public domain can never be
  verified for any tenant.
- Domain comparison is on the normalised form. tamper does not normalise —
  document that the caller must, and reject anything containing uppercase or a
  leading `@` rather than silently fixing it.

**tests** — verified/unverified binding; public-domain rejection;
unnormalised input rejected not coerced; token entropy.

**mutation** — drop the `Verified` check in the resolve path. The
unverified-binding test must go red.

**dod**
- [ ] Unverified domains cannot resolve to a provider
- [ ] Public-domain list is data, with a test asserting a sample
- [ ] Normalisation contract stated and enforced by rejection

---

## Slice 7f-2 — `StartLogin` home-realm routing

```yaml
id: 7f-2
milestone: M3
risk: MED
depends_on: [7f-1]
design_ref: "§5 M3"
```

**writes** — `espresso/startlogin.go`, tests

**new symbols**
```go
// StartLogin resolves an email's domain to a tenant + IdP and returns the
// redirect, or signals the password/invitation fallback.
func StartLogin(ctx context.Context, r Resolver, email string) (StartLoginResult, error)

type StartLoginResult struct {
    TenantID    string
    ProviderID  string // "" = fall back to password/invite
    EnforceSSO  bool
}
```

**invariants — this endpoint is unauthenticated, treat it as hostile**
- **Timing-indistinguishable.** A matched domain and an unmatched domain must
  cost the same. Do the fallback work unconditionally, or add a constant-time
  floor. An unauthenticated endpoint whose latency reveals customer domains is
  a tenant-enumeration oracle.
- The response must not disclose tenant existence, tenant name, or provider
  display name for an unmatched domain.
- Rate-limit hook must be present even before 7k-1 lands (accept a `Throttle`
  that may be nil, and document that nil is unsafe in production).

**tests** — matched/unmatched shapes are structurally identical; no tenant
identifiers in the unmatched response; a suspended tenant behaves exactly like
an unknown one.

**mutation** — early-return on the unmatched path. The structural-identity test
must go red.

**dod**
- [ ] Timing floor implemented and explained in a comment
- [ ] Unmatched response contains zero tenant-derived data
- [ ] Suspended tenant is indistinguishable from unknown

---

## Slice 7g-1 — SCIM principal tenancy (fixes B5)

```yaml
id: 7g-1
milestone: M4
risk: MED
depends_on: [7b-2]
design_ref: "§5 M4"
```

**reads** — `espresso/sagate.go`, `espresso/scimroutes.go`, `espresso/scimusers.go`, `scim/store.go`

**writes** — `espresso/sagate.go`, `espresso/scimroutes.go`, `scim/store.go`, tests

**changes**
```go
type Principal struct {
    ID          string
    TenantID    string   // NEW — "" = single-tenant
    Name        string
    Description string
    CreatedAt   time.Time
}
```
SCIM handlers read the tenant from the **validated principal** and pass it to
the store ports.

**invariants**
- **The tenant comes from the token, never from the URL path or a header.** A
  path-derived tenant is a horizontal-privilege-escalation bug with extra
  steps. Write this in the doc comment above `Principal.TenantID`.
- The RFC 7644 §3.12 error envelope is unchanged. A cross-tenant read returns
  404 with the standard envelope, indistinguishable from a genuine miss.
- `audit.ActorService(principal.ID, principal.Name)` gains the tenant without
  changing the existing actor fields' meaning.

**tests** — tenant A's token cannot read/write/patch/delete tenant B's users
or groups (all verbs); the 404 body is byte-identical to a genuine miss.

**mutation** — derive the tenant from a path parameter instead. The
cross-tenant-write test must go red.

**dod**
- [ ] Every SCIM verb covered by a cross-tenant denial test
- [ ] 404 bodies byte-identical between cross-tenant and genuine miss
- [ ] Doc comment states token-not-path explicitly

---

## Slice 7g-2 — per-tenant SCIM base URL

```yaml
id: 7g-2
milestone: M4
risk: LOW
depends_on: [7g-1]
design_ref: "§5 M4"
```

**writes** — `espresso/scimroutes.go`, `espresso/scimdto.go`, tests

**invariants**
- `meta.location` and `$ref` must resolve to the tenant's own base URL.
- The no-drift invariant extends here: whatever is advertised in
  `ServiceProviderConfig` is what is enforced, per tenant. An advertised limit
  nothing enforces is worse than no limit (the 4e-4 rule).

**tests** — two tenants get distinct `meta.location`; `""` mode byte-identical.

**dod**
- [ ] `""` mode produces byte-identical DTOs
- [ ] Advertised-vs-enforced parity test per tenant

---

## Slice 7h-1 — entitlements port

```yaml
id: 7h-1
milestone: M4
risk: LOW
depends_on: [7g-1]
design_ref: "§5 M4"
```

**writes** — `tenant/entitlements.go`, `espresso/routes.go`, tests

**new symbols**
```go
type Entitlements struct {
    SSOEnabled        bool
    SCIMEnabled       bool
    MaxIdPConnections int  // 0 = unlimited
}

type EntitlementStore interface {
    ForTenant(ctx context.Context, tenantID string) (Entitlements, error)
}
```

**invariants**
- Gated at the **route surface**, not at boot. Boot-time nil-encoding is
  per-process and structurally cannot express per-tenant tiers.
- A disabled capability returns 403 with a stable code, never 404 and never a
  boot failure. The tenant exists; the feature is not purchased. That is a
  different fact from "not found" and the customer needs to see it.
- A store error is deny (§6.2).

**tests** — SSO-disabled tenant gets 403 at the OIDC start route; store error
denies; `MaxIdPConnections` enforced on create.

**dod**
- [ ] Disabled capability is 403 with a stable code, not 404
- [ ] Store error denies
- [ ] No boot-time gating added

---

## Slice 7i-1 — audit canonical v4 with tenant

```yaml
id: 7i-1
milestone: M5
risk: HIGH
depends_on: [7b-2]
design_ref: "§5 M5, §8 open item 1"
```

> **UNBLOCKED 2026-08-08.** Open item 1 is decided: **ONE CHAIN**, tenant in
> the canonical row at v4, **with commitment-based redaction shipped inside
> v4**. Full reasoning in sketch §8 item 1 — including the two original
> premises that were checked and found wrong, and the one condition that would
> flip the answer.
>
> **v4 contains**, in order: v3's field sequence unchanged, then
> `tenant_id` (a NEW top-level `Event.TenantID` — the row's SCOPE) after
> `request_id`, then `actor.tenant_id` (`Actor.TenantID`, promoted from
> carried-not-hashed to hashed).
>
> **Those two are different facts and conflating them is a correctness bug.**
> A support engineer or an ActorTypeSystem actor in tenant A acting on tenant
> B's resource has actor-tenant A and event-tenant B. A tenant export filtered
> on `Actor.TenantID` silently omits exactly the cross-tenant admin actions the
> customer most wants to see. Export filters on `Event.TenantID`.
>
> **The tenant must be INSIDE the hash.** Do not follow the `cluster_id`
> precedent, which is explicitly "purely a query-time filter, not part of
> integrity". `cluster_id` is a visibility filter inside one trust domain; a
> tenant IS the trust boundary, and an unhashed tenant column can be
> re-attributed from A to B without breaking anything. That is the entire
> justification for v4 existing.
>
> **PII fields hash as stored commitments** — `actor.email`, `actor.name`,
> `actor.ip`, `before`, `after` become `H(row_salt || field_name || value)`
> with the salt in its own column. The encoder reads the STORED commitment and
> never re-derives it from plaintext, so erasure (null the plaintext, drop the
> salt, keep the 32 bytes) leaves the hash unchanged and the chain verifies
> through it. A v4 that hashes plaintext PII is the version that cannot answer
> an erasure request and must not ship.
>
> **The migration** adds columns and an index, **rewrites zero existing rows**,
> and emits exactly ONE v4 chain-restart anchor THROUGH `Log` so it carries the
> real latest hash (the zero sentinel is true only on an empty table and would
> fail the boot gate on any real DB). Emit the anchor ONLY when tenancy is
> configured, so a `""`-only deployment keeps writing v3 and invariant 1 is
> satisfied trivially. The anchor must land BEFORE the first v4 write in the
> same boot: `verifyRows` returns the anchor's `canonical_version` and
> `walkChain` uses it to OVERRIDE every row's own column, so v4 rows sitting
> after a v3 anchor read as tamper.
>
> **A tenant-filtered export may claim** per-row authenticity and position —
> each row ships its own prev_hash/hash, recomputable without access to anyone
> else's data, and attribution cannot have been reassigned after the fact
> because the tenant is inside the payload. **It may NOT claim** completeness
> or contiguity: consecutive exported rows do not link to each other, the links
> run through other tenants' rows. Label it `"is_chain": false`,
> `"completeness": "issuer-attested"`. A hash-path restoring contiguity
> discloses every other tenant's event volume and timing, so it is never the
> default — Phase 7 spends a whole slice keeping StartLogin from being an
> enumeration oracle; do not ship one with a signature on it.

**reads** — `audit/audit.go`, `audit/canonical_legacy_v2.go`, `audit/migration.go`, `audit/verify_boot.go`, `audit/sqlitestore/migrations/*`

**writes** — `audit/canonical_v4.go`, `audit/migration.go`, a new migration, tests

**invariants**
- **Per-row `canonical_version` dispatch, exactly as v2/v3.** Existing rows keep
  their version and hash forever. A v3 row re-canonicalised as v4 breaks the
  chain.
- `VerifyChainPostMigration` must pass on a real Barista audit DB across the
  v3→v4 migration. This is the Phase 0c bar, and it is not negotiable.
- Byte-parity diff of chain hashes for untouched rows, EXIT 0 — the same proof
  the audit lift produced.
- Tenant-filtered export must not renumber, re-hash, or imply completeness of
  the chain it slices.

**tests** — mixed v2/v3/v4 chain verifies; migration is idempotent; export
filtered by tenant contains no other tenant's rows; a tampered v4 row is
detected.

**mutation** — re-canonicalise a v3 row as v4 during migration. The chain
verify must go red.

**dod**
- [ ] Open item 1 decided, with the reasoning recorded in the sketch
- [ ] Chain-hash byte-parity diff EXIT 0 for pre-existing rows
- [ ] Boot verify green on a real Barista DB post-migration
- [ ] Docker deploy-artifact walk boots with chain self-test OK

---

## Slice 7j-1 — invitations

```yaml
id: 7j-1
milestone: M5
risk: LOW
depends_on: [7b-2]
design_ref: "§5 M5"
```

**writes** — `identity/invitation.go`, store port additions, tests

**new symbols**
```go
type Invitation struct {
    ID        string
    TenantID  string
    Email     string
    TokenHash string    // plaintext shown once, never stored
    ExpiresAt time.Time
    AcceptedAt time.Time // zero = pending
    InvitedBy string
}

type InvitationStore interface {
    CreateInvitation(ctx context.Context, inv Invitation) error
    InvitationByHash(ctx context.Context, hash string) (Invitation, error)
    MarkAccepted(ctx context.Context, id string, at time.Time) error
}
```

**invariants**
- Token hashing reuses `crypto.HashRefreshToken`'s discipline: plaintext shown
  once, only the hash stored.
- Single-use. Accepting twice fails; the check is at the store, not in a
  read-then-write race in the core.
- Expired and already-accepted are **indistinguishable** in the response —
  both are "this link no longer works".

**tests** — single-use enforced under concurrency (`-race`); expiry; accepting
into the wrong tenant fails.

**dod**
- [ ] Concurrent double-accept: exactly one wins
- [ ] Expired and accepted produce identical responses

---

## Slice 7k-1 — rate limiting

```yaml
id: 7k-1
milestone: M5
risk: LOW
depends_on: []
design_ref: "§5 M5, §8 open item 5"
note: "Independent of tenancy. If Phase 7 slips, ship this on its own."
```

**writes** — `crypto/throttle.go` or `espresso/throttle.go`, wiring, tests

**new symbols**
```go
type Throttle interface {
    // Allow reports whether the action may proceed and, when it may not,
    // how long until it may. key is caller-composed (e.g. "login:"+tenant+":"+email).
    Allow(ctx context.Context, key string) (ok bool, retryAfter time.Duration)
}

func NewTokenBucket(rate int, per time.Duration, burst int) Throttle
```

**wire on** — `Login`, `VerifyTOTP`, `VerifyRecoveryCode`, `StartLogin`, SCIM.

**invariants**
- Keys are **caller-composed** so tamper never decides that email, IP or tenant
  is the right dimension — it is deployment-dependent.
- A nil `Throttle` is allowed (compat) but every constructor that accepts one
  documents that nil is unsafe in production.
- Throttling must not leak account existence: a throttled response is identical
  whether or not the account exists.
- In-process default is explicitly documented as **per-replica**, not global.

**tests** — bucket refill; burst; throttled response identical for
existing/nonexistent accounts.

**dod**
- [ ] Throttled response does not disclose account existence
- [ ] Per-replica limitation documented
- [ ] Wired on all five surfaces

---

## Slice 7l-1 — default flip (v0.4.0)

```yaml
id: 7l-1
milestone: M6
risk: HIGH
depends_on: [7b-3, 7c-2, 7e-2, 7f-2, 7g-2, 7h-1, 7i-1]
design_ref: "§5 M6, §8 open item 2"
```

**Goal.** Fold the tenant-aware interfaces into the base ports, delete the
fallback, and collapse the `*InTenant` names.

**writes** — every port file, `provider.go`, `CHANGELOG.md`, `MIGRATION-v0.4.md`

**invariants**
- Exactly one breaking release. No partial flips.
- `""` stays a legal `TenantID` — an explicit single-tenant value, not an unset
  one. Single-tenant deployments keep working; they just say so.
- The migration guide covers the backfill: assign every existing row a tenant,
  then upgrade. If the backfill turns out to be impossible for some schema
  shape, that is an M1 finding surfaced late — record it, do not paper over it.

**dod**
- [ ] `MIGRATION-v0.4.md` with a worked backfill example
- [ ] `CHANGELOG.md` entry naming every changed signature
- [ ] Barista migrated in the same release cycle
- [ ] No `*InTenant` suffix remains in the public API

---

## Appendix — dependency order

```
7a-1 ─ 7b-1 ─ 7a-2 ─ 7b-2 ─┬─ 7b-3 ───────────────┐
                           ├─ 7c-1 ─┬─ 7c-2 ──────┤
                           │        └─ 7d-1       │
                           ├─ 7e-1 ─┬─ 7e-2 ──────┤
                           │        └─ 7f-1 ─ 7f-2┤
                           ├─ 7g-1 ─┬─ 7g-2 ──────┤
                           │        └─ 7h-1 ──────┤
                           ├─ 7i-1 ───────────────┤
                           └─ 7j-1                │
7k-1 (independent)                                │
                                             7l-1 ┘
```

The `7a-1 → 7b-1 → 7a-2` head is the 2026-08-07 amendment. 7a-2 used to sit
parallel to 7b-1; it now follows it, because the leak suite cannot seed a
tenant without 7b-1's `TenantID` fields and cannot compile without the
`TenantScopedStore` declaration it now carries.

Critical path: `7a-1 → 7b-1 → 7a-2 → 7b-2 → 7e-1 → 7f-1 → 7f-2 → 7l-1`.

`7k-1` has no dependencies and closes a gap that exists today. Ship it first if
anything else stalls.
