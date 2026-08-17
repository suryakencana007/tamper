# Changelog

All notable changes to tamper are recorded here. Versions follow
[semver](https://semver.org/); the format is loosely
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [0.5.0] — 2026-08-17

Social federation for providers with no OpenID Connect layer, a
tenant-aware mint, and one behaviour change worth reading before
upgrading.

### ⚠️ Changed — behaviour

- **`crypto.JWTService.VerifyAccess` now DENIES an unset tenant id.**
  Passing the zero `tenant.ID` — what a caller who never resolved a
  tenant produces — returns the new `crypto.ErrTenantRequired` instead
  of verifying.

  Previously the zero ID and `tenant.Single` were indistinguishable
  here: both render `""` from `String()`, and the check compared
  `String()` values. A deployment whose tenant-resolving step never ran
  therefore verified single-tenant tokens happily and looked correct
  doing it — the missing wiring would surface only on the day a pooled
  tenant was introduced, as a silent cross-tenant accept.

  **Single-tenant deployments are unaffected.** They pass
  `tenant.Single` explicitly, which is valid and always was; the
  `Verify` convenience wrapper does the same on the caller's behalf.
  Only a caller that genuinely forgot to supply a tenant changes
  behaviour, and that caller was already wrong.

  `ErrTenantRequired` is deliberately NOT folded into `ErrInvalidToken`,
  unlike every other failure in that package. The anti-oracle rule earns
  its keep for conditions decided from attacker-supplied input; this one
  is decided from the caller's own argument before the token is
  consulted, discloses nothing about any tenant, and is a wiring bug.
  Transport obligation is unchanged: map it onto the same generic 401.

### Added

- **`oauth2social` — federation for plain-OAuth2 providers, with a
  Discord preset.** Discord issues no `id_token`, so the OIDC path
  cannot serve it; identity comes from an authenticated userinfo round
  trip instead. `Provider.FetchIdentity` returns `*oidc.Claims` — the
  same type the OIDC path produces — so an application's provisioning,
  email-collision veto and account-linking code stays protocol-blind.

  Two fences ship on in the preset: `RequireEmail` (an address-less
  account sits outside the collision veto, invitations and every
  notification) and `RejectUnverifiedEmail` (an app keying its veto on
  an unverified address turns a claim into a takeover primitive).
  Construction refuses `RejectUnverifiedEmail` when no field supplies
  the flag, rather than denying every sign-in at runtime.

- **`espresso.StartOAuth2Flow` / `espresso.VerifyOAuth2Callback`** — the
  flow siblings. PKCE S256 is unconditional; no nonce is sent, because
  nothing in this protocol could verify one. The state cookie therefore
  carries the entire CSRF defence and stays per-flow, provider-bound,
  signed and single-use.

- **`examples/discord`** — a runnable end-to-end example, with an embedded
  fake Discord so it needs no application registration. Its point is not
  that Discord works but that it works through the SAME application code
  as an OIDC provider: the example's `signIn` tail takes `*oidc.Claims`
  and never asks which protocol produced them. `main_test.go` drives the
  whole browser dance twice (JIT-provision, then resolve by
  `(provider, subject)`) and pins both the unverified-email refusal and
  the no-state-cookie refusal.

- **`identity.Core.IssueTokensForUserInTenant`** — mints a session bound
  to a tenant, landing it in both the access token's `tid` claim and the
  refresh session row so rotation inherits it. An unset tenant denies
  with `ErrTenantRequired`; passing `tenant.Single` is byte-identical to
  the existing shims.

### Fixed

- **64-bit provider ids no longer lose precision.** `encoding/json`
  decodes numbers into `float64` (53-bit mantissa), so a userinfo
  document carrying a numeric id above 2^53 — a Discord snowflake, for
  instance — round-tripped as a different value and would have keyed a
  different account. Userinfo is now decoded with `UseNumber()`.

### Security

- Toolchain moved to **go1.26.6**, clearing six standard-library
  advisories present in go1.26.5 (GO-2026-6218 `net/url`, GO-2026-6090
  `crypto/tls`, GO-2026-6089 and GO-2026-5026 `net/http`, GO-2026-6088
  `encoding/xml`, GO-2026-5972 `encoding/asn1`). The XML and ASN.1 ones
  sit directly under SAML assertion parsing.

---

## [0.4.1] — 2026-08-10

Audit hardening. No breaking changes, no database changes, no call-site
changes.

### Fixed

- **A crashed migration no longer bricks the audit store** (#24). Each
  migration file and its `schema_migrations` row commit as ONE transaction.
  Previously every statement autocommitted individually; a process killed
  mid-boot left the schema half-changed, and because 005's `ADD COLUMN`s are
  unreplayable (SQLite has no `ADD COLUMN IF NOT EXISTS`), every subsequent
  boot failed with `duplicate column name` — a durable outage from a
  transient crash. A crash at any point now rolls back to the exact
  pre-migration state and the next boot retries cleanly.
- **`Log` rejects an explicit `CanonicalVersion4` on a logger built without
  `SQLiteLoggerOptions.Tenancy`** (#25). Such a row has no v4 anchor to
  verify under: the boot guard accepted it while `audit verify` later
  reported it as forged — a false tamper alarm on an untouched database.
  The mistake now errors at write time, naming the fix.

### Documentation

- **Single-tenant PII erasure is a stated, supported recipe** (#25).
  `canonical_version=4` carries two capabilities — the tenant in the hash
  and the salted commitments that make erasure possible — behind one switch
  whose docs described only the first and steered single-tenant deployments
  away. The `Tenancy` option now names both and states the recipe (set it,
  leave `TenantID` empty, `BootstrapChainV4` at boot), `RedactEvent`
  explains its silent `(false, nil)` case, and the path is pinned by an
  end-to-end regression test.

---

## [0.4.0] — 2026-08-09

Phase 7: tamper serves N tenants from one process. **One process, N tenants,
pooled — not silo.**

This is the phase's single breaking release, and the break was scheduled
rather than discovered: v0.3.x shipped every tenant capability additively,
behind an empty tenant that meant "today's behavior", so consumers could adopt
the features one at a time and flip once. This is the flip.

Upgrading: **[MIGRATION-v0.4.md](MIGRATION-v0.4.md)**. If you are
single-tenant, §2 is the short answer — your data is already correct and only
your Go call sites change.

### BREAKING — the tenant is a type, and it is in the base ports

The tenant argument is `tenant.ID`, not `string`. This is the whole design and
everything else follows from it.

`""` stays a legal tenant, but only when it is *said*. A `string` could not
express that: `""` was simultaneously the single-tenant value and what a
caller who forgot to thread the tenant passed, so a forgotten tenant silently
read the single-tenant bucket. `tenant.ID`'s zero value is invalid, so absent
and empty are finally different values and only the first one denies.

```go
tenant.Single        // "" said out loud — a single-tenant deployment
tenant.New(s)        // untrusted input; New("") is INVALID, not Single
tenant.FromStored(s) // a value read back out of storage; "" IS Single
```

`New("")` is not an alias for `Single` on purpose: an empty string arriving
from a `tid` claim, a routing header or a config lookup means the lookup
produced nothing, and that is the case that must deny.

#### identity

| Removed / changed | Now |
|---|---|
| `Store.UserByEmail(ctx, email)` | `UserByEmail(ctx, tenant.ID, email)` |
| `Store.CountUsers(ctx)` | `CountUsers(ctx, tenant.ID)` |
| `Store.IdentityByProviderSubject(ctx, provider, subject)` | `IdentityByProviderSubject(ctx, tenant.ID, provider, subject)` |
| — | `Store.RevokeAllRefreshSessionsForTenant(ctx, tenant.ID, at)` (added to the port) |
| `type TenantScopedStore` | **removed** — folded into `Store` |
| `Core.Register(ctx, email, pw)` · `RegisterInTenant(ctx, tid, …)` | `Register(ctx, tenant.ID, email, pw)` |
| `Core.Login(ctx, email, pw)` · `LoginInTenant(ctx, tid, …)` | `Login(ctx, tenant.ID, email, pw)` |
| `Core.ResolveByIdentity(…)` · `ResolveByIdentityInTenant(…)` | `ResolveByIdentity(ctx, tenant.ID, provider, subject)` |
| `Core.ProvisionUserWithIdentity(…)` · `…InTenant(…)` | `ProvisionUserWithIdentity(ctx, tenant.ID, email, provider, subject)` |
| `Core.RevokeAllSessionsForTenant(ctx, string)` | `RevokeAllSessionsForTenant(ctx, tenant.ID)` |
| `Core.Invite(ctx, string, …)` · `AcceptInvitation(ctx, string, …)` | both take `tenant.ID` |
| `identity.WithTenancy(bool)` | **removed** — every `Core` is tenant-scoped |
| `identity.ErrTenancyDisabled` | **removed** — there is no disabled mode |

The boot-time assertion that a `Store` implements `TenantScopedStore` is gone
with it. A store that cannot scope by tenant now **fails to compile**, which
is strictly earlier than the boot error it replaces.

#### crypto

| Removed / changed | Now |
|---|---|
| `IssueAccess(userID, authTime, acr)` · `IssueAccessForTenant(…)` | `IssueAccess(userID, tenant.ID, authTime, acr)` |
| `VerifyAccess(token)` · `VerifyAccessInTenant(token, tid)` | `VerifyAccess(token, tenant.ID)` — **now checks the tenant** |
| — | `ParseAccess(token)` — parse only, tenant **not** checked |

The safety default is inverted. `VerifyAccess` used to be the unpinned form
with the pinned one carrying the suffix, so the safe call was the longer name.
Now `VerifyAccess` checks the tenant and skipping the check requires saying
`ParseAccess`.

#### oidc / saml

| Removed / changed | Now |
|---|---|
| `Manager.GetRegistry(ctx)` · `GetRegistryForTenant(ctx, tid)` | `GetRegistry(ctx, tenant.ID)` |
| `Manager.Reload(ctx)` · `ReloadForTenant(ctx, tid)` | `Reload(ctx, tenant.ID)` |
| `Manager.PinRegistry(reg)` · `PinRegistryForTenant(tid, reg)` | `PinRegistry(tenant.ID, reg)` |
| `Manager.InvalidateTenant(string)` | `InvalidateTenant(tenant.ID)` |
| `ProviderStore.ListEnabledProviders(ctx)` | `ListEnabledProviders(ctx, tenant.ID)` |
| `WithRedirectURLForTenant(func(tid, providerID string) string)` | callback takes `(tenant.ID, string)` |
| `WithSPMetadataURLForTenant(func(tid, id, acsURL string) string)` | callback takes `(tenant.ID, string, string)` |
| `type TenantScopedProviderStore` | **removed** — folded into `ProviderStore` |

#### espresso

| Removed / changed | Now |
|---|---|
| `TenantFromContext(ctx) (string, bool)` | `(tenant.ID, bool)` |
| `TenantFromRoutedContext(r) (string, bool)` | `(tenant.ID, bool)` |
| `RequireEntitlement(store, cap, resolve, …)` | `resolve` is `func(*http.Request) (tenant.ID, bool)` |
| `FederationHooks.Registry` / `SAMLHooks.Registry` | now take `(ctx, tenant.ID)` |
| — | **`PinTenant(resolve)`** — pins a tenant on **pre-auth** routes |

`PinTenant` is required if you serve OIDC/SAML start legs: the registry is
keyed by tenant now, so a start leg must know whose IdP to look up.
`RequireTenant` cannot do it — it cross-checks the token and therefore cannot
run before `RequireAuth`. Two names rather than one flag, so using the weaker
one on an authenticated route has to be deliberate.

#### audit

| Removed / changed | Now |
|---|---|
| `ActorService(saID, saName)` · `ActorServiceInTenant(…)` | `ActorService(saID, saName, tenant.ID)` |
| `ExportForTenant(ctx, tenantID string)` | `ExportForTenant(ctx, tenant.ID)` — an **unset** tenant now errors instead of silently exporting an empty file; `tenant.Single` is a real scope (rows stamped `""`), never a wildcard |
| `tenant.EntitlementStore.ForTenant(ctx, string)` | `ForTenant(ctx, tenant.ID)` |
| **`audit/sqlitestore`** | **`audit/internal/sqlitestore`** |
| `sqlitestore.IsUniqueViolation(err)` | `audit.IsUniqueViolation(err)` |
| `SQLiteAuditQueriesForTest(l)` | `audit.InsertEventDirectForTest(ctx, l, Event)` |
| `StoreForDebug()` + `FromRowForDebug(row)` | `(*SQLiteLogger).ListByCanonicalVersion(ctx, v) ([]Event, error)` |

Making the generated SQLite layer internal is the fix for the *class* of bug
that produced the `row_salt` regression below: tamper's schema was public API,
so every migration adding a `NOT NULL` column could break an outside caller's
struct literal at run time while still compiling.

`CanonicalPayloadV2ForDebug` and `SQLiteAuditDBForTest` are unchanged — they
expose an encoding and a stdlib `*sql.DB`, neither of which leaks the schema.

#### Deliberately unchanged

`RevokeAllSessionsForTenant`, `RevokeAllRefreshSessionsForTenant` and
`audit.ExportForTenant` keep their suffix. There, `ForTenant` names the
**subject** of the operation rather than a scope — routing a single user's
"log out everywhere" onto the first two would sign out an entire customer.

### Added

- **`tamper/tenant`** — `Descriptor`, `Store`, `Resolver`, `MemStore`,
  `WithTenant`/`FromContext`, and the `ID` type above.
- **Per-tenant identity** — email is unique per tenant, so two customers can
  both have `bob@example.com`; the `firstUser` bootstrap signal counts within
  a tenant, so tenant #2's first admin gets it even though tenant #1 is full.
- **`identity/tenanttest.RunLeakSuite`** — the exported cross-tenant leak
  conformance suite. Seeds two tenants, addresses one as the other, requires
  `ErrNotFound` every time. Run it against your store; the compiler cannot
  check that you honour the tenant inside a scoped method.
- **`tid` access-token claim** with per-tenant verification, plus
  `RequireTenant` middleware.
- **`crypto.Signer`** — a seam over sign/verify with `alg` + `kid`. HS256 stays
  the default and its output is byte-identical. Unblocks RS256/ES256 and
  per-tenant keys without committing to either. No JWKS endpoint yet.
- **Tenant-keyed OIDC and SAML registries** — per-tenant caches preserving the
  existing double-checked locking, nil-sentinel symmetry and per-key eager
  invalidation.
- **Home-realm discovery** — `DomainStore`, `DNSVerifier` with a `net.Resolver`
  implementation, a public-email-domain blocklist as data, and
  `espresso.StartLogin`, which is timing-indistinguishable between a matched
  and unmatched domain so it cannot be used to enumerate customers.
- **SCIM principal tenancy** — the tenant comes from the validated token,
  never from the URL path, plus per-tenant `meta.location` / `$ref`.
- **`tenant.EntitlementStore`** — per-tenant capability tiers gated at the
  route surface. A disabled capability is 403 with a stable code, never 404.
- **Invitations** — `Invitation`, `InvitationStore`, single-use tokens with a
  TTL. Expired and already-accepted are indistinguishable in the response.
- **Rate limiting** — `crypto.Throttle` and an in-process token bucket, wired
  on login, TOTP verify, recovery-code verify, `StartLogin` and SCIM. Keys are
  caller-composed. The in-process default is **per-replica, not global**.
- **`audit` `canonical_version=4`** — the tenant enters the hashed payload, and
  PII becomes redactable via stored commitments so an erasure request can be
  answered without breaking the chain. Dispatched per row exactly as v2/v3, and
  a tenancy-disabled deployment keeps writing v3.
- **Tenant-filtered audit export** — labelled `"is_chain": false`,
  `"completeness": "issuer-attested"`. It may claim per-row authenticity and
  position; it may **not** claim completeness, because consecutive exported
  rows link through other tenants' rows.

### Fixed

- **`audit`: nil v4 blobs inserted as NULL for outside callers.** Migration
  005 added six `BLOB NOT NULL DEFAULT x''` columns, but sqlc names every
  column in the INSERT so the DEFAULT can never fire. Any consumer building
  `InsertEventParams` as a struct literal — the only way to build it, and the
  only thing a caller written before v4 could do — sent six explicit NULLs and
  hit `NOT NULL constraint failed: events.row_salt`. It compiled cleanly on
  both versions, so nothing caught it until a real consumer's suite ran.
  Fixed at the shared boundary with `sqltypes.Blob`, whose `driver.Valuer`
  renders nil as `x''`. No SQL change and no row rewritten — SQLite cannot
  relax a column constraint in place, so dropping `NOT NULL` would have meant
  rebuilding the `events` table and copying every row of an append-only hash
  chain.
- **`audit`: two replicas forked the hash chain.** `Log` was a
  read-modify-write guarded only by an in-process mutex, so replicas sharing
  one audit DB both read the same latest hash and both inserted, producing two
  rows claiming the same predecessor — reported at boot as tamper, on a
  database nobody tampered with. Now a `BEGIN IMMEDIATE` transaction.
- **`identity`: refresh rotation dropped the tenant** onto the successor row,
  silently widening a session.

### Known limitation

tamper's model is **one row, one tenant**. A user who legitimately belongs to
more than one tenant — a consultant with two customers, a support engineer
present in every tenant — cannot be expressed as a single `users` row, and the
v0.4.0 backfill has no correct answer for one. The shape that works is one
user row per (person, tenant) with your application owning the membership
table. See MIGRATION-v0.4.md §3.

---

## [0.2.5] and earlier

Not recorded here; this file starts at the Phase 7 release. See the git
history and the `PHASE*.md` design documents for the Phase 0–6 record.
