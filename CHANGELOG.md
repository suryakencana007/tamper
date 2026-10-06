# Changelog

All notable changes to tamper are recorded here. Versions follow
[semver](https://semver.org/); the format is loosely
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

Fixes for sharp edges in pooled deployments, and one breaking change to the
audit log. Each is a separate change (#39, #40, #43, #46 to #52) and is
described in `tech-debt.md`.

### ⚠️ Breaking — the audit log is `canonical_version=4` only (#46)

Every audit row is now written and read at `canonical_version=4`: the tenant
is inside the hash, and PII is hashed as salted commitments so it can be
redacted. Everything that existed for older rows is removed.

**Before you upgrade:**

- **An audit DB written by an earlier version cannot be opened.**
  `NewSQLiteLogger` returns an error that names the file and lists how many
  rows it found at each other version (#54). Archive the old file
  and point the application at a new one. The same error appears when a row's
  version was changed after it was written, so do not delete a file because
  of it without knowing which case it is.
- **Upgrade every writer of one audit DB together.** An old binary that still
  appends a v3 row makes `Verify` report tamper at that row, and the next open
  by the new binary refuses the file.
- **A single-tenant deployment's audit hashes change.** It now writes v4 rows
  with an empty tenant. Nothing else on the single-tenant path changes.
- **An application that writes its own chain-restart anchors at boot must stop.**
  `Log` refuses every version but 4, and the anchor actions are gone.

**What changes:**

- `Log` writes v4 with no option. It accepts an event whose
  `CanonicalVersion` is zero or `CanonicalVersion4` and refuses any other.
- `RedactEvent` works on every row, for every deployment.
- `Verify` and `VerifyChainPostMigration` walk every row from the first one.
  There are no anchors.
- `ComputeHash` accepts only `CanonicalVersion4`.
- `Log` always generates the row salt and the PII commitments itself. A
  `RowSalt`, `Commitments`, `PrevHash` or `Hash` already set on the event is
  replaced.
- `RedactEvent` returns an error when the row lookup fails. It used to report
  every lookup error as "no such row".
- `ListScoped` returns the tenant, the salt and the commitments on each event.
  They were missing before.
- A logger built by `tamper.New` writes v4. `tamper.Config` did not change.

**Removed:**

- `SQLiteLoggerOptions.Tenancy`
- `CanonicalVersion1`, `CanonicalVersion2`, `CanonicalVersion3`
- `SQLiteLogger.VerifyLegacy`
- `SQLiteLogger.BootstrapChainV4`, `HasChainRestartV2`, `HasChainRestartV3`,
  `HasChainRestartV4`, `HasChainMigrate`
- `SQLiteLogger.MigrateLegacyV2Hashes`, `RehashChainInPlace`, `MigrationResult`
- `SQLiteLogger.CountByCanonicalVersion`, `CanonicalVersionCount`,
  `ListByCanonicalVersion`
- `ActionAuditChainRestart`, `ActionAuditChainMigrate`,
  `ReservedActionPrefix`, `IsReservedAction`
- `CanonicalPayloadV2ForDebug`
- `VerifyBootResult.Segments`

### ⚠️ Breaking — the tenant gates' resolvers say whether they found a tenant (#60, TD-28)

- **`RequireTenant`, `RequireTenantAllowEntered` and `PinTenant` take
  `func(*http.Request) (tenant.ID, bool)`** instead of
  `func(*http.Request) string`, the shape `RequireEntitlement` and
  `DecisionGate.Tenant` already take. An empty string used to become
  `tenant.Single`, so a route pattern with no tenant segment was served as a
  single-tenant route. A tenant that does not resolve (`false`, or the zero
  `tenant.ID`) is now refused: `RequireTenant` with the 401 a wrong-tenant
  token gets, `PinTenant` with a 404. The single tenant is said:
  `FixedRequestTenant(tenant.Single)`, new, which panics on an unset id.
- **`TenantFromServiceAccount` returns `(tenant.ID, bool)`**; the principal's
  `TenantID` is a stored fact, so `""` is the single tenant.

### ⚠️ Breaking — the `espresso.IdentityService` port takes the tenant (#59, TD-28)

- **Every `IdentityService` method takes a `tenant.ID`** after `ctx`: the
  tenant the request is routed to. An adapter passes it to the `Core`
  methods that take one, and checks the user's (or the session's) stored
  tenant before the methods keyed by a bare user id or token, answering a
  mismatch with `identity.ErrNotFound` (or `ErrInvalidSession`). The
  examples show the shape.
- **`AuthRoutesConfig.Tenant` is required**: `func(context.Context)
  (tenant.ID, bool)`. `NewAuthRoutes` refuses a config without it. Behind
  `PinTenant` or `RequireTenant` pass `TenantFromContext`; a single-tenant
  application passes the new `FixedTenant(tenant.Single)`, which panics on an
  unset id. A request on which it resolves nothing is refused with the 401
  the tenant gates write for a tenant that did not resolve, and the port is
  not reached; `Refresh` and `Logout` clear the refresh cookie on that path.
- The TOTP routes render the adapter's cross-tenant `ErrNotFound` as the
  401 a dead session gets, not as a 500.
- `IssueTOTPPending` and `VerifyTOTPPending` on the port take a `ctx` as
  well.
- A pooled deployment no longer needs one adapter per tenant;
  `examples/multitenant` has one adapter for every tenant.

### ⚠️ Breaking — `identity` has one mint function (#58, TD-28)

- **`Core.IssueTokensForUser` and `Core.IssueTokensForUserWithACR` are
  removed.** They minted for `tenant.Single` without reading the user's row.
- **`Core.IssueTokensForUserInTenant` is now
  `Core.IssueTokensForUser(ctx, userID, tenant, authTime, acr)`.** It reads
  the row, refuses a tenant that is not the user's with `ErrNotFound`, and
  refuses an inactive user.
- **`authTime` and `acr` are required.** A non-positive `authTime` or an
  empty `acr` is the new `ErrAuthContextRequired`: a caller bug, surfaced
  like `ErrNoTokenService`, and not `ErrInvalidInput` (which adapters map
  to a 400). `Core.EnterTenant` returns it for the same case; it returned
  `ErrInvalidInput`. The method used to fill in "now" and the default ACR.
  A TOTP second leg passes the time the code was verified and the ACR the
  deployment gives that login — `Core.DefaultACR()`, new, is the one `Login`
  stamps, so the two local logins agree; a federated callback passes the
  IdP's.
- **`Core.Refresh` refuses a session row whose `auth_time` is not positive
  or whose `acr` is empty** with `ErrInvalidSession`, and revokes it. The
  predicate is the mint's own, so a store that scans a `NULL` `auth_time` as
  the Unix epoch is caught here and not as a signing failure. It used to rotate such a row
  with "now" and the default ACR. This package has always written both
  fields; a row without them was written by something else.
- `WithDefaultACR` no longer describes a "legacy-row fallback"; it is the
  ACR for the sessions this package authenticates itself.

### ⚠️ Breaking — `crypto` has one set of token functions (#57, TD-28)

No compatibility code is kept (decided 2026-10-05). `crypto.JWTService` had
each token function twice, once with a tenant and once without. The forms
without a tenant are removed.

- **`Issue(userID)` and `Verify(token)` are removed.** Use
  `IssueAccess(userID, tenant, authTime, acr)` and
  `VerifyAccess(token, tenant)`.
- **`IssueTOTPPending` and `VerifyTOTPPending` take a tenant**:
  `IssueTOTPPending(userID, tenant)` and `VerifyTOTPPending(token, tenant)`.
  `IssueTOTPPendingInTenant` and `VerifyTOTPPendingInTenant` are the same
  functions under their old names and are removed.
- **An access token must carry `purpose`, `auth_time` and `acr`.**
  `ParseAccess` and `VerifyAccess` refuse a token that lacks any one of the
  three. They used to accept a token with no `purpose`, and one with no
  `auth_time` or `acr`, as tokens from an older version. Every token `IssueAccess` mints has
  all three, so tokens minted by this version are not affected.

- **`IssueAccess` returns `ErrTenantRequired` for an unset tenant.** It used
  to mint: the zero `tenant.ID` has the same string form as `tenant.Single`,
  so a caller whose tenant was never resolved got a valid single-tenant
  token.

A single-tenant application passes `tenant.Single`. Its tokens are the same
bytes as before: the single tenant is still spelled as no `tid` claim.

### ⚠️ Breaking — the `authz` ports take a tenant (#56, TD-03)

`authz` now has a tenant contract. Design: `PHASE8B-AUTHZ-TENANT-SKETCH.md`.

- **Every method of `authz.Authorizer`, `authz.BindingStore` and
  `authz.PermissionStore` takes a `tenant.ID` after `ctx`.** It is the scope
  of the question: the tenant whose resources are being acted on. Code that
  calls or implements these does not compile until it is changed.
- **`authz.Subject` has a `Tenant` field**, the subject's home tenant, and
  **`authz.Binding` has a `Tenant` field**, the scope the binding lives in.
  Unkeyed literals such as `Subject{"user", "u-1"}` no longer compile.
- **An unset scope, or a subject with no home tenant, is the new error
  `authz.ErrTenantRequired`.** Callers treat it as deny, like every error.
- **`MemPermissionStore.Grant` and `GrantSuperuser` take the scope** as their
  first argument. A superuser is a superuser of one scope.
- **`MemStore.Grant`, `MemStore.Revoke`, and `MemPermissionStore.Grant` and
  `GrantSuperuser` return an error.** They return `ErrTenantRequired`, and
  store nothing, for an unset scope or a subject with no home tenant. A
  keyed literal such as `Binding{Subject: ..., Resource: ..., Role: ...}`
  still compiles after the upgrade; stored quietly it would never match.
  `NewMemStore` panics on such a seed binding. The read methods of both
  stores return `ErrTenantRequired` for the same two cases.
- **`espresso.DecisionGate` has a required `Tenant` resolver**,
  `func(*http.Request) (tenant.ID, bool)`, and `RequireDecision` panics
  without it. The gate asks in the tenant it resolves and builds the subject
  with the token's home tenant. The token must be for exactly that tenant;
  an entered token passes only with the new `AllowEntered` field. Anything
  else is a 401: a tenant that did not resolve, and a user id put in the
  context without a token (`ContextWithUserID`), included. The gate never
  treats "no tenant" as single-tenant.
- **`espresso.DecisionGate.UserExists` takes the subject's home tenant**:
  `func(ctx, home tenant.ID, userID string)`. Look the user up there.

**To upgrade a single-tenant deployment:** pass `tenant.Single` as the scope,
set `Tenant: tenant.Single` on every `Subject` and `Binding`, accept the new
argument in your stores and in `UserExists`, and give every `DecisionGate` a
`Tenant` resolver that returns `(tenant.Single, true)`. Decisions are the
same as before.

**To upgrade a pooled deployment:** filter by the scope in every store query,
match subjects with their home tenant, and run
`authz/tenanttest.RunBindingStoreLeakSuite` or
`RunPermissionStoreLeakSuite` against your store. Give every `DecisionGate`
the resolver its route uses; behind `RequireTenant` that is
`TenantFromRoutedContext`. A route that is not tenant-routed, such as a
platform console, is a route of one tenant: its resolver returns that tenant.

`ListSubjects` returns `ErrTenantRequired` if a store returns a subject with
no home tenant. Backfill that column before the upgrade.

### ⚠️ Changed — behaviour

- **`identity.Core.IssueTokensForUserInTenant` denies a mismatched tenant**
  (#40, TD-10). It now loads the user and refuses unless the tenant on the
  stored row equals the tenant asked for. Before, it minted for any user in
  any tenant and only refused an unset tenant.

  Four consequences:

  - A user id with no row is now refused. It used to mint, because the method
    never read the store.
  - A mismatch and a missing user return the same `identity.ErrNotFound`, so
    the two cannot be told apart.
  - A deactivated user is refused with `identity.ErrUserInactive`. The tenant
    is checked first, so an inactive user addressed from another tenant still
    gets `ErrNotFound`.
  - The method costs one `UserByID` read per mint.

  A user stored in the single tenant, minted with `tenant.Single`, gets the
  same tokens as before. `IssueTokensForUser` and `IssueTokensForUserWithACR`
  are unchanged. The method can no longer be used to give a user a session in
  a tenant they are not stored in.

- **`identity.Store.UserByID` must return the user's tenant, and the leak
  suite checks it** (#40, TD-10). The mint above compares the tenant on the
  row `UserByID` returns, so that row must carry `User.TenantID`.
  `tenanttest.RunLeakSuite` has a new `UserByID` case. A store whose by-id
  query does not select the tenant column now fails the suite; fix the query,
  because every tenant-bound mint would fail with it.

- **A TOTP-pending token is verified for a tenant** (#40, TD-10; final shape
  in #57). `crypto.JWTService.VerifyTOTPPending(token, tenant)` refuses a
  pending token minted for another tenant. See the `crypto` breaking entry
  above for the signatures.

- **A tenant-bound credential on an unscoped SCIM surface is refused** (#39,
  TD-15). With `SCIMConfig.Tenancy` off, a request whose validated principal
  carries a non-empty `TenantID` now gets a 500 `CONFIG_ERROR` before any
  store method runs. Before, it was served from the unscoped store, so tenant
  A's service account could read and change tenant B's directory. A principal
  with an empty `TenantID` is unchanged. If your validator returns a tenant,
  set `SCIMConfig.Tenancy: true`. If your unscoped stores are already confined
  to one tenant by other means, set `SCIMConfig.TenantBoundStores` instead
  (see Added).

- **Rows written by `espresso.Auditor` now carry the tenant** (#43, TD-08).
  `Event.TenantID` is the tenant pinned by `RequireTenant` or `PinTenant`.
  `Actor.TenantID` is the token's `tid`. Before, both were empty, so
  `audit.ExportForTenant` never returned these rows. A request with no `tid`
  and no pinned tenant produces the same event as before. Rows written before
  this change are not migrated.

- **`identity.Core.Refresh` refuses a session bound to another tenant** (#47,
  TD-19). A refresh session whose tenant is not the tenant its user is stored
  in no longer rotates. It returns `ErrInvalidSession` and the session is
  revoked. Before, such a session kept producing access tokens for a tenant
  the user does not belong to, for as long as it was refreshed.

  No path in tamper creates such a session since #40. This affects a row
  written earlier or by the application, and one more case: a pooled adapter
  that mints a tenant user's session through `IssueTokensForUser` or
  `IssueTokensForUserWithACR`. Those two write a session with no tenant, so
  it can no longer be refreshed; mint with `IssueTokensForUserInTenant`.
  Single-tenant deployments are unaffected.

- **`audit` `List` and `ListScoped` apply every `Filter` field** (#49, TD-17).
  `Since`, `Until`, `ActorEmail` and `Action` were declared and never read;
  they now filter. `ResourceType` alone and `ResourceID` alone filter too.
  Fields set together are ANDed; before, only the first one in a fixed order
  was used. `Since` is inclusive, `Until` is exclusive, and the cursor pages
  within the filter. `ListScoped` applies the filter on top of its cluster
  scope. A caller that relied on a field being ignored gets fewer rows.

- **A refused TOTP mint is a 401, not a 500** (#50, TD-18). When the session
  mint at the end of `AuthRoutes.VerifyTOTP` returns `identity.ErrNotFound`,
  the route answers `401 UNAUTHENTICATED`, the same bytes as a pending token
  that is no longer good. This also applies to a single-tenant deployment: a
  user deleted between the password step and the second factor gets 401 where
  it got 500.

- **Step-up denials and service-account rows carry an audit scope** (#51,
  TD-20). A row written by `RequireFreshAuthWithAudit` now has
  `Event.TenantID` (the routed tenant) and `Actor.TenantID` (the token's
  `tid`). A row written by `Auditor` behind `RequireServiceAccount` now has the
  principal's tenant as its scope when no tenant is pinned. Single-tenant rows
  are unchanged.

- **Every token verification failure prints one text** (#52, TD-23). The error
  from `VerifyAccess`, `ParseAccess` and `VerifyTOTPPending` now always reads
  `auth: invalid token: token not valid`. It used to say which check failed,
  which let a log line or an adapter's response tell a wrong-tenant token from
  an expired one. `errors.Is(err, ErrInvalidToken)` is unchanged, and the
  reason is still in the error chain (`errors.Is(err, jwt.ErrTokenExpired)`).
  Code that matched on the old text must use `errors.Is`.

### Added

- **Platform admin: entering a tenant** (#55, TD-01, TD-02). Opt-in; a
  deployment that does not use it is unchanged. Design:
  `PHASE8-PLATFORM-ADMIN-SKETCH.md`.
  - `identity.MembershipStore` (`IsMember`, `MembershipsFor`), enabled with
    `identity.WithMemberships`. A user keeps one home tenant; a membership is
    a right to act inside another.
  - `identity.Core.EnterTenant(session, target)` mints an access token for a
    tenant the user is a member of. `session` is the verified claims of the
    user's home access token; an entered token cannot enter again.
    `EnterableTenants` lists the tenants. There is no refresh session: when
    the token expires, enter again. `WithEnterTenantTTL` shortens the token
    and must not exceed the access token TTL. `Hooks.OnTenantEntered` runs
    after a successful entry. New error: `ErrNoMembershipStore`.
  - `crypto.AccessClaims.HomeTenantID` (`htid`), `Entered()`,
    `ActorTenantID()`, `crypto.JWTService.IssueAccessEntered` and
    `AccessTTL()`. Ordinary tokens carry no `htid` and are byte-identical to
    before.
  - `espresso.RequireTenantAllowEntered` and `EnteredFromContext`.
    **`RequireTenant` refuses an entered token**: every existing route stays
    closed to guests until the application mounts it with the new gate.
  - The audit actor that `espresso.RequireAuth` puts in the context carries
    the token's home tenant. For an ordinary token that is `tid`, as before.
  - `identity.MemStore` implements the port.

- **`authz/tenanttest`** (#56, TD-03). Leak suites for `BindingStore` and
  `PermissionStore`, the `authz` sibling of `identity/tenanttest`.

- **`espresso.SCIMConfig.TenantBoundStores`** (#39, TD-15). The opt-out for
  the SCIM refusal above. Set it when the unscoped stores given to
  `NewSCIMRoutes` are already confined to one tenant: one `SCIMRoutes` per
  tenant over a tenant-bound store, or stores that scope themselves from the
  principal. Tamper cannot verify this. Setting it on a store shared by
  several tenants re-opens the leak. `Tenancy` and `TenantBoundStores`
  together are rejected by `NewSCIMRoutes`.

- **A TOTP-pending token carries a `tid` claim** (#40, TD-10). Verification
  pins it the same way `VerifyAccess` pins an access token, so a pending
  token minted in one tenant cannot be finished in another. The functions
  are `IssueTOTPPending(userID, tenant)` and
  `VerifyTOTPPending(token, tenant)`; #40 added them under `…InTenant` names,
  which #57 removed.

- **Audit DB migration 006** (#54, TD-26). A partial index over rows that are
  not `canonical_version=4`. It is empty on a healthy DB and makes the check
  that `NewSQLiteLogger` runs at every open read nothing. It is applied
  automatically on the next open, like the earlier migrations.

### Fixed

- **`examples/multitenant`** (#40). The post-TOTP session now carries the
  tenant, and the example issues tenant-bound pending tokens.
- **`examples/multitenant`: authenticated routes use `RequireTenant`** (#48,
  TD-22). The `/me` route had only `RequireAuth`, with the tenant check inside
  the adapter. The example now shows the gate that every authenticated route
  in a pooled deployment needs, and its comments no longer describe `tid` and
  `RequireTenant` as future work.

---

## [0.6.0] — 2026-08-31

Additive. No breaking changes, no database changes, no call-site changes.

### Added

- **`audit.ComputeHash`** (#35). The hash-chain computation
  `SQLiteLogger.Log` performs internally — `sha256(prevHash || canonicalPayload)` —
  is now callable directly, so a Logger implementation backed by a store
  this package doesn't ship (Postgres, for one) can produce
  chain-compatible hashes without reimplementing the canonical payload
  encoding. Pairs with `NewRowSalt`/`ComputeCommitments` (already exported
  via `redaction.go`), which cover the rest of what a v4 event needs — and
  `ComputeHash` checks that a v4 event's `Commitments` were actually
  derived from its own `RowSalt` before hashing, rather than silently
  committing to PII that was never there. `ComputeHash` requires an
  explicit `CanonicalVersion3` or `CanonicalVersion4` on the event —
  unlike `Log`, it does not default a zero version, since that defaulting
  depends on a specific `SQLiteLogger`'s own `Tenancy` option. Appending to
  the chain safely under concurrent writers — reading the true latest hash
  and inserting atomically — remains entirely the caller's own store's
  responsibility; see the function's doc comment for the full list of
  invariants (timestamp ordering, the v4 chain-restart anchor, running
  `VerifyCommitments` alongside chain verification) a from-scratch
  `Logger` needs to uphold on its own.

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
