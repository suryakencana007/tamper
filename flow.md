# Tamper — functions and knowledge flow

This document lists what each Tamper package does and how data moves between
the functions. It was written from the code at `v0.6.0` (commit `c1af24e`).
It describes what the code does today. It is not a plan. The gaps for a
cross-tenant platform admin are in [`tech-debt.md`](tech-debt.md).

## 1. What Tamper is

Tamper is a Go auth/authz library that you embed in your application. It is
not a separate service. Three properties shape every flow:

- **Ports, not tables.** Every kind of storage is an interface. The
  application implements it over its own schema. Tamper never names a table or
  a column.
- **Deny by default.** A tenant that is missing, empty, or different is always
  rejected. An error from a store is never read as "allowed".
- **Pooled multi-tenancy.** One process serves N tenants. The tenant is a type
  (`tenant.ID`) and its zero value is invalid. So "I forgot to pass a tenant"
  and "I am single-tenant on purpose" (`tenant.Single`) are two different
  inputs.

## 2. Functions per package

### `tamper` (root) — the assembler

| Function | Purpose |
|---|---|
| `New(Config) (*Provider, error)` | Validates the config, then builds every engine. A wrong config fails here, not per request. |
| `Provider{JWT, KeySet, Audit, Authz, Identity, OIDC, SAML}` | The set of engines. A `nil` field means "not configured". |
| `Provider.Close()` | Closes the audit DB handle. |
| `RBAC(store, hierarchy, policy)` | Builds an `Authorizer` that uses role ladders. |
| `PermissionSet(store)` | Builds an `Authorizer` that uses sets of permission keys. |

### `crypto` — primitives

| Function | Purpose |
|---|---|
| `NewJWTService`, `WithSigner`, `WithVerifiers` | The JWT service. HS256 is built in. Other signers plug in through the `Signer` interface, with `kid` rotation. |
| `IssueAccess(userID, tenant, authTime, acr)` | Creates an access token with the claims `sub`, `tid`, `auth_time`, `acr`, `purpose`. |
| `IssueAccessEntered(userID, tenant, homeTenant, authTime, acr, ttl)` | Creates an *entered* token: `tid` is the tenant entered, `htid` is the user's home tenant. It checks no right; `Core.EnterTenant` is the entry point. |
| `VerifyAccess(token, tenant)` | Verifies the token and pins the tenant: `tid` must match exactly. |
| `ParseAccess(token)` | Verifies the token without the tenant check. `RequireAuth` uses it; the tenant check comes later in `RequireTenant`. |
| `IssueTOTPPending` / `VerifyTOTPPending` | A 5-minute token used between "password is correct" and "TOTP is correct". |
| `HashPassword`, `VerifyPassword`, `VerifyStub` | bcrypt. `VerifyStub` keeps the response time the same when the user does not exist. |
| `NewRefreshToken`, `HashRefreshToken` | A random 32-byte refresh token. Only the hash is stored. |
| `GenerateTOTPSecret`, `VerifyTOTPCode`, `GenerateTOTPRecoveryCodes`, `MatchRecoveryCode` | Second factor. |
| `NewKeySet`, `NewSecretBox` | KEK envelope that seals secrets at rest (TOTP secrets, OIDC client secrets, SAML SP keys). |
| `NewTokenBucket` | In-process rate limiter behind the `Throttle` port. |

### `tenant` — the tenancy vocabulary

| Function / type | Purpose |
|---|---|
| `ID`, `New(s)`, `Single`, `FromStored(s)` | `New("")` is invalid (for untrusted input). `FromStored("")` is `Single` (for values read from storage). |
| `Descriptor{ID, Slug, ParentID, Status}` | The tenant row as Tamper sees it. `ParentID` is RESERVED; nothing reads it yet. |
| `Store` (`ByID`, `BySlug`) | Read port for tenants. |
| `DomainStore`, `ResolveDomain`, `DomainRecord.BoundProviderID` | Home-realm discovery: email domain → tenant → IdP. Only verified domains resolve. |
| `NewVerificationToken`, `NewDNSVerifier` | Proof of domain ownership through a DNS TXT record. |
| `Entitlements`, `EntitlementStore.ForTenant` | The features a tenant has bought (SSO, SCIM, IdP limit). This is not authorization. |
| `WithTenant` / `FromContext` | Context propagation only. Never used as a permission. |

### `identity` — credentials and sessions

| `Core` function | Purpose |
|---|---|
| `Register(tenant, email, pw)` | Creates a user. The `firstUser` signal is counted per tenant. |
| `Login(tenant, email, pw)` | Password login with throttling and equal timing. Returns `ErrTOTPRequired` when a second factor is needed. |
| `Refresh(token)` | Rotates the session. `TenantID`, `auth_time`, and `acr` are copied unchanged. |
| `Logout`, `RevokeAllSessions(user)`, `RevokeAllSessionsForTenant(tenant)` | Revokes sessions: one, all of a user, all of a tenant. |
| `IssueTokensForUser`, `…WithACR`, `…InTenant` | Mints tokens after TOTP or federation. Only the `InTenant` variant carries a tenant. |
| `StartTOTPEnrollment`, `CompleteTOTPEnrollment`, `EnrollTOTP`, `VerifyTOTP`, `VerifyRecoveryCode`, `DisableTOTP`, `ClearTOTP` | TOTP lifecycle. |
| `ResolveByIdentity`, `ProvisionUserWithIdentity`, `Link`, `Unlink`, `ListIdentities` | Multi-IdP account linking and JIT provisioning. |
| `Invite`, `AcceptInvitation` | Onboarding without SSO, through a single-use token. |
| `EnterTenant(session, target)`, `EnterableTenants(user)` | A user of one tenant enters another one they are a member of. `session` is the claims of the home access token. Access token only, no refresh session. |

Ports: `Store` (required), `InvitationStore` and `MembershipStore`
(optional). `MemStore` is the
reference implementation. `identity/tenanttest.RunLeakSuite` is the
cross-tenant leak test. Every `Store` implementation must pass it.

### `authz` — the policy decision point

| Function / type | Purpose |
|---|---|
| `Authorizer.Check(tenant, subject, action, resource)` | Answers one authorization question. `tenant` is the scope: whose resources. `subject` carries its home tenant. |
| `CheckBulk` | Answers many questions in one call. |
| `ListResources(tenant, subject, action, type)` | "Which resources may this subject act on?" `unbounded=true` means all of them. |
| `ListSubjects(tenant, action, resource)` | "Who may do this?" Used for access reviews. A guest is listed with the tenant they are from. |
| `NewRBAC(BindingStore, Hierarchy, Policy)` | The role-ladder engine. A policy is an OR of `Requirement{Type, Min}`. When `Type` differs from the resource type, it is a global alternative. |
| `NewPermissionSet(PermissionStore)` | The permission-key engine. `Superuser` is an explicit flag, not a `*` key. |
| `NewRBACPermissionStore` | A converter that makes `PermissionSet` decide exactly like `RBAC`. |

All indirection (groups, custom roles, inheritance) is the store's job. The
engine only compares.

Every method of `Authorizer`, `BindingStore` and `PermissionStore` takes a
`tenant.ID`. A binding lives in one tenant and never answers a question in
another. `authz/tenanttest` has the leak suites
(`RunBindingStoreLeakSuite`, `RunPermissionStoreLeakSuite`); every store must
pass them.

### `oidc`, `saml`, `oauth2social` — federation

| Function | Purpose |
|---|---|
| `oidc.NewManager`, `saml.NewManager` | Provider CRUD over a `ProviderStore`. Secrets are sealed by the `KeySet`. The live registry has a TTL cache. |
| `Manager.GetRegistry(ctx, tenant)` | The provider registry of one tenant. |
| `oidc.NewFlow`, `VerifyIDToken`, `FetchUserinfo`, `ExtractGroups` | PKCE, ID-token verification, group-claim normalisation. |
| `saml.BuildAuthnRequestURL`, `ParsedAssertion`, `AssertionReplayStore` | AuthnRequest (with step-up), assertion parsing, replay defence. |
| State cookies (`SignOIDCStateWithSecret`, `SignStateCookieWithSecret`, and the matching `Verify…`) | Tie the start step to the callback step. |
| `oauth2social.New`, `Discord(...)` | Social login for providers that have no OIDC layer. |

### `scim` — directory provisioning

| Function | Purpose |
|---|---|
| `Parse`, `Translate(expr, ColumnMapping)` | SCIM filter → SQL WHERE clause, over a column mapping the application supplies. |
| `Apply`, `ParsePath`, `RedactedOps` | RFC 7644 PATCH, and a redacted copy for the audit log. |
| `DetectCycle` | Finds cycles in nested groups. |
| `UserStore`, `GroupStore`, `TenantScopedUserStore`, `TenantScopedGroupStore` | Storage ports. |

### `audit` — the tamper-evident log

| Function | Purpose |
|---|---|
| `NewSQLiteLogger(path, opts)`, `NewNoopLogger` | SQLite hash-chain logger. Every row is `canonical_version=4`. It refuses a DB that holds rows at an older version (#46). |
| `Logger.Log` | Appends in one `BEGIN IMMEDIATE` transaction: `hash = sha256(prevHash ‖ canonical payload)`. |
| `List`, `ListScoped(clusterIDs, filter)` | Paged reads. Only some `Filter` fields are applied (see TD-17). |
| `Verify`, `VerifyChainPostMigration` | Walks every row from the first one and recomputes each hash. Tamper does not call these by itself. The application must call `VerifyChainPostMigration` at boot. |
| `ExportForTenant(tenant)` | One tenant's slice of the log, filtered on `Event.TenantID`. |
| `Redact`, `RedactEvent`, `VerifyCommitments`, `ComputeCommitments`, `NewRowSalt` | Erases PII through salted commitments without breaking the chain. |
| `ComputeHash` | For a `Logger` implemented over another store (for example Postgres). |
| `PruneOlderThan` | Retention. |
| `WithActor` / `ActorFromContext`, `ActorService`, `ActorSystem` | Who did it: a user, a service account, or the system. |

### `espresso` — the HTTP adapter

| Function | Purpose |
|---|---|
| `Routes(provider, RouteConfig)` | Builds `Surfaces`: the auth, OIDC, SAML, and SCIM routes, plus middleware already bound to the engines. |
| `RequireAuth`, `RequireAuthWS` | Bearer JWT → user id, claims, and audit actor in the context. |
| `RequireTenantAllowEntered`, `EnteredFromContext` | `RequireTenant` for a route that platform admins may use: it also accepts a token entered into the routed tenant. `RequireTenant` itself refuses one. |
| `PinTenant(resolve)` | Pins the tenant on a route **before** login. |
| `RequireTenant(resolve)` | Checks that the token `tid` equals the route tenant. Anything else is a 401. |
| `RequireEntitlement(store, capability, resolve)` | Gate for paid features. |
| `RequireFreshAuth(maxAge, acrValues)` | Step-up: requires a recent authentication and an accepted ACR. |
| `RequireDecision(DecisionGate)` | PDP gate: visibility check (404), then tier check (403). The gate has its own `Tenant` resolver (required) and an `AllowEntered` flag; the token must be for that tenant. |
| `RequireServiceAccount(validator)` | Machine credentials. The tenant comes from the token. |
| `Throttled(throttle, key)` | Rate limit per address, per tenant, or per service account. |
| `Auditor.For` / `Auditor.Mutation` | Writes an audit event after a 2xx response. |
| `StartLogin(resolver, email)` | Home-realm discovery with throttling and a minimum response time. |
| `StartOIDCFlow`, `VerifyOIDCCallback`, `StartOAuth2Flow`, `VerifyOAuth2Callback` | The federation core. It can be used without `Routes`. |

## 3. What the application must supply

```
identity.Store            users, refresh sessions, TOTP, identities   (required)
identity.InvitationStore  invitations                                 (optional)
espresso.IdentityService  adapter over identity.Core: Me + TOTP pending
tenant.Store              tenant rows
tenant.DomainStore        verified domains
tenant.EntitlementStore   plan / purchased features
authz.BindingStore   or   authz.PermissionStore
oidc.ProviderStore, saml.ProviderStore
scim.UserStore, scim.GroupStore, espresso.ServiceAccountValidator
resolve func(*http.Request) string   how to read the tenant from the route
```

## 4. Knowledge flow

The route paths in the diagrams are examples only. Route shape belongs to the
application. Tamper supplies the handlers and the middleware.

### 4.1 Boot

```
Config ─> tamper.New
           ├─ validation (no allocation)
           ├─ crypto.NewKeySet(KEKs)          ─> Provider.KeySet
           ├─ crypto.NewJWTService(JWT)       ─> Provider.JWT
           ├─ audit.NewSQLiteLogger | Noop    ─> Provider.Audit
           ├─ Config.Authz (built by the app) ─> Provider.Authz
           ├─ identity.New(Store, JWT, KeySet)─> Provider.Identity
           ├─ oidc.NewManager(Store, KeySet)  ─> Provider.OIDC
           └─ saml.NewManager(Store, KeySet)  ─> Provider.SAML

Provider + RouteConfig ─> espresso.Routes ─> Surfaces{Auth, Federation, SAML,
                                              SCIM, Auditor, RequireAuth, …}
the application mounts the Surfaces on its own Espresso router
```

`tamper.New` opens the audit DB but does not verify the chain. Chain
verification at boot (`audit.VerifyChainPostMigration`) is a call the
application must add. The logger always writes `canonical_version=4` (#46);
there is no option to turn on.

### 4.2 Register and password login

```
POST /login
  └─ PinTenant(route → tenant.ID)
      └─ AuthRoutes.Login ─> IdentityService.Login (application adapter)
          └─ identity.Core.Login(tenant, email, pw)
              ├─ NormaliseEmail
              ├─ allowLogin (throttle, BEFORE the store read)
              ├─ Store.UserByEmail(tenant, email)   miss ─> VerifyStub ─> ErrInvalidCredentials
              ├─ crypto.VerifyPassword
              ├─ TOTP needed? ─> ErrTOTPRequired ─> flow 4.3
              └─ issueTokens
                  ├─ JWT.IssueAccess(user, tenant, authTime, acr)  ─> access {sub, tid, auth_time, acr}
                  └─ Store.CreateRefreshSession{TenantID, AuthTime, ACR, TokenHash}
```

`Register` is the same, plus `Store.CountUsers(tenant)` → `firstUser` →
`Store.CreateUser(…, firstUser)` → the `OnRegistered` hook. The count is per
tenant: the first user of the second tenant still gets `firstUser=true`.

### 4.3 Second factor (TOTP)

```
Login ─> ErrTOTPRequired ─> IssueTOTPPending(user)          5-minute token, purpose=totp_pending
POST /totp/verify {session, code}
  └─ VerifyTOTPPending ─> Core.VerifyTOTP | VerifyRecoveryCode
       └─ KeySet.Open(envelope) ─> crypto.VerifyTOTPCode
  └─ IdentityService.IssueTokensForUser ─> access + refresh
```

The pending token is rejected as a normal bearer token, and an access token is
rejected at `/totp/verify`. The `purpose` claim separates the two in both
directions.

The pending token from `IssueTOTPPending` carries **no tenant**, and
`Core.VerifyTOTP` is not tenant-scoped. A pooled adapter must therefore use
the tenant-bound pair `IssueTOTPPendingInTenant` / `VerifyTOTPPendingInTenant`
and mint with `IssueTokensForUserInTenant`, which refuses a tenant that
differs from the user's stored tenant. These arrive with the fix for TD-10
(#40); see `tech-debt.md`.

### 4.4 Refresh and logout

```
POST /refresh (cookie)
  └─ Core.Refresh
      ├─ HashRefreshToken ─> Store.RefreshSessionByHash
      ├─ revoked / expired ─> ErrInvalidSession
      ├─ Store.UserByID ─> inactive ─> revoke the session ─> ErrUserInactive
      ├─ Store.RevokeRefreshSession(old)
      └─ issueTokens(user, session.TenantID, session.AuthTime, session.ACR)
```

Rotation never moves `auth_time` forward and never changes the tenant.

### 4.4a Entering another tenant (platform admin)

```
POST /t/platform/auth/enter/acme        (application route, home token)
  ├─ RequireAuth ─> RequireTenant(platform)
  └─ Core.EnterTenant(claims, acme)
      ├─ claims are an entered token ───────────┐
      ├─ Store.UserByID ─> missing ─────────────┤
      ├─ claims.tid is not the stored tenant ───┤─> ErrNotFound (one error)
      ├─ single tenant, or acme is home ────────┤
      ├─ MembershipStore.IsMember ─> false ─────┘
      │                           ─> error ─> error (never a yes)
      ├─ inactive ─> ErrUserInactive
      ├─ IssueAccessEntered ─> access {sub, tid=acme, htid=platform}
      │                        auth_time and acr copied from the claims
      │                        no refresh token, no session row
      └─ Hooks.OnTenantEntered(user, acme)
```

The entered token is for `acme` only, and only on routes that invite guests:

```
RequireTenant(acme)               ─> refuses an entered token (401, same body
                                     as a wrong-tenant token)
RequireTenantAllowEntered(acme)   ─> accepts it; EnteredFromContext = platform
```

When the token expires the client calls the enter route again, and the
membership is checked again. In the audit log, a row written while entered has
`Event.TenantID = acme` and `Actor.TenantID = platform`.

### 4.5 Federated login (OIDC / SAML / social)

```
email ─> StartLogin ─> tenant.ResolveDomain ─> DomainRecord{TenantID, ProviderID}
          (unknown domain, unverified domain, public domain, suspended tenant:
           all give the same answer)

GET /oidc/start/{provider}
  └─ PinTenant ─> FederationRoutes.Start
      ├─ Manager.GetRegistry(tenant) ─> Provider
      └─ StartOIDCFlow ─> PKCE + nonce + signed state cookie ─> redirect to the IdP

GET /oidc/callback/{provider}
  └─ PinTenant ─> FederationRoutes.Callback
      └─ redirect to the SPA, code + state in the URL fragment

POST /oidc/exchange {code, state, provider}
  └─ PinTenant ─> FederationRoutes.Exchange
      ├─ VerifyOIDCCallback ─> check state cookie, exchange code, VerifyIDToken ─> OIDCVerified
      └─ FederationHooks.OnFederatedExchange   (owned by the app; returns FederationOutcome)
          ├─ Core.ResolveByIdentity(tenant, provider, subject)       already linked
          ├─ Core.ProvisionUserWithIdentity(tenant, email, …)        JIT, firstUser per tenant
          └─ Core.IssueTokensForUserInTenant(user, tenant, authTime, acr)
```

`PinTenant` is needed on **all three** routes, not only on start. `Start`,
`Callback`, and `Exchange` all look up the provider through
`TenantFromContext`. Without a pinned tenant they return 404
(`OIDC_PROVIDER_NOT_FOUND`).

Tamper owns the verification part. Everything after verification (resolve,
provision, the email-collision check, minting tokens) happens inside the
application's hook.

SAML has the same shape: `SAMLRoutes.Login` → IdP → `SAMLRoutes.ACS`, with a
defence against assertion replay. The SAML routes (`Login`, `ACS`, `Metadata`)
need `PinTenant` for the same reason.

### 4.6 Invitations

```
tenant admin ─> Core.Invite(tenant, email, invitedBy, ttl)
                 └─ random token ─> InvitationStore.CreateInvitation{TokenHash}
                 └─ the plaintext is returned once (the app sends the email)
invitee ─> Core.AcceptInvitation(tenant, token, password)
            ├─ InvitationStore.InvitationByHash   (not tenant-scoped: the key is a 256-bit secret)
            ├─ wrong tenant, expired, already used ─> one error: ErrInvitationInvalid
            └─ create the user with the email FROM the invitation ─> issueTokens
```

### 4.7 Authenticated request

```
Authorization: Bearer <access>
  │
  ├─ RequireAuth          ParseAccess: signature, exp, iss, purpose, sub
  │                        ─> context: userID, AccessClaims, audit.Actor{user}
  ├─ RequireTenant        claims.tid == resolve(request) ? continue : 401
  │                        ─> context: tenant.ID
  ├─ RequireEntitlement   EntitlementStore.ForTenant(tenant) ─> feature bought? : 403 FEATURE_NOT_ENABLED
  ├─ RequireFreshAuth     auth_time recent enough and acr accepted? : 401 STEP_UP_REQUIRED
  ├─ RequireDecision      authz.Check(routed tenant, Subject{token's home tenant, user},
  │                                    action, Resource{type, id from path})
  │                        ├─ visibility check fails ─> 404 (a deny and a miss look the same)
  │                        └─ tier check fails       ─> 403
  ├─ application handler
  └─ Auditor.For          after 2xx ─> audit.Logger.Log(Event)
```

The application chooses this order. Tamper does not force it.

Two middlewares put a tenant in the context, and they give different
guarantees:

- `RequireTenant` sets it **after** checking the token `tid` against the
  route.
- `PinTenant` sets it with **no** token check. It is for routes before login.

So `TenantFromContext` returning `ok=true` does not prove that the token was
checked. On an authenticated route, only `RequireTenant` gives that guarantee.
If `PinTenant` is mounted globally, authenticated routes still need
`RequireTenant`. With neither middleware, a handler gets `(zero, false)`.

(The comment at `espresso/tenantgate.go:31` still says this gate is the only
one that sets the tenant. That comment was written before `PinTenant`
existed.)

### 4.8 Authorization decision

```
authz.Check(scope, sub, act, res)
  scope unset, or sub.Tenant unset ─> ErrTenantRequired (callers deny)

RBAC
  Policy[act] = [Requirement{Type, Min}, …]          (OR)
  for each requirement:
    Type == res.Type ─> BindingStore.BindingsFor(scope, sub, res)               binding on the instance
    Type != res.Type ─> BindingStore.BindingsFor(scope, sub, Resource{Type,""}) global alternative
    drop bindings of another scope or another subject
    rank(highest role) >= rank(Min) ─> ALLOW
  nothing satisfied, or unknown action ─> DENY

PermissionSet
  PermissionStore.PermissionsFor(scope, sub, res) ─> {Keys, Superuser}
  Superuser ─> ALLOW ; act ∈ Keys ─> ALLOW ; otherwise DENY
```

Two tenants are in every question. `scope` is whose resources these are.
`sub.Tenant` is where the subject is stored. They are the same for a tenant's
own user and different for a guest:

```
acme's user in acme          scope=acme  sub={acme, user, u-1}
platform admin entered acme  scope=acme  sub={platform, user, a-9}   needs a binding in acme
single-tenant deployment     scope=""    sub={"", user, u-1}         (tenant.Single)
```

### 4.9 SCIM (machine to machine)

```
Bearer <service account token>
  ├─ RequireServiceAccount ─> Validator.Validate ─> Principal{ID, TenantID}
  │                            ─> audit.ActorService(id, name, tenant)
  ├─ RequireEntitlement(store, CapabilitySCIM, resolver)
  ├─ Throttled(ThrottleKeyByServiceAccount)
  └─ SCIMRoutes
      ├─ SCIMConfig.Tenancy = true  ─> TenantScopedUserStore / TenantScopedGroupStore
      │                                 (…InTenant methods, tenant from the Principal)
      └─ SCIMConfig.Tenancy = false ─> UserStore / GroupStore (no tenant filter)
```

Three things to know:

- **`SCIMConfig.Tenancy` is `false` by default.** With the default, the routes
  call the unscoped store methods. A pooled deployment must set it to `true`.
  With the fix for TD-15 (#39), a principal that carries a tenant is refused
  with a 500 while the flag is off, so a forgotten flag no longer leaks. A
  deployment whose unscoped stores are already confined to one tenant sets
  `SCIMConfig.TenantBoundStores` instead. See `tech-debt.md`.
- When tenancy is on, the SCIM tenant always comes from the validated token.
  It never comes from the URL path or a header.
- The routes pass the raw filter string and the PATCH operations to the store.
  The store implementation is the one that calls `scim.Parse`,
  `scim.Translate`, and `scim.Apply`.

The entitlement resolver needs a small wrapper. `RequireEntitlement` wants
`func(*http.Request) (tenant.ID, bool)`, but `TenantFromServiceAccount` returns
`(string, bool)`. No code in the repository wires these two together yet.

### 4.10 Audit

```
write     Log(Event) ─> BEGIN IMMEDIATE ─> read the last hash ─> canonical payload (v4)
                     ─> hash = sha256(prev ‖ payload) ─> INSERT ─> COMMIT
verify    Verify / VerifyChainPostMigration ─> walk every row ─> index of the first bad row
export    ExportForTenant(tenant) ─> rows where Event.TenantID == tenant
                                     {is_chain:false, completeness:"issuer-attested"}
erase PII RedactEvent(id) ─> the row salt is set to zero; commitments stay, the hash stays valid
retention PruneOlderThan(cutoff)
```

An event has two tenant fields with different meanings. `Event.TenantID` is the
scope of the row (whose log it belongs to). `Actor.TenantID` is the tenant the
actor comes from. The export filters on the first one.

## 5. Rules that shape the flows

### Standing rules

These five come from `CLAUDE.md` and `PHASE7-MULTITENANCY-SKETCH.md` §6. The
numbers match those documents.

1. `tenant.Single` behaves byte-for-byte the same as before tenancy existed.
2. A tenant that is missing, empty, or different means deny.
3. A cross-tenant miss is a 404, never a 403.
4. A tenancy misconfiguration fails at `New`, not as a per-request denial.
5. Tamper names no table.

### Patterns seen in the code

These are observations from reading the code. They are not numbered rules in
the design documents.

- **Tenant-scoped port methods take the tenant as an explicit argument.**
  `tenant.WithTenant` documents why: a tenant read from the context fails open
  when one middleware call is missing. This holds for `identity.Store`,
  `oidc.ProviderStore`, `saml.ProviderStore`, and `tenant.EntitlementStore`.
  It does **not** hold everywhere: the `authz` ports and
  `espresso.IdentityService` take no tenant at all, and lookups by id or by
  token hash (`UserByID`, `RefreshSessionByHash`) are not tenant-scoped.
- **Refresh rotation copies the tenant, `auth_time`, and `acr` unchanged.**
