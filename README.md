# Tamper

An embeddable, Go-native enterprise **auth / authz / tamper-evident-audit**
framework. Tamper was extracted from Barista — a self-hosted PaaS that is its
flagship and proving ground — mirroring the Espresso ← Barista relationship.

Tamper is a **library, not a server**: you compose its engines into your own
single binary and mount its routes on your own Espresso router. Every engine is
decoupled behind a port interface your app implements — Tamper never names a
table, owns a cookie brand, or freezes your audit vocabulary.

> **Status: v0.4.0 — pooled multi-tenancy.** One process, N tenants, deny by
> default. v0.4.0 is Phase 7's single deliberate breaking release: the tenant
> became a type (`tenant.ID`) and entered the base ports. Coming from v0.2.x?
> Step through **v0.3.0** (drop-in, zero code changes) and then follow
> [`MIGRATION-v0.4.md`](./MIGRATION-v0.4.md) — for a single-tenant deployment
> the whole upgrade is mechanical.

## Install

```sh
go get github.com/suryakencana007/tamper@v0.4.0
```

## What's shipped

| Subpackage | What it is |
|---|---|
| `crypto` | JWT issue/verify, bcrypt passwords, refresh-token hashing, TOTP, and the KEK keyset + secretbox envelope that seals at-rest secrets |
| `audit` | tamper-evident hash-chain logging (per-row canonical-version dispatch, boot-time verify, per-tenant export, GDPR-style commitment redaction) over an internal SQLite persistence layer |
| `authz` | the `Authorizer` PDP (`Check` + reverse queries) over two interchangeable engines — the rank `RBAC` and the set-based `PermissionSet` — plus a converter that makes them decide identically |
| `tenant` | the tenancy vocabulary: `tenant.ID` (zero value denies), `Descriptor` + `Store`/`Resolver` ports, home-realm domain discovery, per-tenant entitlements |
| `identity` | credentials + session core (register / login / refresh / logout, TOTP enrollment, multi-IdP linking) behind one `identity.Store` port |
| `oidc` / `saml` | OIDC relying-party + SAML service-provider substrates and store-backed provider managers with KEK-sealed secrets |
| `scim` | SCIM 2.0 substrate — filter engine, RFC 7644 PATCH applier, group-cycle detection — over app-supplied ports |
| `espresso` | the first-class transport adapter: mountable auth / OIDC / SAML / SCIM route surfaces + `RequireAuth` / `RequireServiceAccount` / `RequireDecision` / `RequireFreshAuth` / `PinTenant` / `RequireTenant` middleware |

The framework roadmap, extraction playbook, and design rationale live in
[`TAMPER-DESIGN.md`](./TAMPER-DESIGN.md).

## Getting started

Two additive layers compose the whole surface. A complete, runnable version of
the snippets below — driven end-to-end by a test — is in
[`examples/quickstart`](./examples/quickstart):

```sh
go run ./examples/quickstart      # serves the auth API on :8080
```

### 1. Build the engines — `tamper.New`

`New` bundles the engine constructors into one validated `Provider`, rooted at
the JWT service + KEK keyset. Misconfiguration fails here at boot, never as a
per-request denial. Everything except `JWT` is optional; a nil field means "not
configured".

```go
provider, err := tamper.New(tamper.Config{
	JWT: crypto.JWTConfig{Secret: cfg.Secret, TTL: 15 * time.Minute, Issuer: "myapp"},

	// Optional: seal at-rest secrets (TOTP envelopes, OIDC/SAML client secrets).
	KEKs: []crypto.KEKEntry{{ID: 1, Key: cfg.KEKHex}},

	// Optional: a non-empty DBPath opens the SQLite hash-chain audit log
	// (empty => a no-op logger). provider.Audit is always non-nil.
	Audit: tamper.AuditConfig{DBPath: "audit.db"},

	// Optional: build the identity Core over your own persistent Store.
	Identity: &tamper.IdentityConfig{
		Store:   myStore, // implements identity.Store
		Options: []identity.Option{identity.WithRefreshTTL(30 * 24 * time.Hour)},
	},

	// Optional: your built policy-decision point (see tamper.RBAC / tamper.PermissionSet).
	Authz: pdp,
})
if err != nil {
	return err
}
defer provider.Close() // releases the audit DB handle
```

### 2. Aggregate the HTTP surface — `tamper/espresso.Routes`

`Routes` constructs the route surfaces + middleware from the `Provider`,
auto-wiring the OIDC/SAML registry hooks and binding `RequireAuth` to the JWT
service. It returns the surfaces for **you** to register — there is no `Mount`,
because each surface spans both public and authenticated route blocks and your
app owns its paths (see `PHASE4D-BOUNDARY-DECISION.md` §A10).

```go
surfaces, err := tamperespresso.Routes(provider, tamperespresso.RouteConfig{
	Auth: tamperespresso.AuthRoutesConfig{
		MountPrefix: "/api/auth",
		Cookies:     tamperespresso.CookieConfig{Name: "myapp_refresh"},
		ProjectUser: projectUser, // renders YOUR user DTO into the response
	},
	// Identity is REQUIRED and app-supplied: identity.Core does not satisfy the
	// IdentityService port on its own (it has no Me lookup and no session-token
	// TOTP ceremony — that token is app policy), so you wrap it. The quickstart
	// shows a ~90-line coreIdentity adapter.
	Identity: myIdentityService,
})
if err != nil {
	return err
}
```

### 3. Register the surfaces on your Espresso router

```go
auth := surfaces.Auth
readCookie := auth.ReadRefreshCookie()

r := espresso.Portafilter()
r.Post("/api/auth/register", espresso.Doppio(auth.Register))          // public
r.Post("/api/auth/login", espresso.Doppio(auth.Login))               // public
r.Get("/api/auth/me", surfaces.RequireAuth(espresso.HandlerCtx(auth.Me)))
r.Post("/api/auth/refresh", readCookie(espresso.HandlerCtx(auth.Refresh)))
r.Post("/api/auth/logout", readCookie(espresso.HandlerCtx(auth.Logout)))

// Serve with graceful shutdown; OnShutdown closes the Provider.
r.OnShutdown(func(context.Context) error { return provider.Close() })
ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
defer stop()
return r.BrewContext(ctx, espresso.WithAddr(":8080"))
```

`surfaces` also carries `Federation` (OIDC), `SAML`, and `SCIM` route surfaces
(non-nil only when you configure them and the matching engine is present on the
`Provider`), plus the `RequireServiceAccount` middleware for the SCIM surface.

## OIDC single sign-on — integrating with Keycloak

[`examples/federation`](./examples/federation) is a runnable, end-to-end OIDC
SSO example. It stands up an **embedded fake IdP** so it runs with zero external
dependencies, and its test drives the full authorization-code flow
(`start → IdP → callback → exchange`), JIT-provisioning the federated user via
the identity core and minting a session:

```sh
go run  ./examples/federation      # boots the SSO server on :8080
go test ./examples/federation/...  # drives + verifies the whole flow
```

**The tamper wiring is identical for a real IdP — only the issuer URL and
client credentials change.** To point it at a real Keycloak instead of the fake
IdP:

1. In Keycloak, create a realm + a **confidential** OpenID Connect client, and
   add a valid redirect URI of `<app-base>/api/auth/oidc/callback/<provider-id>`.
2. Seed the provider with your realm's values (the example hardcodes the fake
   IdP's; swap them):

   ```go
   provider.OIDC.Create(ctx, oidc.ProviderDefinition{
       ID:           "keycloak",
       IssuerURL:    "https://keycloak.example.com/realms/myrealm", // the realm's issuer
       ClientID:     "myapp",
       ClientSecret: os.Getenv("KEYCLOAK_CLIENT_SECRET"),           // sealed by the KeySet at rest
       DisplayName:  "Keycloak",
       Enabled:      true,
       Scopes:       []string{"openid", "profile", "email"},
       GroupsClaim:  "groups", // optional — map Keycloak group membership
   })
   ```

That's the whole change — the routes, the `OnFederatedExchange` hook, and the
state-cookie handling are unchanged. The engine runs OIDC discovery against
`IssuerURL`, so the realm's `/.well-known/openid-configuration` must be
reachable from the server. Barista (tamper's flagship) drives exactly this
setup in production — see its `scripts/provision-keycloak.ps1` and
`deploy/helm/barista/INSTALL.md` for a concrete Keycloak-on-Kubernetes wiring.

SAML SSO follows the same shape via the `SAML` engine + `SAML` route bundle.

## Multi-tenancy — one process, many tenants

Since v0.4.0 every tenant-touching call names its tenant as a **`tenant.ID`**
— a type whose zero value is invalid, so "I am single-tenant" and "I forgot
to pass the tenant" are different values and only the second one denies:

```go
tenant.Single         // "this deployment has one tenant" — said on purpose
tenant.New("acme")    // a real tenant from untrusted input (claims, headers, paths)
tenant.FromStored(s)  // a value read back out of your own database ("" == Single)
tenant.ID{}           // forgot? -> ErrTenantRequired. Nothing leaks.
```

The underlying identifier stays an opaque, app-defined string — a UUID, a
slug, a `realm/sub-realm` path are all fine; Tamper never parses it. A
single-tenant deployment passes `tenant.Single` everywhere and pins it once
on the router:

```go
// Single-tenant: one line. Pooled: resolve from subdomain, path or header —
// this resolver is the only line that changes when you go pooled.
r.Use(tamperespresso.PinTenant(func(*http.Request) string { return "" }))
```

(`PinTenant` is for routes *before* login; `RequireTenant` additionally
cross-checks the authenticated token's `tid` against the routed tenant, so it
runs *inside* `RequireAuth`. Two names on purpose.)

`identity.Store`'s lookups take the tenant directly — an email is unique per
tenant rather than globally, `bob@acme.com` and `bob@globex.com` are separate
people, and the first-user bootstrap signal fires once per tenant instead of
once ever. A store that cannot scope by tenant **fails to compile**, which is
strictly earlier than the boot-time error it replaced.

**Implementing the store comes with a proof obligation.** Tamper cannot
enforce isolation — the query lives in your adapter — so it ships the
instrument that checks it. Run the conformance harness against your own store:

```go
func TestMyStoreIsolation(t *testing.T) {
    tenanttest.RunLeakSuite(t, func() identity.Store {
        return newMyStore(t) // fresh and empty on every call
    })
}
```

[`examples/multitenant`](./examples/multitenant) is the runnable proving
ground: two tenants over one store in one process, `bob@acme.com` and
`bob@globex.com` as separate people, and a test asserting that a token minted
for one tenant is refused on the other's route.

```sh
go run  ./examples/multitenant      # serves both tenants on :8080
go test ./examples/multitenant/...  # drives both tenants end to end
```

## What your app supplies

Tamper composes; your app provides the leaves:

- the `Store` implementations (identity / authz / oidc / saml / scim);
- the Espresso router and every route path (`Routes` returns surfaces, not a handler);
- the tenant resolver behind `PinTenant`/`RequireTenant` — subdomain, path
  segment or header; Tamper pins what you resolve and never guesses;
- policy hooks — `ProjectUser`, `OnFederatedExchange`, `SanitizeRedirect`, the `DecisionGate` deny-writers;
- audit **emission** at your port implementations (the transport threads the facts down; the port writes the row);
- an `IdentityService` adapter over `identity.Core` (see the quickstart).

## License

[MIT](./LICENSE) © 2026 Nanang Suryadi.
