# Tamper

An embeddable, Go-native enterprise **auth / authz / tamper-evident-audit**
framework. Tamper is extracted from [Barista](../../README.md) — Barista is its
flagship and proving ground, mirroring the Espresso ← Barista relationship.

Tamper is a **library, not a server**: you compose its engines into your own
single binary and mount its routes on your own Espresso router. Every engine is
decoupled behind a port interface your app implements — Tamper never names a
table, owns a cookie brand, or freezes your audit vocabulary.

> **Status: v0.1.0 — API not frozen.** Tamper currently ships from the Barista
> monorepo at the nested import path below. A move to a clean standalone path
> (`github.com/suryakencana007/tamper`) is planned; until then the nested path
> is the real one and this README says so.

## Install

```sh
go get github.com/suryakencana007/barista/packages/tamper@v0.1.0
```

## What's shipped

| Subpackage | What it is |
|---|---|
| `crypto` | JWT issue/verify, bcrypt passwords, refresh-token hashing, TOTP, and the KEK keyset + secretbox envelope that seals at-rest secrets |
| `audit` | tamper-evident hash-chain logging (per-row canonical-version dispatch, boot-time verify) + the `audit/sqlitestore` persistence layer |
| `authz` | the `Authorizer` PDP (`Check` + reverse queries) over two interchangeable engines — the rank `RBAC` and the set-based `PermissionSet` — plus a converter that makes them decide identically |
| `identity` | credentials + session core (register / login / refresh / logout, TOTP enrollment, multi-IdP linking) behind one `identity.Store` port |
| `oidc` / `saml` | OIDC relying-party + SAML service-provider substrates and store-backed provider managers with KEK-sealed secrets |
| `scim` | SCIM 2.0 substrate — filter engine, RFC 7644 PATCH applier, group-cycle detection — over app-supplied ports |
| `espresso` | the first-class transport adapter: mountable auth / OIDC / SAML / SCIM route surfaces + `RequireAuth` / `RequireServiceAccount` / `RequireDecision` / `RequireFreshAuth` middleware |

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
go run  ./packages/tamper/examples/federation      # boots the SSO server on :8080
go test ./packages/tamper/examples/federation/...  # drives + verifies the whole flow
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

## What your app supplies

Tamper composes; your app provides the leaves:

- the `Store` implementations (identity / authz / oidc / saml / scim);
- the Espresso router and every route path (`Routes` returns surfaces, not a handler);
- policy hooks — `ProjectUser`, `OnFederatedExchange`, `SanitizeRedirect`, the `DecisionGate` deny-writers;
- audit **emission** at your port implementations (the transport threads the facts down; the port writes the row);
- an `IdentityService` adapter over `identity.Core` (see the quickstart).

## License

See the repository root.
