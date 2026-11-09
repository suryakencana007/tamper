# What tamper is

tamper answers four questions, and keeps them apart on purpose:

| Question | Engine |
|---|---|
| **Which customer is this for?** | [`tenant`](./tenancy) |
| **Who is this, and how did they prove it?** | [`identity`](./identity), [`oidc`/`saml`](./federation) |
| **What may they do?** | [`authz`](./authorization) |
| **What did they do?** | [`audit`](./audit) |

Each engine is a package with ports. Your application implements the ports over its own
schema; tamper never names a table. `espresso` is the adapter that mounts HTTP surfaces and
enforces the answers on the request path.

## The three rules everything else follows

**1. Absent denies.** The zero value of `tenant.ID` is not "the default tenant" — it is
*unset*, and every gate that receives it denies. A single-tenant deployment says so
explicitly, with `tenant.Single`, which is a different value that happens to stringify to
`""`. This is why an empty `tid` claim, a missing header and a failed lookup all deny
rather than quietly selecting a bucket.

**2. A deny and a miss are indistinguishable.** Cross-tenant access answers **404**, never
403. A 403 confirms the resource exists and belongs to somebody else, which is a
cross-tenant existence oracle. The same discipline applies to credentials: a wrong scope
and a wrong secret produce byte-identical responses.

**3. Misconfiguration fails at construction, never per request.** A provider with no ACS
URL, a registry with no resolver, a policy that cannot be read — all of these fail at
`New`/`Build`, or deny closed on the request path. Nothing is "off by default" in a way
that only shows up in production.

## What tamper is not

- **Not a database.** Every store is a port. tamper ships in-memory implementations for
  tests and examples, and one SQLite-backed audit chain because an append-only hash chain
  needs its own transaction discipline to be correct.
- **Not an authorization policy.** It gives you a PDP and the vocabulary; which role may
  read which resource is your mapping.
- **Not your UI.** Sessions are cookies or tokens you set; the SPI shape of every response
  is yours.

## A first look

The whole point of the ports is that a small application is genuinely small. A single
tenant, password login, one protected route:

```go ignore
// 1. The engines. Every store is a port your app implements.
core, err := identity.New(store, jwtService)
if err != nil {
    return err
}

// 2. The transport surfaces, bound to the provider's engines. `svc` is your thin
//    adapter from identity.Core to the transport's IdentityService port (the port has
//    no notion of your session-token TOTP ceremony, so the adapter supplies it).
surfaces, err := espresso.Routes(provider, espresso.RouteConfig{
    Auth: espresso.AuthRoutesConfig{
        MountPrefix: "/api/auth",
        Tenant:      espresso.FixedTenant(tenant.Single), // explicit: single-tenant
        Cookies:     espresso.CookieConfig{Name: "app_refresh"},
        ProjectUser: projectUser,
    },
    Identity: svc,
})
if err != nil {
    return err
}

// 3. The app owns its paths and its public/authenticated split.
auth := surfaces.Auth
r.Post("/api/auth/login", espresso.Doppio(auth.Login))
r.Get("/api/auth/me", surfaces.RequireAuth(espresso.HandlerCtx(auth.Me)))
```

`Routes` returns the surfaces instead of mounting them: which paths exist, and which of them
are public, is application policy. The examples use tamper's own `espresso.Portafilter()`
router; the adapters (`Doppio`, `HandlerCtx`) are what make the surface usable from it.

Multi-tenancy is the same shape with a tenant resolver, and it is covered in
[Tenancy](./tenancy).

## Reading order

1. [Install and run](./installation) — get the quickstart example running.
2. [Tenancy](./tenancy) — the type everything else is scoped by.
3. [Authorization](./authorization) — `Check` and the reverse queries.
4. [Identity and factors](./identity) — sessions, TOTP, `acr` versus `amr`, step-up.
5. [Federation](./federation) — OIDC and SAML, per tenant.
6. [Provisioning](./scim) — SCIM 2.0 over your store.
7. [Audit](./audit) — the chain, queries, and redaction.
