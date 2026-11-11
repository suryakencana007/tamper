# Install and run

## Requirements

- Go 1.21 or newer (the module targets the standard library plus a small dependency set:
  `golang-jwt`, `crewjam/saml`, `pquerna/otp`, `modernc.org/sqlite` for the audit chain).
- Nothing else. There is no code generation step, no protobuf, no build tag dance.

## Install

```sh
go get github.com/suryakencana007/tamper@v0.14.0
```

The latest version is always named at the top of the [changelog](../changelog). Pin it:
tamper follows semantic versioning, and every breaking release ships a migration guide.

## Run the quickstart

The [`examples/quickstart`](https://github.com/suryakencana007/tamper/tree/main/examples/quickstart)
program is a working single-tenant deployment in one `main.go`: register, log in, call a
protected route, enrol TOTP, refresh.

```sh
git clone https://github.com/suryakencana007/tamper
cd tamper/examples/quickstart
go run .
```

Then, in another shell:

```sh
# Register the first user (the firstUser signal is per tenant, not per deployment).
curl -sX POST localhost:8080/api/auth/register \
  -H 'content-type: application/json' \
  -d '{"email":"you@example.test","password":"correct horse battery staple"}'

# Log in and keep the cookie jar.
curl -s -c /tmp/jar -X POST localhost:8080/api/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"you@example.test","password":"correct horse battery staple"}'

# A protected route.
curl -s -b /tmp/jar localhost:8080/api/me
```

## The next step: multi-tenant

Once the single-tenant shape is clear, read [Tenancy](./tenancy) and then run the
[`examples/multitenant`](https://github.com/suryakencana007/tamper/tree/main/examples/multitenant)
program. That is the example that proves the tenant path: one session per tenant in a single
browser jar, no restart when a tenant is created at runtime.

## Wiring your own application

You implement ports; tamper implements the engines. The three you will meet first:

| Port | What your app decides |
|---|---|
| `tenant.Store` / `tenant.Resolver` | How a tenant is stored and found for a request (host, path, claim) |
| `identity.Store` | Users, credentials, sessions, TOTP secrets, identity links |
| `audit.Sink`/logger | Where audit events go (the SQLite chain, or your own store) |

```go ignore
type Store interface {
    CreateUser(ctx context.Context, tenantID tenant.ID, email string, hash []byte) (User, error)
    FindUserByEmail(ctx context.Context, tenantID tenant.ID, email string) (User, error)
    // …
}
```

Every method takes the tenant. That is not decoration: it is the only place the tenant of a
request is allowed to enter a query, and it always comes from a resolved value rather than
from the URL.

## Where the tenant comes from

In order of precedence, and this order is the security model:

1. **A validated credential** — for a service account, `Principal.TenantID` is what the
   validator vouched for. Never a path or a header.
2. **A signed token claim** — `tid` on an access token, checked against what the request
   resolved.
3. **A resolver** — host, subdomain, path segment, or a header, depending on your
   `tenant.Resolver`. This decides *routing*, and the token still has to agree.

If none of those produce a tenant, the request is a 401 or a 404 — never "the default
tenant".

---

Looking a name up? The [API reference](../api/) lists every exported package.
