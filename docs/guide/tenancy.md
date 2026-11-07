# Tenancy

The tenant is not an argument you remember to pass. It is a type, and its zero value
denies.

## `tenant.ID`

```go
id := tenant.New("acme")     // a real tenant
id.Valid()                   // true
id.IsSingle()                // false

var unset tenant.ID          // the zero value — this is NOT "acme" and NOT "single"
unset.Valid()                // false — every gate denies
unset.IsSingle()             // false — unset is not single-tenant, it is unset

tenant.Single                // the explicit single-tenant value: "" said deliberately
tenant.Single.IsSingle()     // true
```

`New("")` is invalid on purpose. An empty string arriving from a `tid` claim, a routing
header or a config lookup means *the lookup produced nothing*, and that must deny rather
than quietly select the single-tenant bucket. A deployment that means `""` writes
`tenant.Single`.

That one distinction closes the whole class of "the tenant was not set, so it fell back to
the first row" bugs.

## Ports, not tables

```go
type Store interface {
    Create(ctx context.Context, d Descriptor) (Descriptor, error)
    Get(ctx context.Context, id ID) (Descriptor, error)
    // …
}

type Resolver interface {
    TenantFromRequest(r *http.Request) (ID, bool)
}
```

Your app owns the schema; tamper owns the vocabulary. A `Resolver` that answers
`(ID, false)` is a miss, and a miss denies.

## Mounting one surface for many tenants

A runtime-created tenant must not need a restart. `espresso` mounts the auth surfaces once
and can fill a tenant segment from the tenant the request resolved to:

```go
// /t/{tenant}/auth: one surface, every tenant, present and future.
s.MountPrefix(mux, "/t/{tenant}/auth")
```

The path the cookie is written under is derived from the *same* resolved tenant as the
session it carries, at both set and clear — attribute parity is what makes a deletion
actually delete. If a template meets an unset or `tenant.Single` id, tamper writes no
cookie and answers `NOT_FOUND`, rather than handing out an access token that can never be
renewed.

The [`examples/multitenant`](https://github.com/suryakencana007/tamper/tree/main/examples/multitenant)
program is the proving ground for this, including `TestOneBrowserHoldsASessionPerTenant`.

## Gates on the request path

| Middleware | What it enforces |
|---|---|
| `PinTenant(resolve)` | Pins the tenant **before** login; 404 when none resolves |
| `RequireTenant(resolve)` | The token's `tid` must equal the resolved tenant; anything else is 401 |
| `RequireTenantAllowEntered` / `…AllowImpersonated` / `…AllowEnteredOrImpersonated` | The opt-in forms: an entered (guest) session needs a binding in the tenant entered, an impersonated one needs the explicit allowance |
| `RequireEntitlement(store, capability, resolve)` | The plan gate — is this feature bought by this tenant? 403 when not |
| `RequireActiveTenant(…)` | The lifecycle gate — is this tenant suspended or closed? |

## Entering another tenant

An operator with a home session can *enter* a tenant they are not homed in. The entered
token names both: `tid` is the tenant entered, `htid` is the home tenant. Authorization for
the entered tenant is a binding in that tenant — the subject carries its home tenant, so a
guest without a binding is refused even though the entry succeeded.

Entered tokens have their own TTL and are **not** revoked by
`RevokeAllSessionsForTenant`, because they have no session row. Keep the TTL short.

## Hierarchy and inheritance

Tenants can have parents (`tenant.Ancestors` walks the chain, nearest first, with a depth
cap and a defence against a self-parented row). Two things flow down it, and one does not:

- **Plans and entitlements** inherit: a child that has not bought a plan uses its
  nearest ancestor's (`tenant.InheritingEntitlements`).
- **IdP configuration** inherits: a child with no OIDC/SAML providers of its own uses its
  ancestor's ([Federation](./federation)).
- **Authorization does not inherit.** Bindings are materialized per tenant — a permission
  held in a parent does not silently grant it in a child. This is deliberate, and it is
  recorded in [ADR-0001](../adrs/ADR-0001-tenant-hierarchy-platform-tenantgroup-org).

The [`examples/tenanthierarchy`](https://github.com/suryakencana007/tamper/tree/main/examples/tenanthierarchy)
program demonstrates the whole walk, including reconciliation when a parent's plan changes.
