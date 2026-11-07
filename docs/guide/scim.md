# Provisioning: SCIM

`scim` is a SCIM 2.0 substrate — a filter engine, an RFC 7644 §3.5.2 PATCH applier, DTOs,
and group-cycle detection — over store ports you implement. `espresso` mounts it as a route
surface behind a machine-credential gate.

## The tenant comes from the credential, never from the URL

This is the rule the whole surface is built around:

```go
// Authenticate the machine credential. The tenant it vouches for is the only
// tenant this request will ever touch.
mux.Handle("/scim/v2/", espresso.RequireServiceAccount(validator)(scimRoutes))
```

A path-derived tenant is a horizontal-privilege-escalation bug with extra steps: the caller
is authenticated, so the request looks legitimate in every log, and it reads every other
customer's directory by editing one URL segment. So the store call always receives the
tenant from the validated credential:

```go
// One helper per store method the transport calls, so the place the tenant is handed
// to a store exists exactly once per call site.
func (s *SCIMRoutes) userGet(ctx context.Context, id string) (scim.UserRecord, error) {
    return s.users.Get(ctx, scimTenant(ctx), id)
}
```

If a handler is mounted outside the gate, `scimTenant` panics with a message saying so —
and it does the same if a platform credential somehow reaches it, because a platform
credential has no tenant to scope a store call with.

## Two kinds of machine credential

| Gate | Accepted credential |
|---|---|
| `RequireServiceAccount` | `Scope` unset — a tenant credential, acting inside `Principal.TenantID` |
| `RequirePlatformServiceAccount` | `Scope: platform` — valid only on platform routes, no home tenant |

They are **mutually exclusive**, and both refuse the wrong kind with the same 401 as a bad
token, so a probe cannot learn that its scope rather than its secret was the problem. An
unknown scope satisfies neither. That is how cross-tenant automation (tenant provisioning,
directory sync) gets a principal without inventing a credential that can read everything.

## What you implement

```go
type UserStore interface {
    Create(ctx context.Context, tenantID tenant.ID, u UserWrite, meta WriteMeta) (UserRecord, error)
    Get(ctx context.Context, tenantID tenant.ID, id string) (UserRecord, error)
    ListFiltered(ctx context.Context, tenantID tenant.ID, filter Filter, page Page) (ListResult, error)
    // …
}
```

Every method takes the tenant. `ListFiltered` is the only list: an unfiltered list is the
same call with an empty filter, so there is no second code path to keep in sync.

## What the substrate does for you

- **Filtering**: SCIM filter parsing and evaluation, so `userName eq "x" and active eq true"`
  is not your parser to write.
- **PATCH**: the RFC 7644 operations (`add`, `remove`, `replace`) with the path semantics,
  including the `active` toggle that SCIM clients actually send.
- **Groups**: membership, with **cycle detection** so a client cannot build a group that
  contains itself.
- **Errors**: the SCIM 2.0 error envelope (RFC 7644 §3.12) on every failure path, because
  SCIM clients fail closed on app-branded envelopes.

## Auditing provisioning

Every mutation is attributed to the service account, not "some user":

```go
// The gate stashes an audit actor, so the event says which machine did it.
ctx = audit.WithActor(ctx, audit.ActorService(saID, saName, tenantID))
```

A platform credential's actor carries an empty home tenant — it has no tenant of its own —
while the row's scope is the tenant the resource belongs to. That keeps "who" and "which
customer" answerable separately, which is exactly what you want to read during an incident.

## Try it

[`examples/scim`](https://github.com/suryakencana007/tamper/tree/main/examples/scim) is a
runnable SCIM server with an in-memory store, including the gate ordering
(`RequireServiceAccount` outermost, the rate limiter outside it).
