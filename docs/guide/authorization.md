# Authorization

tamper gives you a decision engine, not a policy. Which role may read which resource is
your mapping — but the engine that applies the mapping, and the reverse queries that let a
console ask "who can do this?", are here.

## Subject, Resource, Action

```go ignore
type Subject struct {
    UserID   string
    TenantID tenant.ID   // the subject's HOME tenant
    // roles/bindings as your store represents them
}

type Resource struct {
    Type string
    ID   string
}

type Action string
```

The **subject carries its home tenant**, which is what makes a guest in another tenant
answerable: a permission is looked up in the tenant being acted on, and an entered session
needs a binding *there*.

## One interface, two engines

```go ignore
type Authorizer interface {
    Check(ctx context.Context, req CheckRequest) (Decision, error)
    // reverse queries: who can do this, and what can this subject do
}
```

| Engine | Shape | When it fits |
|---|---|---|
| `authz.NewRBAC(bindingStore, hierarchy, policy)` | Ranked roles over materialized bindings | The usual console-shaped app: roles with an order, bindings per tenant |
| `authz.NewPermissionSet(permissionStore)` | Set membership, exact keys | When roles are not downward-closed and "higher role implies lower" is wrong |

The two are made to decide **identically** by a converter, and the repository carries a
parity test (a full matrix over subjects, actions and resources) that fails if either
engine drifts. If you switch engines, your decisions do not change.

## Deny by default

Every path that cannot answer confidently denies:

- A missing or zero tenant on the request → `ErrTenantRequired`, denied.
- A store error → denied. Never "allow because we could not check".
- An unknown action → denied, and the engines agree on it.

## The transport gate

```go ignore
// visibility first (404), then the tier check (403).
mux.Handle("/api/projects/", espresso.RequireDecision(gate)(projectsHandler))
```

`RequireDecision` is the only gate that answers **403**, and it does so after the
visibility check has already turned a cross-tenant miss into a 404. That ordering is the
reason a 403 here does not leak existence.

## Reverse queries

A console usually needs the other direction:

- "Which users may administer tenant X?" — so a page can render without asking per row.
- "What may this subject do here?" — so a UI can hide what will be refused.

Both come from the same store the forward check reads, so they cannot disagree with what
`Check` would decide.

## Background jobs and service accounts

Machine credentials do not go through the subject path. They authenticate with their own
gate, and the tenant comes from the validated credential:

```go ignore
// A tenant credential: acts inside Principal.TenantID, nowhere else.
mux.Handle("/scim/v2/", espresso.RequireServiceAccount(validator)(scimHandler))

// A platform credential: valid only on platform routes, no home tenant.
// The two gates are mutually exclusive, and both refuse with the same 401 as a bad token.
mux.Handle("/platform/", espresso.RequirePlatformServiceAccount(validator)(platformHandler))
```

A credential's authority is one of two kinds, never both — see
[SCIM](./scim) for the surface that motivated the split.
