# Phase 8b — the tenant contract for `authz`

Status: **design, decided 2026-10-05**. This sketch covers TD-03 from
`tech-debt.md`. It is the document to amend before changing the code it
describes. It follows `PHASE8-PLATFORM-ADMIN-SKETCH.md`.

## 1. The problem

`authz` did not know about tenants. `Subject` and `Resource` were `{Type, ID}`,
and no port took a `tenant.ID`. Three things followed:

- A store that forgot to filter by tenant compiled and passed every test.
- A user id is unique inside one tenant only. Two tenants can each have a user
  `u-1`, and a binding for one was a binding for the other.
- Since Phase 8 a platform admin can act inside a customer's tenant. The gate
  built the subject from the bare user id, so the roles the admin holds at
  home would have been checked against the customer's resources.

## 2. Decisions

Two were taken by the repo owner on 2026-10-05:

1. **The tenant is in the ports.** This is a breaking change, like the one
   v0.4.0 made to `identity.Store`. A store that ignores tenants does not
   compile.
2. **A guest needs a binding in the tenant entered.** The subject is
   (home tenant, type, id). Roles held at home never apply somewhere else.

## 3. The model

Every question has a **scope**: the tenant whose resources are being acted on.
Every subject has a **home tenant**: the tenant it is stored in.

```
Check(ctx, scope, subject, action, resource)

scope      tenant.ID                        whose resources
subject    Subject{Tenant, Type, ID}        who, and where they are from
binding    Binding{Tenant, Subject, Resource, Role}
           Tenant is the scope the binding lives in
```

| Who | Scope | Subject | What applies |
|---|---|---|---|
| acme's own user | acme | (acme, user, u-1) | bindings in acme for that subject |
| platform admin entered into acme | acme | (platform, user, a-9) | bindings in acme for that subject, and nothing else |
| the same admin at home | platform | (platform, user, a-9) | bindings in platform |
| single-tenant deployment | `tenant.Single` | (`tenant.Single`, user, u-1) | as before Phase 8b |

There is **no binding that spans tenants**. A "global" binding
(`Resource{Type, ""}`) is global inside its scope only. A platform admin who
must work in ten tenants has a binding in each. That is the cost of decision
2, and it is also what lets a customer list exactly who the guests are:
`ListSubjects` returns subjects with their home tenant.

## 4. API

```go
type Subject struct {
    Tenant tenant.ID   // home tenant; the zero value is refused
    Type   string
    ID     string
}

type Binding struct {
    Tenant   tenant.ID // scope
    Subject  Subject
    Resource Resource
    Role     Role
}

type Authorizer interface {
    Check(ctx, tenantID tenant.ID, sub Subject, act Action, res Resource) (Decision, error)
    CheckBulk(ctx, tenantID tenant.ID, reqs []CheckRequest) ([]Decision, error)
    ListResources(ctx, tenantID tenant.ID, sub Subject, act Action, resourceType string) ([]Resource, bool, error)
    ListSubjects(ctx, tenantID tenant.ID, act Action, res Resource) ([]Subject, bool, error)
}
```

`BindingStore` and `PermissionStore` take the same `tenantID` as their first
argument after `ctx`. `Resource` is unchanged: the scope says whose it is.

Rules, for both engines:

1. An unset scope, or a subject with an unset home tenant, is
   `ErrTenantRequired`. Callers treat an error as deny (standing rule 2). It
   is an error and not a quiet deny because it is a wiring bug.
2. The RBAC engine drops any binding whose `Tenant` is not the scope asked
   for, and any whose `Subject` is not exactly the subject asked for. A store
   that returns too much is held to the contract where the engine can see it.
3. The reference stores hold the same line, with the same `gate` the engines
   use. Every read and every write returns `ErrTenantRequired` for an unset
   scope or a subject with no home tenant, and a refused write stores
   nothing. Such a grant could never be read back, and a keyed literal
   written before these fields existed still compiles. `Grant`, `Revoke` and
   `GrantSuperuser` return the error; they do not panic, because the binding
   may come from a request. `NewMemStore` panics on a broken seed literal.
4. `CheckBulk` refuses an unset scope even for an empty batch.
   `ListSubjects` returns `ErrTenantRequired` when a subject that **would be
   listed** has no home tenant. It does not list that subject, and it does
   not drop it quietly either: `Check` refuses such a subject with an error,
   and an empty review would read as "nobody has access". A broken row that
   does not qualify for the action asked about is skipped; it is not that
   question's problem.
5. `tenant.Single` is a scope like any other. A single-tenant deployment
   passes it everywhere and gets the decisions it got before.

### `espresso.RequireDecision`

The gate carries its own tenant:

```go
type DecisionGate struct {
    Tenant       func(*http.Request) (tenant.ID, bool)  // required; the scope
    AllowEntered bool                        // let an entered platform admin through
    ...
    UserExists   func(ctx, home tenant.ID, userID string) (bool, error)
}
```

- `RequireDecision` panics when `Tenant` is nil. A gate that names no tenant
  is a tenancy misconfiguration, and it fails when the gate is built
  (standing rule 4).
- Scope: the tenant `Tenant` resolves. The resolver returns a `tenant.ID` and
  whether one was resolved, the shape `RequireEntitlement` takes.
  `(zero, false)` refuses the request. A single-tenant application returns
  `(tenant.Single, true)`. An empty answer is never turned into the single
  tenant: a route pattern with no tenant segment must not be served as a
  single-tenant route. Behind `RequireTenant`, pass `TenantFromRoutedContext`.
- The token must fit that tenant by the one rule `RequireTenant` applies
  (`tokenFitsTenant`): its `tid` is exactly the resolved tenant, and an
  entered token only where `AllowEntered` is set. Anything else is the 401
  `RequireTenant` writes. A user id that reached the context without a token
  is refused the same way.
- Subject tenant: the scope itself, or the token's `htid` when the token is
  an entered one. So an entered admin is (platform, …) in scope acme.
- On success the gate pins the tenant for `TenantFromContext`, for what runs
  **behind** it. Middleware mounted in front of it (`Auditor.For`,
  `RequireEntitlement`, `RequireFreshAuth`) does not see that tenant; a
  pooled route that uses them still puts `RequireTenant` first.
- `UserExists`, the ghost probe, is given the subject's home tenant. With the
  bare id it looked in the routed tenant, where a guest has no row, and
  reported every denied guest as a deleted user.

**How this got here.** The first three versions took the scope from whatever
tenant gate was mounted in front, and had to answer "what if there is none".
Under the Phase 7 rule that the `""` path stay byte-identical, the answer was
a guess (`tenant.Single`), and three reviews of #56 moved that guess around:
refuse, restore, refuse again. On 2026-10-05 the repo owner dropped the
compatibility rule (`CLAUDE.md` standing rule 1). The gate then needs no
guess: it is told its tenant when it is built, and it does not depend on what
is mounted around it.

### `authz/tenanttest`

`RunBindingStoreLeakSuite` and `RunPermissionStoreLeakSuite`. The ports are
read-only, so each takes a factory that returns the store and a function that
seeds it. The package's own tests run the suites against stores that leak on
purpose and assert that the suites fail. Five kinds of leak are covered: the
scope ignored; the subject's tenant ignored; rows stamped with the scope asked
for; grants (and superusers) found through the subject's home tenant, which
only a guest can reveal; and an empty tenant string read as "no filter", which
only a question in the single scope can reveal.

The RBAC-backed `PermissionStore` (`NewRBACPermissionStore`) is not run
through the suite. The suite grants two independent keys, and a role ladder
cannot express that. Its isolation is tested in `authz/tenant_test.go`, where
every case also runs against `PermissionSet` over that store.

## 5. Invariants

1. A binding in one scope never answers a question in another.
2. A subject of one tenant never matches a binding granted to the same
   `{Type, ID}` of another tenant.
3. No error return is read as allow.
4. A single-tenant deployment that passes `tenant.Single` gets the same
   decisions as before.

## 6. What this does not do

- **Cross-tenant roles.** No "platform superuser over every tenant". See
  section 3.
- **Tenant hierarchy** (TD-04).
- **Who may grant a guest a binding.** Writes are outside the PDP, as before.
- **The `PermissionSet` engine cannot filter by tenant itself.** A
  `PermissionSetResult` carries no tenant. Its store is checked by the leak
  suite only.
- **Barista.** It must pass `tenant.Single` and name the home tenant on its
  subjects. This joins TD-27.

## 7. Proof obligations

Mutation proofs, each failing a named test: the scope not passed to the store;
the engine's tenant filter removed; the subject's tenant ignored in the
in-memory stores; the unset-tenant refusal removed; `RequireDecision` taking
the subject's tenant from the routed tenant instead of the token.
