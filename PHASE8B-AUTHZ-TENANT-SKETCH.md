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
3. `tenant.Single` is a scope like any other. A single-tenant deployment
   passes it everywhere and gets the decisions it got before.

### `espresso.RequireDecision`

- Scope: the tenant a tenant gate put in the context (`RequireTenant`,
  `RequireTenantAllowEntered`, `PinTenant`). With no gate, `tenant.Single`.
- Subject tenant: the token's home tenant (`ActorTenantID`), so an entered
  admin is (platform, …) in scope acme.

A pooled route mounted without a tenant gate therefore asks in the single
scope with a tenanted subject. No binding matches, and it denies.

### `authz/tenanttest`

`RunBindingStoreLeakSuite` and `RunPermissionStoreLeakSuite`. The ports are
read-only, so each takes a factory that returns the store and a function that
seeds it. The package's own tests run the suites against stores that leak on
purpose and assert that the suites fail.

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
