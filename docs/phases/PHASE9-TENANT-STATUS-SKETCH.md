# Phase 9 — tenant status: refusing a suspended tenant on every request

Status: **accepted 2026-11-01; implemented in #82** (`espresso/activetenant.go`,
12 tests, seven mutation proofs). The four open questions in §8 were answered by
adopting this sketch's own proposals; they are recorded there.

This sketch covers TD-06 from `tech-debt.md`. It is the first half of a pair;
TD-05 (a writable tenant lifecycle) gets its own amendment when it lands, and §8
says exactly what changes here when it does.

It follows `PHASE8-PLATFORM-ADMIN-SKETCH.md` and
`PHASE8B-AUTHZ-TENANT-SKETCH.md` in shape and in posture: opt-in, read-only,
deny is a miss.

---

## 1. The problem

`tenant.Descriptor` has a `Status`, and the library mostly ignores it:

- `StartLogin` reads it — but only when `WithStartLoginTenants` is set, and only
  on the login leg (`espresso/startlogin.go:256-267`).
- `RequireTenant` and `PinTenant` take a resolver and a token, never a
  `tenant.Store` (`espresso/tenantgate.go`). They check that the token fits the
  route, not that the tenant is allowed to serve.

So a tenant that is suspended for non-payment, abuse or an admin hold

- keeps serving every **authenticated** request until its access tokens expire,
  and
- keeps accepting **password login**, because the login leg's status check is
  opt-in.

The only thing standing between a suspended tenant and the wire today is an
application-written gate. The library documents what such a gate must decide
(`tenant.ErrSuspended`'s doc, `tenant/store.go:22-31`) and then leaves writing
it to every consumer — which is how a control that auditors ask about ends up
implemented differently, or not at all, per deployment.

TD-05 is adjacent and separate: there is no supported way to *set* a status
through a port. That is not a blocker here — the application already owns the
tenant row, and `tenant.Store.ByID` already reads it.

---

## 2. Decisions

Proposals for review. Each is stated with the invariant it protects.

1. **Opt-in, like every tenancy upgrade since Phase 7.** A deployment that does
   not mount the middleware is unchanged, byte for byte. There is no flag
   inside an existing gate and no default-on behaviour.

2. **Read-only.** The gate resolves a `Descriptor` and decides. It never writes
   a status, never revokes a session, and never repairs anything. Status is the
   application's data (today through its own table, later through TD-05's port).

3. **Deny is a miss on the wire.** An unknown tenant and a suspended tenant
   produce the **same bytes** through the **same writer**. `tenant.ErrSuspended`
   exists so a caller can say which case it decided; it must never reach the
   wire on an unauthenticated surface, because a distinguishable "suspended" is
   a tenant-existence oracle (`tenant/store.go:27-30`, sketch §6.3).

4. **An error is neither a miss nor an allow.** A store failure is not reported
   as "no such tenant": that is a lie that masks an outage. It is also not an
   allow. It goes to its own writer (the app's 5xx). Unlike a status, an outage
   is not tenant-specific, so it discloses nothing.

5. **The tenant comes from the pin, not from a resolver.** The gate reads
   `TenantFromContext`, so it cannot disagree with the tenant the route is
   using. Nothing pinned is a wiring error — the framework's own 500
   `CONFIG_ERROR` envelope, written where `RequireDecision` writes its
   misconfiguration branch, never the app's miss writer — and never a pass.

6. **Any status but `StatusActive` denies**, including a status this version of
   the library does not know. Deny-by-default extends to status: an unknown
   value is not "probably fine".

7. **Placement is after a tenant pin, on both kinds of route.** Pre-authentication
   routes pin with `PinTenant`; authenticated routes pin with `RequireTenant`.
   The gate sits after either. Suspension is a property of the tenant, not of
   the user, so it does not care whether a user is present.

8. **Misconfiguration fails when the gate is built.** A nil store, a nil writer
   or an empty label panics at construction — the posture
   `RequireTenant`/`PinTenant` already take on a nil resolver (`CLAUDE.md`
   standing rule 4). A gate that cannot check status must not exist.

9. **A single-tenant deployment has nothing to suspend.** `tenant.Single` is
   the empty id, and the port states that an empty lookup key never resolves:
   `""` is *"precisely the deployment with no tenant row to find"*
   (`tenant/store.go:45-48`). Looking it up would return `ErrNotFound` and turn
   this gate into a 404 for **every** request in a single-tenant deployment. So
   the gate passes `tenant.Single` straight through and is a no-op there.
   Denying instead would break that deployment for a control that has no
   meaning in it: "suspend the only tenant" is an operator decision about the
   whole deployment, not a row in a tenants table.

---

## 3. The model

One lookup, one decision, no new storage:

```
request
  │
  ▼
PinTenant(resolve)  or  RequireTenant(resolve)      ← the tenant is pinned
  │
  ▼
RequireActiveTenant(ActiveTenantGate{...})
  │
  ├── pinned tenant is tenant.Single ......... next handler  (decision 9)
  ├── tenant not pinned ..................... 500 CONFIG_ERROR (wiring bug)
  ├── Store.ByID error
  │     ├── ErrNotFound ..................... WriteNotActive   (miss)
  │     └── anything else ................... WriteError       (5xx, fail closed)
  │
  ├── Status != StatusActive
  │     ├── StatusSuspended ................. WriteNotActive   (same bytes as a miss)
  │     └── StatusPending, anything else .... WriteNotActive
  │
  └── StatusActive .......................... next handler
```

`tenant.Single` is **not** looked up (decision 9). It is the empty id, and the
store's own contract says an empty lookup key never resolves — a lookup would
return `ErrNotFound`, which this gate maps to the miss writer, and every request
in a single-tenant deployment would be a 404. The branch comes first for that
reason.

**Where status is written is out of scope.** Today the application sets it in
its own table (TD-05's proposal would add a port). The gate reads whatever the
row says at the moment of the request.

**Cost.** One `ByID` per request on a gate every request passes. The app may
wrap its `tenant.Store` with a short-TTL cache. That is supported and named
here as an accepted window: **a suspension takes effect within the cache TTL.**
It is the same shape as the entered-token window Phase 8 accepts
(`WithEnterTenantTTL`), and it should be written down in the deployment's own
runbook rather than discovered.

---

## 4. API

```go
// ActiveTenantGate configures RequireActiveTenant.
type ActiveTenantGate struct {
    // Store resolves the status. Required — nil panics at construction.
    Store tenant.Store
    // Label names the gate in the 500 message ("tenant status"), so operator
    // logs keep their grep-ability. Required: empty panics with the rest.
    Label string
    // WriteNotActive writes the app's miss response. Required. It is used
    // for an unknown tenant AND for a non-active one, so the two are
    // indistinguishable on the wire.
    WriteNotActive DenyWriter
    // WriteError writes the response for a store failure. Required: falling
    // back to WriteNotActive would report an outage as "no such tenant".
    WriteError DenyWriter
}

// RequireActiveTenant returns the middleware. It must run after a tenant is
// pinned (PinTenant on public routes, RequireTenant on authenticated ones).
//
// Panics on a nil Store, a nil writer, or an empty Label: a gate that cannot
// decide must fail when it is built, not on a request.
func RequireActiveTenant(g ActiveTenantGate) func(http.Handler) http.Handler
```

Three shapes were considered and rejected:

- **A flag on `RequireTenant`** (`RequireTenantActive(...)`): it would tie the
  status check to the token check, so a `PinTenant` route could not have it, and
  every existing `RequireTenant` call would gain a parameter it does not use.
- **A method on `tenant.Store`** (`Active(ctx, id) (bool, error)`): status is a
  column on the row `ByID` already returns. A second read is a second chance for
  the two to disagree.
- **Inside `DecisionGate`**: the decision gate is about authorization. A
  suspended tenant must be refused before authorization is asked, and on routes
  with no decision gate at all (a webhook, a public page).

`WriteError` is required rather than optional with a fallback, unlike
`DecisionGate.WriteProbeError`: there, falling back to `WriteDenied` is still a
refusal; here, falling back to `WriteNotActive` would be a false statement about
a tenant's existence.

---

## 5. Invariants

1. **A non-active tenant never reaches the handler.** Every status other than
   `StatusActive` — including one this version does not know — refuses.
2. **Suspended and unknown are indistinguishable**: same writer, same bytes,
   same headers, same status code.
3. **No error return is read as allow**, and none is read as a miss.
4. **The gate cannot disagree with the route**: it reads the pinned tenant and
   nothing else.
5. **Nothing pinned refuses** with the config error, never with a pass.
6. **Opting out is not mounting it.** There is no per-status, per-route or
   per-method configuration, and no way to say "suspended but allowed here".
7. **A build-time mistake fails at build time**: nil store, nil writer, empty
   label panic before the first request.
8. **A single-tenant deployment is not refused**: `tenant.Single` never reaches
   the store and never reaches the miss writer.

---

## 6. What this does not do

- **No writes.** Setting, clearing or resting a status, and pairing a suspension
  with session revocation, is TD-05. This gate only refuses.
- **No session revocation.** A suspension today still leaves valid access tokens
  until they expire; `Core.RevokeAllSessionsForTenant` is the hammer, and TD-05's
  `Suspend` should swing it. The gate shortens the window; it does not close it.
- **No caching of its own.** The application may wrap its store; the accepted
  window is §3's.
- **No audit event.** A refused request is not a mutation, and tamper's gate has
  no log. An application that wants a row for a refused suspension writes it in
  its `WriteNotActive` writer.
- **No partial access.** A route that must keep serving a suspended tenant (a
  billing page, an export) is a route mounted without this gate — an explicit
  decision in the router, not a status allow-list here.
- **No lifecycle.** Create, list, delete, offboard: TD-05.
- **No impersonation.** TD-07.

---

## 7. Proof obligations

Mutation proofs, each failing a named test. **All seven** are required for the
slice to count as done.

| Mutant | Test that must go red |
|---|---|
| Accept every status (drop the `!= StatusActive` branch) | suspended tenant reaches the handler |
| Use a different writer for suspended than for unknown | the byte-identity test |
| Treat a store error as a miss | the outage test (must be the error writer) |
| Treat a store error as allow | the same outage test, allow side |
| Read the tenant from a resolver instead of the pin | the mismatch test (a route pinned to `acme` must not be answered by another tenant) |
| Remove the construction guard | the panic test (rule 6: the guard ships with a test that fires) |
| Look `tenant.Single` up instead of passing it through | the single-tenant test (it must pass, not 404) |

Plus, not mutation-based:

- `tenant.Single` passes without touching the store, and a store whose `ByID`
  would return `ErrNotFound` for it never sees the call.
- A status the library does not know refuses (a literal `tenant.Status("held")`
  seeded in the store).

---

## 8. Relationship to TD-05, and open questions

**TD-05 does not block this.** Status is a column the application already owns;
`ByID` reads it. When TD-05 lands, two things change here and nothing else:

1. `Suspend` will set the status **and** revoke the tenant's sessions in one
   operation, so the gate's window shrinks from "until the token expires" to
   "until the cache TTL".
2. The gate stays exactly as specified — it reads a `Descriptor` either way. If
   TD-05 introduces `tenant.AdminStore`, the gate keeps taking `tenant.Store`,
   because it only reads.

**The four questions this section left open, as implemented** (`#82`). Each was
answered by adopting the proposal above; changing one is an amendment to this
section plus a small change in the gate.

- **Where in the chain?** Immediately after the tenant gate, before any
  authorization gate. The gate itself makes no claim about `RequireAuth`: it
  reads the pin, so an application may put it after the auth gate on an
  authenticated route and before it on a public one. Both placements are tested.
- **Is `StatusPending` refused everywhere?** Yes — one rule for every non-active
  status. A pending tenant that must reach an onboarding route mounts that route
  without this gate.
- **How long may the cache window be?** None: the gate does one `ByID` per
  request and nothing in this package wraps the store. A short TTL on the
  application's own store is still supported; the accepted window is that TTL.
- **Does a refusal deserve an audit row?** Not in tamper. The `WriteNotActive`
  writer is the application's hook if it wants one.
