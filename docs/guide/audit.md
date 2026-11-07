# Audit

`audit` writes a **hash-chained** log: each event's hash covers its own payload and the
previous hash, so removing or editing a row breaks the chain and verification says where.

```go
logger, err := audit.NewSQLiteLogger("audit.db", audit.SQLiteLoggerOptions{ /* … */ })
```

The SQLite logger is the one store tamper ships, because an append-only chain needs its own
transaction discipline to be correct under concurrency: the append is a single
`BEGIN IMMEDIATE` transaction, so two replicas cannot both read the tail and fork the chain.
Anything else — where your events live — is a `audit.Logger` you implement.

## Events

```go
type Event struct {
    Action   audit.Action
    Resource audit.ResourceType
    Actor    audit.Actor
    TenantID tenant.ID      // the row's SCOPE
    At       time.Time
    // plus the PII fields, hashed as salted commitments
}
```

Two tenants in one event, on purpose:

- **`Actor.TenantID`** is the actor's **home** tenant — the account's own tenant.
- **`Event.TenantID`** is the row's **scope** — the tenant the action happened *in*.

For an operator entering another tenant, those differ, and that is the pair you want when
reading an incident: who did this, and for which customer.

## Reading it

```go
page, err := logger.List(ctx, audit.Filter{
    TenantID:      tenant.New("acme"),   // this tenant's activity
    ActorTenantID: tenant.New("acme"),   // and only what acme's own users did
    // action, actor, time range … ↑ omitted = every tenant
})
```

A filter's fields are the query; an empty filter is an export. That is why the tenant fields
exist as a pair — "activity in tenant X" and "actions taken by tenant X's users" are
different questions, and a console needs both.

## Verification

`Verify` walks the chain and reports the first divergence with enough context to be acted
on — which is what you run at boot, and what an auditor runs on an export:

```go
res, err := logger.Verify(ctx)
```

The chain is written under a **canonical payload version** stored on every row (`v4`), so a
later shape can be told apart from this one rather than silently misread.

## Deleting personal data without breaking the chain

A deletion request cannot truncate an append-only chain — that would also erase the record
that the deletion happened. So the PII fields are stored as **salted commitments**, and a
redaction replaces the value while keeping the commitment: the row still verifies, the
chain still verifies, and the personal data is gone.

If you need physical per-tenant removal on a cadence that redaction cannot discharge, that
is a different design and a decision with legal input — it was analysed and found not
triggered for the ISO/IEC 27001 obligations this project works under. The analysis is
recorded rather than deleted, because a GDPR-covered market under DPAs can revive it.

## Two properties worth knowing

- **`Event.At` is not a pure clock reading.** It is the caller's timestamp, bumped forward on
  collision so the chain's ordering stays strict. If you need "when did the machine think
  this happened", it is this value; if you need "when did this land", it is your store's
  clock.
- **Nothing is read back from the chain to answer a permission question.** The audit log is
  a record, never an input to authorization.

## Auditing your own mutations

`espresso.NewAuditor(logger, emailLookup)` wraps a mutating handler and emits an event for
it, so attribution does not depend on every handler remembering to log:

```go
mux.Handle("/api/projects/", espresso.RequireAuth(jwtService)(
    auditor.Mutation("project.create", "project", "")(
        http.HandlerFunc(createProject))))
```

A service-account actor stashed by a gate upstream wins untouched — name, id, and its own
tenant — so a machine's provisioning shows up as the machine.
