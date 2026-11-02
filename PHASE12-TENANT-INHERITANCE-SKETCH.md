# Phase 12 — Tenant inheritance across the three open axes

Status: **draft, for review. Not decided, no code.**

TD-04 closed one of its four axes (roles, via ADR-0001) and left three open,
deliberately: `PHASE7-MULTITENANCY-SKETCH.md` §8 item 3 deferred them as a
product question. The product question has now been answered, per axis, and
this sketch turns the answers into a design.

The answers are recorded in §1 as **decisions taken**, not proposals. What
remains open is mechanism, and §8 lists the little that is still a choice.

---

## 1. The product decisions (recorded 2026-11-01)

The tenant-group is sometimes an **owner** (a school district that owns its 40
schools) and sometimes a **manager** (a reseller for 20 unrelated clinics).
Because the two models want opposite answers, one global switch cannot be
correct for both — so the axes are decided separately, and the two that touch
identity are opt-in.

**D1 — roles. Already closed, unchanged.** ADR-0001: the application
*materializes* an inherited grant as real per-child bindings at provisioning
time. This sketch does not reopen it.

**D2 — entitlements. Effective plan is the MAXIMUM of the tenant's own purchase
and what its ancestors bought.** A child that bought more keeps its own; a
child that bought nothing gets the group's. No opt-in needed, because this axis
touches neither login nor authorization — it answers "was this feature paid
for", and being paid for by the parent is being paid for.

**D3 — IdP. Inheritance is per-group and OFF by default.** A group turns it on
once; its children then log in through the group's providers without their own
rows. Rejected: ON by default. In the manager model, a compromised group IdP
would otherwise be able to authenticate into every child's tenant — a
cross-customer breach that cannot be undone retroactively.

**D4 — domains. A child may claim a domain that is a proper subdomain of a
domain an ancestor has VERIFIED, with one DNS proof at the group, the group
admin's approval, and an audit row.** Rejected: automatic inheritance of
`*.parent` (anyone who can add a record to that zone could map a tenant of their
choosing, which is the tenant-takeover vector `tenant/domain.go` exists to
close) and per-child DNS proof (40 proofs for one district).

Where the four axes disagree, one rule explains all of it: **inheritance may
only ever widen what the customer has, never who this request is.** D2 widens a
capability, D3 widens the set of identity providers, D4 widens the set of
claimable names. None of them changes the tenant a request is scoped to, and
none of them grants a permission — D1's bindings still decide that.

---

## 2. What is true today (verified, not remembered)

| Fact | Where |
|---|---|
| Parentage is a field nothing reads | `tenant/tenant.go:21-25` (`ParentID`, "RESERVED. Nothing in tamper resolves it") |
| Rows keep it | `tenant/memstore.go:116-139` (`Create` stores the whole `Descriptor`) |
| The tenant port is two lookups | `tenant/store.go` (`Store.ByID`, `Store.BySlug`) |
| The plan lookup is exact, and its zero value is the documented "bought nothing" | `tenant/entitlements.go:58-68` |
| `MaxIdPConnections == 0` means UNLIMITED | `tenant/entitlements.go:26` |
| The entitlement gate calls `store.ForTenant` and nothing else | `espresso/routes.go:313-320` |
| The OIDC registry is keyed per tenant and rebuilt from that tenant's rows | `oidc/manager.go:365-382`, `459-504` |
| The redirect URL is computed per tenant at build time | `oidc/manager.go:488` (`m.redirectFor(tenantID, def.ID)`) |
| SAML is the same shape, separately | `saml/manager.go:385-400`, `465-` |
| Home-realm discovery is exact and believes only verified claims | `tenant/domain.go:130-152` |
| No boot guard asserts a tenant-scoped provider store, and one comment says otherwise | `oidc/store.go:71-73` vs `oidc/manager.go:359-361` |

Two consequences worth naming up front:

- **The entitlement axis needs no change to `espresso`.** The gate takes an
  `EntitlementStore`, so a decorator that walks upward is transparent to it. That
  makes D2 the cheapest slice by a wide margin, and it is why it goes first.
- **`oidc/manager.go:359-361` contradicts `oidc/store.go:71-73`.** The first claims
  `tamper.New` refuses a non-tenant-scoped provider store at boot; the second
  says there is no such assertion, and a `grep` of `provider.go` finds only nil
  checks. Both cannot be true. Fixed in 12b, because the IdP axis touches that
  exact paragraph and a reader implementing inheritance must know which is real.

---

## 3. The one new primitive

Every axis needs the same two things: *who are this tenant's ancestors*, and
*is this axis switched on for them*. So one function and one policy shape, and
three consumers.

```go
// tenant/hierarchy.go
func Ancestors(ctx context.Context, s Store, id string) ([]string, error)

// A group's switch for one axis. Absent policy = deny.
type Inheritance func(ctx context.Context, id ID) (bool, error)
```

`Ancestors` returns the chain **nearest-first**, excluding `id` itself.

Decisions inside it, each of which a test pins:

- **`id == ""` returns nothing, always.** `tenant.Single` is a deployment with no
  tenant rows (`tenant/store.go:45-48`), so it has no ancestors; asking the store
  would return `ErrNotFound` and turn every single-tenant call into an error.
  This is the same trap Phase 9 hit.
- **`Descriptor.ParentID == ""` ends the walk.** That is a root, not an error.
- **A parent id that does not resolve is an ERROR**, not a silent root
  (`ErrNotFound`, wrapped). A dangling pointer is corrupt data; treating it as a
  root would quietly change who inherits what.
- **`ErrNotFound` for the starting id is an error too** — except where the caller
  needs the other reading (§4.2).
- **A cycle is an error** (`ErrHierarchyCycle`), not a hang; a chain longer than
  `maxHierarchyDepth` (32) is `ErrHierarchyDepth`. Both are new sentinels in
  `tenant`, next to `ErrNotFound`.
- **The store's other errors propagate.** No error return is read as "root".

No new port. Ancestors come from `tenant.Store` + `Descriptor.ParentID`, which
every deployment already has, and `ParentID` exists precisely "so the answer can
be additive when it comes" (`tenant/tenant.go:21-25`). The tech-debt proposal's
`Children(id)` is **not** added: nothing in these three axes needs to enumerate
children, and provisioning (the one consumer that would) is the application's.

---

## 4. The three axes

Each is opt-in: nobody who does not wire it observes a change, and every axis is
independently switchable (invariant 10).

### 4.1 Entitlements — a decorator, not a port change

```go
func (e Entitlements) Union(parent Entitlements) Entitlements
func InheritingEntitlements(inner EntitlementStore, s Store) EntitlementStore
```

`Union` is "the maximum": booleans OR, `MaxIdPConnections` combined. The cap is
the one place where "maximum" is not `max`, because **`0` means unlimited**
(`tenant/entitlements.go:26`): if either side is 0 the result is 0, otherwise the
larger. A naïve `max` here narrows a tenant from unlimited to 40, and the symptom
is a child that suddenly cannot add an IdP it was always allowed to add.

`InheritingEntitlements` returns a store whose `ForTenant(ctx, id)` unions the
tenant's own value with each ancestor's, nearest first. It is a decorator, so
`espresso.RequireEntitlement` is untouched, and "opt-in" is literal: pass the
plain store, get today's behaviour.

Sharp edges, each testable:

- **The union is the EFFECT; `ForTenant` stays the PURCHASE.** An admin screen
  that shows "your plan" must call the inner store, not the decorator, or it will
  show a customer a plan they did not buy. The doc says so in those words.
- **`MaxIdPConnections` counts the tenant's OWN providers only.** Inherited
  providers are not configured by the child and must not consume its cap, or a
  group with three providers silently blocks a child from adding a fourth of its
  own. The cap check lives in the app (`AllowsAnotherIdP`), so this is a
  documented rule plus one example test — tamper cannot enforce it without
  owning the write path.
- **An error anywhere in the walk fails the lookup.** The gate denies on error,
  so a broken hierarchy closes SSO rather than opening it. (`espresso/routes.go:317`.)

### 4.2 IdP — the registry is built in the CHILD's name

```go
// oidc and saml, same shape
func WithInheritance(ancestors AncestorFunc, allow tenant.Inheritance) ManagerOption
```

The manager's rebuild already takes a tenant id and a list of records and
produces a registry for that tenant (`oidc/manager.go:459-504`). Inheritance
changes **where the records come from**, and nothing else:

1. `listEnabled(child)` is empty, and inheritance is wired.
2. Walk the ancestors nearest-first. For each, ask the group's switch
   (`allow(ancestor)`); if it is false, **the walk ends here — it does not
   continue to a grandparent.** A group that keeps its own IdP but has not opted
   in is saying "children configure their own"; letting a grandparent serve the
   child would override a decision the group actually made. Rejected: skipping
   past a refusing ancestor.
3. The first ancestor whose switch is ON and whose `listEnabled` is non-empty
   supplies the records. Its own `TenantID` is ignored; only the provider
   definitions are used.
4. The registry is built with **`tenantID = the child`**, so `redirectFor` returns
   the child's callback URL, and the cache entry is stored under the child's key.

Step 4 is the security decision of this axis and it is not a detail. Building the
ancestor's registry and handing it to the child would carry the *ancestor's*
redirect URI into the child's login flow: the IdP would then complete a flow that
lands in the wrong tenant's context. Borrowing the definition and compiling it for
the child keeps "which IdP do we ask" inherited and "which tenant is this" not.
The operational cost, documented rather than hidden: the IdP must accept the
child's callback URL, so a per-tenant `redirectURLForTenant` means registering N
callbacks at the customer's IdP — or one tenant-agnostic URL, at which point the
cost is zero.

Two behavioural notes:

- **A child with its own providers never consults an ancestor.** No merge: the
  child's rows win entirely. A merge would put two providers with the same id in
  one registry and make the flow's provider selection ambiguous.
- **An unknown tenant stays `(nil, nil)`.** Today `GetRegistry` documents that a
  tenant with no providers returns a nil registry and no error
  (`oidc/manager.go:364`). The walk must not turn that into an error: `ErrNotFound`
  from `Ancestors` means "nothing to inherit", and the outcome is identical — no
  registry. Any *other* error propagates. Deny and miss stay indistinguishable.

**Staleness.** `Reload(parent)` does not clear a child's cached entry, so a
deleted group provider can keep authenticating a child for up to one `ttl`. This
is the same window the manager already documents for sister replicas
(`oidc/manager.go:63-68`), it is not a new failure mode, and it is accepted: the
alternative is a `Children(id)` port and a fan-out invalidation, for a window
that is already there. A deployment that needs faster takes a shorter TTL.

**Behind the manager, no fallback.** If inheritance is not wired, `GetRegistry`
behaves exactly as today — the `len(recs) == 0` branch caches the nil sentinel.

### 4.3 Domains — authority, not approval

```go
func InheritedDomainAuthority(ctx context.Context, s Store, domains DomainStore,
	tenantID ID, domain string) (DomainRecord, error)

func IsProperSubdomain(child, parent string) bool   // exported for the admin path
```

`InheritedDomainAuthority` walks ancestors nearest-first and, for each, asks
`domains.ListForTenant(ancestor)` for a **verified** claim that `domain` is a
proper subdomain of, returning the first match. Everything else is `ErrNotFound`,
including a public email domain and an unnormalised input — the same three-fold
collapse `ResolveDomain` already documents, for the same reason.

`IsProperSubdomain` is one line and it is where the takeover lives:

```
child != parent  &&  strings.HasSuffix(child, "."+parent)
```

The `.` is the whole guard: without it, `evilacme.com` is a "subdomain" of
`acme.com`. The mutation proof is dropping it.

**The boundary this helper deliberately stops at.** It answers *"may this child
claim this name?"*; it does not approve, store, or audit. The application records
the child's own claim row (`Verified: true`, plus whatever provenance columns it
keeps) and emits the audit row — `domain.inherited_claim`, naming the group whose
proof was borrowed. Two rules come with that, and they are the app's obligation:

- **The row is written only after the group admin approves.** A helper that
  returns authority is not a licence to write an unverified-then-flipped row.
- **`Verified` stays the boundary.** `ResolveDomain` reads exactly one row by
  exact name (`tenant/domain.go:139`) and returns nothing for an unverified one,
  so a child row written *before* approval shadows the ancestor and breaks the
  child's own login. Write after approval, and the two agree.

Why not inherit inside `ResolveDomain`: it takes a `DomainStore` and is the
unauthenticated resolve path. Putting a hierarchy walk behind it would make the
most security-sensitive lookup in a pooled deployment depend on a second store on
every unauthenticated request. The helper is called from the admin path, where a
customer's operator is already authenticated.

---

## 5. Wiring and boot guards

Standing rule 6: an optional upgrade ships a boot guard **and** a test that the
guard fires.

```go
// oidc.OIDCConfig / saml.SAMLConfig
type InheritanceConfig struct {
	Store tenant.Store                       // parentage graph
	Allow func(ctx, tenant.ID) (bool, error) // the group's switch
}
```

`tamper.New` refuses, with a message naming the field:

- `OIDC.Inherit != nil` with a nil `Store` or nil `Allow`;
- `SAML.Inherit != nil` likewise;
- `OIDC.Inherit != nil` while `OIDC` itself is nil (inheritance of an engine that
  is not built is a misconfiguration, not a no-op), and the same for `SAML`.

Each guard gets a test that asserts the error text, so a guard deleted later is
caught by a failing test rather than by a customer.

`Ancestors` and the two constructors panic on a nil store, matching
`RequireEntitlement`'s precedent (`espresso/routes.go:294-297`): a nil store is a
wiring bug that would silently permit.

---

## 6. Invariants

1. Inheritance is opt-in per axis; unwired means today's behaviour, byte for
   byte.
2. Inheritance widens what the customer HAS; it never changes which tenant a
   request is scoped to, and never grants a permission.
3. The ancestor walk fails closed: cycle, over-depth, dangling parent, or a
   store error is an error, never "root" and never "allow".
4. `tenant.Single` (`""`) never walks.
5. A tenant with its own configuration never consults an ancestor, and no axis
   merges — first match wins, whole.
6. The IDP registry is compiled in the inheriting tenant's name: its redirect
   URLs and its cache key.
7. `MaxIdPConnections == 0` is unlimited on both sides of a `Union`, and a cap
   never narrows.
8. The union is the EFFECT; `ForTenant` remains the PURCHASE.
9. A domain is inherited only as a **proper** subdomain of a **Verified**
   ancestor claim, with the dot boundary intact.
10. Three axes, three switches: turning one on changes no other axis's answer.
11. `InheritedDomainAuthority` returns authority and writes nothing; approval and
    the audit row are the application's.

---

## 7. Tests and mutation proofs

Every test below ships with at least one mutant that must turn it red, verified
to compile before it is counted.

**`tenant/hierarchy_test.go`**

| Test | Mutant |
|---|---|
| three-level chain, nearest-first | return the chain root-first |
| root tenant → empty, no error | treat `ParentID == ""` as an error |
| `""` → empty, store never called | walk for `""` |
| dangling parent → error | return the chain so far instead of failing |
| cycle → `ErrHierarchyCycle` | drop the visited set |
| depth > 32 → `ErrHierarchyDepth` | drop the bound |
| store error propagates | return nil, nil on any error |

**`tenant/entitlements_test.go`**

| Test | Mutant |
|---|---|
| union: booleans OR | AND them |
| union: 0 vs 40 → 0 (unlimited) | plain `max` |
| union: 40 vs 10 → 40 | return the child's |
| decorator unions the chain | return the child's own only |
| decorator on a root tenant = inner | walk anyway |
| decorator error → error | swallow on the walk |

**`oidc/inheritance_test.go` and `saml/inheritance_test.go`**

| Test | Mutant |
|---|---|
| child with no providers inherits the opted-in parent's | never call the ancestors func |
| child with its own providers ignores the parent | merge both sets |
| switch off at the parent → no registry, no grandparent | skip past a refusing ancestor |
| switch off, no ancestors → `(nil, nil)` | return an error |
| unknown tenant → `(nil, nil)`, not an error | propagate `ErrNotFound` |
| the child's redirect URL is used, not the parent's | build with the parent's id |
| the registry is cached under the child's key | store it under the parent's |
| inheritance unwired → today's behaviour | — (compile-time: no option, no field) |

**`tenant/domain_inheritance_test.go`**

| Test | Mutant |
|---|---|
| proper subdomain of a verified ancestor → the ancestor's record | — |
| `evilacme.com` vs `acme.com` → not found | drop the `"."` in `IsProperSubdomain` |
| the parent's own domain is not inheritable | allow equality |
| unverified ancestor claim → not found | ignore `Verified` |
| public email domain → not found | drop the public check |
| unnormalised input → `ErrDomainNotNormalised` | normalise silently |
| no ancestor claims the name → not found | return the nearest ancestor regardless |

**`provider_test.go`** — one test per boot guard, asserting the message names the
field.

---

## 8. What is still open

1. **Does the group's switch apply per child too?** This sketch reads D3 as the
   group's decision only: a child opts out by configuring its own providers, which
   is already "first match wins". A per-child consent flow is a bigger product
   change and is not designed here.
2. **When is the audit row `domain.inherited_claim` emitted — at approval, or at
   first use?** Approval. First use would need a row per login, and the chain is
   append-only for a reason.
3. **Do inherited entitlements show on the customer's invoice?** Billing is the
   application's; the union is only the effective value. Nothing here changes what
   is invoiced.
4. **Should `ChildrenOf` land later anyway**, for provisioning? Not needed by any
   of these three axes. Left to the app, as ADR-0001 already does.

---

## 9. Slices

- **12a — entitlements** (`Union` + decorator + the cap rules). Smallest, no
  engine touched, proves the ancestor primitive.
- **12b — the hierarchy primitive** (`tenant/hierarchy.go`, sentinels, the
  `oidc/manager.go` doc correction).
- **12c — IdP** (`oidc` + `saml` options, `tamper.New` wiring and guards, the
  redirect-in-the-child's-name test).
- **12d — domains** (`IsProperSubdomain` + `InheritedDomainAuthority`).
- **12e — docs** (TD-04 in `tech-debt.md`, an ADR-0001 §8 note that three axes are
  now decided, `MIGRATION`, `CHANGELOG`, and this sketch to `accepted`).

12a before 12b is deliberate: the decorator is the least risky consumer, so the
primitive gets exercised before the managers depend on it.

---

## 10. What this phase does not do

- It does not reopen roles. ADR-0001 stands: bindings are materialized per child,
  because the RBAC engine drops any binding whose scope is not the one asked
  (`authz/store.go`), so no runtime walk can substitute for them. The other three
  axes are point lookups, which is why they can walk and roles cannot.
- It does not add a `Children(id)` port, an inheritance flag on `tenant.Store`, or
  any method to an existing port. Every addition is a new function or a new option.
- It does not change `canonical_version`, the audit schema, or `Actor`.
- It does not make any axis inheritance-by-default, and it does not touch
  `tenant.MemStore` beyond what `Descriptor.ParentID` already stores.
