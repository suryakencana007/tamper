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
  checks. Both cannot be true. Fixed in 12a: the correction is a comment, it needs
  no engine, and a reader implementing inheritance must know which of the two is
  real before touching that paragraph.

---

## 3. The one new primitive

Every axis needs the same two things: *who are this tenant's ancestors*, and
*is this axis switched on for them*. So one function and one policy shape, and
three consumers.

```go
// tenant/hierarchy.go
func Ancestors(ctx context.Context, s Store, id ID) ([]ID, error)

// A group's switch for one axis. Absent policy = deny.
type Inheritance func(ctx context.Context, id ID) (bool, error)
```

An implementation must also deny on an unset `ID`. `Ancestors` never yields one,
so that clause is defence in depth — but a policy is an interface the application
implements, and "no error return may be read as allow" applies to a `bool` too.

**A policy that returns an error aborts the walk, and its `bool` is ignored.**
Both halves matter and neither is automatic. The walk must not read `(false, err)`
as a refusal-and-stop (that would turn a broken settings lookup into a silent
deny, indistinguishable from a group that switched the feature off) and must not
read `(true, err)` as permission (the obvious bug). The error propagates, the
tenant gets no inherited providers, and that is the same fail-closed shape as a
store error. A policy backed by a settings table *will* error the day that table
is unreachable, so this path is exercised, not theoretical.

`Ancestors` returns the chain **nearest-first**, excluding `id` itself, as
`tenant.ID` — not as `string`, on either side.

**Why `ID` and not `string`.** `tenant.Store` speaks strings (`ByID(ctx, id
string)`), and copying that surface here would undo the reason `ID` exists. Its
own doc opens by saying a bare string cannot distinguish `""` said deliberately
from `""` because a caller forgot to thread the tenant — an ambiguity "ruled on
twice in this phase", settled both times as deny (`tenant/id.go`). A `string`
signature cannot express that, so `Ancestors(ctx, s, "")` would be legal and would
mean two things at once. It would also push the choice between `tenant.New`
and `tenant.FromStored` onto all three consumers, and `id.go` is explicit that those two
conversions must not be shared or duplicated at call sites. With `ID`, both
consumers that take `ID` — the entitlement store and the registry
(`ForTenant`, `ListEnabledProviders`) — pass the value straight through.

Decisions inside it, each of which a test pins:

- **A zero `ID` returns nothing, always.** `!id.Valid()` means the caller never
  threaded a tenant through. That is not "root" and not "single-tenant"; it is
  unset, and unset denies.
- **`tenant.Single` returns nothing, always.** It is the explicit single-tenant
  deployment, which has no tenant rows (`tenant/store.go:45-48`), so a store
  lookup would return `ErrNotFound` and turn every such call into an error. This
  is the same trap Phase 9 hit. Same outcome as the zero ID, different reason, and
  both are pinned by their own test.
- **`Descriptor.ParentID == ""` ends the walk.** That is a root, not an error.
- **Every ancestor id is read back through `tenant.FromStored`**, because it came
  out of storage — that function's stated purpose, and the reason its doc says
  "NEVER call this on untrusted input: a `tid` claim, a routing header ... Those go
  through New". Its `""` branch returns `Single`, and that branch is
  **unreachable from this walk**: an empty `ParentID` ends the chain before any
  conversion. A test pins it, because the way this breaks later is a refactor that
  converts first and checks afterwards, putting `Single` in an ancestor list.
- **A parent id that does not resolve is an ERROR**, not a silent root
  (`ErrNotFound`, wrapped). A dangling pointer is corrupt data; treating it as a
  root would quietly change who inherits what.
- **`ErrNotFound` for the starting id is an error**, like any other miss — an
  unknown tenant has no ancestors, and saying so is not the same as saying "it
  exists with none". The one consumer that must not see an error is the registry
  (§4.2), and it translates this one sentinel rather than the walk guessing on its
  behalf.
- **A cycle is an error** (`ErrHierarchyCycle`), not a hang; a chain longer than
  `maxHierarchyDepth` (32) is `ErrHierarchyDepth`. Both are new sentinels in
  `tenant`, next to `ErrNotFound`. The number bounds corrupt or adversarial data
  rather than describing a product limit: real hierarchies are three deep, and a
  deployment needing more than 32 has a data-modelling problem whose symptom should
  be a named error rather than a slow request.
- **The store's other errors propagate.** No error return is read as "root".
- **Those sentinels are the operational face of this rule.** Fail-closed means a
  tenant with corrupt parentage has every gated request denied, which looks like
  an outage for that tenant rather than a data fault. The named errors exist so it
  appears in a log as `ErrHierarchyCycle` or `ErrHierarchyDepth` rather than as a
  mystery SSO failure, and callers must not discard them when they deny.

### 3.1 The Phase 7 invariant this phase amends

`ParentID` is not merely "reserved but unused". Three places in the tree say so in
the present tense, and `tenant.Ancestors` makes all three false:

| Where | What it says now |
|---|---|
| `tenant/tenant.go:21-25` | "RESERVED. Nothing in tamper resolves it, inherits through it, or branches on it." |
| `tenant/admin.go:56-58` | "tamper does not resolve it, inherit through it, or branch on it" |
| `tenant/memstore_test.go:165-167` | "ParentID is reserved." |

And `ADR-0001-tenant-hierarchy-platform-tenantgroup-org.md` §5.A **rejected**
resolving `ParentID` in tamper core, for two stated reasons: it violates the
Phase 7 invariant, and it "butuh amend sketch Phase 7 dulu" — needs a Phase 7
sketch amendment first. That precondition is what this section satisfies, and the
rejection is not being overruled by silence: **§5.A stands for roles** (the RBAC
engine still must not walk, §10) and is superseded only for the three inheritance
axes, where the lookup is a point lookup rather than a scope check.

So slice 12a carries four edits that are not follow-up paperwork:

- the `ParentID` comment in `tenant/tenant.go`, reworded to say what is now true —
  the field is carried by stores and resolved by `Ancestors` for inheritance, while
  nothing in tamper derives an *authorization* scope from it;
- the same sentence in `tenant/admin.go`, keeping its last clause ("this is where a
  hierarchy deployment writes the parentage its own port reads"), which was already
  written in anticipation of this;
- the test comment at `tenant/memstore_test.go:165`. The test itself stays: it
  asserts that `MemStore` carries the field and that a miss does not walk to a
  parent, and both remain true — `Ancestors` is the resolver, and the store is
  still forbidden to be one;
- an ADR-0001 note in §5.A and §8 — in that document, not a new ADR: it is the
  same ADR's rejection being scoped, and a second document would leave a reader of
  the first holding an overturned decision with no pointer to where it moved.

A comment that says "nothing in tamper resolves it" while `tenant/hierarchy.go`
does is exactly the kind of drift this repo treats as a defect rather than as
stale prose. Shipping it in a later docs slice would be shipping a lie in the
meantime.

Section 2 is worth re-reading in that light: it quotes `tenant/tenant.go:21-25` as
support ("the field exists so the answer can be additive when it comes") and the
same paragraph contains the sentence this phase invalidates. Only the first half
was quoted there; this section is the second half.

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

**It is uncached, and that is a contract the caller must honour.**
`EntitlementStore`'s own doc says an implementation should be cheap or cached
"because a gate consults this on every gated request"
(`tenant/entitlements.go:56-57`), and this one turns that single read into
1+depth. tamper ships no cache here — there is no clock, TTL or key policy in
this package to hang one on — so a deployment that gates per request wraps the
decorator in its own cache, exactly as it would the plain store. Documented on
the constructor, and §8 records whether a built-in cache should land later.

Sharp edges, each testable:

- **The union is the EFFECT; `ForTenant` stays the PURCHASE.** An admin screen
  that shows "your plan" must call the inner store, not the decorator, or it will
  show a customer a plan they did not buy. The doc says so in those words.
- **`MaxIdPConnections` counts the tenant's OWN providers only.** Inherited
  providers are not configured by the child and must not consume its cap, or a
  group with three providers silently blocks a child from adding a fourth of its
  own. `AllowsAnotherIdP(current int)` takes the count from the caller
  (`tenant/entitlements.go:40-46`), so this is documentation, not a test: no test
  in this repo can enforce a number the caller supplies. Said here rather than
  implied, because it is the kind of rule that reads as enforced.
- **An error anywhere in the walk fails the lookup.** The gate denies on error,
  so a broken hierarchy closes SSO rather than opening it. (`espresso/routes.go:317`.)

### 4.2 IdP — the registry is built in the CHILD's name

```go
// oidc and saml, same shape
func WithInheritance(s tenant.Store, allow tenant.Inheritance) ManagerOption
```

The manager takes the parentage store itself rather than an invented closure
type: it already imports `tenant`, `tenant.Ancestors` takes exactly this, and a
second indirection would be a place for the type mismatch of §3 to reappear.

The manager's rebuild already takes a tenant id and a list of records and
produces a registry for that tenant (`oidc/manager.go:459-503`). Inheritance
changes **where the records come from**, and — for the lock reason below — *when
they are read*. Nothing else about the build changes:

1. `listEnabled(child)` is empty, and inheritance is wired.
2. Walk the ancestors nearest-first. An ancestor with **no enabled providers has
   nothing to lend**, so the walk continues past it without asking its switch —
   asking would let a silent middle layer block a decision made further up.
3. **The first ancestor WITH providers decides, by its switch, and there is no
   skipping past it.** ON: its records are used. OFF: the walk ends here, and a
   grandparent's providers are NOT substituted.
4. The borrowed record's own `TenantID` is ignored; only the provider
   definitions are used.
5. The registry is built with **`tenantID = the child`**, so `redirectFor` returns
   the child's callback URL, and the cache entry is stored under the child's key.

Step 3 is the rule that is easy to get wrong in the other direction. A group that
keeps its own IdP and has not opted in is saying *"children configure their own"*.
Walking past it to a grandparent would override a decision the group actually
made, so the walk stops — rejected: skip past a refusing ancestor.

Step 5 is the security decision of this axis and it is not a detail. Building the
ancestor's registry and handing it to the child would carry the *ancestor's*
redirect URI into the child's login flow: the IdP would then complete a flow that
lands in the wrong tenant's context. SAML has the same seam under a different name
— `spMetadataURLForTenant` (`saml/manager.go:92-95`, `131-141`) is the tenant-aware
form of the SP metadata URL, so "compile it for the child" means the child's
metadata URL and the child's ACS URL, not the group's. Borrowing the definition and compiling it for
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
- **The nil result is still CACHED, with a fresh timestamp, whether it came from
  having no providers or from having nothing to inherit.** This is the existing
  invariant (`oidc/manager.go:464-473`) and inheritance makes it load-bearing for
  a new reason: the walk is 1+depth store reads, and `GetRegistry` is reachable
  with an attacker-chosen tenant id. Without the cache, an id that resolves to
  nothing would re-run the whole walk on every request — a cheap request becoming
  a store-read amplifier. The emptiness must expire on the same TTL as a real
  registry, exactly as it does today.

**Where the walk runs: before the lock.** `rebuildLocked` is called with `mu`
held, and the manager's promise is that concurrent stampedes for the *same*
tenant serialise while different tenants never wait on each other
(`oidc/manager.go:345-349`). An ancestor walk inside that lock would make every
tenant's rebuild wait on the hierarchy store — one slow store read turning a
per-tenant serialisation into a global one. So the inherited records are resolved
**outside** `mu`, then handed to the build step, which stays as it is. The
double-checked locking is unchanged; only what happens before `Lock` grows.

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
// No TenantID field, on purpose — see below.
type DomainAuthority struct {
	AncestorID ID     // whose verification this claim rests on
	Domain     string // that ancestor's VERIFIED domain the name sits under
	ProviderID string // the ancestor's bound IdP, "" when none
}

func InheritedDomainAuthority(ctx context.Context, s Store, domains DomainStore,
	tenantID ID, domain string) (DomainAuthority, error)

func IsProperSubdomain(child, parent string) bool   // exported for the admin path
```

`tenantID` is an `ID` for the reason in §3. `DomainStore` is the one port that
still speaks strings (`ListForTenant(ctx, tenantID string)`), so the helper
converts at that boundary with `ID.String()` and nowhere else. `IsProperSubdomain`
stays pure strings: it is about domains, not tenants, and has no validity to
carry.

**The return type has no tenant in it, and that is the point.** The obvious
signature returns the matched `DomainRecord`, whose `TenantID` is the **ancestor**
— and the consumer that matters is the login path, which reads `rec.TenantID` to
decide who the user is logging in to (`espresso/startlogin.go:283`). Handing back
a record with the ancestor's tenant in it invites exactly one bug: an app passes
it along, and the user is routed into the *group* instead of the child.
Structurally prevented instead of documented: the value carries the authority
(`AncestorID`), the domain, and the provider to bind — and nothing a consumer
could mistake for "which tenant is this". The caller writes its own row for its
own tenant.

`ProviderID` is taken from `BoundProviderID()`, not the raw field
(`tenant/domain.go:66-71`), so the helper cannot pass on a binding that came from
an unproven claim even if the verified filter were later removed.

`InheritedDomainAuthority` walks ancestors nearest-first and, for each, asks
`domains.ListForTenant(ancestor)` for a **verified** claim that `domain` is a
proper subdomain of, returning the first match as a `DomainAuthority` naming the
ancestor it came from. A public email domain, no
matching claim, and an unverified ancestor claim are all `ErrNotFound` — the same
three-fold collapse `ResolveDomain` already documents, for the same reason. An
**unnormalised** input is the one thing said plainly (`ErrDomainNotNormalised`):
it is a caller bug, and `tenant/domain.go` rejects rather than repairs precisely
so an admin learns it once at the edge.

`IsProperSubdomain` is one line and it is where the takeover lives:

```
child != parent  &&  strings.HasSuffix(child, "."+parent)
```

The `.` is the whole guard: without it, `evilacme.com` is a "subdomain" of
`acme.com`. The mutation proof is dropping it.

**The boundary this helper deliberately stops at.** It answers *"may this child
claim this name?"*; it does not approve, store, or audit. The application records
the child's own claim row (`Verified: true`, plus whatever provenance columns it
keeps) and emits the audit row — `domain.inherit`, naming the group whose
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

### 4.4 Where two axes meet

Each axis is independent (invariant 10), which produces two combinations worth
naming, because both look like bugs and neither is.

**D2 without D3: the feature is paid for and no provider exists.** The entitlement
union says the child's `SSOEnabled` is true; the group never opted into IdP
inheritance, and the child configured nothing. The entitlement gate opens and
`GetRegistry` returns nil. That is not a contradiction: nil already means "not
configured" by contract (`oidc/provider.go:202`, `saml/builder.go:27`), and a
route must render that as such rather than as an error. Inheriting a plan is a
statement about money; it is not a promise that a provider row exists.

**D4 without D3: the claim names a provider this tenant cannot resolve.** The
`ProviderID` in a child's inherited domain claim is an id from the *group's*
records. The child's registry contains it only if the child inherits providers —
which needs D3 on for that group. So the rule at claim time is: **bind the
provider only when the child's own registry resolves it; otherwise leave it
empty.** Empty is a legitimate answer, and the login path already treats it as one
(`espresso/startlogin.go:272-278` — a verified domain with no IdP is the password
path, not an error). A claim that binds an unresolvable provider is a login that
fails for one customer and works for its sibling, which is the worst possible way
to discover the coupling.

Neither rule is enforceable in tamper: both need the application's write path.
Both are stated here so that the first deployment that hits them finds a
paragraph rather than a theory.

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
- `SAML.Inherit != nil` likewise.

Two guards, not three. "`Inherit` set while the engine config is nil" cannot be
written: `Config.OIDC` is a pointer, so there is no `OIDC.Inherit` to set when it
is nil. A guard that cannot fire is worse than absent — rule 6 asks for a guard
*and* a test that fires it, and this one could never be tested.

The store travels inside the inheritance config rather than at the top level,
because `tamper.New` has no tenant store today: parentage is the application's
graph, and this is the first framework code to read it. Each engine may be given
a different one; that is a feature, not an oversight.

`Ancestors`, `InheritingEntitlements` and `InheritedDomainAuthority` panic on a nil
store, matching `RequireEntitlement`'s precedent (`espresso/routes.go:294-297`): a
nil store is a wiring bug, and in a package whose rule is "no error return may be
read as allow", a nil one would silently permit.

---

## 6. Invariants

1. **Wiring is opt-in on every axis; a policy switch exists on one.** No axis is
   inheritance-by-default: an unwired deployment is today's behaviour, byte for
   byte. Above that, D3 adds a per-group switch, because an inherited IdP widens
   *who can authenticate*; D2 and D4 do not need one, because a plan and a name
   are things the customer has rather than powers over the request.
2. Inheritance widens what the customer HAS; it never changes which tenant a
   request is scoped to, and never grants a permission.
3. The ancestor walk fails closed: cycle, over-depth, dangling parent, a store
   error, or a policy error is an error, never "root" and never "allow".
4. The zero `ID` and `tenant.Single` both never walk — unset and deliberately
   single-tenant are different facts with the same answer, and neither is an
   error.
5. **Selection differs by axis, and deliberately.** IdP and domains take ONE
   source — first match walking up, whole, never a merge — so a child with its
   own providers, or its own matching claim, never consults an ancestor.
   Entitlements UNION the whole chain, because a capability is additive by
   nature (a plan merged with a plan is a plan) while two provider rows with one
   id are ambiguous. A union across the chain is not a merge of two answers to
   one question.
6. The IdP registry is compiled in the inheriting tenant's name: its redirect
   URLs and its cache key.
7. `MaxIdPConnections == 0` is unlimited on both sides of a `Union`, and a cap
   never narrows.
8. The union is the EFFECT; `ForTenant` remains the PURCHASE.
9. A domain is inherited only as a **proper** subdomain of a **Verified**
   ancestor claim, with the dot boundary intact.
10. Three axes, three wirings, independently chosen: turning one on changes no
    other axis's answer, and no axis's wiring can be inferred from another's.
11. `InheritedDomainAuthority` returns authority and writes nothing; approval and
    the audit row are the application's.
12. A cross-axis value must never be mistaken for the tenant: the domain authority
    carries no tenant, and an inherited domain binds an IdP only when the child's
    own registry resolves that provider.

---

## 7. Tests and mutation proofs

Every test below ships with at least one mutant that must turn it red, verified
to compile before it is counted.

**`tenant/hierarchy_test.go`**

| Test | Mutant |
|---|---|
| three-level chain, nearest-first | return the chain root-first |
| root tenant → empty, no error | treat `ParentID == ""` as an error |
| zero `ID` → empty, store never called | walk for an unset `ID` |
| `tenant.Single` → empty, store never called | walk for the single tenant |
| a `ParentID` of `""` mid-chain stops the walk and never yields `Single` | convert before checking emptiness |
| every returned id passes `Valid()` | return raw strings through a conversion that can produce unset |
| dangling parent → error | return the chain so far instead of failing |
| cycle → `ErrHierarchyCycle` | drop the visited set |
| depth > 32 → `ErrHierarchyDepth` | drop the bound |
| store error propagates | return nil, nil on any error |
| policy error aborts the walk | read `(false, err)` as a stop-with-nil |
| policy error never reaches a grandparent | continue the walk after an error |

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
| a providerless ancestor is passed over WITHOUT asking its switch (three levels) | ask the switch before checking providers |
| switch off, no ancestors → `(nil, nil)` | return an error |
| unknown tenant → `(nil, nil)`, not an error | propagate `ErrNotFound` |
| the child's redirect URL is used, not the parent's | build with the parent's id |
| SAML: the child's SP metadata URL and ACS URL are used | build with the parent's id |
| the registry is cached under the child's key | store it under the parent's |
| an inherited-empty result is cached too (`(nil, nil)` expires on the TTL) | skip `storeLocked` on the walked path |
| the walk does not run while `mu` is held | resolve inherited records inside `rebuildLocked` |
| inheritance unwired → today's behaviour | — (compile-time: no option, no field) |

**`tenant/domain_inheritance_test.go`**

| Test | Mutant |
|---|---|
| proper subdomain of a verified ancestor → a `DomainAuthority` naming that ancestor | return the ancestor's `DomainRecord` instead |
| `evilacme.com` vs `acme.com` → not found | drop the `"."` in `IsProperSubdomain` |
| the parent's own domain is not inheritable | allow equality |
| unverified ancestor claim → not found | ignore `Verified` |
| public email domain → not found | drop the public check |
| unnormalised input → `ErrDomainNotNormalised` | normalise silently |
| no ancestor claims the name → not found | return the nearest ancestor regardless |
| the returned value has no field usable as the resolved tenant | return the ancestor's `DomainRecord` |
| `ProviderID` comes from `BoundProviderID()` | return the raw record field |

**`provider_test.go`** — one test per boot guard, asserting the message names the
field.

---

## 8. What is still open

1. **Does the group's switch apply per child too?** This sketch reads D3 as the
   group's decision only: a child opts out by configuring its own providers, which
   is already "first match wins". A per-child consent flow is a bigger product
   change and is not designed here.
2. **When is the audit row `domain.inherit` emitted — at approval, or at first
   use?** Approval. First use would need a row per login, and the chain is
   append-only for a reason.
3. **Do inherited entitlements show on the customer's invoice?** Billing is the
   application's; the union is only the effective value. Nothing here changes what
   is invoiced.
4. **Should `ChildrenOf` land later anyway**, for provisioning? Not needed by any
   of these three axes. Left to the app, as ADR-0001 already does.
5. **Should `InheritingEntitlements` ship with a TTL cache?** Today the caller
   wraps it (§4.1). A built-in one would need a clock and a size bound, both of
   which this package has deliberately avoided; the decision is to leave it out
   until a deployment actually measures the walk.

---

## 9. Slices

- **12a — the primitive** (`tenant/hierarchy.go`: `Ancestors`, `Inheritance`, the
  two sentinels), the `oidc/manager.go:359-361` doc correction, and the four
  statements of the Phase 7 invariant that this amends (§3.1). Those ship in the
  same commit: the comment and the code that contradicts it must not coexist.
- **12b — entitlements** (`Union` + `InheritingEntitlements`). No engine touched,
  so the primitive gets a real consumer before any manager depends on it.
- **12c — IdP** (`oidc` + `saml` options, `tamper.New` wiring and guards, the
  redirect-in-the-child's-name test, the pre-lock walk).
- **12d — domains** (`IsProperSubdomain` + `InheritedDomainAuthority`).
- **12e — docs** (TD-04 in `tech-debt.md`, an ADR-0001 §8 note that three axes are
  now decided, `MIGRATION`, `CHANGELOG`, and this sketch to `accepted`).

The primitive lands first because both consumers need it and it is the smallest
thing that can be wrong in a way the others would inherit.

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
