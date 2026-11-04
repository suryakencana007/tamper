# Phase 14 — A dynamic tenant surface (TD-14)

Status: **accepted 2026-11-03, with A3 replaced by A4** — see §3.1, found while
starting 14b: A3's boot guard cannot be written in Go.

TD-14 is the last P2 that is tamper's own, and it is the only one whose remaining work
turned out to be **in the library rather than in the example**. §1 explains why, because
the item as written says the opposite.

---

## 1. Re-verification, per `/slice` step 1

The item's own evidence is stale in two places and correct in one:

| `tech-debt.md` claims | Verified against the code |
|---|---|
| *"`IdentityService.Login(ctx, email, password)` takes no tenant (`authroutes.go:39-41`)"* | **False now.** #59 gave every port method the tenant: `Login(ctx, tenantID, email, password)` (`espresso/authroutes.go:67`). The cited lines had already moved. |
| *"That adapter must still check the user's stored tenant on the TOTP path (see TD-10)"* | **False now.** TD-10 closed in #40, and since #100 (`identity`) the *library* performs the check. An adapter that re-checks is writing what it no longer owes. |
| *"`main.go:122` mounts one auth surface per tenant in a loop"* | **True.** `examples/multitenant/main.go:88` loops, `:142` passes `FixedTenant(...)`. |

And one thing the item does not say: **the dynamic pattern already exists** —
`examples/tenanthierarchy/http.go:76` passes `TenantFromRoutedContext` to its gate, with
`PinTenant`/`RequireTenantAllowEntered(RouteTenant)` in front of it. What is missing is
that the *multitenant* example — the one an application copies when it has tenant routes
— still shows the static loop.

**So the gap is not knowledge. It is that this example cannot be made dynamic without a
library change.** §2 is why.

---

## 2. The blocker, and the decision taken

The refresh cookie's `Path` **is** `MountPrefix`, by construction, and the
unconfigurability is deliberate: "the CSRF fence cannot be misconfigured". It is written
at **two** sites — the set (`espresso/authroutes.go:255`) and the **clear**
(`:270`, `MaxAge: -1`), which must carry attribute parity or some browsers ignore the
deletion. Both therefore need the per-request prefix, and the clear is the easy one to
miss: a logout that clears the wrong path deletes nothing and leaves the user logged in
on a route that has already signed them out.

A single surface serving dynamic tenants has a per-request prefix, so it needs a
per-request `Path` — and `MountPrefix` is a `string`.

**Product decision (2026-11-03): the cookie stays separated by PATH, not by name.**

Cookie identity is `(name, domain, path)`, so:
- the current per-tenant *names* (`mt_acme_refresh`) are **redundant** — the paths
  `/t/acme/auth` and `/t/globex/auth` are already distinct jar slots;
- one name plus a per-request path keeps what the example promises: **one browser can
  hold a session per tenant at the same time**. That property is the point; a shared
  single slot would evict the first session when the second tenant logs in, and the
  stale tab's next refresh would rotate a session that no longer exists.
- `EnterTenant` remains the answer to a *different* question (an admin acting as a guest
  inside a tenant, with a short-lived token), not a replacement for this.

What a cookie does **not** model: several *users* in one browser. Two humans in the same
tenant evict each other in every scheme here; that is unchanged and not what TD-14 is
about.

---

## 3. The one design problem this sketch must settle

Invariant to preserve: **Path always equals the concrete mount prefix of the request**,
because that equality *is* the CSRF fence. So the fix must make the prefix per-request
without ever letting the path be computed from something that is not the routing.

Three candidates were considered. **A3 has since been replaced by A4** — see §3.1, which
records why its guard cannot exist; the table below is kept because the reasoning is the
record of how A4 was reached.

| | Shape | Verdict |
|---|---|---|
| A1 | `CookiePath func(*http.Request) string`, separate from `MountPrefix` | **Rejected.** Two sources of truth for one value; the fence is "they are equal by construction", and this makes them equal by convention. |
| A2 | `MountPrefix` becomes `func(*http.Request) string` (a breaking change for every caller) | Rejected for now: it removes the guarantee that the prefix is a fixed string the router mounts at, and every caller pays to express a single-tenant constant. |
| **A3** | Keep `MountPrefix string`; add **`RouteTenant func(*http.Request) (tenant.ID, bool)`** and derive the path as `MountPrefix` with its tenant segment filled from that resolver | **Recommended.** The app already owns "how do I get the tenant out of this request" (`FixedTenant`, `TenantFromRoutedContext`, a path-param reader); the library owns "the cookie path is the mount prefix, resolved". One resolver, one derived path, fence intact. |

A3 keeps the single-source-of-truth property in the library and puts the *app-specific*
part (where the tenant lives in the URL) where it already lives: a resolver function of
the same shape the tenant gates take.

**But A3 has a trap of its own, and it is the same trap A1 was rejected for.** `Tenant`
and `RouteTenant` are two resolvers; if they can disagree, the cookie path can belong to
one tenant while the session is minted for another — and the request would then be
writing tenant A's cookie slot with tenant B's session, which is worse than either
candidate above. So A3 carries a hard rule:

- **With `RouteTenant` set, `Tenant` must be `TenantFromRoutedContext`** — the pin, not a
  second opinion. One resolver reads the request, pins the tenant, and everything after
  (the port's tenant argument, the cookie path, the audit scope) reads that pin.
- `RouteTenant` set together with `FixedTenant` is a **wiring error and fails at `New`**
  (standing rule 6: the guard ships with a test that it fires). A fixed tenant cannot
  serve a dynamic path, so the pair is not a configuration — it is a bug that would
  otherwise show up as one tenant's cookie under another tenant's path.

Sketch-level shape (not final until reviewed):

```go
// AuthRoutesConfig
MountPrefix string                        // unchanged: the mount, e.g. "/t/{tenant}/auth"
RouteTenant func(*http.Request) (tenant.ID, bool)  // NEW, optional: resolve the tenant segment

// resolved per request, internally:
//   prefix = authPrefixFor(MountPrefix, RouteTenant(r))
//   cookie.Path = prefix            // fence: still by construction
//   Tenant (existing) may be TenantFromRoutedContext, which reads the pin
```

**Fail closed**: `RouteTenant` returns `(zero, false)` ⇒ the route answers the
`NOT_FOUND` the tenant gates already answer, and no cookie is written.

### 3.1 A3 is unimplementable, and A4 is what replaces it

Starting 14b found the hole in one grep: **`FixedTenant` returns a plain function**
(`espresso/authroutes.go:218`), and Go cannot compare functions. So "`RouteTenant` +
`FixedTenant` fails at `New`" — the guard A3 leaned on to stop two disagreeing resolvers —
**cannot be written**. A guard that cannot exist is exactly what standing rule 6 forbids:
an upgrade shipped without the test that proves its guard fires.

A3 also still carried the defect it was trying to manage rather than remove: two
resolvers that *can* disagree, plus a runtime rule that they must not. Removing the
second resolver is better than policing it, so:

**A4 — one resolver, and a template in the mount prefix.**

```go
const TenantPathSegment = "{tenant}"        // the placeholder, exported and documented

MountPrefix: "/t/{tenant}/auth"             // a template; unchanged field
Tenant:      TenantFromRoutedContext        // the ONE resolver, unchanged field
// per request:  prefix, ok := authPrefixFor(MountPrefix, tid)   // tid from Tenant
//               cookie.Path = prefix                            // set AND clear
```

- **No new config field**, so there is no pair to conflict: the tenant that decides the
  path is the same value `Tenant` already returned and the same one passed to the port.
  Invariant 1a becomes structural instead of enforced.
- **`authPrefixFor(mount, tid)`** returns `(mount, true)` when the template has no
  placeholder (single-tenant and every existing caller, byte-identical), and
  `(replaced, true)` when it does and `tid` is a real tenant. It returns `("", false)`
  when the template has the placeholder and `tid` is unset or `tenant.Single` — the
  `NOT_FOUND` path, no cookie written or cleared.
- **A dynamic prefix without a dynamic resolver is caught where it can be**: at
  `NewAuthRoutes`, a `MountPrefix` containing `{tenant}` is accepted (it needs nothing
  else), but a request that resolves `tenant.Single` under it fails closed instead of
  writing a cookie at `/t/{tenant}/auth`. That is a shape that *can* be tested, unlike a
  function comparison.
- `Set-Cookie` for a template prefix that resolves properly is
  `/t/acme/auth`; the placeholder never reaches a browser.

**Why `{tenant}` and not `:tenant`.** It is the spelling the repo already reads:
`examples/tenanthierarchy` resolves its path parameter with `r.PathValue(OrgParam)`
(Go 1.22 `ServeMux` syntax), so the mount pattern a deployment writes and the template
this phase substitutes are **the same string**. One constant serves both ends, which is
also what keeps them from drifting apart.

The cost, stated: `{tenant}` is a literal the app must not accidentally use in a real
path. It is exported as `TenantPathSegment` so the collision is nameable, and
`authPrefixFor` refuses rather than guessing when substitution cannot happen.

---

## 4. Invariants

1. `cookie.Path` equals the request's concrete mount prefix, **on both the set and the
   clear**. No exception, no caller override.
1a. One resolver decides the tenant for the whole request — structurally: the value that
    fills `{tenant}` is the same value passed to the port, because there is only one.
2. The tenant segment comes from **routing**, never from the token, the body, or the
   cookie itself. A token naming another tenant cannot move the cookie path.
3. A request under tenant X never reads tenant Y's cookie — asserted with a real cookie
   jar holding both, not by inspection of the `Set-Cookie` header alone.
4. An unresolvable tenant writes no cookie and answers `NOT_FOUND`, indistinguishable
   from a tenant that does not exist.
5. Single-tenant deployments are unchanged: no `RouteTenant`, `MountPrefix` is used
   verbatim, `Path` is what it was, cookies are the same bytes.
6. The example's property survives: one browser, two tenants, two live sessions.

---

## 5. Tests and mutation proofs

| Test | Mutant |
|---|---|
| a request under `/t/acme/auth/...` sets `Path=/t/acme/auth` | use `MountPrefix` verbatim as the path |
| a jar holding both tenants' cookies sends only the matching one to each route | set `Path=/` |
| an unresolvable tenant sets no cookie and answers `NOT_FOUND` | default to `tenant.Single` on a failed resolve |
| a token for another tenant cannot move the cookie path | resolve the tenant from the claims |
| `Logout` clears **that tenant's** path (`MaxAge=-1`) and the jar actually drops it | clear `MountPrefix` verbatim while the set uses the derived prefix |
| a template prefix under an unresolvable tenant sets and clears **no** cookie | substitute anyway with `""` |
| a static prefix (`/api/auth`) is byte-identical to before | run the substitution unconditionally |
| single-tenant: byte-identical `Set-Cookie` before and after | (golden header test) |

---

## 6. Slices

1. **14a — this sketch**, accepted, with A3 decided.
2. **14b — `espresso`**: `RouteTenant`, `authPrefixFor`, the cookie path derived from it,
   the fail-closed answer, and the five tests above.
3. **14c — `examples/multitenant`**: one dynamic surface, `PinTenant` +
   `TenantFromRoutedContext`, per-tenant names dropped in favour of the path.
4. **14d — docs**: TD-14 closed in `tech-debt.md` **with its two stale claims corrected**
   (a reader who trusted them would have written the adapter check twice), `flow.md`,
   `CHANGELOG`. Breaking only if A3 turns out to need a config change for existing
   callers; as sketched it is additive.

---

## 7. What this does not do

- It does not change `Entered`/impersonation semantics, and it does not make the cookie
  carry a tenant.
- It does not touch the `identity` surface (TD-28 removed the tenant-less paths there;
  nothing here reopens that).
- It does not change subdomain-based tenancy. If a deployment resolves the tenant from
  the host rather than the path, A3's resolver still fits — the *path* then stays the
  fixed mount prefix, and cookie isolation comes from the host, which is the `domain`
  half of the cookie identity.
- It does not close TD-11, TD-12 or TD-13.
