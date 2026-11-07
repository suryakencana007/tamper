# Phase 4e — SCIM transport lift: design sketch

> Status: **DESIGN — pre-implementation.** This is the port-design gate the
> transport lift waits on (PHASE4-TRANSPORT-PLAN.md §4e, lines 274-282).
> Nothing here is code yet. It resolves the open questions the 4e scoping
> pass surfaced, drafts the `scim.UserStore` / `scim.GroupStore` port
> shapes, and fixes the sub-PR arc. Reuses the 4d amendments
> (PHASE4D-BOUNDARY-DECISION.md): **A2** (app projects), **A10** (app
> registers, no Mount), **A11** (a lift moves its tests). A9
> (resolve-before-burn) has **no** SCIM analogue — do not cargo-cult it.

## 0. Scope — corrected

- **Sanctioned lift-time fix (the only one for 4e):** the advertised-vs-actual
  `maxResults` drift. `ServiceProviderConfig` advertises `Filter.maxResults=200`
  (`handler/scim/config.go:49`) while the List handler enforces 100. The lift
  derives the discovery flag from the actual mounted cap. **Direction chosen:
  advertise the real cap (100).** A later, versioned PR can raise both together
  if 200 is wanted.
- **`CanonicalVersion` stamping is NOT a fix and NOT in scope.** The plan lists
  it as a *reproduce-byte-identically* NON-goal (#10 / Decision D3), and it is
  an audit-chain concept absent from all SCIM code. Reproduce SCIM's ETag /
  version behaviour byte-for-byte; change nothing.
- The two genuinely-sanctioned *phase-wide* fixes (`RequireAuthWS→VerifyAccess`,
  `stepUpNow` per-instance clock) shipped in 4a/4b and are not 4e.

## 1. What lifts, what stays

Most of the RFC substrate already lifted in Phase 3e (filter Parse/Translate,
the PATCH applier, `DetectCycle`, and the `RequireServiceAccount` gate +
`Principal` + §3.12 error envelope in `tamper/espresso`). 4e lifts the **HTTP
transport** on top of it.

| Tamper owns (protocol-mechanic) | Barista owns (app policy) |
|---|---|
| The Users + Groups route methods on a `SCIMRoutes` type; discovery endpoints | Route paths, `/scim/v2` prefix, the per-route `RequireServiceAccount` wrap, the `enabled` gate |
| Wire DTOs (`userResource`/`groupResource`/`resourceMeta`/`listResponse`/…) | The `scim.UserStore` / `scim.GroupStore` port **implementations** |
| ETag emission + If-Match precondition (`etag.go` — pure RFC 7232, zero app deps) | `ColumnMapping` (the attr→column schema; IS Barista's schema) |
| §3.12 error envelope + `scimType` codes (dedupe with the already-lifted SA-gate copy) | Audit vocabulary + emission (tamper never emits — **A3**) |
| PATCH map round-trip (`Apply` is already tamper/scim) | `SCIMConfig` literal *values* (baseURL, bulkMax, doc URI, auth-scheme text) |
| Bulk dispatcher + inner router (→ `tamper/espresso`; excludes Bulk+Me) | **`/Me`** (synthetic SA URN — stays app-side, see §6) |
| Discovery flags derived from mounted features (maxResults fix) | `/admin/scim/bulk-history` (audit-log read surface — not SCIM protocol) |
| The `scim.UserStore` / `scim.GroupStore` port **interfaces** | Validation policy (userName-required, PUT-resets-to-zero, member-type default) |

**The blocker being removed:** `RegisterRoutes` takes concrete
`*service.AuthService` + `*service.GroupService` (`handler/scim/router.go:31-32`).
4e replaces them with app-implemented store ports, exactly as
`internal/identity/store.go` implements `tamperidentity.Store` for 2b/4d.

## 2. Central design — the projection seam

The service methods all return Barista domain types (`*domain.User` /
`*domain.Group`); tamper must not know those. So the port trades in **neutral
records**, and Barista's port impl owns the projection in both directions:

- **Inbound:** the transport parses the RFC wire (`userName`, member refs) into a
  neutral **write** struct and hands it to the port. The impl applies Barista's
  policy — `userName=email`, member id resolution, `source='scim'` filtering,
  the `ActorServiceAccountID` threading — then calls `AuthService`/`GroupService`.
- **Outbound:** the port returns a neutral **record**; the transport renders it
  into the RFC DTO (`userName`, `$ref` from baseURL, `meta.location`, weak-ETag
  `version` from the record's `Updated`).

This is **A2 applied to SCIM**: the RFC DTOs are standard, so they lift *into*
tamper (unlike 4d, where the app's user DTO stayed app-side); what stays
app-side is the *projection* — `userName=email`, soft-disable DELETE, group
nesting — inside the port impl.

## 3. The ports (draft — 4e-2 finalises exact fields)

Placed in `packages/tamper/scim`, alongside the existing `ColumnMapping` /
`GroupMemberQueries` seams.

```go
// Neutral records the transport renders into RFC DTOs. Updated is the
// weak-ETag / meta.version source; the transport builds $ref + location
// from cfg.BaseURL, so those are NOT on the record.
type UserRecord struct {
    ID         string
    UserName   string      // app projects (Barista: = email)
    FamilyName string
    GivenName  string
    Formatted  string
    Emails     []Email     // v1.0: 0 or 1
    Active     bool
    ExternalID string
    Created    time.Time
    Updated    time.Time
}
type Email struct{ Value string; Primary bool; Type string }

type GroupRecord struct {
    ID          string
    DisplayName string
    ExternalID  string
    Members     []MemberRef // resolved; transport adds $ref
    Created     time.Time
    Updated     time.Time
}
type MemberRef struct{ Value string; Type string; Display string } // Type: "User"|"Group"

// Neutral writes: the RFC-parsed inbound shape, pre-projection.
type UserWrite struct {
    UserName   string
    FamilyName string
    GivenName  string
    Emails     []Email
    Active     bool
    ExternalID string
}
type GroupWrite struct {
    DisplayName string
    ExternalID  string
    Members     []MemberRef // raw refs; the impl resolves + validates
}

// Page is a resource page + the unfiltered/ filtered total for the
// ListResponse envelope.
type UserPage struct{ Users []UserRecord; Total int }
type GroupPage struct{ Groups []GroupRecord; Total int }

type UserStore interface {
    Create(ctx context.Context, w UserWrite) (UserRecord, error)
    Get(ctx context.Context, id string) (UserRecord, error)
    Replace(ctx context.Context, id string, w UserWrite) (UserRecord, error)
    Delete(ctx context.Context, id string) error // impl chooses soft-disable
    List(ctx context.Context, startIndex, count int) (UserPage, error)
    // ListFiltered receives the tamper/scim.Translate output. Injection is
    // bounded by ColumnMapping (the accepted Phase-3e precedent); the impl
    // binds args positionally.
    ListFiltered(ctx context.Context, startIndex, count int, where string, args []any) (UserPage, error)
    // SavePatch persists a PATCH-mutated record. The transport applies the
    // RFC patch (tamper/scim.Apply) to the rendered map, projects the result
    // to a UserWrite-like delta, and hands it here — kept distinct from
    // Replace because PATCH is partial + Barista skips manual/oidc wins.
    SavePatch(ctx context.Context, id string, w UserWrite) (UserRecord, error)
}

type GroupStore interface {
    Create(ctx context.Context, w GroupWrite) (GroupRecord, error)
    Get(ctx context.Context, id string) (GroupRecord, error)
    Replace(ctx context.Context, id string, w GroupWrite) (GroupRecord, error)
    Delete(ctx context.Context, id string) error
    List(ctx context.Context, startIndex, count int) (GroupPage, error)
    ListFiltered(ctx context.Context, startIndex, count int, where string, args []any) (GroupPage, error)
    SavePatch(ctx context.Context, id string, w GroupWrite) (GroupRecord, error)
}
```

Errors cross as tamper/scim sentinels the transport maps to §3.12 codes
(`ErrNotFound`→404, a uniqueness sentinel→409 `uniqueness`, an invalid-value
sentinel→400). The impl folds Barista's `domain.Err*` onto these — the same
`foldAuthErr`-style seam 4d uses.

## 4. Crossing the boundary — per concern

- **PATCH.** Transport: `Get` → render to `map[string]any` → `tamperscim.Apply`
  (already lifted) → project the mutated map to a `UserWrite`/`GroupWrite` delta
  → `SavePatch`. The manual/oidc-membership-wins skip stays in the impl.
- **Filtered List.** Transport: `tamperscim.Parse` → `tamperscim.Translate(expr,
  cfg.UserColumnMapping)` → `(where,args)` → `ListFiltered`. The `ColumnMapping`
  is app data, injected via `SCIMConfig` (one per resource). The whitelist is the
  injection fence — unchanged from 3e.
- **Member resolution.** The impl resolves + validates member ids (defaults
  missing `type` to `User`, refuses non-SCIM rows), because that reads Barista's
  user/group tables and applies `source='scim'` policy.
- **ETag / version.** `record.Updated` → transport computes weak ETag
  `W/"<unix-nanos>"` (verbatim from `etag.go`). Barista's migration-034 AFTER
  UPDATE triggers keep `updated_at` fresh; that stays in the impl. Reproduce
  byte-identically (NON-goal #10).
- **Audit.** Stays app-side, emitted **by the port impl** (it holds before/after
  via Get-then-write and reads the SA `Principal` from `ctx`). Transport facts
  the payload needs (e.g. `if_match_present`) thread in via a small `WriteMeta`
  on the write methods so audit stays byte-identical. Tamper never emits a row
  (A3). *(Alternative considered: a single audit hook — rejected as a big switch
  over ~10 distinct actions; per-method emission in the impl is cleaner.)*

## 5. Bulk dispatcher → `tamper/espresso`

`bulk.go` builds a fresh `espresso.Portafilter()` inner router and replays
sub-ops through `httptest` recorders — it needs the router + net/http, so it
lands in `tamper/espresso` (the transport layer), **not** `tamper/scim` (the
pure protocol substrate). Invariants to preserve, pinned by a moved test:

- The inner router mounts the **Users+Groups methods only — Bulk and Me
  excluded** (recursion is the bug; `bulk.go:283-309`).
- Sub-ops **inherit the outer request context** so the `Principal` + audit actor
  survive (`bulk.go:195`).
- `failOnErrors` **halts without rolling back** prior successes; `op.Version` →
  inner `If-Match` forwarding is preserved.

## 6. `/Me` stays app-side

`/Me` synthesises a non-standard `urn:barista:scim:schemas:1.0:ServiceAccount`
because the v0.8 service-account model has no `owner_user_id` (`me.go:22`). It is
already excluded from the bulk inner router. Rather than invent a generic
self-discovery mechanic in tamper for a one-off SA shape, **`/Me` stays app-side
in 4e** — Barista keeps registering it with its own handler. Revisit only if a
future cycle adds `OwnerUserID` (then a generic self-endpoint with an injected
URN + an owner-projection hook becomes worth it). This keeps the lift to the
standard Users/Groups/Bulk/discovery surface.

## 7. Discovery + the maxResults fix

Tamper owns the response *shapes*; the *values* are injected via `SCIMConfig`
(documentationURI, auth-scheme description text, baseURL, bulkMax). Capability
flags derive from what's actually mounted — in particular the advertised
`filter.maxResults` reports the transport's real enforced cap (**100**), closing
the drift. Parity bar: connector-validation golden responses
(ServiceProviderConfig / ResourceTypes / Schemas) byte-diffed modulo the injected
literals.

## 8. `SCIMRoutes` shape + registration (A10)

```go
type SCIMConfig struct {
    Prefix             string // "/scim/v2" (app wire surface, injected)
    BaseURL            string
    MaxResults         int    // 100 — advertised AND enforced
    BulkMaxOperations  int
    DocumentationURI   string
    AuthSchemeDesc     string
    UserColumnMapping  scim.ColumnMapping
    GroupColumnMapping scim.ColumnMapping
}
func NewSCIMRoutes(cfg SCIMConfig, users scim.UserStore, groups scim.GroupStore) (*SCIMRoutes, error)
```

Validated at wiring time (like `NewFederationRoutes`). **The app registers each
method on its own router and applies the `RequireServiceAccount` wrap — no
Mount** (A10; Espresso `Use` is positional). The transport-plan text that still
says "mounts SCIM under `cfg.SCIM.Prefix`" (:182) predates A10; 4e applies A10.

## 9. The A11 wiring guard

No `server_scim_wiring_test.go` exists today, so the invariant "SCIM sits above
`r.Use(RequireAuth)` and is wrapped by `RequireServiceAccount`, **not**
`RequireAuth`" is **unguarded** — a lift could silently re-auth SCIM under the
wrong gate and every handler test would stay green. Author it *with* the lift
(mirroring `server_saml_wiring_test.go` / `server_oidc_wiring_test.go`),
driven through the real `NewServer`, and prove it bites via a compiling
mutation. Move the handler test corpus (`scim_test.go`, `scim_task01_test.go`,
`bulk_me_nesting_test.go`, `admin_scim_audit_test.go`) with the mechanic (A11).

## 10. Sub-PR arc

1. **4e-1 — this sketch** (doc). ← you are here.
2. **4e-2 — ports + adapter.** `scim.UserStore`/`scim.GroupStore` + record/write
   types in `tamper/scim`; Barista implements them over `AuthService`/
   `GroupService` and the handlers switch to call the ports. *No transport moved
   yet* — proves the port shape end-to-end behind the existing handlers.
3. **4e-3 — leaf mechanics.** Lift `etag` + `dto` + the §3.12 error envelope into
   tamper; façade aliases; dedupe the error copy with the SA-gate one.
4. **4e-4 — discovery + maxResults.** Lift the discovery endpoints; advertise 100;
   connector-validation golden diff.
5. **4e-5 — Users/Groups CRUD + List + PATCH** onto the ports; audit crossing
   (port-impl-emits + `WriteMeta`).
6. **4e-6 — Bulk + delete corpses + A11 guard.** Lift the bulk dispatcher into
   `tamper/espresso`; delete `handler/scim/` transport files; author
   `server_scim_wiring_test.go`; move the test corpus. (`/Me` stays app-side.)

## 11. Resolved questions

| # | Question | Decision |
|---|---|---|
| 1 | Port granularity | Fine-grained CRUD+List+ListFiltered+SavePatch, like `identity.Store`. |
| 2 | Port returns domain or neutral type | Neutral `UserRecord`/`GroupRecord`; impl projects (§2). |
| 3 | `userName=email` projection home | Port impl (app side). |
| 4 | `(where,args)` crossing | `ListFiltered(where,args)`; injection fenced by `ColumnMapping`. |
| 5 | `ColumnMapping` home | App data, injected via `SCIMConfig`. |
| 6 | Audit crossing | App-side, emitted by port impl; transport threads `WriteMeta`. |
| 7 | Bulk dispatcher home | `tamper/espresso`; inner router excludes Bulk+Me. |
| 8 | `/Me` | Stays app-side in 4e. |
| 9 | maxResults direction | Advertise the real cap (100). |
| 10 | Mount? | No Mount — app registers (A10). |
| 11 | A9 param | None — no burned artifact in SCIM. |

**Flagged for review:** whether `SavePatch` should be a distinct port method
(this sketch) or PATCH should reduce to targeted field updates the impl already
has (`SetSCIMUserName` etc.) — a 4e-2/4e-5 detail, not a boundary decision.
