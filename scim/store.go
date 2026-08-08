package scim

import (
	"context"
	"errors"
	"time"
)

// Phase 4e — the SCIM transport's persistence ports.
//
// The transport (Users/Groups route methods, lifting in later 4e slices)
// never touches the app's tables or domain model. It trades in the
// NEUTRAL records below, and the app implements these ports to project
// its own schema onto them — the same "the mapping IS the app's schema"
// seam ColumnMapping established in Phase 3e, now for CRUD. This file is
// the port half; the app's adapter (Barista: internal/scimstore) is the
// implementation half.
//
// This file ships the UserStore + GroupStore ports and their adapters
// (Barista: internal/scimstore). The SavePatch method (the RFC 7644
// §3.5.2 PATCH persist) and the handler rewire onto these ports follow in
// subsequent 4e slices — see PHASE4E-SCIM-SKETCH.md.

// Store-port sentinels. The transport maps these onto the RFC 7644 §3.12
// error envelope: ErrNotFound → 404, ErrConflict → 409 (scimType
// "uniqueness"), ErrInvalidInput → 400 ("invalidValue"). A port
// implementation folds its own app errors onto these (errors.Is-wrapped),
// keeping the transport ignorant of the app's error taxonomy.
var (
	ErrNotFound     = errors.New("scim store: not found")
	ErrConflict     = errors.New("scim store: conflict")
	ErrInvalidInput = errors.New("scim store: invalid input")
)

// Email is a SCIM multi-valued email (RFC 7643 §4.1.2). v1.0 carries
// zero or one; Type/Primary are app-projection choices the transport
// renders verbatim.
type Email struct {
	Value   string
	Primary bool
	Type    string
}

// UserRecord is the neutral projection a UserStore returns. The transport
// renders it into the RFC 7643 core:User wire shape, deriving the fields
// it owns from cfg + the record: userName is UserName; $ref and
// meta.location come from the base URL; meta.version is the weak ETag of
// Updated. The app's adapter owns the projection FROM its domain model
// (Barista: userName = email).
type UserRecord struct {
	ID         string
	UserName   string
	FamilyName string
	GivenName  string
	Emails     []Email
	Active     bool
	ExternalID string
	Created    time.Time
	Updated    time.Time // weak-ETag / meta.version source
}

// UserWrite is the RFC-parsed inbound shape a UserStore persists,
// pre-projection. UserName is ALREADY resolved by the transport — the
// SCIM userName, or, when the client omitted it, the primary emails[]
// value (RFC 7644 lets the IdP send the email in either place). That
// resolution (pickUserName) is a transport concern; the adapter maps the
// resolved UserName onto the app's write model (Barista: → email, plus
// the name-column update). There is no Emails field: v1.0 stores exactly
// one email and it IS the userName, so the write carries no separate
// email list.
type UserWrite struct {
	UserName   string
	FamilyName string
	GivenName  string
	Active     bool
	ExternalID string
}

// UserPage is a resource page plus the (filtered) total the SCIM
// ListResponse envelope reports as totalResults.
type UserPage struct {
	Users []UserRecord
	Total int
}

// WriteMeta carries the request-scoped facts a write's audit payload needs
// but that the port impl can't see once the transport has lifted into
// tamper — the audit stays app-side (emitted by the port impl, amendment
// A3), so the transport threads these facts down.
//
// IfMatchPresent records whether the mutation carried an If-Match
// precondition header; the impl folds it into the audit row so the pre-lift
// `if_match_present` marker stays byte-identical. Create ignores it (POST
// has no If-Match); Replace and Delete honor it.
//
// Before is the pre-write record the transport already read (for the
// If-Match precondition) — the SAME snapshot, so the impl's audit Before
// payload is the exact state If-Match validated against, preserving the
// pre-lift handler's single-read invariant (audit Before == If-Match
// snapshot) that a second impl-side read would break under a concurrent
// same-row write. nil on Create (no before-state); non-nil on Replace and
// Delete, where the transport has always read it before reaching the port.
type WriteMeta struct {
	IfMatchPresent bool
	Before         *UserRecord
}

// UserStore is the app-implemented persistence port the SCIM Users
// transport calls, fine-grained like tamperidentity.Store. startIndex is
// 1-based (RFC 7644 §3.4.2); count is the already-capped page size.
// ListFiltered receives a WHERE fragment + positional args produced by
// Translate over the app's ColumnMapping — injection is fenced by that
// whitelist (the accepted Phase-3e precedent), and the adapter binds args
// positionally.
// The write methods (Create/Replace/Delete) take a WriteMeta so the impl
// can emit byte-identical audit rows app-side (A3); the read methods do not.
type UserStore interface {
	Create(ctx context.Context, w UserWrite, meta WriteMeta) (UserRecord, error)
	Get(ctx context.Context, id string) (UserRecord, error)
	Replace(ctx context.Context, id string, w UserWrite, meta WriteMeta) (UserRecord, error)
	Delete(ctx context.Context, id string, meta WriteMeta) error
	// SavePatch persists a PATCH-mutated user (the transport applies the RFC
	// 7644 §3.5.2 ops to the resource, then hands the resolved write here).
	// It is distinct from Replace: PATCH is a partial update that does NOT
	// reset the name columns Replace resets. ops is passed through for the
	// impl's redacted-ops audit row (the transport emits none — A3).
	SavePatch(ctx context.Context, id string, w UserWrite, ops []Operation) (UserRecord, error)
	List(ctx context.Context, startIndex, count int) (UserPage, error)
	// ListFiltered takes the RAW client filter string — the impl owns
	// Parse+Translate (so it holds the ColumnMapping + the SQL dialect) and
	// emits the read-audit with the raw filter (A3). A filter-syntax error
	// folds to ErrInvalidFilter (transport → 400 invalidFilter).
	ListFiltered(ctx context.Context, startIndex, count int, filter string) (UserPage, error)
}

// MemberRef is a SCIM group member (RFC 7643 §4.2.1). Type is "User" or
// "Group"; an empty Type is treated as "User" (the SCIM v1.0 default).
// On a read the app has already resolved the type; on a write the
// transport passes the client's value verbatim and the adapter defaults
// + validates. The transport builds members[].$ref from the base URL +
// Value + Type; the record carries no $ref.
type MemberRef struct {
	Value string
	Type  string
}

// GroupRecord is the neutral projection a GroupStore returns. Members is
// the SCIM-sourced membership ONLY — the app filters out manual/OIDC rows
// so the SCIM client sees only what it manages. Updated feeds the weak
// ETag / meta.version.
type GroupRecord struct {
	ID          string
	DisplayName string
	ExternalID  string
	Members     []MemberRef
	Created     time.Time
	Updated     time.Time
}

// GroupWrite is the RFC-parsed inbound shape a GroupStore persists.
// ActorServiceAccountID is the calling service account the transport
// resolves from the request Principal (the app attributes the write to
// it). Members carry resolved-or-empty types; the adapter validates each
// id exists, defaults a missing type to User, splits User/Group, and
// refuses nesting a non-SCIM group through the SCIM channel.
type GroupWrite struct {
	DisplayName           string
	ExternalID            string
	Members               []MemberRef
	ActorServiceAccountID string
}

// GroupPage is a resource page plus the (filtered) total.
type GroupPage struct {
	Groups []GroupRecord
	Total  int
}

// GroupWriteMeta is WriteMeta's Group twin — the transport-only facts a
// Group write's audit payload needs, threaded down so the impl emits a
// byte-identical row (A3; tamper emits nothing). Before is the transport's
// pre-write GroupRecord snapshot (the If-Match-validated state), so the
// audit Before is race-free with a concurrent same-row write; nil on Create.
type GroupWriteMeta struct {
	IfMatchPresent bool
	Before         *GroupRecord
}

// GroupStore is the app-implemented SCIM Groups persistence port. Create
// and Replace run the app's nested-group cycle check; a cyclic write
// surfaces ErrCyclicGroup (defined in nesting.go), which the transport
// maps to CIRCULAR_GROUP_REFERENCE. A member id the store can't resolve
// folds to ErrInvalidInput. The write methods take a GroupWriteMeta so the
// impl emits the app-side scim.group.* audit byte-identically.
type GroupStore interface {
	Create(ctx context.Context, w GroupWrite, meta GroupWriteMeta) (GroupRecord, error)
	Get(ctx context.Context, id string) (GroupRecord, error)
	Replace(ctx context.Context, id string, w GroupWrite, meta GroupWriteMeta) (GroupRecord, error)
	Delete(ctx context.Context, id string, meta GroupWriteMeta) error
	// SavePatch persists a PATCH-mutated group (the transport applies the
	// RFC 7644 §3.5.2 ops, then hands the resolved write here). Distinct from
	// Replace — it calls the app's SaveGroupFromSCIMPatch. The impl resolves
	// members + emits the redacted-ops audit; ops threads through for it.
	SavePatch(ctx context.Context, id string, w GroupWrite, ops []Operation) (GroupRecord, error)
	// ValidateMembers validates the members[] (each id exists + is
	// SCIM-managed) WITHOUT mutating — the transport calls it up-front on
	// Replace so a bad member is reported (ErrInvalidInput → 400) BEFORE the
	// existence + If-Match checks, matching the pre-lift handler's ordering.
	// Create needs no separate call (its member validation already precedes
	// the write, with no existence/If-Match ahead of it).
	ValidateMembers(ctx context.Context, members []MemberRef) error
	List(ctx context.Context, startIndex, count int) (GroupPage, error)
	// ListFiltered takes the RAW client filter string (see UserStore).
	ListFiltered(ctx context.Context, startIndex, count int, filter string) (GroupPage, error)
}

// --- Phase 7: pooled multi-tenancy -----------------------------------
//
// TenantScopedUserStore is the pooled-multi-tenancy upgrade of
// UserStore: the same surface, plus a tenant-constrained form of every
// method that can cross a tenant boundary. All seven can, which is why
// all seven are here — shrinking the list is exactly where a leak gets
// in.
//
// OPTIONAL interface, the same mechanism identity.Store and
// oidc.ProviderStore already use. Implementing it is additive: an
// existing UserStore keeps compiling and keeps its behavior, and a ""
// tenantID selects the single-tenant table shape it already has.
//
// The tenant reaches these methods from the VALIDATED SERVICE-ACCOUNT
// TOKEN and from nowhere else — never a URL path segment, never a
// header. See espresso.Principal.TenantID.
//
// tamper still names no column. How a row is filed under a tenant is the
// application's schema; this port only says which tenant is asking.
//
// Implementations MUST be safe for concurrent use.
type TenantScopedUserStore interface {
	UserStore

	// CreateInTenant persists a new user INTO tenantID. The tenant is
	// stamped on the row here; it is not derived from the payload, which
	// the client controls.
	//
	// Isolation contract. The implementation MUST constrain the query to
	// tenantID and MUST return ErrNotFound — never a permission error and
	// never another tenant's row — when the addressed object belongs to a
	// different tenant. A "" tenantID selects the single-tenant table
	// shape. tamper cannot verify this; the cross-tenant leak suite
	// (§3.3) is the proof obligation that comes with implementing this
	// interface.
	CreateInTenant(ctx context.Context, tenantID string, w UserWrite, meta WriteMeta) (UserRecord, error)

	// GetInTenant reads one user by id WITHIN tenantID. An id belonging to
	// another tenant is ErrNotFound — the SCIM transport renders that as a
	// 404 byte-identical to a genuine miss, so the response cannot be used
	// to discover that a resource exists elsewhere.
	//
	// Isolation contract. The implementation MUST constrain the query to
	// tenantID and MUST return ErrNotFound — never a permission error and
	// never another tenant's row — when the addressed object belongs to a
	// different tenant. A "" tenantID selects the single-tenant table
	// shape. tamper cannot verify this; the cross-tenant leak suite
	// (§3.3) is the proof obligation that comes with implementing this
	// interface.
	GetInTenant(ctx context.Context, tenantID, id string) (UserRecord, error)

	// ReplaceInTenant rewrites a user WITHIN tenantID.
	//
	// Isolation contract. The implementation MUST constrain the query to
	// tenantID and MUST return ErrNotFound — never a permission error and
	// never another tenant's row — when the addressed object belongs to a
	// different tenant. A "" tenantID selects the single-tenant table
	// shape. tamper cannot verify this; the cross-tenant leak suite
	// (§3.3) is the proof obligation that comes with implementing this
	// interface.
	ReplaceInTenant(ctx context.Context, tenantID, id string, w UserWrite, meta WriteMeta) (UserRecord, error)

	// DeleteInTenant removes a user WITHIN tenantID.
	//
	// Isolation contract. The implementation MUST constrain the query to
	// tenantID and MUST return ErrNotFound — never a permission error and
	// never another tenant's row — when the addressed object belongs to a
	// different tenant. A "" tenantID selects the single-tenant table
	// shape. tamper cannot verify this; the cross-tenant leak suite
	// (§3.3) is the proof obligation that comes with implementing this
	// interface.
	DeleteInTenant(ctx context.Context, tenantID, id string, meta WriteMeta) error

	// SavePatchInTenant persists a PATCH-mutated user WITHIN tenantID.
	//
	// Isolation contract. The implementation MUST constrain the query to
	// tenantID and MUST return ErrNotFound — never a permission error and
	// never another tenant's row — when the addressed object belongs to a
	// different tenant. A "" tenantID selects the single-tenant table
	// shape. tamper cannot verify this; the cross-tenant leak suite
	// (§3.3) is the proof obligation that comes with implementing this
	// interface.
	SavePatchInTenant(ctx context.Context, tenantID, id string, w UserWrite, ops []Operation) (UserRecord, error)

	// ListInTenant pages the tenant's users. A page that included another
	// tenant's rows would leak on the very first unfiltered request an
	// integration makes.
	//
	// Isolation contract. The implementation MUST constrain the query to
	// tenantID and MUST return ErrNotFound — never a permission error and
	// never another tenant's row — when the addressed object belongs to a
	// different tenant. A "" tenantID selects the single-tenant table
	// shape. tamper cannot verify this; the cross-tenant leak suite
	// (§3.3) is the proof obligation that comes with implementing this
	// interface.
	ListInTenant(ctx context.Context, tenantID string, startIndex, count int) (UserPage, error)

	// ListFilteredInTenant pages the tenant's users under a client filter.
	// The tenant constraint is the implementation's, ANDed with the
	// translated filter — a client-supplied filter must never be the only
	// thing narrowing the query.
	//
	// Isolation contract. The implementation MUST constrain the query to
	// tenantID and MUST return ErrNotFound — never a permission error and
	// never another tenant's row — when the addressed object belongs to a
	// different tenant. A "" tenantID selects the single-tenant table
	// shape. tamper cannot verify this; the cross-tenant leak suite
	// (§3.3) is the proof obligation that comes with implementing this
	// interface.
	ListFilteredInTenant(ctx context.Context, tenantID string, startIndex, count int, filter string) (UserPage, error)
}

// TenantScopedGroupStore is the pooled-multi-tenancy upgrade of
// GroupStore. Same contract as TenantScopedUserStore, plus
// ValidateMembersInTenant — read its doc, it is the method most likely
// to be left untenanted and the one that leaks a WRITE when it is.
type TenantScopedGroupStore interface {
	GroupStore

	// CreateInTenant persists a new group INTO tenantID.
	//
	// Isolation contract. The implementation MUST constrain the query to
	// tenantID and MUST return ErrNotFound — never a permission error and
	// never another tenant's row — when the addressed object belongs to a
	// different tenant. A "" tenantID selects the single-tenant table
	// shape. tamper cannot verify this; the cross-tenant leak suite
	// (§3.3) is the proof obligation that comes with implementing this
	// interface.
	CreateInTenant(ctx context.Context, tenantID string, w GroupWrite, meta GroupWriteMeta) (GroupRecord, error)

	// GetInTenant reads one group by id WITHIN tenantID.
	//
	// Isolation contract. The implementation MUST constrain the query to
	// tenantID and MUST return ErrNotFound — never a permission error and
	// never another tenant's row — when the addressed object belongs to a
	// different tenant. A "" tenantID selects the single-tenant table
	// shape. tamper cannot verify this; the cross-tenant leak suite
	// (§3.3) is the proof obligation that comes with implementing this
	// interface.
	GetInTenant(ctx context.Context, tenantID, id string) (GroupRecord, error)

	// ReplaceInTenant rewrites a group WITHIN tenantID.
	//
	// Isolation contract. The implementation MUST constrain the query to
	// tenantID and MUST return ErrNotFound — never a permission error and
	// never another tenant's row — when the addressed object belongs to a
	// different tenant. A "" tenantID selects the single-tenant table
	// shape. tamper cannot verify this; the cross-tenant leak suite
	// (§3.3) is the proof obligation that comes with implementing this
	// interface.
	ReplaceInTenant(ctx context.Context, tenantID, id string, w GroupWrite, meta GroupWriteMeta) (GroupRecord, error)

	// DeleteInTenant removes a group WITHIN tenantID.
	//
	// Isolation contract. The implementation MUST constrain the query to
	// tenantID and MUST return ErrNotFound — never a permission error and
	// never another tenant's row — when the addressed object belongs to a
	// different tenant. A "" tenantID selects the single-tenant table
	// shape. tamper cannot verify this; the cross-tenant leak suite
	// (§3.3) is the proof obligation that comes with implementing this
	// interface.
	DeleteInTenant(ctx context.Context, tenantID, id string, meta GroupWriteMeta) error

	// SavePatchInTenant persists a PATCH-mutated group WITHIN tenantID.
	//
	// Isolation contract. The implementation MUST constrain the query to
	// tenantID and MUST return ErrNotFound — never a permission error and
	// never another tenant's row — when the addressed object belongs to a
	// different tenant. A "" tenantID selects the single-tenant table
	// shape. tamper cannot verify this; the cross-tenant leak suite
	// (§3.3) is the proof obligation that comes with implementing this
	// interface.
	SavePatchInTenant(ctx context.Context, tenantID, id string, w GroupWrite, ops []Operation) (GroupRecord, error)

	// ValidateMembersInTenant checks that every member id exists, is
	// SCIM-managed, AND belongs to tenantID.
	//
	// This is the one that looks skippable and is the most dangerous.
	// Without the tenant constraint, tenant A can nest tenant B's user into
	// an A group: a cross-tenant WRITE that never touches a tenant-scoped
	// read path, so no amount of scoping the reads catches it.
	//
	// Isolation contract. The implementation MUST constrain the query to
	// tenantID and MUST return ErrNotFound — never a permission error and
	// never another tenant's row — when the addressed object belongs to a
	// different tenant. A "" tenantID selects the single-tenant table
	// shape. tamper cannot verify this; the cross-tenant leak suite
	// (§3.3) is the proof obligation that comes with implementing this
	// interface.
	ValidateMembersInTenant(ctx context.Context, tenantID string, members []MemberRef) error

	// ListInTenant pages the tenant's groups.
	//
	// Isolation contract. The implementation MUST constrain the query to
	// tenantID and MUST return ErrNotFound — never a permission error and
	// never another tenant's row — when the addressed object belongs to a
	// different tenant. A "" tenantID selects the single-tenant table
	// shape. tamper cannot verify this; the cross-tenant leak suite
	// (§3.3) is the proof obligation that comes with implementing this
	// interface.
	ListInTenant(ctx context.Context, tenantID string, startIndex, count int) (GroupPage, error)

	// ListFilteredInTenant pages the tenant's groups under a client filter.
	// See UserStore's note: the tenant constraint is ANDed with the filter.
	//
	// Isolation contract. The implementation MUST constrain the query to
	// tenantID and MUST return ErrNotFound — never a permission error and
	// never another tenant's row — when the addressed object belongs to a
	// different tenant. A "" tenantID selects the single-tenant table
	// shape. tamper cannot verify this; the cross-tenant leak suite
	// (§3.3) is the proof obligation that comes with implementing this
	// interface.
	ListFilteredInTenant(ctx context.Context, tenantID string, startIndex, count int, filter string) (GroupPage, error)
}
