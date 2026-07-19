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
	List(ctx context.Context, startIndex, count int) (UserPage, error)
	ListFiltered(ctx context.Context, startIndex, count int, where string, args []any) (UserPage, error)
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

// GroupStore is the app-implemented SCIM Groups persistence port. Create
// and Replace run the app's nested-group cycle check; a cyclic write
// surfaces ErrCyclicGroup (defined in nesting.go), which the transport
// maps to CIRCULAR_GROUP_REFERENCE. A member id the store can't resolve
// folds to ErrInvalidInput.
type GroupStore interface {
	Create(ctx context.Context, w GroupWrite) (GroupRecord, error)
	Get(ctx context.Context, id string) (GroupRecord, error)
	Replace(ctx context.Context, id string, w GroupWrite) (GroupRecord, error)
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, startIndex, count int) (GroupPage, error)
	ListFiltered(ctx context.Context, startIndex, count int, where string, args []any) (GroupPage, error)
}
