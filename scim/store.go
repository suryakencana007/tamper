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
// This slice ships the UserStore port + its adapter. GroupStore, the
// SavePatch method (the RFC 7644 §3.5.2 PATCH persist), and the handler
// rewire follow in subsequent 4e slices — see PHASE4E-SCIM-SKETCH.md.

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

// UserStore is the app-implemented persistence port the SCIM Users
// transport calls, fine-grained like tamperidentity.Store. startIndex is
// 1-based (RFC 7644 §3.4.2); count is the already-capped page size.
// ListFiltered receives a WHERE fragment + positional args produced by
// Translate over the app's ColumnMapping — injection is fenced by that
// whitelist (the accepted Phase-3e precedent), and the adapter binds args
// positionally.
type UserStore interface {
	Create(ctx context.Context, w UserWrite) (UserRecord, error)
	Get(ctx context.Context, id string) (UserRecord, error)
	Replace(ctx context.Context, id string, w UserWrite) (UserRecord, error)
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, startIndex, count int) (UserPage, error)
	ListFiltered(ctx context.Context, startIndex, count int, where string, args []any) (UserPage, error)
}
