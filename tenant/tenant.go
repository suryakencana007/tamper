package tenant

// Descriptor is the identity core's projection of a tenant — the few
// fields tamper needs in order to route and gate a request.
// Applications carry more columns on the same row (billing, branding,
// plan, quotas); the Store maps between its own wide row and this
// struct, exactly as identity.User projects the app's wide users row.
type Descriptor struct {
	// ID is the tenant's stable identifier: opaque, app-defined, and
	// never parsed by tamper. It is compared for equality and passed
	// through; nothing in the framework reads structure into it.
	ID string

	// Slug is the human-facing handle — a subdomain label, a URL
	// segment. Also opaque. tamper never derives ID from Slug or the
	// reverse, and never case-folds or otherwise normalises either.
	Slug string

	// ParentID names the parent tenant; "" is a root tenant.
	//
	// Carried by a Store and resolved by [Ancestors] — nothing else, and
	// never for authority. A Store stores it and resolves NOTHING through
	// it; [Ancestors] walks it for inheritance asked about explicitly (a
	// plan, a set of IdPs, a claimable domain) and builds no
	// authorization scope from it. The RBAC engine's per-scope bindings
	// are unaffected (ADR-0001 §5.A, narrowed by
	// PHASE12-TENANT-INHERITANCE-SKETCH.md §3.1).
	ParentID string

	// Status is the tenant's lifecycle state. A Store returns the row
	// as it stands and does NOT interpret this field; the caller
	// decides what a non-active tenant means for its surface.
	// Deny-by-default applies at that decision (sketch §6.2), and on an
	// unauthenticated surface a suspended tenant must be
	// indistinguishable from an unknown one (§6.3). See ErrSuspended.
	Status Status
}

// Status is a tenant's lifecycle state.
type Status string

// The lifecycle states. These strings are the application's PERSISTED
// vocabulary — a Store maps its own column onto them — so they are part
// of the storage contract and do not change.
const (
	// StatusActive — the tenant is live and serves requests.
	StatusActive Status = "active"

	// StatusSuspended — the tenant exists but must not serve requests
	// (non-payment, abuse, an admin hold). See ErrSuspended.
	StatusSuspended Status = "suspended"

	// StatusPending — provisioned but not yet activated: signup
	// incomplete, domain unverified, awaiting approval.
	StatusPending Status = "pending"
)
