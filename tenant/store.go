package tenant

import (
	"context"
	"errors"
)

// Error taxonomy. The application maps these onto its own wire errors,
// the way the identity sentinels already work. Store implementations
// MUST return the sentinels noted on the interfaces below; wrapped is
// fine — callers match with errors.Is.
var (
	// ErrNotFound — no tenant matches the addressed id, slug or domain.
	//
	// This is the ONLY error a lookup miss may produce. A permission
	// error would disclose that the tenant exists and turns any of
	// these methods into a tenant-existence oracle; the 404-never-403
	// discipline espresso/decision.go already documents for the org
	// case applies here unchanged (sketch §6.3).
	ErrNotFound = errors.New("tenant: not found")

	// ErrSuspended — the tenant exists but is not serving requests.
	//
	// Returned by CALLERS that have resolved a Descriptor and decided
	// what StatusSuspended means for their surface. No method in this
	// package returns it: a Store hands back the row as stored and does
	// not interpret Status. On an unauthenticated surface the caller
	// must collapse this onto ErrNotFound before it reaches the wire —
	// a distinguishable "suspended" is a tenant-existence oracle
	// (sketch §6.3).
	ErrSuspended = errors.New("tenant: suspended")
)

// Store is the tenant persistence port. The application implements it
// over its own tenants table; MemStore is the reference implementation
// and test double. tamper names no table.
//
// Sentinel contract: ByID and BySlug return an error matching
// ErrNotFound (errors.Is) when no tenant matches — never a permission
// error, and never a zero Descriptor with a nil error. Both of those
// disclose existence; the second also fails open. Other errors
// propagate as-is and the caller fails the operation: deny-by-default,
// and no error return may be read as allow (sketch §6.2).
//
// An empty lookup key never resolves. Absent, empty or mismatched all
// mean deny (§6.2) — "" is a legal tenant id meaning "the
// single-tenant deployment", which is precisely the deployment with no
// tenant row to find.
//
// Implementations MUST be safe for concurrent use.
type Store interface {
	// ByID returns the tenant with this id, ErrNotFound when none does.
	ByID(ctx context.Context, id string) (Descriptor, error)

	// BySlug returns the tenant with this slug, ErrNotFound when none
	// does. Matching is on the value as stored — tamper does not
	// case-fold or otherwise normalise a slug.
	BySlug(ctx context.Context, slug string) (Descriptor, error)
}

// Resolver answers home-realm discovery: which tenant owns this email
// domain? Implemented over the application's verified-domain table.
//
// Consumed in slice 7f-1; defined here so the whole tenancy vocabulary
// lands in one place. There is deliberately NO reference implementation
// yet — a MemStore.ResolveByDomain written before 7f-1 would have no
// concept of a verified domain, and an unverified domain that resolves
// to an IdP is exactly the tenant-takeover vector 7f-1 exists to close.
//
// Sentinel contract: as Store's, and it matters more here. The resolve
// path is reachable unauthenticated, so a distinguishable error is a
// customer-domain enumeration oracle.
type Resolver interface {
	// ResolveByDomain returns the tenant owning emailDomain.
	// ErrNotFound when the domain is unknown, unverified, or bound to
	// no tenant — the three are indistinguishable by design.
	//
	// emailDomain is the bare domain ("acme.com"), lowercased and
	// punycode-normalised BY THE CALLER. tamper does not normalise; an
	// implementation that silently fixes up its input makes two
	// spellings of one domain resolve differently across call sites.
	ResolveByDomain(ctx context.Context, emailDomain string) (Descriptor, error)
}
