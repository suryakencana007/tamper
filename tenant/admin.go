package tenant

import (
	"context"
	"errors"
	"fmt"
)

// Error taxonomy for the write port. The application maps these onto its own
// wire errors, the way the identity sentinels already work.
var (
	// ErrConflict — the id or slug is already taken. Provisioning the same
	// tenant twice must not quietly reset a suspended tenant to pending, or
	// re-point a slug another tenant holds.
	ErrConflict = errors.New("tenant: tenant already exists")

	// ErrInvalidDescriptor — the descriptor, or the status asked for, is not
	// something this version can store. Deny-by-default applies to writes as
	// much as to reads: a value the library does not know is refused, never
	// stored and never guessed at.
	ErrInvalidDescriptor = errors.New("tenant: invalid tenant descriptor")

	// ErrSingleTenant — the single tenant is not administrable. It is the empty
	// id, and it is precisely the deployment with no tenant row to find
	// (Store's doc); there is nothing to create and no row to change.
	ErrSingleTenant = errors.New("tenant: the single tenant is not administrable")
)

// AdminStore is the opt-in write port: the console's half of tenancy. It is the
// write-shaped sibling of [Store], which stays read-only so that every consumer
// — routing code, gates, tests — can hold a tenant port without also holding
// permission to change one.
//
// The application implements it over its own tenants table. tamper names no
// table, adds no schema, and runs no migration.
//
// Write contract, common to both mutating methods:
//
//   - Every refusal leaves the table exactly as it was. Validation happens
//     before the write, and a refused call writes nothing.
//   - tenant.Single is refused with ErrSingleTenant; an unset id, or a Status
//     this version does not know, with ErrInvalidDescriptor.
//   - An implementation MUST be safe for concurrent use, like Store.
type AdminStore interface {
	// List returns every tenant, ordered by id so a console renders stably. The
	// admin surface legitimately needs them all, which is why this read is not
	// scoped by tenant.
	List(ctx context.Context) ([]Descriptor, error)

	// Create provisions one tenant.
	//
	// ErrConflict when the id or the slug is already taken; ErrSingleTenant
	// when the id is empty (which IS the single tenant); ErrInvalidDescriptor
	// for an unknown Status. Nothing is written on any error.
	//
	// A non-empty ParentID is stored as given and nothing more: tamper does not
	// resolve it, inherit through it, or branch on it (Store's doc). This is
	// where a hierarchy deployment writes the parentage its own port reads.
	Create(ctx context.Context, d Descriptor) error

	// SetStatus moves one tenant to status. ErrNotFound for an unknown id;
	// ErrSingleTenant for tenant.Single; ErrInvalidDescriptor for an unknown
	// Status. Nothing is written on any error.
	//
	// Idempotent: setting the status a tenant already has succeeds and changes
	// nothing. A retried suspension must not fail.
	SetStatus(ctx context.Context, id ID, status Status) error
}

// checkStatus refuses a status this version cannot store.
func checkStatus(s Status) error {
	switch s {
	case StatusActive, StatusSuspended, StatusPending:
		return nil
	}
	return fmt.Errorf("%w: unknown status %q", ErrInvalidDescriptor, s)
}

// checkWritableID refuses an id that cannot name a stored tenant.
func checkWritableID(id ID) error {
	if !id.Valid() {
		return fmt.Errorf("%w: the tenant id is unset", ErrInvalidDescriptor)
	}
	if id.IsSingle() {
		return fmt.Errorf("%w: %q is the single tenant", ErrSingleTenant, id)
	}
	return nil
}
