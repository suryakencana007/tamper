package oidc

import (
	"context"
	"errors"
	"time"
)

// ErrProviderNotFound surfaces from ProviderStore reads when no row
// matches the id. Apps fold it onto their not-found error.
var ErrProviderNotFound = errors.New("oidc: provider not found")

// ErrProviderExists surfaces from ProviderStore.InsertProvider when
// the id is already taken. Apps fold it onto their conflict error.
var ErrProviderExists = errors.New("oidc: provider already exists")

// ProviderRecord is the persisted shape of one managed IdP entry.
// The client secret is stored SEALED (the crypto.KeySet envelope
// bytes) — plaintext never reaches the store. Scopes are a decoded
// list; how the store serialises them (JSON column, join table) is
// its own concern.
type ProviderRecord struct {
	ID                 string
	IssuerURL          string
	ClientID           string
	SealedClientSecret []byte
	DisplayName        string
	Scopes             []string
	GroupsClaim        string
	GroupClaimFormat   string
	Enabled            bool
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// ProviderStore is the persistence port the Manager drives. The app
// implements it over its own storage (Barista: the oidc_providers
// sqlc surface). Ordering contract: ListProviders and
// ListEnabledProviders return rows sorted by display name ascending
// (what provider-list UIs expect).
type ProviderStore interface {
	// InsertProvider persists a new record. ErrProviderExists when
	// the id is taken.
	InsertProvider(ctx context.Context, rec ProviderRecord) error
	// GetProvider returns one record by id. ErrProviderNotFound when
	// no row matches.
	GetProvider(ctx context.Context, id string) (ProviderRecord, error)
	// ListProviders returns every record, enabled or not.
	ListProviders(ctx context.Context) ([]ProviderRecord, error)
	// ListEnabledProviders returns only records with Enabled=true.
	ListEnabledProviders(ctx context.Context) ([]ProviderRecord, error)
	// UpdateProvider rewrites every mutable column of the record with
	// rec.ID. ErrProviderNotFound when no row matches.
	UpdateProvider(ctx context.Context, rec ProviderRecord) error
	// UpdateProviderSealedSecret rewrites only the sealed secret +
	// updated-at (the rotate-KEK path).
	UpdateProviderSealedSecret(ctx context.Context, id string, sealed []byte, updatedAt time.Time) error
	// DeleteProvider drops the record. Idempotent on a missing id.
	DeleteProvider(ctx context.Context, id string) error
}

// TenantScopedProviderStore is the pooled-multi-tenancy upgrade of
// ProviderStore: the same surface, plus the one read the live registry
// must constrain to a tenant. A store that also satisfies this interface
// can back a deployment where each tenant federates with its own IdPs.
//
// It is an OPTIONAL interface, the same mechanism identity.Store uses.
// Implementing it is additive: existing ProviderStores keep compiling
// and keep their behavior, and a "" tenantID selects exactly the
// single-tenant shape they already have.
//
// Note what is NOT here: no tenant column on ProviderRecord, and no
// tenant-scoped insert or update. tamper names no column. The tenant is
// the application's, expressed as an argument to this one read; how a
// row is filed under a tenant — a column, a schema, a separate database
// — never enters the framework.
//
// Implementations MUST be safe for concurrent use.
type TenantScopedProviderStore interface {
	ProviderStore

	// ListEnabledProvidersForTenant returns the tenant's enabled
	// providers, sorted by display name ascending like its untenanted
	// sibling.
	//
	// Isolation contract. The implementation MUST constrain the query to
	// tenantID and MUST return ErrNotFound — never a permission error and
	// never another tenant's row — when the addressed object belongs to a
	// different tenant. A "" tenantID selects the single-tenant table
	// shape. tamper cannot verify this; the cross-tenant leak suite
	// (§3.3) is the proof obligation that comes with implementing this
	// interface.
	//
	// A tenant with no enabled providers returns an empty slice and a nil
	// error — NOT an error. The Manager caches that emptiness for the
	// full TTL, exactly as it caches a populated result.
	ListEnabledProvidersForTenant(ctx context.Context, tenantID string) ([]ProviderRecord, error)
}
