package saml

import (
	"context"
	"errors"
	"time"
)

// ErrProviderNotFound surfaces from ProviderStore reads when no row
// matches the id. Apps fold it onto their not-found error.
var ErrProviderNotFound = errors.New("saml: provider not found")

// ErrProviderExists surfaces from ProviderStore.InsertProvider when
// the id is already taken. Apps fold it onto their conflict error.
var ErrProviderExists = errors.New("saml: provider already exists")

// ProviderRecord is the persisted shape of one managed SAML IdP
// entry. The SP signing key is stored SEALED (the crypto.KeySet
// envelope bytes) — plaintext never reaches the store. The SP cert
// is public material and rides as PEM text.
type ProviderRecord struct {
	ID                     string
	IdPMetadataURL         string
	EntityID               string
	ACSURL                 string
	SPSigningCertPEM       string
	SealedSigningKey       []byte
	AttributeMappingGroups string
	AttributeMappingEmail  string
	AttributeMappingName   string
	DisplayName            string
	Enabled                bool
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

// ProviderStore is the persistence port the Manager drives. The app
// implements it over its own storage (Barista: the saml_providers
// sqlc surface). Ordering contract: list methods return rows sorted
// by display name ascending.
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
	// UpdateProviderSealedKey rewrites only the sealed signing key +
	// updated-at (the rotate-KEK path).
	UpdateProviderSealedKey(ctx context.Context, id string, sealed []byte, updatedAt time.Time) error
	// DeleteProvider drops the record. Idempotent on a missing id.
	DeleteProvider(ctx context.Context, id string) error
}

// TenantScopedProviderStore is the pooled-multi-tenancy upgrade of
// ProviderStore. It mirrors oidc.TenantScopedProviderStore exactly —
// same shape, same contract, same reasoning — because two federation
// protocols with two different tenancy contracts would be a bug in one
// of them.
//
// It is an OPTIONAL interface, the same mechanism identity.Store uses.
// Implementing it is additive: existing ProviderStores keep compiling
// and keep their behavior, and a "" tenantID selects exactly the
// single-tenant shape they already have.
//
// Note what is NOT here: no tenant column on ProviderRecord, and no
// tenant-scoped insert or update. tamper names no column. The tenant is
// the application's, expressed as an argument to this one read.
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
