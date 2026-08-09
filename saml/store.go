package saml

import (
	"context"
	"errors"
	"time"

	"github.com/suryakencana007/tamper/tenant"
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
	// Isolation contract. The implementation MUST constrain the query to
	// tenantID and MUST return ErrNotFound — never a permission error and
	// never another tenant's row — when the addressed object belongs to a
	// different tenant. tenant.Single selects the single-tenant table
	// shape. tamper cannot verify this; the cross-tenant leak suite
	// (§3.3) is the proof obligation that comes with implementing this
	// interface.
	ListEnabledProviders(ctx context.Context, tenantID tenant.ID) ([]ProviderRecord, error)
	// UpdateProvider rewrites every mutable column of the record with
	// rec.ID. ErrProviderNotFound when no row matches.
	UpdateProvider(ctx context.Context, rec ProviderRecord) error
	// UpdateProviderSealedKey rewrites only the sealed signing key +
	// updated-at (the rotate-KEK path).
	UpdateProviderSealedKey(ctx context.Context, id string, sealed []byte, updatedAt time.Time) error
	// DeleteProvider drops the record. Idempotent on a missing id.
	DeleteProvider(ctx context.Context, id string) error
}

// TenantScopedProviderStore was here — the optional upgrade that added
// ListEnabledProvidersForTenant while the additive phase was open. v0.4.0
// folded it into ProviderStore, so there is no second interface and no
// boot-time assertion: a store that cannot scope by tenant fails to compile.
