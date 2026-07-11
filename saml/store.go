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
