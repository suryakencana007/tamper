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
