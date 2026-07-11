package oidc

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"

	"github.com/suryakencana007/barista/packages/tamper/crypto"
)

// ErrNoKeySet surfaces from Manager mutations that need to seal or
// open a client secret when no KeySet was configured.
var ErrNoKeySet = errors.New("oidc: no keyset configured")

// ProviderDefinition is the plaintext-at-the-boundary CRUD shape.
// ClientSecret is plaintext here; the Manager seals it under the
// KeySet before it reaches the ProviderStore and opens it on reads.
// App-side validation policy (issuer scheme rules, etc.) runs BEFORE
// the app calls the Manager — the Manager owns lifecycle mechanics,
// not policy.
type ProviderDefinition struct {
	ID               string
	IssuerURL        string
	ClientID         string
	ClientSecret     string
	DisplayName      string
	Scopes           []string
	GroupsClaim      string
	GroupClaimFormat string
	Enabled          bool
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// DiscoveryResult is the discovery-probe shape returned by
// TestDiscovery. Admin UIs render it as a per-endpoint status row.
type DiscoveryResult struct {
	IssuerURL     string
	AuthURL       string
	TokenURL      string
	JWKSURL       string
	UserInfoURL   string
	SupportedAlgs []string
}

// RotateResult is the per-pass summary of RotateSealedSecrets.
type RotateResult struct {
	Scanned int
	Rotated int
}

// Manager owns the DB-backed provider lifecycle: CRUD with at-rest
// secret sealing, the TTL-cached live ProviderRegistry, the
// discovery Test probe, and the rotate-KEK re-seal loop. It drives a
// ProviderStore port — the app owns rows, serialisation, and any
// validation policy (run before calling in).
//
// Caching: each process rebuilds its registry from the store at most
// once every ttl. Sister replicas in a multi-replica install
// converge on each other's changes within the TTL window without
// explicit reload notifications; same-process mutations invalidate
// eagerly.
type Manager struct {
	store ProviderStore
	keys  *crypto.KeySet

	// redirectURL maps a provider id to the full callback URL used
	// when building the live registry. Route shapes are the app's —
	// this is the seam that keeps them out of the framework.
	redirectURL func(id string) string

	// mu guards registry + cachedAt. RWMutex because the read path
	// (GetRegistry on every federated-auth call) dominates the write
	// path (admin CRUD + Reload).
	mu       sync.RWMutex
	registry *ProviderRegistry
	cachedAt time.Time
	// ttl bounds how long the cached registry stays fresh before the
	// next GetRegistry rebuilds from the store. Zero means "rebuild
	// on every call" — useful for testing, prohibitively expensive in
	// production.
	ttl time.Duration

	// now and newDiscoveryProvider are test seams. Production wiring
	// leaves them as time.Now and coreoidc.NewProvider.
	now                  func() time.Time
	newDiscoveryProvider func(ctx context.Context, issuerURL string) (*coreoidc.Provider, error)
}

// ManagerOption configures a Manager at construction.
type ManagerOption func(*Manager)

// WithTTL sets the registry cache-freshness window. Zero (the
// default) rebuilds on every GetRegistry call.
func WithTTL(d time.Duration) ManagerOption {
	return func(m *Manager) { m.ttl = d }
}

// WithRedirectURL supplies the provider-id → callback-URL mapping
// used when building the live registry. Required before GetRegistry
// or Reload can build a non-empty registry.
func WithRedirectURL(fn func(id string) string) ManagerOption {
	return func(m *Manager) {
		if fn != nil {
			m.redirectURL = fn
		}
	}
}

// NewManager constructs a Manager over the given store. keys may be
// nil — reads then surface sealed secrets as empty and mutations
// that must seal refuse with ErrNoKeySet.
func NewManager(store ProviderStore, keys *crypto.KeySet, opts ...ManagerOption) *Manager {
	m := &Manager{
		store:                store,
		keys:                 keys,
		now:                  time.Now,
		newDiscoveryProvider: coreoidc.NewProvider,
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

// Keys returns the configured envelope keyset. Surfaced for app-side
// rotate-KEK CLI wiring.
func (m *Manager) Keys() *crypto.KeySet { return m.keys }

// SetClock swaps the clock seam. Test-seam only — production code
// never calls this.
func (m *Manager) SetClock(now func() time.Time) {
	if now != nil {
		m.now = now
	}
}

// SetDiscovery swaps the coreoidc.NewProvider seam so tests can run
// TestDiscovery without a live issuer. Test-seam only.
func (m *Manager) SetDiscovery(fn func(ctx context.Context, issuerURL string) (*coreoidc.Provider, error)) {
	if fn != nil {
		m.newDiscoveryProvider = fn
	}
}

// PinRegistry installs a pre-built registry that stays cached until
// the next mutation, regardless of ttl — the cachedAt timestamp is
// set to a far-future sentinel the freshness check recognises.
// Passing nil clears the cache. Test-seam only: it lets handler-level
// tests exercise the federated-auth surface without store rows or
// discovery round-trips. Production code only ever writes time.Now()
// into cachedAt, so the sentinel can't collide.
func (m *Manager) PinRegistry(reg *ProviderRegistry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.registry = reg
	if reg == nil {
		m.cachedAt = time.Time{}
		return
	}
	m.cachedAt = time.Date(pinnedCacheTimestampYear, time.December, 31, 23, 59, 59, 0, time.UTC)
}

// Create persists a new provider, sealing the client secret. The
// caller stamps no timestamps — Create stamps CreatedAt/UpdatedAt
// from the Manager clock. ErrProviderExists when the id is taken;
// ErrNoKeySet when sealing is impossible.
func (m *Manager) Create(ctx context.Context, def ProviderDefinition) error {
	if def.ID == "" {
		return fmt.Errorf("oidc: provider id is required")
	}
	if m.keys == nil {
		return ErrNoKeySet
	}
	sealed, err := m.keys.Seal([]byte(def.ClientSecret))
	if err != nil {
		return fmt.Errorf("oidc: seal client secret: %w", err)
	}
	now := m.now().UTC()
	rec := recordFromDefinition(def, sealed)
	rec.CreatedAt = now
	rec.UpdatedAt = now
	if err := m.store.InsertProvider(ctx, rec); err != nil {
		return err // ErrProviderExists passes through for the app to fold
	}
	m.invalidateCache()
	return nil
}

// Get returns one provider by id with the client secret opened.
// ErrProviderNotFound passes through from the store.
func (m *Manager) Get(ctx context.Context, id string) (ProviderDefinition, error) {
	if id == "" {
		return ProviderDefinition{}, fmt.Errorf("oidc: provider id is required")
	}
	rec, err := m.store.GetProvider(ctx, id)
	if err != nil {
		return ProviderDefinition{}, err
	}
	return m.definitionFromRecord(rec)
}

// List returns every provider with client secrets opened, in the
// store's ordering (display name ascending).
func (m *Manager) List(ctx context.Context) ([]ProviderDefinition, error) {
	recs, err := m.store.ListProviders(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]ProviderDefinition, 0, len(recs))
	for _, rec := range recs {
		def, err := m.definitionFromRecord(rec)
		if err != nil {
			return nil, err
		}
		out = append(out, def)
	}
	return out, nil
}

// Update rewrites every mutable column, re-sealing the client secret
// under the current write key. Pass the same plaintext to keep the
// existing secret. ErrProviderNotFound when the id is unknown.
func (m *Manager) Update(ctx context.Context, def ProviderDefinition) error {
	if def.ID == "" {
		return fmt.Errorf("oidc: provider id is required")
	}
	if m.keys == nil {
		return ErrNoKeySet
	}
	// Existence check so callers surface not-found rather than a
	// silent no-op on a wrong id.
	if _, err := m.store.GetProvider(ctx, def.ID); err != nil {
		return err
	}
	sealed, err := m.keys.Seal([]byte(def.ClientSecret))
	if err != nil {
		return fmt.Errorf("oidc: seal client secret: %w", err)
	}
	rec := recordFromDefinition(def, sealed)
	rec.UpdatedAt = m.now().UTC()
	if err := m.store.UpdateProvider(ctx, rec); err != nil {
		return err
	}
	m.invalidateCache()
	return nil
}

// Delete drops a provider. Idempotent on a missing id.
func (m *Manager) Delete(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("oidc: provider id is required")
	}
	if err := m.store.DeleteProvider(ctx, id); err != nil {
		return err
	}
	m.invalidateCache()
	return nil
}

// TestDiscovery runs OIDC discovery against the issuer WITHOUT
// persisting anything. Admin UIs call it to validate a freshly
// entered IdP before committing Create. Failures wrap
// ErrDiscoveryFailed.
func (m *Manager) TestDiscovery(ctx context.Context, issuerURL string) (*DiscoveryResult, error) {
	provider, err := m.newDiscoveryProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDiscoveryFailed, err)
	}
	endpoints := provider.Endpoint()
	var extras struct {
		JWKSURL       string   `json:"jwks_uri"`
		UserInfoURL   string   `json:"userinfo_endpoint"`
		SupportedAlgs []string `json:"id_token_signing_alg_values_supported"`
	}
	if err := provider.Claims(&extras); err != nil {
		return nil, fmt.Errorf("%w: parse discovery extras: %v", ErrDiscoveryFailed, err)
	}
	return &DiscoveryResult{
		IssuerURL:     issuerURL,
		AuthURL:       endpoints.AuthURL,
		TokenURL:      endpoints.TokenURL,
		JWKSURL:       extras.JWKSURL,
		UserInfoURL:   extras.UserInfoURL,
		SupportedAlgs: extras.SupportedAlgs,
	}, nil
}

// GetRegistry returns the cached live registry, rebuilding from the
// store on a cache miss OR when the cached value is older than ttl.
// Thread-safe via double-checked locking — the read-side fast path
// takes only RLock; the slow path takes Lock and re-checks the
// freshness predicate so concurrent stampedes serialise into a
// single store read.
//
// The freshness check keys on cachedAt (not registry != nil) so a
// genuinely empty store caches the nil sentinel for ttl just like a
// populated registry does — that symmetry is what makes multi-replica
// convergence predictable in both directions.
//
// Returns (nil, nil) when no enabled providers exist.
func (m *Manager) GetRegistry(ctx context.Context) (*ProviderRegistry, error) {
	m.mu.RLock()
	cached := m.registry
	cachedAt := m.cachedAt
	m.mu.RUnlock()
	if m.cacheFresh(cachedAt) {
		return cached, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cacheFresh(m.cachedAt) {
		return m.registry, nil
	}
	return m.rebuildLocked(ctx)
}

// Reload clears the cache + eagerly rebuilds from the store. Called
// by admin CRUD handlers after each write so same-process federated
// flows see the change immediately; the eager rebuild fronts the
// discovery cost on the operator's request instead of serialising
// user logins behind it.
func (m *Manager) Reload(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.registry = nil
	m.cachedAt = time.Time{}
	_, err := m.rebuildLocked(ctx)
	return err
}

// RotateSealedSecrets re-seals every record's client secret under
// the keyset's current write key. Rows already at the write key are
// skipped, so re-runs after a successful rotate are no-ops.
func (m *Manager) RotateSealedSecrets(ctx context.Context) (RotateResult, error) {
	if m.keys == nil {
		return RotateResult{}, ErrNoKeySet
	}
	recs, err := m.store.ListProviders(ctx)
	if err != nil {
		return RotateResult{}, fmt.Errorf("oidc: rotate: scan providers: %w", err)
	}
	writeID := m.keys.WriteKeyID()
	result := RotateResult{}
	for _, rec := range recs {
		if len(rec.SealedClientSecret) == 0 {
			continue
		}
		result.Scanned++
		if rec.SealedClientSecret[0] == writeID {
			log.Printf("oidc: rotate: provider %q already at keyId=%d; skipping", rec.ID, writeID)
			continue
		}
		plaintext, openErr := m.keys.Open(rec.SealedClientSecret)
		if openErr != nil {
			return result, fmt.Errorf("oidc: rotate: decrypt %q: %w", rec.ID, openErr)
		}
		sealed, sealErr := m.keys.Seal(plaintext)
		if sealErr != nil {
			return result, fmt.Errorf("oidc: rotate: seal %q: %w", rec.ID, sealErr)
		}
		if upErr := m.store.UpdateProviderSealedSecret(ctx, rec.ID, sealed, m.now().UTC()); upErr != nil {
			return result, fmt.Errorf("oidc: rotate: persist %q: %w", rec.ID, upErr)
		}
		log.Printf("oidc: rotate: provider %q re-sealed under keyId=%d", rec.ID, writeID)
		result.Rotated++
	}
	return result, nil
}

// cacheFresh reports whether a previous rebuild cached a result
// within the ttl window. ttl=0 normally returns false (every call
// rebuilds); a zero cachedAt (never built) also returns false. The
// one exception is the PinRegistry far-future sentinel, which always
// reads fresh. Callers must hold mu (either mode) for the cachedAt
// read to be race-free.
func (m *Manager) cacheFresh(cachedAt time.Time) bool {
	if cachedAt.IsZero() {
		return false
	}
	if cachedAt.Year() == pinnedCacheTimestampYear {
		return true
	}
	if m.ttl == 0 {
		return false
	}
	return m.now().Sub(cachedAt) < m.ttl
}

// pinnedCacheTimestampYear is the sentinel year PinRegistry writes
// into cachedAt so a pinned fixture survives the freshness check
// regardless of ttl. Test-seam only.
const pinnedCacheTimestampYear = 9999

// rebuildLocked is the store read + registry build. Caller MUST hold
// mu.Lock. Opens each enabled record's secret, maps the app-supplied
// redirect URL, and builds with partialOK=true so a single
// unreachable IdP logs + is omitted instead of failing the tick.
func (m *Manager) rebuildLocked(ctx context.Context) (*ProviderRegistry, error) {
	recs, err := m.store.ListEnabledProviders(ctx)
	if err != nil {
		return nil, fmt.Errorf("oidc: list enabled providers: %w", err)
	}
	if len(recs) == 0 {
		// Cache the nil "not configured" sentinel with a fresh
		// timestamp so a post-Delete rebuild drops the previous
		// registry AND the empty result honours the ttl window.
		m.registry = nil
		m.cachedAt = m.now()
		return nil, nil
	}
	if m.redirectURL == nil {
		return nil, fmt.Errorf("oidc: manager has no redirect-URL mapping (WithRedirectURL)")
	}
	configs := make([]ProviderConfig, 0, len(recs))
	for _, rec := range recs {
		def, derr := m.definitionFromRecord(rec)
		if derr != nil {
			return nil, derr
		}
		configs = append(configs, ProviderConfig{
			ID:           def.ID,
			IssuerURL:    def.IssuerURL,
			ClientID:     def.ClientID,
			ClientSecret: def.ClientSecret,
			RedirectURL:  m.redirectURL(def.ID),
			DisplayName:  def.DisplayName,
			Scopes:       def.Scopes,
			GroupsClaim:  def.GroupsClaim,
		})
	}
	reg, err := BuildRegistryFromConfigs(ctx, configs, true)
	if err != nil {
		return nil, fmt.Errorf("oidc: build registry: %w", err)
	}
	m.registry = reg
	m.cachedAt = m.now()
	return reg, nil
}

// invalidateCache clears the cached registry so the next GetRegistry
// rebuilds. Called by Create/Update/Delete.
func (m *Manager) invalidateCache() {
	m.mu.Lock()
	m.registry = nil
	m.cachedAt = time.Time{}
	m.mu.Unlock()
}

// definitionFromRecord opens the sealed secret + projects the record
// to the plaintext boundary shape. A nil keyset surfaces the secret
// as empty (read-only installs); a sealed value that fails to open is
// an error — silent empty secrets would break token exchange in ways
// that are miserable to debug.
func (m *Manager) definitionFromRecord(rec ProviderRecord) (ProviderDefinition, error) {
	var plaintext []byte
	if m.keys != nil && len(rec.SealedClientSecret) > 0 {
		pt, err := m.keys.Open(rec.SealedClientSecret)
		if err != nil {
			return ProviderDefinition{}, fmt.Errorf("oidc: provider %q: open client secret: %w", rec.ID, err)
		}
		plaintext = pt
	}
	return ProviderDefinition{
		ID:               rec.ID,
		IssuerURL:        rec.IssuerURL,
		ClientID:         rec.ClientID,
		ClientSecret:     string(plaintext),
		DisplayName:      rec.DisplayName,
		Scopes:           rec.Scopes,
		GroupsClaim:      rec.GroupsClaim,
		GroupClaimFormat: rec.GroupClaimFormat,
		Enabled:          rec.Enabled,
		CreatedAt:        rec.CreatedAt,
		UpdatedAt:        rec.UpdatedAt,
	}, nil
}

// recordFromDefinition projects the boundary shape to a store record
// with the supplied sealed secret. Timestamps are the caller's to
// stamp.
func recordFromDefinition(def ProviderDefinition, sealed []byte) ProviderRecord {
	return ProviderRecord{
		ID:                 def.ID,
		IssuerURL:          def.IssuerURL,
		ClientID:           def.ClientID,
		SealedClientSecret: sealed,
		DisplayName:        def.DisplayName,
		Scopes:             def.Scopes,
		GroupsClaim:        def.GroupsClaim,
		GroupClaimFormat:   def.GroupClaimFormat,
		Enabled:            def.Enabled,
		CreatedAt:          def.CreatedAt,
		UpdatedAt:          def.UpdatedAt,
	}
}
