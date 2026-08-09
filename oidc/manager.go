package oidc

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"

	"github.com/suryakencana007/tamper/crypto"
	"github.com/suryakencana007/tamper/tenant"
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

	// redirectURLForTenant is the tenant-aware form. When set it wins
	// over redirectURL, because a pooled deployment's callback URL
	// usually varies by tenant (a subdomain, a path segment).
	redirectURLForTenant func(tenantID, providerID string) string

	// mu guards registries. STILL an RWMutex, and still for the same
	// reason: the read path (GetRegistry on every federated-auth call)
	// dominates the write path (admin CRUD + Reload). Going per-tenant
	// changes the single cached value into a keyed map; it does not add
	// a second lock and does not make the write path hot (§6.6).
	mu sync.RWMutex
	// registries is the cache, keyed by tenant. The "" key is the
	// single-tenant deployment and holds exactly one registry, which is
	// what keeps the untenanted path byte-identical.
	//
	// MAP GROWTH — the decision, since the invariant demands one be
	// stated. The Manager has no tenant.Store to validate ids against, so
	// the map is BOUNDED rather than restricted to known tenants: at
	// maxCachedTenants an insert evicts the least-recently-rebuilt entry.
	// A cache keyed on an attacker-influenced tenant id is otherwise a
	// memory-exhaustion vector, and refusing to cache past the cap would
	// be worse — an attacker could fill it with junk and force every real
	// tenant onto the uncached path. Eviction means junk ages out as real
	// traffic flows. A pinned registry carries a far-future timestamp and
	// is therefore evicted last, so the test seam survives pressure.
	registries map[tenant.ID]*cachedRegistry
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

// cachedRegistry is one tenant's cache entry: the built registry (nil is
// the legitimate "no enabled providers" sentinel) and when it was built.
// Freshness keys on cachedAt, never on registry != nil — that is what
// makes an empty tenant cache its emptiness for the full TTL rather than
// re-querying the store on every request.
type cachedRegistry struct {
	registry *ProviderRegistry
	cachedAt time.Time
}

// maxCachedTenants bounds the registry cache. See the comment on
// Manager.registries for why the map is bounded rather than restricted
// to known tenants.
const maxCachedTenants = 1024

// ManagerOption configures a Manager at construction.
type ManagerOption func(*Manager)

// WithRedirectURLForTenant supplies the (tenant, provider) → callback-URL
// mapping for pooled deployments, where the callback usually differs per
// tenant. It takes precedence over WithRedirectURL when both are set.
//
// Single-tenant deployments keep using WithRedirectURL and are entirely
// unaffected.
func WithRedirectURLForTenant(fn func(tenantID, providerID string) string) ManagerOption {
	return func(m *Manager) {
		if fn != nil {
			m.redirectURLForTenant = fn
		}
	}
}

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
		registries:           make(map[tenant.ID]*cachedRegistry),
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

// PinRegistry is PinRegistry for one tenant's key, so a pooled
// deployment's handler tests can pin each tenant independently.
func (m *Manager) PinRegistry(tenantID tenant.ID, reg *ProviderRegistry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if reg == nil {
		delete(m.registries, tenantID)
		return
	}
	m.registries[tenantID] = &cachedRegistry{
		registry: reg,
		cachedAt: time.Date(pinnedCacheTimestampYear, time.December, 31, 23, 59, 59, 0, time.UTC),
	}
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

// GetRegistry is GetRegistry scoped to one tenant: the cached
// live registry for tenantID, rebuilt from the store on a miss or once
// the entry is older than ttl.
//
// Every caching semantic of GetRegistry is preserved PER KEY rather than
// globally. The double-checked locking is unchanged — RLock on the fast
// path, Lock plus a re-check on the slow one, so concurrent stampedes
// for the SAME tenant serialise into a single store read while different
// tenants never wait on each other's rebuild beyond the shared lock.
//
// The nil sentinel is cached per tenant with the same symmetry: a tenant
// with no enabled providers stores a nil registry with a fresh
// timestamp, so it honours the TTL exactly like a populated one. Without
// that, an empty tenant would re-query the store on every request and
// multi-replica convergence would be asymmetric — populated tenants
// converging within the TTL, empty ones immediately.
//
// A non-empty tenantID requires the store to implement
// the tenant-scoped ProviderStore. It fails rather than falling back to the
// untenanted list, which would serve every tenant's providers to one
// tenant. tamper.New already refuses this configuration at boot; this is
// the second line for a Manager constructed directly.
//
// Returns (nil, nil) when the tenant has no enabled providers.
func (m *Manager) GetRegistry(ctx context.Context, tenantID tenant.ID) (*ProviderRegistry, error) {
	m.mu.RLock()
	entry := m.registries[tenantID]
	m.mu.RUnlock()
	if entry != nil && m.cacheFresh(entry.cachedAt) {
		return entry.registry, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if e := m.registries[tenantID]; e != nil && m.cacheFresh(e.cachedAt) {
		return e.registry, nil
	}
	return m.rebuildLocked(ctx, tenantID)
}

// Reload is Reload for one tenant's key. It touches no other
// tenant's entry: an admin editing acme's IdP must not cost globex a
// discovery round-trip on its next login.
func (m *Manager) Reload(ctx context.Context, tenantID tenant.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.registries, tenantID)
	_, err := m.rebuildLocked(ctx, tenantID)
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
func (m *Manager) rebuildLocked(ctx context.Context, tenantID tenant.ID) (*ProviderRegistry, error) {
	recs, err := m.listEnabled(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if len(recs) == 0 {
		// Cache the nil "not configured" sentinel with a fresh
		// timestamp so a post-Delete rebuild drops the previous
		// registry AND the empty result honours the ttl window. Per
		// tenant, and with the same symmetry: an empty tenant caches its
		// emptiness for exactly as long as a populated one caches its
		// providers.
		m.storeLocked(tenantID, nil)
		return nil, nil
	}
	if m.redirectURL == nil && m.redirectURLForTenant == nil {
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
			RedirectURL:  m.redirectFor(tenantID.String(), def.ID),
			DisplayName:  def.DisplayName,
			Scopes:       def.Scopes,
			GroupsClaim:  def.GroupsClaim,
		})
	}
	reg, err := BuildRegistryFromConfigs(ctx, configs, true)
	if err != nil {
		return nil, fmt.Errorf("oidc: build registry: %w", err)
	}
	m.storeLocked(tenantID, reg)
	return reg, nil
}

// listEnabled reads the tenant's enabled providers. The untenanted key
// There is one call now. Before v0.4.0 this branched: an empty tenant
// took the unscoped store call and a named tenant required the optional
// scoped upgrade. Folding the interfaces removed the branch, and with it
// the possibility of the unscoped call ever running for a named tenant —
// which was the leak the branch existed to prevent.
func (m *Manager) listEnabled(ctx context.Context, tenantID tenant.ID) ([]ProviderRecord, error) {
	recs, err := m.store.ListEnabledProviders(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("oidc: list enabled providers: %w", err)
	}
	return recs, nil
}

// redirectFor maps a provider to its callback URL. The tenant-aware
// mapping wins when configured; otherwise the original per-id one is
// used exactly as before.
func (m *Manager) redirectFor(tenantID, providerID string) string {
	if m.redirectURLForTenant != nil {
		return m.redirectURLForTenant(tenantID, providerID)
	}
	return m.redirectURL(providerID)
}

// storeLocked caches one tenant's result and enforces the map bound.
// Caller MUST hold mu.Lock.
//
// Eviction is least-recently-rebuilt. It only runs when inserting a NEW
// key at the cap, so a steady-state deployment never evicts, and a
// pinned registry's far-future timestamp puts it last in line.
func (m *Manager) storeLocked(tenantID tenant.ID, reg *ProviderRegistry) {
	if _, exists := m.registries[tenantID]; !exists && len(m.registries) >= maxCachedTenants {
		var oldestKey tenant.ID
		var oldest time.Time
		for k, e := range m.registries {
			if oldest.IsZero() || e.cachedAt.Before(oldest) {
				oldestKey, oldest = k, e.cachedAt
			}
		}
		delete(m.registries, oldestKey)
	}
	m.registries[tenantID] = &cachedRegistry{registry: reg, cachedAt: m.now()}
}

// invalidateCache clears the untenanted cache entry so the next
// GetRegistry rebuilds. Called by Create/Update/Delete, whose store
// operations carry no tenant — they are the single-tenant CRUD surface
// and they invalidate the single-tenant key.
func (m *Manager) invalidateCache() {
	m.InvalidateTenant(tenant.Single)
}

// InvalidateTenant drops one tenant's cached registry so its next
// GetRegistry rebuilds from the store. ONE key: another
// tenant's cache is never touched, because an admin editing acme's
// providers is not a reason to make globex pay for a rebuild — and in a
// pooled deployment that cost is paid by a customer who did nothing.
//
// A pooled deployment calls this after writing a tenant's provider rows.
// It is the seam that exists because tamper names no tenant column:
// Create/Update/Delete take a provider id and cannot know which tenant a
// row belongs to, so the application — which owns that column — says so.
func (m *Manager) InvalidateTenant(tenantID tenant.ID) {
	m.mu.Lock()
	delete(m.registries, tenantID)
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
