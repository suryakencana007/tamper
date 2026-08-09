package saml

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	crewjamsaml "github.com/crewjam/saml"

	tampercrypto "github.com/suryakencana007/tamper/crypto"
	"github.com/suryakencana007/tamper/tenant"
)

// ErrNoKeySet surfaces from Manager mutations that need to seal or
// open an SP signing key when no KeySet was configured.
var ErrNoKeySet = errors.New("saml: no keyset configured")

// ProviderDefinition is the plaintext-at-the-boundary CRUD shape.
// SPSigningKey is the plaintext PEM here; the Manager seals it under
// the KeySet before it reaches the ProviderStore and opens it on
// reads. App-side validation policy (metadata-URL scheme rules, ACS
// shape checks) runs BEFORE the app calls the Manager.
type ProviderDefinition struct {
	ID                     string
	IdPMetadataURL         string
	EntityID               string
	ACSURL                 string
	SPSigningCertPEM       string
	SPSigningKey           string
	AttributeMappingGroups string
	AttributeMappingEmail  string
	AttributeMappingName   string
	DisplayName            string
	Enabled                bool
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

// MetadataTestResult is the probe shape returned by TestMetadata.
// Admin UIs render it as a per-endpoint status row.
type MetadataTestResult struct {
	EntityID          string
	SSOServiceURL     string
	SSOServiceBinding string
	SigningCertCount  int
}

// RotateResult is the per-pass summary of RotateSealedKeys.
type RotateResult struct {
	Scanned int
	Rotated int
}

// Manager owns the store-backed SAML provider lifecycle: CRUD with
// at-rest signing-key sealing, the TTL-cached live ProviderRegistry,
// the IdP-metadata Test probe, and the rotate-KEK re-seal loop.
// Mirrors the OIDC Manager's caching contract exactly (double-checked
// locking, symmetric nil-sentinel caching, eager same-process
// invalidation, Year-9999 pin seam).
type Manager struct {
	store   ProviderStore
	keys    *tampercrypto.KeySet
	fetcher MetadataFetcher

	// spMetadataURL maps (provider id, ACS URL) to the full SP
	// metadata URL used when building the live registry. Route shapes
	// are the app's — this is the seam that keeps them out of the
	// framework.
	spMetadataURL func(id, acsURL string) string

	// allowIDPInitiated + skewTolerance are threaded into every
	// per-provider ProviderConfig at rebuild. Note the library-global
	// clock-skew pin (SetMaxClockSkew) stays the APP's boot-time call
	// — it is process-global state, not per-Manager.
	allowIDPInitiated bool
	skewTolerance     time.Duration

	// replay is the assertion-replay ledger threaded into every rebuilt
	// registry. REQUIRED (WithAssertionReplayStore): rebuildLocked refuses
	// to build without one, matching the spMetadataURL contract, since
	// NewManager returns no error.
	replay AssertionReplayStore

	// warnedNoReplay fires the one-shot SECURITY log at most once when the
	// configured ledger is NoReplayDefence.
	warnedNoReplay sync.Once

	// spMetadataURLForTenant is the tenant-aware form of spMetadataURL.
	// When set it wins, because a pooled deployment's ACS/metadata URLs
	// usually vary by tenant. Mirrors oidc.WithRedirectURLForTenant.
	spMetadataURLForTenant func(tenantID, id, acsURL string) string

	// mu guards registries. STILL an RWMutex, for the reason the OIDC
	// Manager records: the read path dominates. Per-tenant keying turns a
	// single cached value into a keyed map; it adds no second lock (§6.6).
	mu sync.RWMutex
	// registries is the cache, keyed by tenant. The "" key is the
	// single-tenant deployment and holds exactly one registry.
	//
	// MAP GROWTH: bounded, not restricted to known tenants — identical
	// decision and identical reasoning to oidc.Manager.registries. The
	// Manager has no tenant.Store to validate ids against, so at
	// maxCachedTenants an insert evicts the least-recently-rebuilt entry.
	// Refusing to cache past the cap would let an attacker fill it with
	// junk and force every real tenant onto the uncached path.
	registries map[tenant.ID]*cachedRegistry
	ttl        time.Duration

	now func() time.Time
}

// cachedRegistry is one tenant's cache entry. Mirrors the OIDC type:
// freshness keys on cachedAt, never on registry != nil, so an empty
// tenant caches its emptiness for the full TTL.
type cachedRegistry struct {
	registry *ProviderRegistry
	cachedAt time.Time
}

// maxCachedTenants bounds the registry cache. Same value and same
// reasoning as the OIDC Manager's.
const maxCachedTenants = 1024

// ManagerOption configures a Manager at construction.
type ManagerOption func(*Manager)

// WithSPMetadataURLForTenant supplies the (tenant, provider, ACS URL) →
// SP-metadata-URL mapping for pooled deployments. Takes precedence over
// WithSPMetadataURL when both are set.
//
// The SAML analogue of oidc.WithRedirectURLForTenant, carrying the extra
// acsURL argument the single-tenant form already had — the one shape
// difference between the two packages, and it is SAML's, not tenancy's.
func WithSPMetadataURLForTenant(fn func(tenantID, id, acsURL string) string) ManagerOption {
	return func(m *Manager) {
		if fn != nil {
			m.spMetadataURLForTenant = fn
		}
	}
}

// WithTTL sets the registry cache-freshness window. Zero (the
// default) rebuilds on every GetRegistry call.
func WithTTL(d time.Duration) ManagerOption {
	return func(m *Manager) { m.ttl = d }
}

// WithMetadataFetcher swaps the IdP metadata fetcher (default:
// DefaultMetadataFetcher).
func WithMetadataFetcher(fn MetadataFetcher) ManagerOption {
	return func(m *Manager) {
		if fn != nil {
			m.fetcher = fn
		}
	}
}

// WithSPMetadataURL supplies the (id, ACS URL) → SP-metadata-URL
// mapping used when building the live registry. Required before
// GetRegistry or Reload can build a non-empty registry.
func WithSPMetadataURL(fn func(id, acsURL string) string) ManagerOption {
	return func(m *Manager) {
		if fn != nil {
			m.spMetadataURL = fn
		}
	}
}

// WithAllowIDPInitiated sets the IdP-initiated-SSO policy threaded
// into every per-provider config at rebuild. Default false.
func WithAllowIDPInitiated(v bool) ManagerOption {
	return func(m *Manager) { m.allowIDPInitiated = v }
}

// WithSkewTolerance records the assertion clock-skew tolerance on
// each per-provider config (forensic — see ProviderConfig). The
// process-global crewjam pin is the app's separate SetMaxClockSkew
// call.
func WithSkewTolerance(d time.Duration) ManagerOption {
	return func(m *Manager) { m.skewTolerance = d }
}

// WithAssertionReplayStore installs the single-use assertion-replay ledger
// that every rebuilt Provider consumes assertions against. REQUIRED: a
// Manager without one cannot build a registry (rebuildLocked errors, the
// same shape as a missing WithSPMetadataURL). Pass NoReplayDefence{} to opt
// out explicitly — safe only when AllowIDPInitiated is false for every
// provider, since Layer 1 correlation then covers the whole surface.
func WithAssertionReplayStore(s AssertionReplayStore) ManagerOption {
	return func(m *Manager) { m.replay = s }
}

// NewManager constructs a Manager over the given store. keys may be
// nil — reads then surface the signing key as empty and mutations
// that must seal refuse with ErrNoKeySet.
func NewManager(store ProviderStore, keys *tampercrypto.KeySet, opts ...ManagerOption) *Manager {
	m := &Manager{
		store:      store,
		keys:       keys,
		fetcher:    DefaultMetadataFetcher,
		registries: make(map[tenant.ID]*cachedRegistry),
		now:        time.Now,
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

// Keys returns the configured envelope keyset.
func (m *Manager) Keys() *tampercrypto.KeySet { return m.keys }

// AllowIDPInitiated returns the configured IdP-initiated-SSO policy.
func (m *Manager) AllowIDPInitiated() bool { return m.allowIDPInitiated }

// SetClock swaps the clock seam. Test-seam only.
func (m *Manager) SetClock(now func() time.Time) {
	if now != nil {
		m.now = now
	}
}

// SetMetadataFetcher swaps the fetcher post-construction. Test-seam
// only.
func (m *Manager) SetMetadataFetcher(fn MetadataFetcher) {
	if fn != nil {
		m.fetcher = fn
	}
}

// PinRegistry is PinRegistry for one tenant's key. Mirrors
// oidc.Manager.PinRegistry.
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

const pinnedCacheTimestampYear = 9999

// Create persists a new provider, sealing the signing key and
// stamping CreatedAt/UpdatedAt from the Manager clock.
func (m *Manager) Create(ctx context.Context, def ProviderDefinition) error {
	if def.ID == "" {
		return fmt.Errorf("saml: provider id is required")
	}
	if m.keys == nil {
		return ErrNoKeySet
	}
	sealed, err := m.keys.Seal([]byte(def.SPSigningKey))
	if err != nil {
		return fmt.Errorf("saml: seal signing key: %w", err)
	}
	now := m.now().UTC()
	rec := recordFromDefinition(def, sealed)
	rec.CreatedAt = now
	rec.UpdatedAt = now
	if err := m.store.InsertProvider(ctx, rec); err != nil {
		return err
	}
	m.invalidateCache()
	return nil
}

// Get returns one provider by id with the signing key opened.
func (m *Manager) Get(ctx context.Context, id string) (ProviderDefinition, error) {
	if id == "" {
		return ProviderDefinition{}, fmt.Errorf("saml: provider id is required")
	}
	rec, err := m.store.GetProvider(ctx, id)
	if err != nil {
		return ProviderDefinition{}, err
	}
	return m.definitionFromRecord(rec)
}

// List returns every provider with signing keys opened, in the
// store's ordering.
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

// Update rewrites every mutable column, re-sealing the signing key.
func (m *Manager) Update(ctx context.Context, def ProviderDefinition) error {
	if def.ID == "" {
		return fmt.Errorf("saml: provider id is required")
	}
	if m.keys == nil {
		return ErrNoKeySet
	}
	if _, err := m.store.GetProvider(ctx, def.ID); err != nil {
		return err
	}
	sealed, err := m.keys.Seal([]byte(def.SPSigningKey))
	if err != nil {
		return fmt.Errorf("saml: seal signing key: %w", err)
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
		return fmt.Errorf("saml: provider id is required")
	}
	if err := m.store.DeleteProvider(ctx, id); err != nil {
		return err
	}
	m.invalidateCache()
	return nil
}

// TestMetadata fetches + parses IdP metadata WITHOUT persisting.
// The returned error preserves the fetcher's sentinel chain
// (ErrMetadataFetchFailed / ErrMetadataInvalid) so callers can
// errors.Is through their own wrapping.
func (m *Manager) TestMetadata(ctx context.Context, idpMetadataURL string) (*MetadataTestResult, error) {
	entity, err := m.fetcher(ctx, idpMetadataURL)
	if err != nil {
		return nil, err
	}
	res := &MetadataTestResult{EntityID: entity.EntityID}
	if len(entity.IDPSSODescriptors) > 0 {
		desc := entity.IDPSSODescriptors[0]
		// Prefer HTTP-Redirect binding for SP-initiated AuthnRequests;
		// fall back to the first available binding (some IdPs only
		// emit HTTP-POST).
		for _, svc := range desc.SingleSignOnServices {
			if svc.Binding == crewjamsaml.HTTPRedirectBinding {
				res.SSOServiceURL = svc.Location
				res.SSOServiceBinding = svc.Binding
				break
			}
		}
		if res.SSOServiceURL == "" && len(desc.SingleSignOnServices) > 0 {
			res.SSOServiceURL = desc.SingleSignOnServices[0].Location
			res.SSOServiceBinding = desc.SingleSignOnServices[0].Binding
		}
		for _, kd := range desc.KeyDescriptors {
			if kd.Use == "" || kd.Use == "signing" {
				if len(kd.KeyInfo.X509Data.X509Certificates) > 0 {
					res.SigningCertCount += len(kd.KeyInfo.X509Data.X509Certificates)
				}
			}
		}
	}
	return res, nil
}

// GetRegistry is GetRegistry scoped to one tenant. Mirrors
// oidc.Manager.GetRegistry exactly: same double-checked
// locking, same per-key nil-sentinel symmetry, same fail-closed on a
// store that cannot scope.
//
// Returns (nil, nil) when the tenant has no usable enabled providers.
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

// Reload is Reload for one tenant's key, touching no other
// tenant's entry. Mirrors oidc.Manager.Reload.
func (m *Manager) Reload(ctx context.Context, tenantID tenant.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.registries, tenantID)
	_, err := m.rebuildLocked(ctx, tenantID)
	return err
}

// RotateSealedKeys re-seals every record's signing key under the
// keyset's current write key. Idempotent on re-run.
func (m *Manager) RotateSealedKeys(ctx context.Context) (RotateResult, error) {
	if m.keys == nil {
		return RotateResult{}, ErrNoKeySet
	}
	recs, err := m.store.ListProviders(ctx)
	if err != nil {
		return RotateResult{}, fmt.Errorf("saml: rotate: scan providers: %w", err)
	}
	writeID := m.keys.WriteKeyID()
	result := RotateResult{}
	for _, rec := range recs {
		if len(rec.SealedSigningKey) == 0 {
			continue
		}
		result.Scanned++
		if rec.SealedSigningKey[0] == writeID {
			log.Printf("saml: rotate: provider %q already at keyId=%d; skipping", rec.ID, writeID)
			continue
		}
		plaintext, openErr := m.keys.Open(rec.SealedSigningKey)
		if openErr != nil {
			return result, fmt.Errorf("saml: rotate: decrypt %q: %w", rec.ID, openErr)
		}
		sealed, sealErr := m.keys.Seal(plaintext)
		if sealErr != nil {
			return result, fmt.Errorf("saml: rotate: seal %q: %w", rec.ID, sealErr)
		}
		if upErr := m.store.UpdateProviderSealedKey(ctx, rec.ID, sealed, m.now().UTC()); upErr != nil {
			return result, fmt.Errorf("saml: rotate: persist %q: %w", rec.ID, upErr)
		}
		log.Printf("saml: rotate: provider %q re-sealed under keyId=%d", rec.ID, writeID)
		result.Rotated++
	}
	return result, nil
}

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

// rebuildLocked reads enabled records, opens signing keys, parses
// PEM material (a bad cert/key logs + omits that provider — one
// mis-provisioned IdP must not take the rest down), and builds the
// registry with partialOK=true. Caller MUST hold mu.Lock.
func (m *Manager) rebuildLocked(ctx context.Context, tenantID tenant.ID) (*ProviderRegistry, error) {
	recs, err := m.listEnabled(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if len(recs) == 0 {
		// Per-tenant nil sentinel, cached with a fresh timestamp so an
		// empty tenant honours the TTL exactly as a populated one does.
		m.storeLocked(tenantID, nil)
		return nil, nil
	}
	if m.spMetadataURL == nil && m.spMetadataURLForTenant == nil {
		return nil, fmt.Errorf("saml: manager has no SP-metadata-URL mapping (WithSPMetadataURL)")
	}
	if m.replay == nil {
		return nil, fmt.Errorf("saml: manager has no assertion replay store (WithAssertionReplayStore); " +
			"pass saml.NewMemAssertionReplayStore() for one process, a shared store for multiple " +
			"replicas, or saml.NoReplayDefence{} to opt out explicitly")
	}
	if _, isNoop := m.replay.(NoReplayDefence); isNoop {
		m.warnedNoReplay.Do(func() {
			log.Printf("saml: SECURITY: assertion replay defence is DISABLED (NoReplayDefence). " +
				"Safe only when AllowIDPInitiated=false for every provider; otherwise a captured " +
				"IdP-initiated assertion is replayable within its validity window.")
		})
	}
	configs := make([]ProviderConfig, 0, len(recs))
	for _, rec := range recs {
		def, derr := m.definitionFromRecord(rec)
		if derr != nil {
			return nil, derr
		}
		cert, certErr := ParseCertPEM(def.SPSigningCertPEM)
		if certErr != nil {
			log.Printf("saml: provider %q: cert parse failed; omitting from registry: %v", def.ID, certErr)
			continue
		}
		key, keyErr := ParsePrivateKeyPEM(def.SPSigningKey)
		if keyErr != nil {
			log.Printf("saml: provider %q: key parse failed; omitting from registry: %v", def.ID, keyErr)
			continue
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			log.Printf("saml: provider %q: parsed key is not a crypto.Signer; omitting", def.ID)
			continue
		}
		configs = append(configs, ProviderConfig{
			ID:                     def.ID,
			IdPMetadataURL:         def.IdPMetadataURL,
			EntityID:               def.EntityID,
			ACSURL:                 def.ACSURL,
			MetadataURL:            m.spMetadataFor(tenantID.String(), def.ID, def.ACSURL),
			SPCert:                 cert,
			SPKey:                  signer,
			DisplayName:            def.DisplayName,
			AttributeMappingGroups: def.AttributeMappingGroups,
			AttributeMappingEmail:  def.AttributeMappingEmail,
			AttributeMappingName:   def.AttributeMappingName,
			AllowIDPInitiated:      m.allowIDPInitiated,
			SkewTolerance:          m.skewTolerance,
		})
	}
	if len(configs) == 0 {
		// Every provider for this tenant failed PEM parsing and was
		// logged + omitted above. That is the rebuild resilience, and it
		// is now PER TENANT: one mis-provisioned IdP takes down neither
		// its own tenant's other providers nor any other tenant's.
		m.storeLocked(tenantID, nil)
		return nil, nil
	}
	reg, err := BuildRegistryFromConfigs(ctx, configs, m.fetcher, true, m.replay)
	if err != nil {
		return nil, fmt.Errorf("saml: build registry: %w", err)
	}
	m.storeLocked(tenantID, reg)
	return reg, nil
}

// listEnabled reads the tenant's enabled providers. The untenanted key
// uses the original call, unchanged. A named tenant REQUIRES the scoped
// store; falling back to ListEnabledProviders would hand one tenant
// every tenant's IdPs. Mirrors oidc.Manager.listEnabled.
func (m *Manager) listEnabled(ctx context.Context, tenantID tenant.ID) ([]ProviderRecord, error) {
	recs, err := m.store.ListEnabledProviders(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("saml: list enabled providers: %w", err)
	}
	return recs, nil
}

// spMetadataFor maps a provider to its SP-metadata URL. The
// tenant-aware mapping wins when configured. Mirrors
// oidc.Manager.redirectFor, plus SAML's acsURL argument.
func (m *Manager) spMetadataFor(tenantID, providerID, acsURL string) string {
	if m.spMetadataURLForTenant != nil {
		return m.spMetadataURLForTenant(tenantID, providerID, acsURL)
	}
	return m.spMetadataURL(providerID, acsURL)
}

// storeLocked caches one tenant's result and enforces the map bound.
// Caller MUST hold mu.Lock. Mirrors oidc.Manager.storeLocked.
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

// invalidateCache clears the untenanted entry. Called by
// Create/Update/Delete, whose store operations carry no tenant.
func (m *Manager) invalidateCache() {
	m.InvalidateTenant(tenant.Single)
}

// InvalidateTenant drops one tenant's cached registry. ONE key: another
// tenant's cache is never touched. Mirrors oidc.Manager.InvalidateTenant,
// and exists for the same reason — tamper names no tenant column, so
// Create/Update/Delete cannot know which tenant a provider row belongs
// to and the application says so.
func (m *Manager) InvalidateTenant(tenantID tenant.ID) {
	m.mu.Lock()
	delete(m.registries, tenantID)
	m.mu.Unlock()
}

// definitionFromRecord opens the sealed signing key + projects the
// record to the plaintext boundary shape. A nil keyset surfaces the
// key as empty; a sealed value that fails to open is an error.
func (m *Manager) definitionFromRecord(rec ProviderRecord) (ProviderDefinition, error) {
	var plaintext []byte
	if m.keys != nil && len(rec.SealedSigningKey) > 0 {
		pt, err := m.keys.Open(rec.SealedSigningKey)
		if err != nil {
			return ProviderDefinition{}, fmt.Errorf("saml: provider %q: open signing key: %w", rec.ID, err)
		}
		plaintext = pt
	}
	return ProviderDefinition{
		ID:                     rec.ID,
		IdPMetadataURL:         rec.IdPMetadataURL,
		EntityID:               rec.EntityID,
		ACSURL:                 rec.ACSURL,
		SPSigningCertPEM:       rec.SPSigningCertPEM,
		SPSigningKey:           string(plaintext),
		AttributeMappingGroups: rec.AttributeMappingGroups,
		AttributeMappingEmail:  rec.AttributeMappingEmail,
		AttributeMappingName:   rec.AttributeMappingName,
		DisplayName:            rec.DisplayName,
		Enabled:                rec.Enabled,
		CreatedAt:              rec.CreatedAt,
		UpdatedAt:              rec.UpdatedAt,
	}, nil
}

func recordFromDefinition(def ProviderDefinition, sealed []byte) ProviderRecord {
	return ProviderRecord{
		ID:                     def.ID,
		IdPMetadataURL:         def.IdPMetadataURL,
		EntityID:               def.EntityID,
		ACSURL:                 def.ACSURL,
		SPSigningCertPEM:       def.SPSigningCertPEM,
		SealedSigningKey:       sealed,
		AttributeMappingGroups: def.AttributeMappingGroups,
		AttributeMappingEmail:  def.AttributeMappingEmail,
		AttributeMappingName:   def.AttributeMappingName,
		DisplayName:            def.DisplayName,
		Enabled:                def.Enabled,
		CreatedAt:              def.CreatedAt,
		UpdatedAt:              def.UpdatedAt,
	}
}
