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

	tampercrypto "github.com/suryakencana007/barista/packages/tamper/crypto"
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

	mu       sync.RWMutex
	registry *ProviderRegistry
	cachedAt time.Time
	ttl      time.Duration

	now func() time.Time
}

// ManagerOption configures a Manager at construction.
type ManagerOption func(*Manager)

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

// NewManager constructs a Manager over the given store. keys may be
// nil — reads then surface the signing key as empty and mutations
// that must seal refuse with ErrNoKeySet.
func NewManager(store ProviderStore, keys *tampercrypto.KeySet, opts ...ManagerOption) *Manager {
	m := &Manager{
		store:   store,
		keys:    keys,
		fetcher: DefaultMetadataFetcher,
		now:     time.Now,
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

// PinRegistry installs a pre-built registry that stays cached until
// the next mutation regardless of ttl (Year-9999 cachedAt sentinel).
// Passing nil clears the cache. Test-seam only.
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

// GetRegistry returns the cached live registry, rebuilding from the
// store on a cache miss or TTL expiry. Same caching contract as the
// OIDC Manager. Returns (nil, nil) when no usable enabled providers
// exist.
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

// Reload clears the cache + eagerly rebuilds from the store.
func (m *Manager) Reload(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.registry = nil
	m.cachedAt = time.Time{}
	_, err := m.rebuildLocked(ctx)
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
func (m *Manager) rebuildLocked(ctx context.Context) (*ProviderRegistry, error) {
	recs, err := m.store.ListEnabledProviders(ctx)
	if err != nil {
		return nil, fmt.Errorf("saml: list enabled providers: %w", err)
	}
	if len(recs) == 0 {
		m.registry = nil
		m.cachedAt = m.now()
		return nil, nil
	}
	if m.spMetadataURL == nil {
		return nil, fmt.Errorf("saml: manager has no SP-metadata-URL mapping (WithSPMetadataURL)")
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
			MetadataURL:            m.spMetadataURL(def.ID, def.ACSURL),
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
		m.registry = nil
		m.cachedAt = m.now()
		return nil, nil
	}
	reg, err := BuildRegistryFromConfigs(ctx, configs, m.fetcher, true)
	if err != nil {
		return nil, fmt.Errorf("saml: build registry: %w", err)
	}
	m.registry = reg
	m.cachedAt = m.now()
	return reg, nil
}

func (m *Manager) invalidateCache() {
	m.mu.Lock()
	m.registry = nil
	m.cachedAt = time.Time{}
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
