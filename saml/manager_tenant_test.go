package saml

import (
	"context"
	"fmt"
	"github.com/suryakencana007/tamper/tenant"
	"sync"
	"testing"
	"time"
)

// Slice 7e-2 — the tenant-keyed registry cache for SAML. This suite is
// oidc/manager_tenant_test.go transposed: same test names modulo the
// SAML-specific ones at the bottom, so a reviewer diffing the two files
// sees only SAML differences. Any divergence is a bug in one of them.

// tenantProviderStore is a ProviderStore whose rows are filed under a
// tenant. The tenant lives in the STORE, not in ProviderRecord — tamper
// names no column.
type tenantProviderStore struct {
	mu        sync.Mutex
	byTenant  map[string][]ProviderRecord
	listCalls map[string]int
}

var _ ProviderStore = (*tenantProviderStore)(nil)

func newTenantProviderStore() *tenantProviderStore {
	return &tenantProviderStore{
		byTenant:  map[string][]ProviderRecord{},
		listCalls: map[string]int{},
	}
}

func (s *tenantProviderStore) put(tenantID tenant.ID, recs ...ProviderRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byTenant[tenantID.String()] = append(s.byTenant[tenantID.String()], recs...)
}

func (s *tenantProviderStore) calls(tenantID tenant.ID) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listCalls[tenantID.String()]
}

func (s *tenantProviderStore) ListEnabledProviders(_ context.Context, tenantID tenant.ID) ([]ProviderRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listCalls[tenantID.String()]++
	out := make([]ProviderRecord, 0)
	for _, r := range s.byTenant[tenantID.String()] {
		if r.Enabled {
			out = append(out, r)
		}
	}
	return out, nil
}

func (s *tenantProviderStore) ListProviders(context.Context) ([]ProviderRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ProviderRecord, 0)
	for _, recs := range s.byTenant {
		out = append(out, recs...)
	}
	return out, nil
}

func (s *tenantProviderStore) InsertProvider(context.Context, ProviderRecord) error { return nil }
func (s *tenantProviderStore) GetProvider(context.Context, string) (ProviderRecord, error) {
	return ProviderRecord{}, ErrProviderNotFound
}
func (s *tenantProviderStore) UpdateProvider(context.Context, ProviderRecord) error { return nil }
func (s *tenantProviderStore) UpdateProviderSealedKey(context.Context, string, []byte, time.Time) error {
	return nil
}
func (s *tenantProviderStore) DeleteProvider(context.Context, string) error { return nil }

func tenantManager(t *testing.T, s ProviderStore, ttl time.Duration) *Manager {
	t.Helper()
	return NewManager(s, nil,
		WithTTL(ttl),
		WithAssertionReplayStore(NoReplayDefence{}),
		WithSPMetadataURLForTenant(func(tenantID, id, _ string) string {
			return "https://" + tenantID + ".example.test/sp/" + id
		}),
	)
}

// brokenCertRec is an enabled provider whose PEM will not parse, so the
// rebuild logs and omits it. That is the resilience path this slice must
// keep working PER TENANT.
func brokenCertRec(id string) ProviderRecord {
	return ProviderRecord{
		ID: id, IdPMetadataURL: "https://idp.invalid/" + id, EntityID: "e-" + id,
		ACSURL: "https://sp.invalid/acs", SPSigningCertPEM: "-----BEGIN CERTIFICATE-----\nnot-a-cert\n-----END CERTIFICATE-----",
		SealedSigningKey: nil, Enabled: true,
	}
}

// --- invariant 1: no cross-visibility --------------------------------

func TestTenantRegistry_DisjointProviderSets(t *testing.T) {
	ctx := context.Background()
	s := newTenantProviderStore()
	s.put(tenant.New("acme"), brokenCertRec("acme-idp"))
	s.put(tenant.New("globex"), brokenCertRec("globex-idp"))
	m := tenantManager(t, s, time.Hour)

	regEmpty, err := m.GetRegistry(ctx, tenant.New("initech"))
	if err != nil {
		t.Fatalf("GetRegistryForTenant(initech): %v", err)
	}
	if regEmpty != nil {
		t.Errorf("a tenant with no providers got a registry: %+v", regEmpty)
	}

	for _, tid := range []string{"acme", "globex"} {
		if _, err := m.GetRegistry(ctx, tenant.New(tid)); err != nil {
			t.Fatalf("GetRegistryForTenant(%s): %v", tid, err)
		}
		if s.calls(tenant.New(tid)) != 1 {
			t.Errorf("tenant %s: store reads = %d, want 1", tid, s.calls(tenant.New(tid)))
		}
	}
}

// --- invariant 2: independent TTL expiry ------------------------------

func TestTenantRegistry_TTLExpiryIsPerTenant(t *testing.T) {
	ctx := context.Background()
	s := newTenantProviderStore()
	m := tenantManager(t, s, time.Hour)

	now := time.Unix(1700000000, 0).UTC()
	m.SetClock(func() time.Time { return now })

	if _, err := m.GetRegistry(ctx, tenant.New("acme")); err != nil {
		t.Fatalf("acme: %v", err)
	}
	now = now.Add(30 * time.Minute)
	if _, err := m.GetRegistry(ctx, tenant.New("globex")); err != nil {
		t.Fatalf("globex: %v", err)
	}
	now = now.Add(31 * time.Minute)
	if _, err := m.GetRegistry(ctx, tenant.New("acme")); err != nil {
		t.Fatalf("acme refresh: %v", err)
	}
	if _, err := m.GetRegistry(ctx, tenant.New("globex")); err != nil {
		t.Fatalf("globex refresh: %v", err)
	}
	if got := s.calls(tenant.New("acme")); got != 2 {
		t.Errorf("acme store reads = %d, want 2 (its TTL elapsed)", got)
	}
	if got := s.calls(tenant.New("globex")); got != 1 {
		t.Errorf("globex store reads = %d, want 1 — it expired on acme's schedule", got)
	}
}

// --- invariant 3: invalidation is per key -----------------------------

func TestTenantRegistry_InvalidatingOneTenantSparesTheOther(t *testing.T) {
	ctx := context.Background()
	s := newTenantProviderStore()
	m := tenantManager(t, s, time.Hour)

	for _, tid := range []string{"acme", "globex"} {
		if _, err := m.GetRegistry(ctx, tenant.New(tid)); err != nil {
			t.Fatalf("warm %s: %v", tid, err)
		}
	}

	m.InvalidateTenant(tenant.New("acme"))

	if _, err := m.GetRegistry(ctx, tenant.New("acme")); err != nil {
		t.Fatalf("acme after invalidate: %v", err)
	}
	if _, err := m.GetRegistry(ctx, tenant.New("globex")); err != nil {
		t.Fatalf("globex after acme's invalidate: %v", err)
	}
	if got := s.calls(tenant.New("acme")); got != 2 {
		t.Errorf("acme store reads = %d, want 2 (invalidated, so it rebuilt)", got)
	}
	if got := s.calls(tenant.New("globex")); got != 1 {
		t.Errorf("globex store reads = %d, want 1 — invalidating acme cleared globex's "+
			"cache too, so the whole map was dropped", got)
	}
}

// --- invariant 4: the nil sentinel is cached symmetrically ------------

func TestTenantRegistry_NilSentinelCachedForTTL(t *testing.T) {
	ctx := context.Background()
	s := newTenantProviderStore()
	m := tenantManager(t, s, time.Hour)
	now := time.Unix(1700000000, 0).UTC()
	m.SetClock(func() time.Time { return now })

	for range 5 {
		reg, err := m.GetRegistry(ctx, tenant.New("empty-tenant"))
		if err != nil {
			t.Fatalf("GetRegistryForTenant: %v", err)
		}
		if reg != nil {
			t.Fatalf("expected the nil sentinel, got %+v", reg)
		}
	}
	if got := s.calls(tenant.New("empty-tenant")); got != 1 {
		t.Errorf("store reads = %d, want 1 — the empty result was not cached", got)
	}

	now = now.Add(2 * time.Hour)
	if _, err := m.GetRegistry(ctx, tenant.New("empty-tenant")); err != nil {
		t.Fatalf("after ttl: %v", err)
	}
	if got := s.calls(tenant.New("empty-tenant")); got != 2 {
		t.Errorf("store reads after TTL = %d, want 2", got)
	}
}

// --- invariant 5: concurrency ----------------------------------------

func TestTenantRegistry_ConcurrentAcrossTenants(t *testing.T) {
	ctx := context.Background()
	s := newTenantProviderStore()
	m := tenantManager(t, s, time.Hour)

	var wg sync.WaitGroup
	for i := range 8 {
		tid := fmt.Sprintf("t-%d", i%4)
		wg.Add(3)
		go func() { defer wg.Done(); _, _ = m.GetRegistry(ctx, tenant.New(tid)) }()
		go func() { defer wg.Done(); m.InvalidateTenant(tenant.New(tid)) }()
		go func() { defer wg.Done(); _, _ = m.GetRegistry(ctx, tenant.New(tid)) }()
	}
	wg.Wait()

	if _, err := m.GetRegistry(ctx, tenant.New("t-0")); err != nil {
		t.Fatalf("after concurrent load: %v", err)
	}
}

// --- the untenanted path is unchanged ---------------------------------

func TestTenantRegistry_UntenantedKeyHoldsExactlyOneRegistry(t *testing.T) {
	ctx := context.Background()
	s := newTenantProviderStore()
	m := tenantManager(t, s, time.Hour)

	for range 3 {
		if _, err := m.GetRegistry(ctx, tenant.Single); err != nil {
			t.Fatalf("GetRegistry: %v", err)
		}
	}
	if got := s.calls(tenant.Single); got != 1 {
		t.Errorf("untenanted store reads = %d, want 1", got)
	}
	m.mu.RLock()
	n := len(m.registries)
	_, hasEmptyKey := m.registries[tenant.Single]
	m.mu.RUnlock()
	if n != 1 || !hasEmptyKey {
		t.Errorf("cache holds %d entries (empty key present: %v), want exactly 1 under \"\"", n, hasEmptyKey)
	}
}

func TestTenantRegistry_PinWorksPerTenant(t *testing.T) {
	ctx := context.Background()
	s := newTenantProviderStore()
	m := tenantManager(t, s, 0)

	pinned := &ProviderRegistry{}
	m.PinRegistry(tenant.New("acme"), pinned)

	got, err := m.GetRegistry(ctx, tenant.New("acme"))
	if err != nil {
		t.Fatalf("acme: %v", err)
	}
	if got != pinned {
		t.Errorf("pinned registry not returned for acme")
	}
	if s.calls(tenant.New("acme")) != 0 {
		t.Errorf("pinned tenant still read the store %d times", s.calls(tenant.New("acme")))
	}
	if _, err := m.GetRegistry(ctx, tenant.New("globex")); err != nil {
		t.Fatalf("globex: %v", err)
	}
	if s.calls(tenant.New("globex")) != 1 {
		t.Errorf("globex store reads = %d, want 1 — acme's pin leaked", s.calls(tenant.New("globex")))
	}
}

// --- fail closed on a store that cannot scope -------------------------

// --- map growth is bounded --------------------------------------------

func TestTenantRegistry_MapGrowthIsBounded(t *testing.T) {
	ctx := context.Background()
	s := newTenantProviderStore()
	m := tenantManager(t, s, time.Hour)
	now := time.Unix(1700000000, 0).UTC()
	m.SetClock(func() time.Time { now = now.Add(time.Millisecond); return now })

	for i := range maxCachedTenants + 250 {
		if _, err := m.GetRegistry(ctx, tenant.New(fmt.Sprintf("junk-%d", i))); err != nil {
			t.Fatalf("tenant %d: %v", i, err)
		}
	}
	m.mu.RLock()
	n := len(m.registries)
	m.mu.RUnlock()
	if n > maxCachedTenants {
		t.Errorf("cache holds %d entries, want at most %d", n, maxCachedTenants)
	}
}

// --- SAML-SPECIFIC: the parts that are not in the OIDC suite ----------

// TestTenantRegistry_BrokenCertInOneTenantSparesTheOther is the
// per-tenant form of SAML's log-and-omit rebuild resilience. A
// mis-provisioned IdP must take down neither its own tenant's other
// providers nor any other tenant — and before the cache was keyed, a
// broken cert anywhere degraded the single shared registry for everyone.
func TestTenantRegistry_BrokenCertInOneTenantSparesTheOther(t *testing.T) {
	ctx := context.Background()
	s := newTenantProviderStore()
	// acme's only provider has unparseable PEM.
	s.put(tenant.New("acme"), brokenCertRec("acme-broken"))
	// globex has none at all, so it takes the empty-sentinel path.
	m := tenantManager(t, s, time.Hour)

	// acme rebuilds to the nil sentinel rather than erroring: the broken
	// provider was logged and omitted.
	reg, err := m.GetRegistry(ctx, tenant.New("acme"))
	if err != nil {
		t.Fatalf("a broken cert failed the whole rebuild instead of being omitted: %v", err)
	}
	if reg != nil {
		t.Errorf("expected the nil sentinel for a tenant whose only provider is broken, got %+v", reg)
	}

	// globex is untouched by acme's bad row.
	if _, err := m.GetRegistry(ctx, tenant.New("globex")); err != nil {
		t.Errorf("globex broke because acme had a bad cert: %v", err)
	}
	if got := s.calls(tenant.New("globex")); got != 1 {
		t.Errorf("globex store reads = %d, want 1", got)
	}
}

// TestSetMaxClockSkew_IsProcessGlobalNotPerTenant re-documents the
// constraint as an executable statement rather than a comment that can
// drift.
//
// crewjam/saml v0.5.x holds MaxClockSkew in a PACKAGE-LEVEL variable, so
// there is no per-provider — and therefore no per-tenant — form of it.
// The right response is to leave it as the app's process-global boot
// call, not to wrap it in a per-tenant API that cannot honour its own
// signature. A per-tenant API over a process-global is a lie, and the
// lie would only surface as one tenant's skew silently applying to
// another's assertions.
func TestSetMaxClockSkew_IsProcessGlobalNotPerTenant(t *testing.T) {
	if _, ok := any(&Manager{}).(interface {
		SetMaxClockSkewForTenant(string, time.Duration)
	}); ok {
		t.Error("Manager grew a per-tenant clock-skew setter. crewjam's MaxClockSkew is " +
			"package-level state; a per-tenant API over it cannot be honoured and would " +
			"apply one tenant's skew to every tenant.")
	}
	// The process-global entry point is still the package function.
	if _, ok := any(&Manager{}).(interface{ SetMaxClockSkew(time.Duration) }); ok {
		t.Error("SetMaxClockSkew moved onto the Manager, implying per-Manager scope it " +
			"does not have; it must stay a package-level call the app makes once at boot.")
	}
}
