package oidc

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/suryakencana007/tamper/tenant"
)

// Slice 7e-1 — the tenant-keyed registry cache. Every caching semantic
// the single-value cache had must hold PER KEY, and each one gets a
// named test because the cache is load-bearing: it sits on the read path
// of every federated login.

// tenantProviderStore is a ProviderStore whose rows are filed under a
// tenant. The tenant lives in the STORE, not in ProviderRecord — tamper
// names no column, so the app's schema is the only thing that knows
// which tenant a provider belongs to.
type tenantProviderStore struct {
	mu sync.Mutex
	// byTenant is the app's schema, standing in for a WHERE tenant_id = ?
	byTenant map[string][]ProviderRecord
	// listCalls counts scoped reads so a test can prove the cache
	// actually prevented a store round-trip.
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
func (s *tenantProviderStore) UpdateProviderSealedSecret(context.Context, string, []byte, time.Time) error {
	return nil
}
func (s *tenantProviderStore) DeleteProvider(context.Context, string) error { return nil }

func tenantManager(t *testing.T, s ProviderStore, ttl time.Duration) *Manager {
	t.Helper()
	m := NewManager(s, nil,
		WithTTL(ttl),
		WithRedirectURLForTenant(func(tenantID, id string) string {
			return "https://" + tenantID + ".example.test/cb/" + id
		}),
	)
	return m
}

// rec builds an enabled record whose issuer points at a URL that will
// never be dialled — every test here pins or expects an empty registry,
// so no discovery happens.
func rec(id string) ProviderRecord {
	return ProviderRecord{ID: id, IssuerURL: "https://idp.invalid/" + id, ClientID: "c", Enabled: true}
}

// --- invariant 1: no cross-visibility --------------------------------

// TestTenantRegistry_DisjointProviderSets: each tenant's rebuild reads
// only its own rows. This is the leak the slice exists to close — one
// process-wide registry meant every tenant saw every IdP.
func TestTenantRegistry_DisjointProviderSets(t *testing.T) {
	ctx := context.Background()
	s := newTenantProviderStore()
	s.put(tenant.New("acme"), rec("acme-idp"))
	s.put(tenant.New("globex"), rec("globex-idp"))
	m := tenantManager(t, s, time.Hour)

	// A provider-less tenant sees nothing, and crucially not the others'.
	regEmpty, err := m.GetRegistry(ctx, tenant.New("initech"))
	if err != nil {
		t.Fatalf("GetRegistryForTenant(initech): %v", err)
	}
	if regEmpty != nil {
		t.Errorf("a tenant with no providers got a registry: %+v", regEmpty)
	}

	// And each populated tenant's rebuild asked the store for ITS rows.
	for _, tid := range []string{"acme", "globex"} {
		if _, err := m.GetRegistry(ctx, tenant.New(tid)); err != nil {
			// Discovery against idp.invalid fails, and partialOK omits the
			// provider — an empty registry, not an error.
			t.Fatalf("GetRegistryForTenant(%s): %v", tid, err)
		}
		if s.calls(tenant.New(tid)) != 1 {
			t.Errorf("tenant %s: store reads = %d, want 1", tid, s.calls(tenant.New(tid)))
		}
	}
	// Nobody read another tenant's rows on their behalf.
	if s.calls(tenant.New("acme")) != 1 || s.calls(tenant.New("globex")) != 1 {
		t.Errorf("cross-tenant store reads: acme=%d globex=%d", s.calls(tenant.New("acme")), s.calls(tenant.New("globex")))
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
	// 30 minutes later globex builds for the first time.
	now = now.Add(30 * time.Minute)
	if _, err := m.GetRegistry(ctx, tenant.New("globex")); err != nil {
		t.Fatalf("globex: %v", err)
	}
	// At +61m acme is stale and rebuilds; globex (built at +30m) is not.
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
		t.Errorf("globex store reads = %d, want 1 — its TTL had not elapsed, so it "+
			"expired on acme's schedule instead of its own", got)
	}
}

// --- invariant 3: invalidation is per key -----------------------------

// TestTenantRegistry_InvalidatingOneTenantSparesTheOther is the mutation
// target. Clearing the whole map on any mutation makes an admin editing
// acme's IdP cost globex a rebuild — a customer paying for work they did
// not cause, on the read path of every login.
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

// TestTenantRegistry_NilSentinelCachedForTTL: a tenant with no providers
// must cache its emptiness for the full TTL, exactly as a populated
// tenant caches its providers. Without the symmetry, every request from
// an unconfigured tenant hits the store, and multi-replica convergence
// becomes asymmetric — populated tenants converging within the TTL,
// empty ones instantly.
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
		t.Errorf("store reads = %d, want 1 — the empty result was not cached, so a tenant "+
			"with no IdPs re-queries the store on every single login", got)
	}

	// Past the TTL it rebuilds, like any other entry.
	now = now.Add(2 * time.Hour)
	if _, err := m.GetRegistry(ctx, tenant.New("empty-tenant")); err != nil {
		t.Fatalf("after ttl: %v", err)
	}
	if got := s.calls(tenant.New("empty-tenant")); got != 2 {
		t.Errorf("store reads after TTL = %d, want 2", got)
	}
}

// --- invariant 5: concurrency ----------------------------------------

// TestTenantRegistry_ConcurrentAcrossTenants exercises the double-checked
// locking under -race. Concurrent requests for the SAME tenant must
// serialise into one store read; different tenants must not corrupt each
// other's entries.
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

// TestTenantRegistry_UntenantedKeyHoldsExactlyOneRegistry: with tenancy
// off the cache holds one entry under "", and GetRegistry is
// GetRegistryForTenant("").
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

// TestTenantRegistry_PinWorksPerTenant: the Year-9999 test seam still
// works, and now per tenant.
func TestTenantRegistry_PinWorksPerTenant(t *testing.T) {
	ctx := context.Background()
	s := newTenantProviderStore()
	m := tenantManager(t, s, 0) // ttl 0: everything rebuilds unless pinned

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
	// The pin is one tenant's; globex is unaffected.
	if _, err := m.GetRegistry(ctx, tenant.New("globex")); err != nil {
		t.Fatalf("globex: %v", err)
	}
	if s.calls(tenant.New("globex")) != 1 {
		t.Errorf("globex store reads = %d, want 1 — acme's pin leaked", s.calls(tenant.New("globex")))
	}
}

// --- fail closed on a store that cannot scope -------------------------

// --- map growth is bounded --------------------------------------------

// TestTenantRegistry_MapGrowthIsBounded: the cache is keyed by a value
// an attacker can influence, so it must not grow without limit.
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
		t.Errorf("cache holds %d entries, want at most %d — an attacker-influenced tenant id "+
			"grows the map without bound", n, maxCachedTenants)
	}
}
