package oidc

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/suryakencana007/tamper/tenant"
)

// Slice 12c — IdP inheritance (../docs/phases/PHASE12-TENANT-INHERITANCE-SKETCH.md §4.2/§4.2.1).
//
// These tests build REAL registries: rebuildLocked ends in BuildProvider, which
// runs discovery against the issuer, so the fake IdP fixture is the only way to
// assert what the child actually serves.

// allowSpy records which ancestors a policy was asked about, so "the switch is
// asked only of an ancestor that has providers to lend" is provable.
type allowSpy struct {
	mu  sync.Mutex
	ask []string
	yes map[string]bool
	err error
}

func (a *allowSpy) policy(_ context.Context, id tenant.ID) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ask = append(a.ask, id.String())
	if a.err != nil {
		return false, a.err
	}
	return a.yes[id.String()], nil
}

func (a *allowSpy) asked() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.ask...)
}

// inhHierarchy seeds group → org → team.
func inhHierarchy(t *testing.T) *tenant.MemStore {
	t.Helper()
	h := tenant.NewMemStore()
	h.Seed(tenant.Descriptor{ID: "group", Status: tenant.StatusActive})
	h.Seed(tenant.Descriptor{ID: "org", ParentID: "group", Status: tenant.StatusActive})
	h.Seed(tenant.Descriptor{ID: "team", ParentID: "org", Status: tenant.StatusActive})
	return h
}

// inhManager wires inheritance over h, with the per-tenant redirect URL the
// existing tenant helper supplies (https://<tenant>.example.test/cb/<id>).
func inhManager(t *testing.T, s ProviderStore, h tenant.Store, allow tenant.Inheritance, ttl time.Duration) *Manager {
	t.Helper()
	return NewManager(s, nil,
		WithTTL(ttl),
		WithRedirectURLForTenant(func(tenantID tenant.ID, id string) string {
			return "https://" + tenantID.String() + ".example.test/cb/" + id
		}),
		WithInheritance(h, allow),
	)
}

// The feature, and the security decision inside it: the borrowed provider is
// compiled in the CHILD's name.
func TestInheritance_ChildServesTheGroupsProviderInItsOwnName(t *testing.T) {
	ctx := context.Background()
	idp := newTestIdP(t, "barista", "secret")

	s := newTenantProviderStore()
	s.put(tenant.New("group"), ProviderRecord{ID: "group-idp", IssuerURL: idp.URL, ClientID: "barista", Enabled: true})

	m := inhManager(t, s, inhHierarchy(t), (&allowSpy{yes: map[string]bool{"group": true}}).policy, time.Hour)

	reg, err := m.GetRegistry(ctx, tenant.New("team"))
	if err != nil {
		t.Fatalf("GetRegistry(team): %v", err)
	}
	if reg == nil {
		t.Fatal("the child has no providers of its own and the group opted in; want the group's")
	}
	p, err := reg.Get("group-idp")
	if err != nil {
		t.Fatalf("child registry has no group-idp: %v", err)
	}
	if want := "https://team.example.test/cb/group-idp"; p.Config.RedirectURL != want {
		t.Fatalf("RedirectURL = %q, want %q — a borrowed provider must be compiled for the CHILD, "+
			"or the flow completes in the wrong tenant's context", p.Config.RedirectURL, want)
	}

	// The group's own entry is untouched and still names itself.
	groupReg, err := m.GetRegistry(ctx, tenant.New("group"))
	if err != nil {
		t.Fatalf("GetRegistry(group): %v", err)
	}
	gp, err := groupReg.Get("group-idp")
	if err != nil {
		t.Fatalf("group registry: %v", err)
	}
	if want := "https://group.example.test/cb/group-idp"; gp.Config.RedirectURL != want {
		t.Fatalf("group RedirectURL = %q, want %q", gp.Config.RedirectURL, want)
	}
}

// A child with providers of its own never consults an ancestor, and nothing is
// merged: two rows sharing an id would make the flow's provider selection
// ambiguous.
func TestInheritance_OwnProvidersWinEntirely(t *testing.T) {
	ctx := context.Background()
	idp := newTestIdP(t, "barista", "secret")

	s := newTenantProviderStore()
	s.put(tenant.New("group"), ProviderRecord{ID: "group-idp", IssuerURL: idp.URL, ClientID: "barista", Enabled: true})
	s.put(tenant.New("team"), ProviderRecord{ID: "team-idp", IssuerURL: idp.URL, ClientID: "barista", Enabled: true})

	spy := &allowSpy{yes: map[string]bool{"group": true}}
	m := inhManager(t, s, inhHierarchy(t), spy.policy, time.Hour)

	reg, err := m.GetRegistry(ctx, tenant.New("team"))
	if err != nil {
		t.Fatalf("GetRegistry(team): %v", err)
	}
	if _, err := reg.Get("team-idp"); err != nil {
		t.Fatalf("the child's own provider is missing: %v", err)
	}
	if _, err := reg.Get("group-idp"); err == nil {
		t.Fatal("the group's provider leaked into a child that has its own — inheritance must not merge")
	}
	if asked := spy.asked(); len(asked) != 0 {
		t.Fatalf("the switch was asked about %v for a child with its own providers", asked)
	}
}

// A group that keeps its own IdP without opting in is saying "children configure
// their own": the walk STOPS, and a grandparent's providers are not substituted.
func TestInheritance_ARefusingAncestorEndsTheWalk(t *testing.T) {
	ctx := context.Background()
	idp := newTestIdP(t, "barista", "secret")

	s := newTenantProviderStore()
	s.put(tenant.New("group"), ProviderRecord{ID: "group-idp", IssuerURL: idp.URL, ClientID: "barista", Enabled: true})
	s.put(tenant.New("org"), ProviderRecord{ID: "org-idp", IssuerURL: idp.URL, ClientID: "barista", Enabled: true})

	spy := &allowSpy{yes: map[string]bool{"group": true}} // group allows; org has NOT opted in
	m := inhManager(t, s, inhHierarchy(t), spy.policy, time.Hour)

	reg, err := m.GetRegistry(ctx, tenant.New("team"))
	if err != nil {
		t.Fatalf("GetRegistry(team): %v", err)
	}
	if reg != nil {
		t.Fatal("the nearest ancestor with providers refused; its IdP must not be replaced by a grandparent's")
	}
	if asked := spy.asked(); len(asked) != 1 || asked[0] != "org" {
		t.Fatalf("switch asked about %v, want exactly [org] — the walk stops at the refusal", asked)
	}
}

// An ancestor with nothing to lend is passed over WITHOUT asking its switch: a
// silent middle layer must not block a decision made further up.
func TestInheritance_AProviderlessAncestorIsSkippedWithoutAsking(t *testing.T) {
	ctx := context.Background()
	idp := newTestIdP(t, "barista", "secret")

	s := newTenantProviderStore() // org has NO providers at all
	s.put(tenant.New("group"), ProviderRecord{ID: "group-idp", IssuerURL: idp.URL, ClientID: "barista", Enabled: true})

	spy := &allowSpy{yes: map[string]bool{"group": true}}
	m := inhManager(t, s, inhHierarchy(t), spy.policy, time.Hour)

	reg, err := m.GetRegistry(ctx, tenant.New("team"))
	if err != nil {
		t.Fatalf("GetRegistry(team): %v", err)
	}
	if reg == nil {
		t.Fatal("want the group's provider through a providerless org")
	}
	if asked := spy.asked(); len(asked) != 1 || asked[0] != "group" {
		t.Fatalf("switch asked about %v, want exactly [group]", asked)
	}
}

// A settings-table-backed policy errors the day the table is unreachable. Both
// readings of the bool would be wrong, so the error is returned.
func TestInheritance_PolicyErrorFailsTheLookup(t *testing.T) {
	ctx := context.Background()
	idp := newTestIdP(t, "barista", "secret")

	s := newTenantProviderStore()
	s.put(tenant.New("org"), ProviderRecord{ID: "org-idp", IssuerURL: idp.URL, ClientID: "barista", Enabled: true})

	boom := errors.New("settings table is down")
	m := inhManager(t, s, inhHierarchy(t), (&allowSpy{err: boom}).policy, time.Hour)

	_, err := m.GetRegistry(ctx, tenant.New("team"))
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the policy's own error — reading (false, err) as a refusal would make "+
			"an outage look like a group that switched the feature off", err)
	}
}

// With inheritance wired a store error can come from an ANCESTOR's rows, so the
// message must say whose table failed — the unwired message ("list enabled
// providers") would leave an operator guessing which tenant broke.
func TestInheritance_AStoreErrorNamesTheTenantItCameFrom(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("provider table is down")

	s := &failingTenantStore{tenantProviderStore: newTenantProviderStore(), failFor: "org", err: boom}
	m := inhManager(t, s, inhHierarchy(t), (&allowSpy{yes: map[string]bool{}}).policy, time.Hour)

	_, err := m.GetRegistry(ctx, tenant.New("team"))
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the store's own error", err)
	}
	if !strings.Contains(err.Error(), `"org"`) {
		t.Fatalf("err = %q, want it to name the ancestor whose rows failed", err.Error())
	}
}

// failingTenantStore wraps the tenant store and fails for one tenant id.
type failingTenantStore struct {
	*tenantProviderStore
	failFor string
	err     error
}

func (f *failingTenantStore) ListEnabledProviders(ctx context.Context, tenantID tenant.ID) ([]ProviderRecord, error) {
	if tenantID.String() == f.failFor {
		return nil, f.err
	}
	return f.tenantProviderStore.ListEnabledProviders(ctx, tenantID)
}

// Corrupt parentage propagates; an unknown tenant does not.
func TestInheritance_ErrorsAndTheUnknownTenant(t *testing.T) {
	ctx := context.Background()

	t.Run("dangling parent", func(t *testing.T) {
		h := tenant.NewMemStore()
		h.Seed(tenant.Descriptor{ID: "team", ParentID: "vanished", Status: tenant.StatusActive})
		m := inhManager(t, newTenantProviderStore(), h, (&allowSpy{yes: map[string]bool{}}).policy, time.Hour)

		_, err := m.GetRegistry(ctx, tenant.New("team"))
		if !errors.Is(err, tenant.ErrHierarchyDangling) {
			t.Fatalf("err = %v, want ErrHierarchyDangling — swallowing it would hide a data fault "+
				"behind an empty registry", err)
		}
	})

	t.Run("unknown tenant stays (nil, nil)", func(t *testing.T) {
		m := inhManager(t, newTenantProviderStore(), inhHierarchy(t), (&allowSpy{yes: map[string]bool{}}).policy, time.Hour)

		reg, err := m.GetRegistry(ctx, tenant.New("ghost"))
		if err != nil {
			t.Fatalf("err = %v, want nil: the registry's contract is (nil, nil) for a tenant with "+
				"no providers, and an unknown tenant has the same answer", err)
		}
		if reg != nil {
			t.Fatalf("registry = %v, want nil", reg)
		}
	})
}

// Unwired is today's behaviour, path for path.
func TestInheritance_UnwiredIsUnchanged(t *testing.T) {
	ctx := context.Background()
	idp := newTestIdP(t, "barista", "secret")

	s := newTenantProviderStore()
	s.put(tenant.New("group"), ProviderRecord{ID: "group-idp", IssuerURL: idp.URL, ClientID: "barista", Enabled: true})

	// No WithInheritance: the group's provider exists and must not reach the child.
	m := tenantManager(t, s, time.Hour)
	reg, err := m.GetRegistry(ctx, tenant.New("team"))
	if err != nil {
		t.Fatalf("GetRegistry(team): %v", err)
	}
	if reg != nil {
		t.Fatal("inheritance is not wired; the child must still see nothing")
	}
	// And the unwired path still reads the store under the lock exactly once.
	m.InvalidateTenant(tenant.New("team"))
	if _, err := m.GetRegistry(ctx, tenant.New("team")); err != nil {
		t.Fatalf("GetRegistry: %v", err)
	}
	if got := s.calls(tenant.New("team")); got != 2 {
		t.Fatalf("store reads = %d, want 2 (one per uncached lookup)", got)
	}
}

// The nil result is cached with a fresh timestamp so an id that resolves to
// nothing does not re-run the walk on every request.
func TestInheritance_TheEmptyResultIsCached(t *testing.T) {
	ctx := context.Background()
	s := newTenantProviderStore()
	m := inhManager(t, s, inhHierarchy(t), (&allowSpy{yes: map[string]bool{}}).policy, time.Hour)

	for i := 0; i < 3; i++ {
		if _, err := m.GetRegistry(ctx, tenant.New("team")); err != nil {
			t.Fatalf("GetRegistry: %v", err)
		}
	}
	// One walk: the child itself, then org and group (both providerless).
	if got := s.calls(tenant.New("team")); got != 1 {
		t.Fatalf("the child's own rows were read %d times, want 1 — the empty result must be cached", got)
	}
}

// With inheritance wired, a provider change clears the cache rather than one key,
// because the changed tenant's providers may be serving every tenant that
// inherits them (§4.2.1).
func TestInheritance_InvalidationClearsTheCacheWhenWired(t *testing.T) {
	ctx := context.Background()
	idp := newTestIdP(t, "barista", "secret")

	s := newTenantProviderStore()
	s.put(tenant.New("group"), ProviderRecord{ID: "group-idp", IssuerURL: idp.URL, ClientID: "barista", Enabled: true})
	m := inhManager(t, s, inhHierarchy(t), (&allowSpy{yes: map[string]bool{"group": true}}).policy, time.Hour)

	if _, err := m.GetRegistry(ctx, tenant.New("team")); err != nil {
		t.Fatalf("GetRegistry(team): %v", err)
	}
	if _, err := m.GetRegistry(ctx, tenant.New("group")); err != nil {
		t.Fatalf("GetRegistry(group): %v", err)
	}

	m.InvalidateTenant(tenant.New("group"))

	m.mu.RLock()
	cached := len(m.registries)
	m.mu.RUnlock()
	if cached != 0 {
		t.Fatalf("%d entries cached after invalidating one tenant; with inheritance wired a group's "+
			"provider change must reach its inheritors", cached)
	}
}

// A blocked hierarchy store must not stall another tenant's lookup: the walk runs
// outside mu. Without the split this test hangs, so it fails by timeout rather
// than by assertion — which is exactly the regression it exists to catch.
func TestInheritance_TheWalkDoesNotRunUnderTheLock(t *testing.T) {
	ctx := context.Background()
	idp := newTestIdP(t, "barista", "secret")

	s := newTenantProviderStore()
	s.put(tenant.New("other"), ProviderRecord{ID: "other-idp", IssuerURL: idp.URL, ClientID: "barista", Enabled: true})

	h := &blockingStore{
		store:   inhHierarchy(t),
		block:   make(chan struct{}),
		entered: make(chan struct{}),
		onID:    "team",
	}
	m := inhManager(t, s, h, (&allowSpy{yes: map[string]bool{}}).policy, time.Hour)

	go func() { _, _ = m.GetRegistry(ctx, tenant.New("team")) }() // blocks inside the walk
	<-h.entered                                                   // the walk is now in progress

	done := make(chan error, 1)
	go func() {
		_, err := m.GetRegistry(ctx, tenant.New("other"))
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("GetRegistry(other): %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a tenant with its own providers waited on another tenant's hierarchy read; " +
			"the walk is running under the registry lock")
	}
	close(h.block)
}

// blockingStore blocks ByID for one id until released, and signals when it is
// entered. Used to prove the lock is not held across the walk.
type blockingStore struct {
	store   tenant.Store
	block   chan struct{}
	onID    string
	once    sync.Once
	entered chan struct{}
}

func (b *blockingStore) ByID(ctx context.Context, id string) (tenant.Descriptor, error) {
	if id == b.onID {
		b.once.Do(func() { close(b.entered) })
		<-b.block
	}
	return b.store.ByID(ctx, id)
}

func (b *blockingStore) BySlug(ctx context.Context, slug string) (tenant.Descriptor, error) {
	return b.store.BySlug(ctx, slug)
}
