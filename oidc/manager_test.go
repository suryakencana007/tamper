package oidc

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/suryakencana007/tamper/crypto"
)

// hex-encoded 32-byte test keys (NOT real secrets).
const (
	testKEK1 = "0101010101010101010101010101010101010101010101010101010101010101"
	testKEK2 = "0202020202020202020202020202020202020202020202020202020202020202"
)

func testKeys(t *testing.T, entries ...crypto.KEKEntry) *crypto.KeySet {
	t.Helper()
	ks, err := crypto.NewKeySet(entries, 0)
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	return ks
}

func testManager(t *testing.T, opts ...ManagerOption) (*Manager, *MemProviderStore) {
	t.Helper()
	store := NewMemProviderStore()
	keys := testKeys(t, crypto.KEKEntry{ID: 1, Key: testKEK1})
	m := NewManager(store, keys, opts...)
	return m, store
}

func TestManager_CRUDRoundTripSealsSecret(t *testing.T) {
	ctx := context.Background()
	m, store := testManager(t)

	def := ProviderDefinition{
		ID: "kc", IssuerURL: "https://idp.example", ClientID: "app",
		ClientSecret: "hunter2", DisplayName: "Keycloak",
		Scopes: []string{"openid", "groups"}, GroupsClaim: "groups", Enabled: true,
	}
	if err := m.Create(ctx, def); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// The stored record must NOT carry plaintext.
	rec, _ := store.GetProvider(ctx, "kc")
	if string(rec.SealedClientSecret) == "hunter2" || len(rec.SealedClientSecret) == 0 {
		t.Fatal("client secret must be sealed at rest")
	}
	if rec.CreatedAt.IsZero() || !rec.CreatedAt.Equal(rec.UpdatedAt) {
		t.Fatalf("Create must stamp CreatedAt==UpdatedAt: %v / %v", rec.CreatedAt, rec.UpdatedAt)
	}
	// Reads open the secret.
	got, err := m.Get(ctx, "kc")
	if err != nil || got.ClientSecret != "hunter2" {
		t.Fatalf("Get: %+v err=%v, want opened secret", got, err)
	}
	// Duplicate id passes ErrProviderExists through.
	if err := m.Create(ctx, def); !errors.Is(err, ErrProviderExists) {
		t.Fatalf("dup Create err=%v, want ErrProviderExists", err)
	}
	// Update on unknown id surfaces ErrProviderNotFound.
	if err := m.Update(ctx, ProviderDefinition{ID: "ghost", ClientSecret: "x"}); !errors.Is(err, ErrProviderNotFound) {
		t.Fatalf("Update(ghost) err=%v, want ErrProviderNotFound", err)
	}
	// Update re-seals and preserves CreatedAt.
	def.ClientSecret = "hunter3"
	if err := m.Update(ctx, def); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, _ = m.Get(ctx, "kc")
	if got.ClientSecret != "hunter3" || !got.CreatedAt.Equal(rec.CreatedAt) {
		t.Fatalf("Update round trip: %+v", got)
	}
	// Delete is idempotent.
	if err := m.Delete(ctx, "kc"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := m.Delete(ctx, "kc"); err != nil {
		t.Fatalf("Delete twice: %v", err)
	}
	if _, err := m.Get(ctx, "kc"); !errors.Is(err, ErrProviderNotFound) {
		t.Fatalf("Get after delete err=%v, want ErrProviderNotFound", err)
	}
}

func TestManager_NoKeySetRefusesMutations(t *testing.T) {
	ctx := context.Background()
	m := NewManager(NewMemProviderStore(), nil)
	if err := m.Create(ctx, ProviderDefinition{ID: "kc"}); !errors.Is(err, ErrNoKeySet) {
		t.Fatalf("Create err=%v, want ErrNoKeySet", err)
	}
	if _, err := m.RotateSealedSecrets(ctx); !errors.Is(err, ErrNoKeySet) {
		t.Fatalf("Rotate err=%v, want ErrNoKeySet", err)
	}
}

func TestManager_RegistryTTLCache(t *testing.T) {
	ctx := context.Background()
	idp := newTestIdP(t, "app", "secret")

	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	m, _ := testManager(t,
		WithTTL(30*time.Second),
		WithRedirectURL(func(id string) string { return "https://rp.example.local/cb/" + id }),
	)
	m.SetClock(func() time.Time { return now })

	if err := m.Create(ctx, ProviderDefinition{
		ID: "test", IssuerURL: idp.URL, ClientID: "app", ClientSecret: "secret",
		DisplayName: "Test", Enabled: true,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	reg1, err := m.GetRegistry(ctx)
	if err != nil || reg1 == nil {
		t.Fatalf("GetRegistry: reg=%v err=%v", reg1, err)
	}
	p, err := reg1.Get("test")
	if err != nil {
		t.Fatalf("registry Get: %v", err)
	}
	if p.OAuth2.RedirectURL != "https://rp.example.local/cb/test" {
		t.Fatalf("redirect mapping not applied: %q", p.OAuth2.RedirectURL)
	}

	// Within ttl: same instance served from cache.
	now = now.Add(10 * time.Second)
	reg2, _ := m.GetRegistry(ctx)
	if reg2 != reg1 {
		t.Fatal("within ttl the cached registry instance must be reused")
	}

	// Past ttl: rebuilt (fresh instance).
	now = now.Add(31 * time.Second)
	reg3, err := m.GetRegistry(ctx)
	if err != nil {
		t.Fatalf("GetRegistry rebuild: %v", err)
	}
	if reg3 == reg1 {
		t.Fatal("past ttl the registry must rebuild")
	}

	// Mutation invalidates eagerly even within ttl.
	if err := m.Delete(ctx, "test"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	reg4, err := m.GetRegistry(ctx)
	if err != nil {
		t.Fatalf("GetRegistry after delete: %v", err)
	}
	if reg4 != nil {
		t.Fatal("empty store must cache the nil not-configured sentinel")
	}
	// The nil sentinel is itself cached for ttl (multi-replica
	// convergence symmetry) — a Create on a SISTER replica would not
	// be visible here until ttl elapses; same-process Create
	// invalidates eagerly, so exercise the window via the clock only.
	reg5, _ := m.GetRegistry(ctx)
	if reg5 != nil {
		t.Fatal("nil sentinel must be served from cache within ttl")
	}
}

func TestManager_PinRegistrySurvivesTTLZero(t *testing.T) {
	ctx := context.Background()
	m, _ := testManager(t) // ttl=0: every call would rebuild
	pinned := &ProviderRegistry{providers: map[string]*Provider{}, order: nil}
	m.PinRegistry(pinned)
	got, err := m.GetRegistry(ctx)
	if err != nil || got != pinned {
		t.Fatalf("pinned registry must be served regardless of ttl: %v %v", got, err)
	}
	// Clearing the pin drops back to rebuild-from-store (empty → nil).
	m.PinRegistry(nil)
	got, err = m.GetRegistry(ctx)
	if err != nil || got != nil {
		t.Fatalf("cleared pin: got=%v err=%v, want nil registry", got, err)
	}
}

func TestManager_RotateSealedSecrets(t *testing.T) {
	ctx := context.Background()
	store := NewMemProviderStore()
	// Seal under key 1 first.
	m1 := NewManager(store, testKeys(t, crypto.KEKEntry{ID: 1, Key: testKEK1}))
	if err := m1.Create(ctx, ProviderDefinition{ID: "kc", ClientSecret: "hunter2", DisplayName: "KC", Enabled: true}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Rotate under a keyset whose write key is 2.
	m2 := NewManager(store, testKeys(t,
		crypto.KEKEntry{ID: 1, Key: testKEK1},
		crypto.KEKEntry{ID: 2, Key: testKEK2},
	))
	res, err := m2.RotateSealedSecrets(ctx)
	if err != nil || res.Scanned != 1 || res.Rotated != 1 {
		t.Fatalf("rotate: %+v err=%v, want 1/1", res, err)
	}
	rec, _ := store.GetProvider(ctx, "kc")
	if rec.SealedClientSecret[0] != 2 {
		t.Fatalf("envelope keyId=%d, want 2", rec.SealedClientSecret[0])
	}
	// Re-run is a no-op.
	res, err = m2.RotateSealedSecrets(ctx)
	if err != nil || res.Rotated != 0 || res.Scanned != 1 {
		t.Fatalf("rotate re-run: %+v err=%v, want scanned=1 rotated=0", res, err)
	}
	// The secret still opens to the original plaintext.
	got, err := m2.Get(ctx, "kc")
	if err != nil || got.ClientSecret != "hunter2" {
		t.Fatalf("post-rotate Get: %+v err=%v", got, err)
	}
}

func TestManager_TestDiscovery(t *testing.T) {
	ctx := context.Background()
	idp := newTestIdP(t, "app", "secret")
	m, _ := testManager(t)

	res, err := m.TestDiscovery(ctx, idp.URL)
	if err != nil {
		t.Fatalf("TestDiscovery: %v", err)
	}
	if res.AuthURL == "" || res.TokenURL == "" || res.JWKSURL == "" {
		t.Fatalf("discovery result incomplete: %+v", res)
	}
	if !strings.HasPrefix(res.AuthURL, idp.URL) {
		t.Fatalf("AuthURL %q not under issuer %q", res.AuthURL, idp.URL)
	}

	if _, err := m.TestDiscovery(ctx, "https://127.0.0.1:1/nope"); !errors.Is(err, ErrDiscoveryFailed) {
		t.Fatalf("bad issuer err=%v, want ErrDiscoveryFailed", err)
	}
}
