package saml

import (
	"context"
	"errors"
	"testing"
	"time"

	crewjamsaml "github.com/crewjam/saml"
	tampercrypto "github.com/suryakencana007/tamper/crypto"
	"github.com/suryakencana007/tamper/tenant"
)

// Slice 12c — IdP inheritance, SAML. Same semantics as the OIDC Manager's, and
// the tests here are the ones that differ: SAML has a SECOND per-tenant seam, the
// SP metadata URL, and it must be compiled for the child exactly as the OIDC
// redirect URL is.

func inhHierarchy(t *testing.T) *tenant.MemStore {
	t.Helper()
	h := tenant.NewMemStore()
	h.Seed(tenant.Descriptor{ID: "group", Status: tenant.StatusActive})
	h.Seed(tenant.Descriptor{ID: "org", ParentID: "group", Status: tenant.StatusActive})
	h.Seed(tenant.Descriptor{ID: "team", ParentID: "org", Status: tenant.StatusActive})
	return h
}

type allowSpy struct {
	ask []string
	yes map[string]bool
	err error
}

func (a *allowSpy) policy(_ context.Context, id tenant.ID) (bool, error) {
	a.ask = append(a.ask, id.String())
	if a.err != nil {
		return false, a.err
	}
	return a.yes[id.String()], nil
}

// inhManager wires inheritance over h with a per-tenant SP metadata URL, a
// metadata fetcher that never dials, and a real-enough keyset to open sealed
// signing keys.
func inhManager(t *testing.T, s ProviderStore, h tenant.Store, allow tenant.Inheritance,
	keys *tampercrypto.KeySet, certPEM string,
) *Manager {
	t.Helper()
	return NewManager(s, keys,
		WithTTL(time.Hour),
		WithSPMetadataURLForTenant(func(tenantID tenant.ID, id, _ string) string {
			return "https://" + tenantID.String() + ".example.test/sp/" + id
		}),
		WithMetadataFetcher(func(_ context.Context, _ string) (*crewjamsaml.EntityDescriptor, error) {
			return fakeEntity(certPEM), nil
		}),
		WithAssertionReplayStore(NewMemAssertionReplayStore()),
		WithInheritance(h, allow),
	)
}

// sealedRec builds an enabled record whose signing key is sealed under keys, so a
// rebuild can open it and actually construct the provider.
func sealedRec(t *testing.T, keys *tampercrypto.KeySet, id, certPEM, keyPEM string) ProviderRecord {
	t.Helper()
	sealed, err := keys.Seal([]byte(keyPEM))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return ProviderRecord{
		ID: id, IdPMetadataURL: "https://idp.example/md-" + id, EntityID: "sp-" + id,
		ACSURL: "https://sp.invalid/acs/" + id, SPSigningCertPEM: certPEM,
		SealedSigningKey: sealed, DisplayName: id, Enabled: true,
	}
}

// The feature, and the SAML half of the security decision: the borrowed provider's
// SP metadata URL is compiled in the CHILD's name.
func TestInheritanceSAML_ChildServesTheGroupsProviderInItsOwnName(t *testing.T) {
	ctx := context.Background()
	certPEM, keyPEM := testCertKeyPEM(t)
	keys := mgrKeys(t, tampercrypto.KEKEntry{ID: 1, Key: mgrKEK1})

	s := newTenantProviderStore()
	s.put(tenant.New("group"), sealedRec(t, keys, "group-idp", certPEM, keyPEM))

	m := inhManager(t, s, inhHierarchy(t), (&allowSpy{yes: map[string]bool{"group": true}}).policy, keys, certPEM)

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
	if want := "https://team.example.test/sp/group-idp"; p.Config.MetadataURL != want {
		t.Fatalf("MetadataURL = %q, want %q — a borrowed provider's SP metadata must be compiled "+
			"for the CHILD, never for the group it came from", p.Config.MetadataURL, want)
	}
}

// The walk's semantics, asserted on the records the Manager resolved — cheaper
// than building registries, and the same code path.
func TestInheritanceSAML_RecordsFor(t *testing.T) {
	ctx := context.Background()
	certPEM, keyPEM := testCertKeyPEM(t)
	keys := mgrKeys(t, tampercrypto.KEKEntry{ID: 1, Key: mgrKEK1})

	t.Run("own providers win entirely", func(t *testing.T) {
		s := newTenantProviderStore()
		s.put(tenant.New("group"), sealedRec(t, keys, "group-idp", certPEM, keyPEM))
		s.put(tenant.New("team"), sealedRec(t, keys, "team-idp", certPEM, keyPEM))

		spy := &allowSpy{yes: map[string]bool{"group": true}}
		m := inhManager(t, s, inhHierarchy(t), spy.policy, keys, certPEM)

		recs, err := m.recordsFor(ctx, tenant.New("team"))
		if err != nil {
			t.Fatalf("recordsFor: %v", err)
		}
		if len(recs) != 1 || recs[0].ID != "team-idp" {
			t.Fatalf("records = %+v, want only the child's own", recs)
		}
		if len(spy.ask) != 0 {
			t.Fatalf("the switch was asked about %v for a child with its own providers", spy.ask)
		}
	})

	t.Run("a refusing ancestor ends the walk", func(t *testing.T) {
		s := newTenantProviderStore()
		s.put(tenant.New("group"), sealedRec(t, keys, "group-idp", certPEM, keyPEM))
		s.put(tenant.New("org"), sealedRec(t, keys, "org-idp", certPEM, keyPEM))

		spy := &allowSpy{yes: map[string]bool{"group": true}}
		m := inhManager(t, s, inhHierarchy(t), spy.policy, keys, certPEM)

		recs, err := m.recordsFor(ctx, tenant.New("team"))
		if err != nil {
			t.Fatalf("recordsFor: %v", err)
		}
		if len(recs) != 0 {
			t.Fatalf("records = %+v; the nearest ancestor with providers refused", recs)
		}
		if len(spy.ask) != 1 || spy.ask[0] != "org" {
			t.Fatalf("switch asked about %v, want exactly [org]", spy.ask)
		}
	})

	t.Run("a providerless ancestor is skipped without asking", func(t *testing.T) {
		s := newTenantProviderStore()
		s.put(tenant.New("group"), sealedRec(t, keys, "group-idp", certPEM, keyPEM))

		spy := &allowSpy{yes: map[string]bool{"group": true}}
		m := inhManager(t, s, inhHierarchy(t), spy.policy, keys, certPEM)

		recs, err := m.recordsFor(ctx, tenant.New("team"))
		if err != nil {
			t.Fatalf("recordsFor: %v", err)
		}
		if len(recs) != 1 || recs[0].ID != "group-idp" {
			t.Fatalf("records = %+v, want the group's through a providerless org", recs)
		}
		if len(spy.ask) != 1 || spy.ask[0] != "group" {
			t.Fatalf("switch asked about %v, want exactly [group]", spy.ask)
		}
	})

	t.Run("a policy error fails the lookup", func(t *testing.T) {
		boom := errors.New("settings table is down")
		s := newTenantProviderStore()
		s.put(tenant.New("org"), sealedRec(t, keys, "org-idp", certPEM, keyPEM))

		m := inhManager(t, s, inhHierarchy(t), (&allowSpy{err: boom}).policy, keys, certPEM)
		if _, err := m.recordsFor(ctx, tenant.New("team")); !errors.Is(err, boom) {
			t.Fatalf("err = %v, want the policy's own error", err)
		}
	})

	t.Run("dangling parent propagates, unknown tenant does not", func(t *testing.T) {
		h := tenant.NewMemStore()
		h.Seed(tenant.Descriptor{ID: "team", ParentID: "vanished", Status: tenant.StatusActive})
		m := inhManager(t, newTenantProviderStore(), h, (&allowSpy{yes: map[string]bool{}}).policy, keys, certPEM)

		if _, err := m.recordsFor(ctx, tenant.New("team")); !errors.Is(err, tenant.ErrHierarchyDangling) {
			t.Fatalf("err = %v, want ErrHierarchyDangling", err)
		}

		m2 := inhManager(t, newTenantProviderStore(), inhHierarchy(t), (&allowSpy{yes: map[string]bool{}}).policy, keys, certPEM)
		recs, err := m2.recordsFor(ctx, tenant.New("ghost"))
		if err != nil || len(recs) != 0 {
			t.Fatalf("recordsFor(unknown) = (%+v, %v), want (empty, nil)", recs, err)
		}
	})

	t.Run("unwired is unchanged", func(t *testing.T) {
		s := newTenantProviderStore()
		s.put(tenant.New("group"), sealedRec(t, keys, "group-idp", certPEM, keyPEM))

		m := NewManager(s, keys,
			WithTTL(time.Hour),
			WithSPMetadataURLForTenant(func(tenantID tenant.ID, id, _ string) string {
				return "https://" + tenantID.String() + ".example.test/sp/" + id
			}),
			WithMetadataFetcher(func(_ context.Context, _ string) (*crewjamsaml.EntityDescriptor, error) {
				return fakeEntity(certPEM), nil
			}),
			WithAssertionReplayStore(NewMemAssertionReplayStore()),
		)
		recs, err := m.recordsFor(ctx, tenant.New("team"))
		if err != nil || len(recs) != 0 {
			t.Fatalf("recordsFor(team) = (%+v, %v), want (empty, nil) with inheritance unwired", recs, err)
		}
	})
}
