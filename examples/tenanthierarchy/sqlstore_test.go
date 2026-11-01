package tenanthierarchy

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/suryakencana007/tamper/authz"
	"github.com/suryakencana007/tamper/authz/tenanttest"
	"github.com/suryakencana007/tamper/tenant"
)

// newSQLStore opens a fresh SQLite file for one test (or one leak-harness
// call — the suite requires an empty store per case).
func newSQLStore(t *testing.T) *SQLStore {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "authz.db")
	s, err := OpenSQLStore(dsn)
	if err != nil {
		t.Fatalf("OpenSQLStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func newSQLProvisioner(t *testing.T, roles RoleMap) (*Provisioner, *SQLStore, *fakeHierarchy) {
	t.Helper()
	s := newSQLStore(t)
	h := newHierarchy()
	p, err := NewProvisioner(s, h, roles)
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	return p, s, h
}

func countRows(t *testing.T, s *SQLStore) int {
	t.Helper()
	var n int
	if err := s.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM authz_binding`).Scan(&n); err != nil {
		t.Fatalf("count bindings: %v", err)
	}
	return n
}

// ---------------------------------------------------------------------
// The authz isolation contract, against the real adapter.
// ---------------------------------------------------------------------

func TestSQLStore_PassesBindingStoreLeakSuite(t *testing.T) {
	tenanttest.RunBindingStoreLeakSuite(t, func() tenanttest.BindingHarness {
		s := newSQLStore(t)
		return tenanttest.BindingHarness{
			Store: s,
			Grant: func(b authz.Binding) error { return s.Grant(context.Background(), b) },
		}
	})
}

// ---------------------------------------------------------------------
// Provisioning and provenance behave exactly as they do in memory.
// ---------------------------------------------------------------------

func TestSQLStore_ProvisioningRoundTrip(t *testing.T) {
	p, s, _ := newSQLProvisioner(t, roleMap())

	if err := p.GrantGroupAdmin(ctx, bob, tg, groupRole()); err != nil {
		t.Fatalf("GrantGroupAdmin: %v", err)
	}
	if got := countRows(t, s); got != 4 {
		t.Fatalf("rows = %d, want 4 (1 intent + 3 children)", got)
	}
	// Idempotent.
	if err := p.GrantGroupAdmin(ctx, bob, tg, groupRole()); err != nil {
		t.Fatalf("re-grant: %v", err)
	}
	if got := countRows(t, s); got != 4 {
		t.Fatalf("rows = %d, want 4 after a second grant", got)
	}
	// The reverse query sees the materialized binding in the child scope.
	got, err := s.BindingsForSubject(ctx, org1, bob, ResourceOrganization)
	if err != nil {
		t.Fatalf("BindingsForSubject: %v", err)
	}
	if len(got) != 1 || got[0].Role != "org_admin" {
		t.Fatalf("org-1 bindings = %+v, want one org_admin", got)
	}

	if err := p.RevokeGroupAdmin(ctx, bob, tg); err != nil {
		t.Fatalf("RevokeGroupAdmin: %v", err)
	}
	if got := countRows(t, s); got != 0 {
		t.Fatalf("rows = %d, want 0 after revoke", got)
	}
}

func TestSQLStore_DirectGrantSurvivesGroupRevoke(t *testing.T) {
	p, s, _ := newSQLProvisioner(t, roleMap())

	direct := materializedBinding(bob, "org-1", "org_admin")
	if err := s.Grant(ctx, direct); err != nil {
		t.Fatalf("direct grant: %v", err)
	}
	if err := p.GrantGroupAdmin(ctx, bob, tg, groupRole()); err != nil {
		t.Fatalf("GrantGroupAdmin: %v", err)
	}
	if err := p.RevokeGroupAdmin(ctx, bob, tg); err != nil {
		t.Fatalf("RevokeGroupAdmin: %v", err)
	}

	got, err := s.BindingsFor(ctx, org1, bob, resOrg1)
	if err != nil {
		t.Fatalf("BindingsFor: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("org-1 = %+v, want the direct grant to survive the group revoke", got)
	}
	if got := countRows(t, s); got != 1 {
		t.Fatalf("rows = %d, want 1 (the direct grant only)", got)
	}
}

func TestSQLStore_ApplyRollsBack(t *testing.T) {
	s := newSQLStore(t)
	existing := authz.Binding{Tenant: org2, Subject: erin, Resource: resOrg1, Role: "org_admin"}
	if err := s.Grant(ctx, existing); err != nil {
		t.Fatalf("seed: %v", err)
	}

	boom := errors.New("provisioning failed")
	err := s.Apply(ctx, func(tx Tx) error {
		if err := tx.Grant(ctx, bobOrg1); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("Apply = %v, want the sentinel", err)
	}
	if got := countRows(t, s); got != 1 {
		t.Fatalf("rows = %d, want 1 — the failed Apply must leave the store as it was", got)
	}
	if _, err := s.BindingsFor(ctx, org1, bob, resOrg1); err != nil {
		t.Fatalf("BindingsFor: %v", err)
	}
}

func TestSQLStore_TxReadsSeeStagedWrites(t *testing.T) {
	s := newSQLStore(t)
	err := s.Apply(ctx, func(tx Tx) error {
		if err := tx.Grant(ctx, bobOrg1); err != nil {
			return err
		}
		got, err := tx.BindingsFor(ctx, org1, bob, resOrg1)
		if err != nil {
			return err
		}
		if len(got) != 1 {
			t.Fatalf("staged read = %d, want 1", len(got))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
}

// ---------------------------------------------------------------------
// Reconciliation works on the SQL adapter, including the group whose intent
// row was lost.
// ---------------------------------------------------------------------

func TestSQLStore_ReconcileDetectsAndSyncRepairs(t *testing.T) {
	p, s, _ := newSQLProvisioner(t, roleMap())
	if err := p.GrantGroupAdmin(ctx, bob, tg, groupRole()); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if err := Guard(ctx, p); err != nil {
		t.Fatalf("Guard on a clean SQL store: %v", err)
	}

	// Missing: drop one materialized row.
	if err := s.RevokeFrom(ctx, keyOf(materializedBinding(bob, "org-2", "org_admin")), GroupOrigin(tg)); err != nil {
		t.Fatalf("seed missing: %v", err)
	}
	// Orphan: a group-origin row with no intent behind it.
	if err := s.GrantFrom(ctx, materializedBinding(carol, "org-1", "org_admin"), GroupOrigin(tg)); err != nil {
		t.Fatalf("seed orphan: %v", err)
	}

	d, err := p.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(d.Missing) != 1 || len(d.Orphan) != 1 {
		t.Fatalf("drift = %d missing / %d orphan, want 1/1", len(d.Missing), len(d.Orphan))
	}
	if err := Guard(ctx, p); !errors.Is(err, ErrDrift) {
		t.Fatalf("Guard = %v, want ErrDrift", err)
	}

	if err := p.SyncGroup(ctx, tg); err != nil {
		t.Fatalf("SyncGroup: %v", err)
	}
	if err := Guard(ctx, p); err != nil {
		t.Fatalf("Guard after SyncGroup: %v", err)
	}
	if got := countRows(t, s); got != 4 {
		t.Fatalf("rows = %d, want 4 after repair", got)
	}
}

func TestSQLStore_ReconcileFindsOrphanAfterIntentLost(t *testing.T) {
	p, s, _ := newSQLProvisioner(t, roleMap())
	if err := p.GrantGroupAdmin(ctx, bob, tg, groupRole()); err != nil {
		t.Fatalf("grant: %v", err)
	}
	// Lose the intent row; the three materialized rows remain.
	if err := s.RevokeFrom(ctx, keyOf(intentBinding(bob, tg, groupRole())), GroupOrigin(tg)); err != nil {
		t.Fatalf("drop intent: %v", err)
	}

	d, err := p.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(d.Orphan) != 3 || len(d.Missing) != 0 {
		t.Fatalf("drift = %d missing / %d orphan, want 0/3", len(d.Missing), len(d.Orphan))
	}
	if err := p.SyncGroup(ctx, tg); err != nil {
		t.Fatalf("SyncGroup: %v", err)
	}
	if got := countRows(t, s); got != 0 {
		t.Fatalf("rows = %d, want 0 — with no intent, converging removes the rows", got)
	}
}

// ---------------------------------------------------------------------
// Derived membership reads the same intent rows through the adapter.
// ---------------------------------------------------------------------

func TestSQLStore_Membership(t *testing.T) {
	p, s, h := newSQLProvisioner(t, roleMap())
	if err := p.GrantGroupAdmin(ctx, bob, tg, groupRole()); err != nil {
		t.Fatalf("grant: %v", err)
	}
	m := NewMembership(s, h)

	for _, org := range []tenant.ID{org1, org2, org3} {
		ok, err := m.IsMember(ctx, "bob", org)
		if err != nil || !ok {
			t.Fatalf("IsMember(bob, %s) = (%v, %v), want true", org, ok, err)
		}
	}
	if ok, err := m.IsMember(ctx, "bob", org9); err != nil || ok {
		t.Fatalf("IsMember(bob, org-9) = (%v, %v), want false", ok, err)
	}
	if got, err := m.MembershipsFor(ctx, "bob"); err != nil || len(got) != 3 {
		t.Fatalf("MembershipsFor(bob) = (%v, %v), want 3 orgs", ids(got), err)
	}
}

// A membership change re-syncs over SQL too.
func TestSQLStore_AddOrg(t *testing.T) {
	p, s, h := newSQLProvisioner(t, roleMap())
	if err := p.GrantGroupAdmin(ctx, bob, tg, groupRole()); err != nil {
		t.Fatalf("grant: %v", err)
	}
	newOrg := tenant.New("org-4")
	h.setParent("org-4", "tg-acme")
	if err := p.AddOrg(ctx, tg, newOrg); err != nil {
		t.Fatalf("AddOrg: %v", err)
	}
	got, err := s.BindingsForSubject(ctx, newOrg, bob, ResourceOrganization)
	if err != nil {
		t.Fatalf("BindingsForSubject: %v", err)
	}
	if len(got) != 1 || got[0].Role != "org_admin" {
		t.Fatalf("org-4 = %+v, want bob's org_admin", got)
	}
	if got := countRows(t, s); got != 5 {
		t.Fatalf("rows = %d, want 5", got)
	}
}
