package tenanthierarchy

import (
	"errors"
	"strings"
	"testing"

	"github.com/suryakencana007/tamper/authz"
)

var carol = authz.Subject{Tenant: tg, Type: "user", ID: "carol"}

// seedClean grants bob group admin of tg-acme and asserts the state is clean.
func seedClean(t *testing.T) (*Provisioner, *Store) {
	t.Helper()
	p, s := newP(t, newHierarchy(), roleMap())
	if err := p.GrantGroupAdmin(ctx, bob, tg, groupRole()); err != nil {
		t.Fatalf("grant: %v", err)
	}
	return p, s
}

// ---------------------------------------------------------------------
// Reconcile: both directions of drift are reported.
// ---------------------------------------------------------------------

func TestReconcile_CleanStateIsEmpty(t *testing.T) {
	p, _ := seedClean(t)
	d, err := p.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !d.Empty() {
		t.Fatalf("drift = %+v, want empty", d)
	}
	if err := Guard(ctx, p); err != nil {
		t.Fatalf("Guard on a clean store: %v", err)
	}
}

func TestReconcile_DetectsMissing(t *testing.T) {
	p, s := seedClean(t)
	// Delete one materialized row behind the provisioner's back.
	drop := keyOf(materializedBinding(bob, "org-2", "org_admin"))
	if err := s.RevokeFrom(ctx, drop, GroupOrigin(tg)); err != nil {
		t.Fatalf("seed missing: %v", err)
	}

	d, err := p.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(d.Missing) != 1 || len(d.Orphan) != 0 {
		t.Fatalf("drift = %d missing / %d orphan, want 1/0", len(d.Missing), len(d.Orphan))
	}
	if d.Missing[0].Resource.ID != "org-2" {
		t.Fatalf("missing = %+v, want org-2", d.Missing[0])
	}

	if err := Guard(ctx, p); !errors.Is(err, ErrDrift) {
		t.Fatalf("Guard = %v, want ErrDrift", err)
	}
}

func TestReconcile_DetectsOrphan(t *testing.T) {
	p, s := seedClean(t)
	// A group-origin binding in a child scope with no intent behind it.
	if err := s.GrantFrom(ctx, materializedBinding(carol, "org-1", "org_admin"), GroupOrigin(tg)); err != nil {
		t.Fatalf("seed orphan: %v", err)
	}

	d, err := p.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(d.Orphan) != 1 || len(d.Missing) != 0 {
		t.Fatalf("drift = %d missing / %d orphan, want 0/1", len(d.Missing), len(d.Orphan))
	}
	if d.Orphan[0].Subject != carol {
		t.Fatalf("orphan = %+v, want carol's", d.Orphan[0])
	}

	if err := Guard(ctx, p); !errors.Is(err, ErrDrift) {
		t.Fatalf("Guard = %v, want ErrDrift", err)
	}
}

func TestReconcile_DetectsRoleDrift(t *testing.T) {
	p, s := seedClean(t)
	admin := materializedBinding(bob, "org-1", "org_admin")
	viewer := materializedBinding(bob, "org-1", "org_viewer")
	if err := s.RevokeFrom(ctx, keyOf(admin), GroupOrigin(tg)); err != nil {
		t.Fatalf("drop admin: %v", err)
	}
	if err := s.GrantFrom(ctx, viewer, GroupOrigin(tg)); err != nil {
		t.Fatalf("add viewer: %v", err)
	}

	d, err := p.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(d.Missing) != 1 || len(d.Orphan) != 1 {
		t.Fatalf("drift = %d missing / %d orphan, want 1/1 (role changed)", len(d.Missing), len(d.Orphan))
	}
	if d.Missing[0].Role != "org_admin" || d.Orphan[0].Role != "org_viewer" {
		t.Fatalf("drift roles = %q/%q, want org_admin/org_viewer", d.Missing[0].Role, d.Orphan[0].Role)
	}
}

// ---------------------------------------------------------------------
// SyncGroup repairs, idempotently.
// ---------------------------------------------------------------------

func TestSyncGroup_Repairs(t *testing.T) {
	p, s := seedClean(t)
	// One missing, one orphan.
	if err := s.RevokeFrom(ctx, keyOf(materializedBinding(bob, "org-3", "org_admin")), GroupOrigin(tg)); err != nil {
		t.Fatalf("seed missing: %v", err)
	}
	if err := s.GrantFrom(ctx, materializedBinding(carol, "org-2", "org_admin"), GroupOrigin(tg)); err != nil {
		t.Fatalf("seed orphan: %v", err)
	}

	if err := p.SyncGroup(ctx, tg); err != nil {
		t.Fatalf("SyncGroup: %v", err)
	}
	d, err := p.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !d.Empty() {
		t.Fatalf("drift after SyncGroup = %+v, want empty", d)
	}
	if err := Guard(ctx, p); err != nil {
		t.Fatalf("Guard after SyncGroup: %v", err)
	}
}

func TestSyncGroup_IsIdempotent(t *testing.T) {
	p, s := seedClean(t)
	if err := s.RevokeFrom(ctx, keyOf(materializedBinding(bob, "org-2", "org_admin")), GroupOrigin(tg)); err != nil {
		t.Fatalf("seed missing: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := p.SyncGroup(ctx, tg); err != nil {
			t.Fatalf("SyncGroup #%d: %v", i+1, err)
		}
	}
	d, err := p.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !d.Empty() {
		t.Fatalf("drift = %+v, want empty", d)
	}
}

// TestGuard_DoesNotRepair is the rule-6 witness: the guard must report and stop.
func TestGuard_DoesNotRepair(t *testing.T) {
	p, s := seedClean(t)
	if err := s.RevokeFrom(ctx, keyOf(materializedBinding(bob, "org-1", "org_admin")), GroupOrigin(tg)); err != nil {
		t.Fatalf("seed missing: %v", err)
	}

	if err := Guard(ctx, p); !errors.Is(err, ErrDrift) {
		t.Fatalf("Guard = %v, want ErrDrift", err)
	}
	// Still drifted: a guard that repaired would have hidden the bug.
	d, err := p.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(d.Missing) != 1 {
		t.Fatalf("missing after Guard = %d, want 1 (the guard must not repair)", len(d.Missing))
	}
}

func TestSyncGroup_RespectsTheCap(t *testing.T) {
	h := newHierarchy()
	seedP, s := newP(t, h, roleMap())
	if err := seedP.GrantGroupAdmin(ctx, bob, tg, groupRole()); err != nil {
		t.Fatalf("grant: %v", err)
	}
	for _, id := range []string{"org-1", "org-2", "org-3"} {
		if err := s.RevokeFrom(ctx, keyOf(materializedBinding(bob, id, "org_admin")), GroupOrigin(tg)); err != nil {
			t.Fatalf("seed missing %s: %v", id, err)
		}
	}

	p, err := NewProvisioner(s, h, roleMap(), WithMaxProvisionRows(2))
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	if err := p.SyncGroup(ctx, tg); !errors.Is(err, ErrTooManyRows) {
		t.Fatalf("SyncGroup = %v, want ErrTooManyRows", err)
	}
	d, err := p.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(d.Missing) != 3 {
		t.Fatalf("missing = %d, want 3 untouched by the capped SyncGroup", len(d.Missing))
	}
}

// A group whose INTENT row was lost still gets reconciled: its materialized
// rows are orphans, and enumerating intent rows alone would never look at that
// group.
func TestReconcile_DetectsOrphanAfterIntentLost(t *testing.T) {
	p, s := seedClean(t)
	if err := s.RevokeFrom(ctx, keyOf(intentBinding(bob, tg, groupRole())), GroupOrigin(tg)); err != nil {
		t.Fatalf("drop intent: %v", err)
	}

	d, err := p.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(d.Orphan) != 3 || len(d.Missing) != 0 {
		t.Fatalf("drift = %d missing / %d orphan, want 0/3 (the lost intent's rows are orphans)",
			len(d.Missing), len(d.Orphan))
	}
	if err := Guard(ctx, p); !errors.Is(err, ErrDrift) {
		t.Fatalf("Guard = %v, want ErrDrift", err)
	}

	// With no intent left, converging means removing the materialized rows.
	if err := p.SyncGroup(ctx, tg); err != nil {
		t.Fatalf("SyncGroup: %v", err)
	}
	after, err := p.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !after.Empty() {
		t.Fatalf("drift after SyncGroup = %+v, want empty", after)
	}
}

// The guard's message has to say WHICH org drifted, or an operator cannot act.
func TestGuard_MessageNamesTheOrg(t *testing.T) {
	p, s := seedClean(t)
	if err := s.RevokeFrom(ctx, keyOf(materializedBinding(bob, "org-2", "org_admin")), GroupOrigin(tg)); err != nil {
		t.Fatalf("seed missing: %v", err)
	}
	err := Guard(ctx, p)
	if !errors.Is(err, ErrDrift) {
		t.Fatalf("Guard = %v, want ErrDrift", err)
	}
	for _, want := range []string{"org-2", "bob", "org_admin", "tg-acme"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Guard message %q does not name %q", err.Error(), want)
		}
	}
}
