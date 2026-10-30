package tenanthierarchy

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/suryakencana007/tamper/authz"
	"github.com/suryakencana007/tamper/authz/tenanttest"
	"github.com/suryakencana007/tamper/tenant"
)

var (
	ctx = context.Background()

	org1 = tenant.New("org-1")
	org2 = tenant.New("org-2")
	tg   = tenant.New("tg-acme")

	bob  = authz.Subject{Tenant: tg, Type: "user", ID: "bob"}
	erin = authz.Subject{Tenant: tenant.New("tg-other"), Type: "user", ID: "erin"}

	resOrg1 = authz.Resource{Type: "organization", ID: "org-1"}
	resTg   = authz.Resource{Type: "tenant_group", ID: "tg-acme"}

	bobOrg1 = authz.Binding{Tenant: org1, Subject: bob, Resource: resOrg1, Role: "org_admin"}
)

func newStore() *Store { return NewStore() }

// ---------------------------------------------------------------------
// Conformance: the authz isolation contract, via the shipped leak suite.
// ---------------------------------------------------------------------

func TestStore_PassesBindingStoreLeakSuite(t *testing.T) {
	tenanttest.RunBindingStoreLeakSuite(t, func() tenanttest.BindingHarness {
		s := NewStore()
		return tenanttest.BindingHarness{
			Store: s,
			Grant: func(b authz.Binding) error { return s.Grant(context.Background(), b) },
		}
	})
}

// ---------------------------------------------------------------------
// Writes: idempotent, atomic, no-op on an absent revoke.
// ---------------------------------------------------------------------

func TestGrant_IsIdempotentOnKey(t *testing.T) {
	s := newStore()
	for i := 0; i < 2; i++ {
		if err := s.Grant(ctx, bobOrg1); err != nil {
			t.Fatalf("Grant #%d: %v", i+1, err)
		}
	}
	if got := len(s.rows); got != 1 {
		t.Fatalf("rows = %d, want 1 — the same BindingKey must not duplicate", got)
	}
}

func TestGrant_DistinctRolesAreDistinctRows(t *testing.T) {
	s := newStore()
	admin := bobOrg1
	viewer := bobOrg1
	viewer.Role = "org_viewer"
	if err := s.Grant(ctx, admin); err != nil {
		t.Fatalf("Grant(admin): %v", err)
	}
	if err := s.Grant(ctx, viewer); err != nil {
		t.Fatalf("Grant(viewer): %v", err)
	}
	if got := len(s.rows); got != 2 {
		t.Fatalf("rows = %d, want 2 — role is part of the key", got)
	}
}

func TestRevoke_AbsentKeyIsNoOp(t *testing.T) {
	s := newStore()
	if err := s.Grant(ctx, bobOrg1); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	absent := BindingKey{Scope: org2, Subject: erin, Res: resOrg1, Role: "org_admin"}
	if err := s.Revoke(ctx, absent); err != nil {
		t.Fatalf("Revoke(absent): %v, want nil", err)
	}
	if got := len(s.rows); got != 1 {
		t.Fatalf("rows = %d, want 1 — revoking an absent key changes nothing", got)
	}

	if err := s.Revoke(ctx, keyOf(bobOrg1)); err != nil {
		t.Fatalf("Revoke(present): %v", err)
	}
	if got := len(s.rows); got != 0 {
		t.Fatalf("rows = %d, want 0", got)
	}
}

func TestApply_CommitsOnSuccess(t *testing.T) {
	s := newStore()
	err := s.Apply(ctx, func(tx Tx) error {
		if err := tx.Grant(ctx, bobOrg1); err != nil {
			return err
		}
		return tx.Grant(ctx, authz.Binding{Tenant: org1, Subject: bob, Resource: resTg, Role: "tenant_group_admin"})
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := len(s.rows); got != 2 {
		t.Fatalf("rows = %d, want 2", got)
	}
}

func TestApply_RollsBackOnError(t *testing.T) {
	s := newStore()
	// Seed one row so the rollback test proves it restores the PRIOR state,
	// not merely an empty one.
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
		t.Fatalf("Apply error = %v, want %v", err, boom)
	}

	if got := len(s.rows); got != 1 {
		t.Fatalf("rows = %d, want 1 — a failed Apply must leave the store as it was", got)
	}
	if _, ok := s.rows[keyOf(bobOrg1)]; ok {
		t.Fatal("the staged grant survived a failed Apply")
	}
	if _, ok := s.rows[keyOf(existing)]; !ok {
		t.Fatal("the failed Apply dropped a pre-existing row")
	}
}

// ---------------------------------------------------------------------
// The tenant gate: an unset scope, or a subject with no home tenant, is
// authz.ErrTenantRequired on read and write — never a silent success.
// ---------------------------------------------------------------------

func TestUnsetScopeIsErrTenantRequired(t *testing.T) {
	s := newStore()
	zero := tenant.ID{}

	reads := []struct {
		name string
		call func() error
	}{
		{"BindingsFor", func() error { _, err := s.BindingsFor(ctx, zero, bob, resOrg1); return err }},
		{"BindingsForSubject", func() error { _, err := s.BindingsForSubject(ctx, zero, bob, "organization"); return err }},
		{"BindingsOnResource", func() error { _, err := s.BindingsOnResource(ctx, zero, resOrg1); return err }},
	}
	for _, tc := range reads {
		if err := tc.call(); !errors.Is(err, authz.ErrTenantRequired) {
			t.Fatalf("%s: err = %v, want ErrTenantRequired", tc.name, err)
		}
	}

	if err := s.Grant(ctx, authz.Binding{Tenant: zero, Subject: bob, Resource: resOrg1, Role: "org_admin"}); !errors.Is(err, authz.ErrTenantRequired) {
		t.Fatalf("Grant: err = %v, want ErrTenantRequired", err)
	}
	if err := s.Revoke(ctx, BindingKey{Scope: zero, Subject: bob, Res: resOrg1, Role: "org_admin"}); !errors.Is(err, authz.ErrTenantRequired) {
		t.Fatalf("Revoke: err = %v, want ErrTenantRequired", err)
	}
	if got := len(s.rows); got != 0 {
		t.Fatalf("rows = %d, want 0 — a refused write stores nothing", got)
	}
}

func TestSubjectWithoutHomeTenantIsErrTenantRequired(t *testing.T) {
	s := newStore()
	homeless := authz.Subject{Type: "user", ID: "nobody"}

	if err := s.Grant(ctx, authz.Binding{Tenant: org1, Subject: homeless, Resource: resOrg1, Role: "org_admin"}); !errors.Is(err, authz.ErrTenantRequired) {
		t.Fatalf("Grant: err = %v, want ErrTenantRequired", err)
	}
	if _, err := s.BindingsFor(ctx, org1, homeless, resOrg1); !errors.Is(err, authz.ErrTenantRequired) {
		t.Fatalf("BindingsFor: err = %v, want ErrTenantRequired", err)
	}
}

// ---------------------------------------------------------------------
// Read isolation: scope and subject are matched whole.
// ---------------------------------------------------------------------

func TestReads_AreScopedAndExact(t *testing.T) {
	s := newStore()
	for _, b := range []authz.Binding{
		bobOrg1,
		{Tenant: org2, Subject: bob, Resource: resOrg1, Role: "org_admin"},  // other scope, same subject/resource
		{Tenant: org1, Subject: erin, Resource: resOrg1, Role: "org_admin"}, // same scope, other subject
		{Tenant: org1, Subject: bob, Resource: resTg, Role: "tenant_group_admin"},
	} {
		if err := s.Grant(ctx, b); err != nil {
			t.Fatalf("Grant(%+v): %v", b, err)
		}
	}

	got, err := s.BindingsFor(ctx, org1, bob, resOrg1)
	if err != nil {
		t.Fatalf("BindingsFor: %v", err)
	}
	if len(got) != 1 || got[0].Role != "org_admin" {
		t.Fatalf("BindingsFor(org1, bob, org1) = %+v, want only bob's org_admin in scope org1", got)
	}

	// The global-role query still answers per scope.
	globals, err := s.BindingsOnResource(ctx, org1, resTg)
	if err != nil {
		t.Fatalf("BindingsOnResource: %v", err)
	}
	if len(globals) != 1 || globals[0].Subject != bob {
		t.Fatalf("BindingsOnResource(org1, tenant_group) = %+v, want bob's intent row", globals)
	}
}

// ---------------------------------------------------------------------
// Concurrency: reads, single-row writes and Apply all serialize on one lock.
// ---------------------------------------------------------------------

func TestStore_ConcurrentUse(t *testing.T) {
	s := newStore()

	const goroutines, perGoroutine = 8, 50
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			sub := authz.Subject{Tenant: tg, Type: "user", ID: fmt.Sprintf("u-%d", g)}
			for i := 0; i < perGoroutine; i++ {
				if err := s.Grant(ctx, authz.Binding{Tenant: org1, Subject: sub, Resource: resOrg1, Role: "org_admin"}); err != nil {
					t.Errorf("goroutine %d Grant: %v", g, err)
					return
				}
				if err := s.Apply(ctx, func(tx Tx) error {
					return tx.Grant(ctx, authz.Binding{Tenant: org2, Subject: sub, Resource: resOrg1, Role: "org_admin"})
				}); err != nil {
					t.Errorf("goroutine %d Apply: %v", g, err)
					return
				}
				if _, err := s.BindingsFor(ctx, org1, sub, resOrg1); err != nil {
					t.Errorf("goroutine %d BindingsFor: %v", g, err)
					return
				}
			}
		}(g)
	}
	wg.Wait()

	// Each goroutine writes exactly two rows, idempotent across its 50 passes.
	if got := len(s.rows); got != goroutines*2 {
		t.Fatalf("rows = %d, want %d", got, goroutines*2)
	}
}

// ---------------------------------------------------------------------
// Provenance: a row can have several origins, and goes only when the last
// one does. This is what stops a group revoke from removing a direct grant
// that happens to land on the same binding.
// ---------------------------------------------------------------------

func TestProvenance_DirectSurvivesGroupOriginRevoke(t *testing.T) {
	s := newStore()
	group := GroupOrigin(tg)

	if err := s.Grant(ctx, bobOrg1); err != nil {
		t.Fatalf("direct Grant: %v", err)
	}
	if err := s.GrantFrom(ctx, bobOrg1, group); err != nil {
		t.Fatalf("group GrantFrom: %v", err)
	}
	if len(s.rows) != 1 {
		t.Fatalf("rows = %d, want 1 — both origins name the same key", len(s.rows))
	}
	if got := len(s.origins[keyOf(bobOrg1)]); got != 2 {
		t.Fatalf("origins = %d, want 2", got)
	}

	if err := s.RevokeFrom(ctx, keyOf(bobOrg1), group); err != nil {
		t.Fatalf("RevokeFrom(group): %v", err)
	}
	if _, ok := s.rows[keyOf(bobOrg1)]; !ok {
		t.Fatal("revoking the group origin removed the direct grant")
	}

	if err := s.Revoke(ctx, keyOf(bobOrg1)); err != nil {
		t.Fatalf("Revoke(direct): %v", err)
	}
	if _, ok := s.rows[keyOf(bobOrg1)]; ok {
		t.Fatal("the row survived its last origin")
	}
}

func TestProvenance_GrantFromIsIdempotent(t *testing.T) {
	s := newStore()
	group := GroupOrigin(tg)
	for i := 0; i < 2; i++ {
		if err := s.GrantFrom(ctx, bobOrg1, group); err != nil {
			t.Fatalf("GrantFrom #%d: %v", i+1, err)
		}
	}
	if len(s.rows) != 1 || len(s.origins[keyOf(bobOrg1)]) != 1 {
		t.Fatalf("rows=%d origins=%d, want 1 and 1", len(s.rows), len(s.origins[keyOf(bobOrg1)]))
	}
}

func TestProvenance_RevokeFromAbsentOriginIsNoOp(t *testing.T) {
	s := newStore()
	if err := s.Grant(ctx, bobOrg1); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if err := s.RevokeFrom(ctx, keyOf(bobOrg1), GroupOrigin(tg)); err != nil {
		t.Fatalf("RevokeFrom(absent origin): %v", err)
	}
	if _, ok := s.rows[keyOf(bobOrg1)]; !ok {
		t.Fatal("an absent origin must not remove the row")
	}
}

// A Tx sees its own staged writes: provisioning reads inside Apply, which is
// what closes the read-then-apply race.
func TestTx_ReadsSeeStagedWrites(t *testing.T) {
	s := newStore()
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
