package authz

import (
	"context"
	"testing"
)

// TestRBACPermissionStore_ParityWithRBAC is the framework-level proof that
// PermissionSet(NewRBACPermissionStore(store, h, p)) decides IDENTICALLY to
// RBAC(store, h, p) on every (subject, action, resource) — parity BY
// CONSTRUCTION. This is the mechanism Barista's slice-3 swap relies on for its
// built-in roles. Unlike the Superuser-seeded fixture in
// permissionset_parity_test.go, the converter folds the system keyset per action
// (not a Superuser flag), so it reproduces RBAC EXACTLY — including
// unknown-action deny and any action that lacks the bypass — with no divergence.
func TestRBACPermissionStore_ParityWithRBAC(t *testing.T) {
	h := Hierarchy{
		"cluster": {"cluster-viewer", "cluster-deployer", "cluster-admin"},
		"system":  {"system-user", "system-admin"},
		"org":     {"org-member", "org-admin", "org-owner"},
	}
	sysBypass := Requirement{Type: "system", Min: "system-admin"}
	p := Policy{
		"cluster.view":   {{Type: "cluster", Min: "cluster-viewer"}, sysBypass},
		"cluster.deploy": {{Type: "cluster", Min: "cluster-deployer"}, sysBypass},
		"cluster.manage": {{Type: "cluster", Min: "cluster-admin"}, sysBypass},
		"org.view":       {{Type: "org", Min: "org-member"}, sysBypass},
		"org.own":        {{Type: "org", Min: "org-owner"}, sysBypass},
		"system.admin":   {sysBypass},
	}
	alice := Subject{"user", "alice"} // system admin, NO scoped rows (bypass case)
	bob := Subject{"user", "bob"}     // cluster deployer on c1 + org member on o1
	erin := Subject{"user", "erin"}   // nothing
	store := NewMemStore(
		Binding{alice, Resource{"system", ""}, "system-admin"},
		Binding{bob, Resource{"cluster", "c1"}, "cluster-deployer"},
		Binding{bob, Resource{"org", "o1"}, "org-member"},
	)

	rbac, err := NewRBAC(store, h, p)
	if err != nil {
		t.Fatalf("NewRBAC: %v", err)
	}
	conv, err := NewRBACPermissionStore(store, h, p)
	if err != nil {
		t.Fatalf("NewRBACPermissionStore: %v", err)
	}
	pset, err := NewPermissionSet(conv)
	if err != nil {
		t.Fatalf("NewPermissionSet: %v", err)
	}

	ctx := context.Background()
	subjects := []Subject{alice, bob, erin}
	actions := []Action{"cluster.view", "cluster.deploy", "cluster.manage", "org.view", "org.own", "system.admin", "unknown.action"}
	resources := []Resource{{"cluster", "c1"}, {"cluster", "c2"}, {"org", "o1"}, {"org", "o2"}, {"system", ""}}

	for _, sub := range subjects {
		for _, act := range actions {
			for _, res := range resources {
				dR, errR := rbac.Check(ctx, sub, act, res)
				dP, errP := pset.Check(ctx, sub, act, res)
				if (errR == nil) != (errP == nil) {
					t.Errorf("(%s, %q, %s): error mismatch rbac=%v permset=%v", sub.ID, act, res.ID, errR, errP)
					continue
				}
				if errR == nil && dR.Allowed != dP.Allowed {
					t.Errorf("DIVERGENCE (%s, %q, %s): rbac=%v permset=%v", sub.ID, act, res.ID, dR.Allowed, dP.Allowed)
				}
			}
		}
	}

	// Reverse queries delegate to RBAC, so they match exactly.
	rsR, uR, _ := rbac.ListResources(ctx, bob, "cluster.view", "cluster")
	rsP, uP, _ := pset.ListResources(ctx, bob, "cluster.view", "cluster")
	if uR != uP || len(rsR) != len(rsP) {
		t.Fatalf("ListResources parity: rbac=(%v,%v) permset=(%v,%v)", rsR, uR, rsP, uP)
	}
	for i := range rsR {
		if rsR[i] != rsP[i] {
			t.Errorf("ListResources[%d]: rbac=%v permset=%v", i, rsR[i], rsP[i])
		}
	}
}
