package authz

import (
	"context"
	"testing"
)

// This is the Slice-1 byte-parity gate (PHASE5-CUSTOM-ROLE-RBAC-SKETCH.md §3.2,
// framework layer): a PermissionSet engine seeded so each built-in role resolves
// to the downward-closure of its rank reproduces an RBAC engine's decisions
// byte-for-byte (Decision.Allowed) on a Barista-shaped fixture.
//
// Anti-circularity: the anchor is a HAND-AUTHORED golden decision table
// (parityGolden) — values computed by hand from the intended access semantics,
// not from either engine's formula. BOTH engines must match it. The full-matrix
// cross-check then asserts the two engines never diverge on any cell.
//
// The fixture mirrors Barista's policy shape: independent role ladders per type
// and a system-scope role that bypasses every action (the systemBypass
// OR-requirement, policy.go). Because EVERY action here carries the system
// bypass, the set-model analogue of a system admin is a plain Superuser — that
// equivalence holds only under the "every action is bypass-satisfiable"
// invariant Barista's policy currently upholds.
//
// Coverage scope: this Slice-1 fixture exercises ONE non-system ladder
// (cluster) + system. Org is structurally identical (independent ladder, same
// bypass); real 4-scope parity is Slice 3's job, where it reuses Barista's own
// internal/authz/authz_test.go fixture unchanged (sketch §3.2).
//
// Slice-3 TODO (from the Slice-1 review): make the "system-admin ⇒ Superuser"
// seeding precondition MACHINE-enforced — add a test that iterates Barista's
// Policy() and asserts every action's requirement list contains systemBypass,
// so a future non-bypass action can't silently make a superuser over-grant it
// (a false-allow the fixture would only catch if someone also updated it).

type parityFixture struct {
	rbac      Authorizer
	permset   Authorizer
	subjects  []Subject
	actions   []Action // KNOWN policy actions only (see unknown-action note below)
	resources []Resource
}

// Subjects.
var (
	pAlice = Subject{"user", "alice"} // system admin, global; NO cluster row (the bypass case)
	pBob   = Subject{"user", "bob"}   // cluster deployer on c1
	pCarol = Subject{"user", "carol"} // cluster viewer on c1
	pDave  = Subject{"user", "dave"}  // system admin global + cluster viewer on c1 (mixed)
	pErin  = Subject{"user", "erin"}  // nothing
)

// Resources.
var (
	pC1  = Resource{"cluster", "c1"}
	pC2  = Resource{"cluster", "c2"}
	pSys = Resource{"system", ""} // the global system singleton
)

func newParityFixture(t *testing.T) parityFixture {
	t.Helper()
	h := Hierarchy{
		"cluster": {"cluster-viewer", "cluster-deployer", "cluster-admin"},
		"system":  {"system-user", "system-admin"},
	}
	sysBypass := Requirement{Type: "system", Min: "system-admin"}
	p := Policy{
		"cluster.view":   {{Type: "cluster", Min: "cluster-viewer"}, sysBypass},
		"cluster.deploy": {{Type: "cluster", Min: "cluster-deployer"}, sysBypass},
		"cluster.manage": {{Type: "cluster", Min: "cluster-admin"}, sysBypass},
		"system.admin":   {sysBypass},
	}

	// RBAC over role bindings.
	ms := NewMemStore(
		Binding{pAlice, pSys, "system-admin"},
		Binding{pBob, pC1, "cluster-deployer"},
		Binding{pCarol, pC1, "cluster-viewer"},
		Binding{pDave, pSys, "system-admin"},
		Binding{pDave, pC1, "cluster-viewer"},
	)
	rbac, err := NewRBAC(ms, h, p)
	if err != nil {
		t.Fatalf("NewRBAC: %v", err)
	}

	// PermissionSet over the equivalent permission sets: each built-in role is
	// the downward-closure of its rank, and a system admin — who bypasses every
	// action — is a global Superuser.
	pstore := NewMemPermissionStore()
	pstore.GrantSuperuser(pAlice)
	pstore.Grant(pBob, pC1, "cluster.view", "cluster.deploy")
	pstore.Grant(pCarol, pC1, "cluster.view")
	pstore.GrantSuperuser(pDave) // system admin ⇒ superuser; his cluster-viewer row is subsumed
	permset, err := NewPermissionSet(pstore)
	if err != nil {
		t.Fatalf("NewPermissionSet: %v", err)
	}

	return parityFixture{
		rbac: rbac, permset: permset,
		subjects:  []Subject{pAlice, pBob, pCarol, pDave, pErin},
		actions:   []Action{"cluster.view", "cluster.deploy", "cluster.manage", "system.admin"},
		resources: []Resource{pC1, pC2, pSys},
	}
}

// parityGolden is the hand-authored truth table — the anti-circularity anchor.
var parityGolden = []struct {
	sub  Subject
	act  Action
	res  Resource
	want bool
}{
	// alice: system admin, NO cluster row — the Finding-1 bypass cases.
	{pAlice, "cluster.view", pC1, true},
	{pAlice, "cluster.manage", pC1, true},
	{pAlice, "cluster.manage", pC2, true},
	{pAlice, "system.admin", pSys, true},
	// bob: cluster deployer on c1.
	{pBob, "cluster.view", pC1, true},
	{pBob, "cluster.deploy", pC1, true},
	{pBob, "cluster.manage", pC1, false}, // deployer < admin
	{pBob, "cluster.view", pC2, false},   // no grant on c2
	{pBob, "system.admin", pSys, false},
	// carol: cluster viewer on c1.
	{pCarol, "cluster.view", pC1, true},
	{pCarol, "cluster.deploy", pC1, false},
	{pCarol, "cluster.manage", pC1, false},
	// dave: system admin (superuser) + cluster viewer.
	{pDave, "cluster.manage", pC1, true},
	{pDave, "cluster.manage", pC2, true},
	{pDave, "system.admin", pSys, true},
	// erin: nothing.
	{pErin, "cluster.view", pC1, false},
	{pErin, "system.admin", pSys, false},
}

func TestParity_GoldenTable(t *testing.T) {
	fx := newParityFixture(t)
	for _, tc := range parityGolden {
		mustAllow(t, fx.rbac, tc.sub, tc.act, tc.res, tc.want)
		mustAllow(t, fx.permset, tc.sub, tc.act, tc.res, tc.want)
	}
}

// TestParity_FullMatrix asserts the two engines NEVER diverge on any
// (subject, known-action, resource) cell — the belt-and-suspenders over the
// hand table.
func TestParity_FullMatrix(t *testing.T) {
	fx := newParityFixture(t)
	ctx := context.Background()
	for _, sub := range fx.subjects {
		for _, act := range fx.actions {
			for _, res := range fx.resources {
				dR, errR := fx.rbac.Check(ctx, sub, act, res)
				dP, errP := fx.permset.Check(ctx, sub, act, res)
				if errR != nil || errP != nil {
					t.Fatalf("Check(%s,%q,%s): rbac err=%v permset err=%v", sub.ID, act, res.ID, errR, errP)
				}
				if dR.Allowed != dP.Allowed {
					t.Errorf("DIVERGENCE at (%s, %q, %s): rbac=%v permset=%v",
						sub.ID, act, res.ID, dR.Allowed, dP.Allowed)
				}
			}
		}
	}
}

// TestParity_UnknownActionDivergenceIsScoped documents + pins the ONE deliberate
// difference: RBAC denies an unknown action (deny-by-default via its policy),
// while a Superuser PermissionSet allows it (the engine holds no policy, so it
// cannot distinguish "unknown" from "not-yet-granted"). This is unreachable in
// production — Barista's action set is a closed set of Action consts, so an
// unknown action never reaches Check — hence the parity matrix above iterates
// KNOWN actions only. For a NON-superuser subject the engines still agree
// (no grant ⇒ deny on both).
func TestParity_UnknownActionDivergenceIsScoped(t *testing.T) {
	fx := newParityFixture(t)
	ctx := context.Background()
	const unknown Action = "nonexistent.action"

	// Non-superuser: both deny — parity holds.
	dR, _ := fx.rbac.Check(ctx, pBob, unknown, pC1)
	dP, _ := fx.permset.Check(ctx, pBob, unknown, pC1)
	if dR.Allowed || dP.Allowed {
		t.Errorf("unknown action on a non-superuser must deny on both: rbac=%v permset=%v", dR.Allowed, dP.Allowed)
	}

	// Superuser: the documented divergence. RBAC denies (unknown action),
	// PermissionSet superuser allows. Pinned so a future reader understands it
	// is intentional, not a regression.
	dR, _ = fx.rbac.Check(ctx, pAlice, unknown, pC1)
	dP, _ = fx.permset.Check(ctx, pAlice, unknown, pC1)
	if dR.Allowed {
		t.Error("RBAC must deny an unknown action even for a system admin")
	}
	if !dP.Allowed {
		t.Error("a Superuser PermissionSet allows unknown actions by design (no policy to deny against)")
	}
}
