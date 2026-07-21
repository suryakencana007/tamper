package tamper

import "github.com/suryakencana007/barista/packages/tamper/authz"

// RBAC builds a rank-based Authorizer over a BindingStore, ready to drop into
// Config.Authz. It is a thin one-liner over authz.NewRBAC so a greenfield
// consumer does not have to reach into the authz subpackage for the common
// case; applications that build their own PDP (a converter, an overlay, a
// custom store) pass that directly to Config.Authz instead.
//
// The rank engine expresses downward-closed roles (a higher rank subsumes
// every lower one). For roles that are NOT downward-closed — arbitrary
// permission subsets like {view, manage} without deploy — use PermissionSet.
func RBAC(store authz.BindingStore, h authz.Hierarchy, p authz.Policy) (authz.Authorizer, error) {
	// Return an explicit nil interface on error — a bare `return
	// authz.NewRBAC(...)` would pack the nil *RBAC into a NON-nil Authorizer
	// (the typed-nil-in-interface trap), so a caller who checks the result
	// before the error would hold a landmine that panics at Check time.
	a, err := authz.NewRBAC(store, h, p)
	if err != nil {
		return nil, err
	}
	return a, nil
}

// PermissionSet builds a set-based Authorizer over a PermissionStore, ready
// to drop into Config.Authz. The set engine decides by permission-key
// membership over the union of a subject's roles, so it expresses
// non-downward-closed roles the rank engine cannot; it subsumes RBAC (a
// downward-closed role is just a particular key set).
func PermissionSet(store authz.PermissionStore) (authz.Authorizer, error) {
	// Explicit nil interface on error — same typed-nil-in-interface trap as
	// RBAC above.
	a, err := authz.NewPermissionSet(store)
	if err != nil {
		return nil, err
	}
	return a, nil
}
