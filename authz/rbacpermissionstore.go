package authz

import (
	"context"
	"fmt"
)

// rbacPermissionStore adapts a rank model (BindingStore + Hierarchy + Policy)
// into a PermissionStore, so a PermissionSet engine over it decides IDENTICALLY
// to an RBAC engine over the same inputs. It is the bridge that lets a consumer
// already modeled as rank-ladder RBAC (Barista) adopt the set engine for its
// expressiveness — non-nested custom roles — with NO decision drift on its
// built-in roles: parity is by construction here, not merely tested.
//
// PermissionsFor(sub, res) returns exactly the set of actions RBAC would allow
// sub on res, computed via the same requirement evaluation with binding reads
// memoized per call (so the DB cost matches RBAC's). The cross-type (global)
// requirement fold — e.g. Barista's system-admin bypass — falls out naturally:
// a satisfied cross-type requirement adds that action's key, so a system
// admin's keys appear on every scoped resource WITHOUT a Superuser flag or a
// hard-coded scope-containment graph. There is therefore no "every action
// carries the bypass" precondition (the concern the slice-1 review flagged for
// a Superuser-based seeding): an action that lacks the bypass is simply not
// folded in, exactly as RBAC would not grant it.
//
// Reverse queries delegate to the internal RBAC so ListResources / ListSubjects
// reproduce its enumeration + unbounded semantics exactly.
type rbacPermissionStore struct {
	e *RBAC
}

var _ PermissionStore = (*rbacPermissionStore)(nil)

// NewRBACPermissionStore validates the hierarchy + policy at construction (like
// NewRBAC) and returns a PermissionStore whose PermissionSet engine is
// decision-equivalent to NewRBAC(store, h, p).
func NewRBACPermissionStore(store BindingStore, h Hierarchy, p Policy) (PermissionStore, error) {
	e, err := NewRBAC(store, h, p)
	if err != nil {
		return nil, err
	}
	return &rbacPermissionStore{e: e}, nil
}

// PermissionsFor returns the set of actions RBAC would allow sub on res.
func (s *rbacPermissionStore) PermissionsFor(ctx context.Context, sub Subject, res Resource) (PermissionSetResult, error) {
	// Memoize effective rank per target: RBAC reads the same target across
	// multiple actions' requirements (especially the shared global singleton),
	// so caching keeps the DB cost at RBAC's level.
	ranks := make(map[Resource]int)
	effRank := func(target Resource) (int, error) {
		if r, ok := ranks[target]; ok {
			return r, nil
		}
		_, r, err := s.e.effective(ctx, sub, target)
		if err != nil {
			return 0, err
		}
		ranks[target] = r
		return r, nil
	}

	keys := make(map[string]struct{})
	for act, reqs := range s.e.p {
		for _, req := range reqs {
			target := res
			if req.Type != res.Type {
				target = Resource{Type: req.Type}
			}
			r, err := effRank(target)
			if err != nil {
				return PermissionSetResult{}, fmt.Errorf("authz: permissions for %s: %w", label(res), err)
			}
			if r >= s.e.h.rank(req.Type, req.Min) {
				keys[string(act)] = struct{}{}
				break
			}
		}
	}
	return PermissionSetResult{Keys: keys}, nil
}

// ResourcesWithPermission delegates to the internal RBAC's ListResources so the
// enumeration + unbounded semantics are reproduced exactly.
func (s *rbacPermissionStore) ResourcesWithPermission(ctx context.Context, sub Subject, key string, resourceType string) ([]Resource, bool, error) {
	return s.e.ListResources(ctx, sub, Action(key), resourceType)
}

// SubjectsWithPermission delegates to the internal RBAC's ListSubjects.
func (s *rbacPermissionStore) SubjectsWithPermission(ctx context.Context, key string, res Resource) ([]Subject, error) {
	subs, _, err := s.e.ListSubjects(ctx, Action(key), res)
	return subs, err
}
