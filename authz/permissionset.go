package authz

import (
	"context"
	"fmt"
	"sort"
)

// SuperuserKey is the wildcard permission string that must NEVER appear as a
// stored key: superuser is granted EXCLUSIVELY via PermissionSetResult.Superuser
// (an explicit flag a store sets deliberately), and this constant exists so
// stores + schemas can REJECT it. It models Barista's system-admin bypass —
// exactly one built-in role resolves to Superuser, and custom roles must never
// reach it. The write side rejects it (MemPermissionStore.Grant strips it) and
// the Slice-3 DB CHECK structurally excludes it from role_permissions (see
// PHASE5-CUSTOM-ROLE-RBAC-SKETCH.md §4). allows() treats a leaked "*" as an
// inert literal key (fail-closed), never as superuser.
const SuperuserKey = "*"

// PermissionSetResult is the effective permission set a PermissionStore reports
// for one (subject, resource). Superuser short-circuits membership: when true,
// every action is allowed on that resource regardless of Keys. Keys holds the
// exact permission keys otherwise (an action is allowed iff its string form is
// present). A nil/empty Keys with Superuser false is a clean deny — the
// deny-by-default floor.
type PermissionSetResult struct {
	Keys      map[string]struct{}
	Superuser bool
}

// allows reports whether act is granted by this set. Superuser is expressed
// EXCLUSIVELY by the Superuser flag, never by a key: a stray "*" in Keys is
// treated as the literal key "*", which matches no real action (Barista's
// action set is closed dotted verbs), so it grants nothing. This is deliberate
// fail-CLOSED — if the wildcard invariant is ever violated (a "*" leaking into
// Keys via a bug or data corruption), the safe response for a PDP is to deny,
// not to escalate to superuser. Both the store (MemPermissionStore.Grant strips
// "*") and the Slice-3 DB CHECK keep "*" out of Keys in the first place; this
// method's job is to not turn a leaked wildcard into root.
func (r PermissionSetResult) allows(act Action) bool {
	if r.Superuser {
		return true
	}
	_, ok := r.Keys[string(act)]
	return ok
}

// PermissionStore supplies the PermissionSet engine with EFFECTIVE permission
// keys for a subject. Like BindingStore, ALL indirection is the store's
// concern — group grants, built-in-role→key expansion, custom-role keys, and
// the superuser bypass are resolved into the returned set, so the engine only
// tests membership and never walks a graph. This is the same division of labor
// RBAC uses (store.go): keeping resolution store-side is what lets the engine
// stay a pure, auditable membership test.
//
// Implementations MUST be safe for concurrent use. Queries are read-only; how
// permissions are granted/revoked is out of the PDP's scope.
type PermissionStore interface {
	// PermissionsFor returns the effective permission set sub holds on exactly
	// res (same Type AND ID; an empty ID is the global/type-level query). A
	// store error means "could not decide" — the engine surfaces it and
	// callers must treat it as deny.
	PermissionsFor(ctx context.Context, sub Subject, res Resource) (PermissionSetResult, error)

	// ResourcesWithPermission enumerates the CONCRETE resources (ID != "") of
	// resourceType on which sub holds key. Fuel for ListResources.
	// unbounded=true means a grant makes the subject's access non-enumerable
	// (a superuser, or a global grant covering every resource of the type);
	// the caller owns the catalog and must treat that as "all".
	ResourcesWithPermission(ctx context.Context, sub Subject, key string, resourceType string) (resources []Resource, unbounded bool, err error)

	// SubjectsWithPermission enumerates the subjects holding key on exactly
	// res. Fuel for ListSubjects. SQL stores can enumerate global-role holders,
	// which is why the engine's ListSubjects never reports unbounded.
	SubjectsWithPermission(ctx context.Context, key string, res Resource) ([]Subject, error)
}

// PermissionSet is an Authorizer that decides by set membership: an action is
// allowed iff its key is in the subject's effective permission set (or the
// subject is superuser) on the resource. It is the set-based counterpart to
// RBAC — where RBAC compares ranks in a ladder, PermissionSet tests membership
// in a set, which lets it express NON-nested roles (grant view + manage but not
// deploy) a rank ladder structurally cannot. It holds no taxonomy; role→key
// resolution, group indirection, and the superuser bypass all live in the
// PermissionStore.
//
// A PermissionSet seeded so that each built-in role resolves to the
// downward-closure of its rank reproduces an RBAC engine's decisions
// byte-for-byte (Decision.Allowed; Reason differs and is non-control-flow) —
// see PHASE5-CUSTOM-ROLE-RBAC-SKETCH.md §3.2 and permissionset_parity_test.go.
//
// Deny-by-default is a hard contract: an empty set, an unknown key, and a store
// error all resolve to deny (error where the question could not be evaluated).
// All methods are safe for concurrent use as long as the PermissionStore is.
type PermissionSet struct {
	store PermissionStore
}

var _ Authorizer = (*PermissionSet)(nil)

// NewPermissionSet returns the engine over the given store.
func NewPermissionSet(store PermissionStore) (*PermissionSet, error) {
	if store == nil {
		return nil, fmt.Errorf("authz: NewPermissionSet requires a PermissionStore")
	}
	return &PermissionSet{store: store}, nil
}

// Check implements Authorizer. Empty/unknown actions deny with a nil error (the
// engine has no policy to validate against — every string is a potential key,
// so an absent key is simply a deny); store failures return an error, which
// callers must also treat as deny.
func (e *PermissionSet) Check(ctx context.Context, sub Subject, act Action, res Resource) (Decision, error) {
	if act == "" {
		return Decision{Allowed: false, Reason: "empty action"}, nil
	}
	set, err := e.store.PermissionsFor(ctx, sub, res)
	if err != nil {
		return Decision{}, fmt.Errorf("authz: check %q on %s: %w", act, label(res), err)
	}
	if set.Superuser {
		return Decision{Allowed: true, Reason: fmt.Sprintf("superuser on %s allows %q", label(res), act)}, nil
	}
	if set.allows(act) {
		return Decision{Allowed: true, Reason: fmt.Sprintf("permission %q held on %s", act, label(res))}, nil
	}
	return Decision{Allowed: false, Reason: fmt.Sprintf("permission %q not held on %s", act, label(res))}, nil
}

// CheckBulk implements Authorizer. Results are index-aligned with reqs; the
// first evaluation error fails the whole call.
func (e *PermissionSet) CheckBulk(ctx context.Context, reqs []CheckRequest) ([]Decision, error) {
	out := make([]Decision, len(reqs))
	for i, r := range reqs {
		d, err := e.Check(ctx, r.Subject, r.Action, r.Resource)
		if err != nil {
			return nil, err
		}
		out[i] = d
	}
	return out, nil
}

// ListResources implements Authorizer: the concrete resources of resourceType
// on which sub may perform act. Unlike RBAC this engine holds no policy, so it
// cannot reject an "unknown action" (every string is a potential key) — an
// action nobody was granted simply yields an empty, non-unbounded result. The
// store owns enumeration; the engine sorts by ID for a deterministic listing
// (matching RBAC's ordering, rbac.go:136).
func (e *PermissionSet) ListResources(ctx context.Context, sub Subject, act Action, resourceType string) ([]Resource, bool, error) {
	if act == "" {
		return nil, false, nil
	}
	rs, unbounded, err := e.store.ResourcesWithPermission(ctx, sub, string(act), resourceType)
	if err != nil {
		return nil, false, fmt.Errorf("authz: list resources for %q: %w", act, err)
	}
	seen := make(map[Resource]bool, len(rs))
	out := make([]Resource, 0, len(rs))
	for _, r := range rs {
		if r.Type != resourceType || r.ID == "" || seen[r] {
			continue // defensive: hold the store to its contract
		}
		seen[r] = true
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, unbounded, nil
}

// ListSubjects implements Authorizer: the subjects who may perform act on res.
// The engine never reports unbounded — SQL stores enumerate global-role holders
// concretely (matching RBAC, rbac.go:144). Sorted by (Type, ID).
func (e *PermissionSet) ListSubjects(ctx context.Context, act Action, res Resource) ([]Subject, bool, error) {
	if act == "" {
		return nil, false, nil
	}
	subs, err := e.store.SubjectsWithPermission(ctx, string(act), res)
	if err != nil {
		return nil, false, fmt.Errorf("authz: list subjects for %q: %w", act, err)
	}
	seen := make(map[Subject]bool, len(subs))
	out := make([]Subject, 0, len(subs))
	for _, s := range subs {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].ID < out[j].ID
	})
	return out, false, nil
}
