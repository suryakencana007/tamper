package authz

import (
	"context"
	"sync"
)

// MemPermissionStore is an in-memory PermissionStore — the reference
// implementation and the natural test double, mirroring MemStore for the
// BindingStore. Linear scans: fine for tests and small embedded deployments,
// not intended for large grant sets (that is an application's SQL-backed store).
//
// It models two grant shapes: exact per-(subject, resource) key sets, and
// global superusers (a subject allowed every action on every resource — the
// set-model analogue of Barista's system-admin bypass). A real adapter folds
// its own indirection (groups, built-in-role expansion, custom-role rows,
// the '*' fold) into PermissionsFor; this reference keeps to the two primitives.
type MemPermissionStore struct {
	mu         sync.RWMutex
	grants     map[permGrantKey]map[string]struct{}
	superusers map[Subject]struct{}
}

type permGrantKey struct {
	sub Subject
	res Resource
}

var _ PermissionStore = (*MemPermissionStore)(nil)

// NewMemPermissionStore returns an empty store.
func NewMemPermissionStore() *MemPermissionStore {
	return &MemPermissionStore{
		grants:     make(map[permGrantKey]map[string]struct{}),
		superusers: make(map[Subject]struct{}),
	}
}

// Grant adds permission keys for sub on exactly res (idempotent). A "*" key is
// rejected silently — superuser is expressed via GrantSuperuser, never as a
// stored key, so a wildcard can never leak in through a grant.
func (m *MemPermissionStore) Grant(sub Subject, res Resource, keys ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := permGrantKey{sub, res}
	set := m.grants[k]
	if set == nil {
		set = make(map[string]struct{})
		m.grants[k] = set
	}
	for _, key := range keys {
		if key == SuperuserKey {
			continue
		}
		set[key] = struct{}{}
	}
}

// GrantSuperuser marks sub as superuser on every resource.
func (m *MemPermissionStore) GrantSuperuser(sub Subject) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.superusers[sub] = struct{}{}
}

// PermissionsFor implements PermissionStore.
func (m *MemPermissionStore) PermissionsFor(_ context.Context, sub Subject, res Resource) (PermissionSetResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, ok := m.superusers[sub]; ok {
		return PermissionSetResult{Superuser: true}, nil
	}
	src := m.grants[permGrantKey{sub, res}]
	keys := make(map[string]struct{}, len(src))
	for k := range src {
		keys[k] = struct{}{}
	}
	return PermissionSetResult{Keys: keys}, nil
}

// ResourcesWithPermission implements PermissionStore. A superuser's access is
// non-enumerable (every resource of the type), so it reports unbounded.
func (m *MemPermissionStore) ResourcesWithPermission(_ context.Context, sub Subject, key string, resourceType string) ([]Resource, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, ok := m.superusers[sub]; ok {
		return nil, true, nil
	}
	var out []Resource
	for gk, set := range m.grants {
		if gk.sub != sub || gk.res.Type != resourceType || gk.res.ID == "" {
			continue
		}
		if _, ok := set[key]; ok {
			out = append(out, gk.res)
		}
	}
	return out, false, nil
}

// SubjectsWithPermission implements PermissionStore: every subject holding key
// on exactly res, plus every global superuser (they hold every key everywhere).
func (m *MemPermissionStore) SubjectsWithPermission(_ context.Context, key string, res Resource) ([]Subject, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	seen := make(map[Subject]struct{})
	var out []Subject
	for gk, set := range m.grants {
		if gk.res != res {
			continue
		}
		if _, ok := set[key]; ok {
			if _, dup := seen[gk.sub]; !dup {
				seen[gk.sub] = struct{}{}
				out = append(out, gk.sub)
			}
		}
	}
	for sub := range m.superusers {
		if _, dup := seen[sub]; !dup {
			seen[sub] = struct{}{}
			out = append(out, sub)
		}
	}
	return out, nil
}
