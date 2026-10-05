package authz

import (
	"context"
	"sync"

	"github.com/suryakencana007/tamper/tenant"
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
	superusers map[permSuperKey]struct{}
}

type permGrantKey struct {
	tenant tenant.ID // the scope the grant lives in
	sub    Subject
	res    Resource
}

// permSuperKey: a superuser is a superuser of one scope, not of every
// tenant.
type permSuperKey struct {
	tenant tenant.ID
	sub    Subject
}

var _ PermissionStore = (*MemPermissionStore)(nil)

// NewMemPermissionStore returns an empty store.
func NewMemPermissionStore() *MemPermissionStore {
	return &MemPermissionStore{
		grants:     make(map[permGrantKey]map[string]struct{}),
		superusers: make(map[permSuperKey]struct{}),
	}
}

// Grant adds permission keys for sub on exactly res (idempotent). A "*" key is
// rejected silently — superuser is expressed via GrantSuperuser, never as a
// stored key, so a wildcard can never leak in through a grant.
func (m *MemPermissionStore) Grant(tenantID tenant.ID, sub Subject, res Resource, keys ...string) error {
	if err := gate(tenantID, sub); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	k := permGrantKey{tenantID, sub, res}
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
	return nil
}

// GrantSuperuser marks sub as superuser on every resource.
func (m *MemPermissionStore) GrantSuperuser(tenantID tenant.ID, sub Subject) error {
	if err := gate(tenantID, sub); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.superusers[permSuperKey{tenantID, sub}] = struct{}{}
	return nil
}

// PermissionsFor implements PermissionStore.
func (m *MemPermissionStore) PermissionsFor(_ context.Context, tenantID tenant.ID, sub Subject, res Resource) (PermissionSetResult, error) {
	if err := gate(tenantID, sub); err != nil {
		return PermissionSetResult{}, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, ok := m.superusers[permSuperKey{tenantID, sub}]; ok {
		return PermissionSetResult{Superuser: true}, nil
	}
	src := m.grants[permGrantKey{tenantID, sub, res}]
	keys := make(map[string]struct{}, len(src))
	for k := range src {
		keys[k] = struct{}{}
	}
	return PermissionSetResult{Keys: keys}, nil
}

// ResourcesWithPermission implements PermissionStore. A superuser's access is
// non-enumerable (every resource of the type), so it reports unbounded.
func (m *MemPermissionStore) ResourcesWithPermission(_ context.Context, tenantID tenant.ID, sub Subject, key string, resourceType string) ([]Resource, bool, error) {
	if err := gate(tenantID, sub); err != nil {
		return nil, false, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, ok := m.superusers[permSuperKey{tenantID, sub}]; ok {
		return nil, true, nil
	}
	var out []Resource
	for gk, set := range m.grants {
		if gk.tenant != tenantID || gk.sub != sub || gk.res.Type != resourceType || gk.res.ID == "" {
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
func (m *MemPermissionStore) SubjectsWithPermission(_ context.Context, tenantID tenant.ID, key string, res Resource) ([]Subject, error) {
	if err := scopeGate(tenantID); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	seen := make(map[Subject]struct{})
	var out []Subject
	for gk, set := range m.grants {
		if gk.tenant != tenantID || gk.res != res {
			continue
		}
		if _, ok := set[key]; ok {
			if _, dup := seen[gk.sub]; !dup {
				seen[gk.sub] = struct{}{}
				out = append(out, gk.sub)
			}
		}
	}
	for sk := range m.superusers {
		if sk.tenant != tenantID {
			continue
		}
		if _, dup := seen[sk.sub]; !dup {
			seen[sk.sub] = struct{}{}
			out = append(out, sk.sub)
		}
	}
	return out, nil
}
