package authz

import (
	"context"
	"sync"

	"github.com/suryakencana007/tamper/tenant"
)

// MemStore is an in-memory BindingStore — the reference implementation and
// the natural test double. Linear scans over a slice: fine for tests and
// small embedded deployments, not intended for large binding sets (that is
// what an application's SQL-backed store is for).
type MemStore struct {
	mu       sync.RWMutex
	bindings []Binding
}

var _ BindingStore = (*MemStore)(nil)

// NewMemStore returns a store pre-seeded with bindings.
func NewMemStore(bindings ...Binding) *MemStore {
	m := &MemStore{}
	for _, b := range bindings {
		m.Grant(b)
	}
	return m
}

// Grant adds a binding. Exact duplicates are ignored (idempotent).
// b.Tenant is the scope the binding lives in.
//
// Panics on a binding with an unset Tenant or a Subject with no home
// tenant. Such a binding can never be read back, so storing it quietly
// would turn a forgotten field into "everyone lost access" with no
// error anywhere. This matters on upgrade: a keyed literal written
// before Subject and Binding had a Tenant still compiles.
func (m *MemStore) Grant(b Binding) {
	mustTenants("MemStore.Grant", b.Tenant, b.Subject)
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.bindings {
		if existing == b {
			return
		}
	}
	m.bindings = append(m.bindings, b)
}

// Revoke removes every binding exactly equal to b.
func (m *MemStore) Revoke(b Binding) {
	m.mu.Lock()
	defer m.mu.Unlock()
	kept := m.bindings[:0]
	for _, existing := range m.bindings {
		if existing != b {
			kept = append(kept, existing)
		}
	}
	m.bindings = kept
}

// BindingsFor implements BindingStore (exact subject + resource match).
func (m *MemStore) BindingsFor(_ context.Context, tenantID tenant.ID, sub Subject, res Resource) ([]Binding, error) {
	if err := scopeGate(tenantID); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []Binding
	for _, b := range m.bindings {
		if b.Tenant == tenantID && b.Subject == sub && b.Resource == res {
			out = append(out, b)
		}
	}
	return out, nil
}

// BindingsForSubject implements BindingStore (concrete resources only).
func (m *MemStore) BindingsForSubject(_ context.Context, tenantID tenant.ID, sub Subject, resourceType string) ([]Binding, error) {
	if err := scopeGate(tenantID); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []Binding
	for _, b := range m.bindings {
		if b.Tenant == tenantID && b.Subject == sub && b.Resource.Type == resourceType && b.Resource.ID != "" {
			out = append(out, b)
		}
	}
	return out, nil
}

// BindingsOnResource implements BindingStore (exact resource match).
func (m *MemStore) BindingsOnResource(_ context.Context, tenantID tenant.ID, res Resource) ([]Binding, error) {
	if err := scopeGate(tenantID); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []Binding
	for _, b := range m.bindings {
		if b.Tenant == tenantID && b.Resource == res {
			out = append(out, b)
		}
	}
	return out, nil
}

// mustTenants panics when a grant names no scope or a subject with no
// home tenant. Shared by the two reference stores.
func mustTenants(where string, scope tenant.ID, sub Subject) {
	if !scope.Valid() {
		panic("authz: " + where + ": the scope (Tenant) is unset; a single-tenant deployment sets tenant.Single")
	}
	if !sub.Tenant.Valid() {
		panic("authz: " + where + ": subject " + sub.Type + ":" + sub.ID + " has no home tenant; a single-tenant deployment sets tenant.Single")
	}
}
