package tenanthierarchy

import (
	"context"
	"fmt"
	"maps"
	"sync"

	"github.com/suryakencana007/tamper/authz"
	"github.com/suryakencana007/tamper/tenant"
)

// BindingKey identifies one row. Idempotence is defined on the full key:
// granting the same scope, subject, resource and role twice is one row.
//
// It is the store's primary key — the in-memory analogue of the
// authz_binding table's composite key (ADR-0001 decision 1). A SQL adapter
// swaps the map for that table; the key does not change.
type BindingKey struct {
	Scope   tenant.ID
	Subject authz.Subject
	Res     authz.Resource
	Role    authz.Role
}

// keyOf returns the key of a binding.
func keyOf(b authz.Binding) BindingKey {
	return BindingKey{Scope: b.Tenant, Subject: b.Subject, Res: b.Resource, Role: b.Role}
}

// Store is an authz.BindingStore (read) plus atomic, idempotent writes. It
// holds both kinds of row the hierarchy needs — the group-scope INTENT row
// and the org-scope MATERIALIZED rows — in one keyed set, the in-memory
// form of the single authz_binding table (ADR-0001 decision 1).
//
// It implements authz.BindingStore, so it drops into authz.NewRBAC with no
// change to any call site, and it implements [BindingWriter], the port the
// Provisioner (slice 9a-2) writes through.
//
// Linear scans over the keyed set: fine for the example and small embedded
// deployments, not for large binding sets (an application's SQL-backed store
// is for that). Safe for concurrent use.
type Store struct {
	mu   sync.RWMutex
	rows map[BindingKey]authz.Binding
}

var (
	_ authz.BindingStore = (*Store)(nil)
	_ BindingWriter      = (*Store)(nil)
)

// NewStore returns an empty store.
func NewStore() *Store {
	return &Store{rows: map[BindingKey]authz.Binding{}}
}

// Tx is the write surface an [Store.Apply] callback mutates. Every call is
// staged; the store changes only if the callback returns nil.
//
// A Tx is not safe for concurrent use and is only valid for the duration of
// the Apply call. Do not call the Store's own methods from inside the
// callback — Apply holds the write lock; go through the Tx.
type Tx interface {
	Grant(ctx context.Context, b authz.Binding) error
	Revoke(ctx context.Context, key BindingKey) error
}

// BindingWriter is what provisioning depends on, so a SQL adapter can
// replace the in-memory store without touching provisioning logic.
//
// Grant and Revoke are idempotent on [BindingKey]; Apply is all-or-nothing.
type BindingWriter interface {
	Grant(ctx context.Context, b authz.Binding) error
	Revoke(ctx context.Context, key BindingKey) error
	Apply(ctx context.Context, fn func(tx Tx) error) error
}

// Grant stores b. Granting the same [BindingKey] twice is one row
// (idempotent).
//
// ErrTenantRequired for a binding with an unset scope or a subject with no
// home tenant, and nothing is stored: such a row could never be read back, so
// storing it quietly would turn a forgotten field into "everyone lost
// access" with no error anywhere. The same rule the reference authz stores
// apply.
func (s *Store) Grant(_ context.Context, b authz.Binding) error {
	if err := gate(b.Tenant, b.Subject); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows[keyOf(b)] = b
	return nil
}

// Revoke removes the binding the key names. Revoking an absent key is a
// no-op, not an error — a re-sync may revoke a row that a previous pass
// already removed.
//
// ErrTenantRequired, like Grant, for a key without a scope or a subject with
// no home tenant.
func (s *Store) Revoke(_ context.Context, key BindingKey) error {
	if err := gate(key.Scope, key.Subject); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rows, key)
	return nil
}

// Apply runs fn against a staged copy of the store. If fn returns nil the
// staged copy replaces the live one; if it returns an error the store is left
// exactly as it was. This is the all-or-nothing boundary provisioning uses: a
// grant writes its intent row and every materialized row in one Apply, so a
// failure can never leave an intent without its expansion.
//
// The cost is O(total rows), not O(rows changed): the staged copy is a full
// map copy. Fine for the example; a SQL adapter stages in the transaction
// instead. ctx is accepted for that adapter, which can honour cancellation —
// the in-memory implementation has nothing to cancel.
func (s *Store) Apply(_ context.Context, fn func(tx Tx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	staged := make(map[BindingKey]authz.Binding, len(s.rows))
	maps.Copy(staged, s.rows)

	if err := fn(&tx{rows: staged}); err != nil {
		return err
	}
	s.rows = staged
	return nil
}

// tx stages writes into a caller-owned map. It carries no lock: Apply holds
// the Store's write lock for the whole callback.
type tx struct {
	rows map[BindingKey]authz.Binding
}

func (t *tx) Grant(_ context.Context, b authz.Binding) error {
	if err := gate(b.Tenant, b.Subject); err != nil {
		return err
	}
	t.rows[keyOf(b)] = b
	return nil
}

func (t *tx) Revoke(_ context.Context, key BindingKey) error {
	if err := gate(key.Scope, key.Subject); err != nil {
		return err
	}
	delete(t.rows, key)
	return nil
}

// BindingsFor implements authz.BindingStore: the bindings sub holds on
// exactly res, in the scope asked for.
func (s *Store) BindingsFor(_ context.Context, scope tenant.ID, sub authz.Subject, res authz.Resource) ([]authz.Binding, error) {
	if err := gate(scope, sub); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []authz.Binding
	for k, b := range s.rows {
		if k.Scope == scope && k.Subject == sub && k.Res == res {
			out = append(out, b)
		}
	}
	return out, nil
}

// BindingsForSubject implements authz.BindingStore: the bindings sub holds
// on concrete resources (ID != "") of the given type, in the scope asked for.
func (s *Store) BindingsForSubject(_ context.Context, scope tenant.ID, sub authz.Subject, resourceType string) ([]authz.Binding, error) {
	if err := gate(scope, sub); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []authz.Binding
	for k, b := range s.rows {
		if k.Scope == scope && k.Subject == sub && k.Res.Type == resourceType && k.Res.ID != "" {
			out = append(out, b)
		}
	}
	return out, nil
}

// BindingsOnResource implements authz.BindingStore: every subject's bindings
// on exactly res, in the scope asked for. Global-role holders (res.ID == "")
// are enumerated the same way.
func (s *Store) BindingsOnResource(_ context.Context, scope tenant.ID, res authz.Resource) ([]authz.Binding, error) {
	if err := scopeGate(scope); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []authz.Binding
	for k, b := range s.rows {
		if k.Scope == scope && k.Res == res {
			out = append(out, b)
		}
	}
	return out, nil
}

// gate refuses a question that names no scope, or a subject with no home
// tenant, with authz.ErrTenantRequired — the port's own error, not a new one.
// Written here because authz's own gate is unexported.
func gate(scope tenant.ID, sub authz.Subject) error {
	if err := scopeGate(scope); err != nil {
		return err
	}
	if !sub.Tenant.Valid() {
		return fmt.Errorf("%w: subject %s:%s has no home tenant", authz.ErrTenantRequired, sub.Type, sub.ID)
	}
	return nil
}

func scopeGate(scope tenant.ID) error {
	if !scope.Valid() {
		return fmt.Errorf("%w: the scope is unset", authz.ErrTenantRequired)
	}
	return nil
}
