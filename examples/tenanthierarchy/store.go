package tenanthierarchy

import (
	"context"
	"fmt"
	"maps"
	"sort"
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

// Origin names WHAT justifies a binding row. A row can have more than one: a
// direct grant and a tenant-group grant can produce the identical binding, and
// revoking one must not remove the other. The row is deleted only when its
// last origin is gone.
//
// This is the side table ADR-0001 decision 1 anticipates, keyed by the binding
// key. Without it a revoke is keyed only by (scope, subject, resource, role)
// and cannot tell a direct grant from a group-materialized one — it would
// remove both.
type Origin string

// OriginDirect is the origin of every row written by a plain Grant, and the
// only origin a plain Revoke removes.
const OriginDirect Origin = "direct"

// GroupOrigin is the origin of every row a tenant-group grant materializes,
// plus its intent row. A group grant contributes this origin; revoking the
// grant removes only this origin, so a direct grant on the same binding
// survives.
func GroupOrigin(group tenant.ID) Origin {
	return Origin("group:" + group.String())
}

// Store is an authz.BindingStore (read) plus atomic, idempotent writes with
// per-origin ref counting. It holds both kinds of row the hierarchy needs —
// the group-scope INTENT row and the org-scope MATERIALIZED rows — in one
// keyed set, the in-memory form of the single authz_binding table (ADR-0001
// decision 1).
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
	// origins holds, per row, the set of sources that justify it. Empty (or
	// absent) means no row; the row is removed when the last origin goes.
	origins map[BindingKey]map[Origin]struct{}
}

var (
	_ authz.BindingStore = (*Store)(nil)
	_ BindingWriter      = (*Store)(nil)
)

// NewStore returns an empty store.
func NewStore() *Store {
	return &Store{
		rows:    map[BindingKey]authz.Binding{},
		origins: map[BindingKey]map[Origin]struct{}{},
	}
}

// Tx is the read+write view an [Store.Apply] callback works against. Every
// write is staged; the store changes only if the callback returns nil. Reads
// see the staged view, so a callback can read-then-write atomically — that is
// what closes the read-then-apply race a revoke would otherwise have.
//
// A Tx is not safe for concurrent use and is only valid for the duration of
// the Apply call. Do not call the Store's own methods from inside the
// callback — Apply holds the write lock; go through the Tx.
type Tx interface {
	Grant(ctx context.Context, b authz.Binding) error
	GrantFrom(ctx context.Context, b authz.Binding, origin Origin) error
	Revoke(ctx context.Context, key BindingKey) error
	RevokeFrom(ctx context.Context, key BindingKey, origin Origin) error

	BindingsFor(ctx context.Context, scope tenant.ID, sub authz.Subject, res authz.Resource) ([]authz.Binding, error)
	BindingsForSubject(ctx context.Context, scope tenant.ID, sub authz.Subject, resourceType string) ([]authz.Binding, error)
	BindingsOnResource(ctx context.Context, scope tenant.ID, res authz.Resource) ([]authz.Binding, error)
	BindingsFrom(ctx context.Context, scope tenant.ID, origin Origin) ([]authz.Binding, error)
}

// BindingWriter is what provisioning depends on, so a SQL adapter can
// replace the in-memory store without touching provisioning logic.
//
// Grant and Revoke write/remove the OriginDirect contribution; GrantFrom and
// RevokeFrom do the same for a named origin. All are idempotent on
// [BindingKey]; Apply is all-or-nothing.
type BindingWriter interface {
	Grant(ctx context.Context, b authz.Binding) error
	GrantFrom(ctx context.Context, b authz.Binding, origin Origin) error
	Revoke(ctx context.Context, key BindingKey) error
	RevokeFrom(ctx context.Context, key BindingKey, origin Origin) error
	Apply(ctx context.Context, fn func(tx Tx) error) error
}

// Grant stores b with the OriginDirect contribution. Granting the same
// [BindingKey] twice is one row (idempotent).
//
// ErrTenantRequired for a binding with an unset scope or a subject with no
// home tenant, and nothing is stored: such a row could never be read back, so
// storing it quietly would turn a forgotten field into "everyone lost
// access" with no error anywhere. The same rule the reference authz stores
// apply.
func (s *Store) Grant(ctx context.Context, b authz.Binding) error {
	return s.GrantFrom(ctx, b, OriginDirect)
}

// GrantFrom stores b, contributing origin. A second GrantFrom with the same
// key and origin is idempotent.
func (s *Store) GrantFrom(_ context.Context, b authz.Binding, origin Origin) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return put(s.rows, s.origins, b, origin)
}

// Revoke removes the OriginDirect contribution from the binding key names. The
// row goes only if no other origin remains; revoking an absent key or an
// absent origin is a no-op, not an error.
//
// ErrTenantRequired, like Grant, for a key without a scope or a subject with
// no home tenant.
func (s *Store) Revoke(ctx context.Context, key BindingKey) error {
	return s.RevokeFrom(ctx, key, OriginDirect)
}

// RevokeFrom removes the origin contribution from the binding key names. The
// row is deleted only when its last origin goes, so revoking a group grant
// leaves a direct grant on the same binding in place.
func (s *Store) RevokeFrom(_ context.Context, key BindingKey, origin Origin) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return drop(s.rows, s.origins, key, origin)
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

	stagedRows := make(map[BindingKey]authz.Binding, len(s.rows))
	maps.Copy(stagedRows, s.rows)
	stagedOrigins := cloneOrigins(s.origins)

	if err := fn(&tx{rows: stagedRows, origins: stagedOrigins}); err != nil {
		return err
	}
	s.rows = stagedRows
	s.origins = stagedOrigins
	return nil
}

// tx stages writes into caller-owned maps. It carries no lock: Apply holds
// the Store's write lock for the whole callback.
type tx struct {
	rows    map[BindingKey]authz.Binding
	origins map[BindingKey]map[Origin]struct{}
}

func (t *tx) Grant(ctx context.Context, b authz.Binding) error {
	return t.GrantFrom(ctx, b, OriginDirect)
}

func (t *tx) GrantFrom(_ context.Context, b authz.Binding, origin Origin) error {
	return put(t.rows, t.origins, b, origin)
}

func (t *tx) Revoke(ctx context.Context, key BindingKey) error {
	return t.RevokeFrom(ctx, key, OriginDirect)
}

func (t *tx) RevokeFrom(_ context.Context, key BindingKey, origin Origin) error {
	return drop(t.rows, t.origins, key, origin)
}

func (t *tx) BindingsFor(_ context.Context, scope tenant.ID, sub authz.Subject, res authz.Resource) ([]authz.Binding, error) {
	if err := gate(scope, sub); err != nil {
		return nil, err
	}
	return scanFor(t.rows, scope, sub, res), nil
}

func (t *tx) BindingsForSubject(_ context.Context, scope tenant.ID, sub authz.Subject, resourceType string) ([]authz.Binding, error) {
	if err := gate(scope, sub); err != nil {
		return nil, err
	}
	return scanForSubject(t.rows, scope, sub, resourceType), nil
}

func (t *tx) BindingsOnResource(_ context.Context, scope tenant.ID, res authz.Resource) ([]authz.Binding, error) {
	if err := scopeGate(scope); err != nil {
		return nil, err
	}
	return scanOnResource(t.rows, scope, res), nil
}

func (t *tx) BindingsFrom(_ context.Context, scope tenant.ID, origin Origin) ([]authz.Binding, error) {
	if err := scopeGate(scope); err != nil {
		return nil, err
	}
	return scanFrom(t.rows, t.origins, scope, origin), nil
}

// BindingsFor implements authz.BindingStore: the bindings sub holds on
// exactly res, in the scope asked for.
func (s *Store) BindingsFor(_ context.Context, scope tenant.ID, sub authz.Subject, res authz.Resource) ([]authz.Binding, error) {
	if err := gate(scope, sub); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return scanFor(s.rows, scope, sub, res), nil
}

// BindingsForSubject implements authz.BindingStore: the bindings sub holds
// on concrete resources (ID != "") of the given type, in the scope asked for.
func (s *Store) BindingsForSubject(_ context.Context, scope tenant.ID, sub authz.Subject, resourceType string) ([]authz.Binding, error) {
	if err := gate(scope, sub); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return scanForSubject(s.rows, scope, sub, resourceType), nil
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
	return scanOnResource(s.rows, scope, res), nil
}

// BindingsFrom returns the bindings in scope that carry origin. It is the
// origin-scoped read a group-materialization pass needs: in the group's own
// scope, GroupOrigin(group) selects exactly that group's INTENT rows, and a
// direct grant on the same resource — which carries OriginDirect — is not
// swept in.
func (s *Store) BindingsFrom(_ context.Context, scope tenant.ID, origin Origin) ([]authz.Binding, error) {
	if err := scopeGate(scope); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return scanFrom(s.rows, s.origins, scope, origin), nil
}

// GroupAdmins returns the intent rows of a tenant-group: the bindings in the
// group's scope that carry GroupOrigin(group). It is the read a membership
// change uses to know whose grants to extend. A direct grant on the group
// resource (OriginDirect) is not included — that is the provenance guard, not
// a convenience.
func (s *Store) GroupAdmins(ctx context.Context, group tenant.ID) ([]authz.Binding, error) {
	return s.BindingsFrom(ctx, group, GroupOrigin(group))
}

// IntentGroupsForSubject returns the tenant-groups in which the subject
// (subjectType, userID) holds an intent row: a row in the group's own scope,
// on a {tenant_group, group} resource, carrying GroupOrigin(group). It is the
// cross-scope read a derived membership needs for MembershipsFor, where the
// groups are not known in advance. The subject type is matched so a
// service_account named "bob" is not a user membership. A direct binding on the
// group resource is not an intent and is skipped.
func (s *Store) IntentGroupsForSubject(_ context.Context, subjectType, userID string) ([]tenant.ID, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := make(map[tenant.ID]bool)
	var out []tenant.ID
	for k, b := range s.rows {
		if b.Subject.Type != subjectType || b.Subject.ID != userID || b.Resource.Type != ResourceTenantGroup {
			continue
		}
		if _, ok := s.origins[k][GroupOrigin(k.Scope)]; !ok {
			continue
		}
		if !seen[b.Tenant] {
			seen[b.Tenant] = true
			out = append(out, b.Tenant)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out, nil
}

func scanFor(rows map[BindingKey]authz.Binding, scope tenant.ID, sub authz.Subject, res authz.Resource) []authz.Binding {
	var out []authz.Binding
	for k, b := range rows {
		if k.Scope == scope && k.Subject == sub && k.Res == res {
			out = append(out, b)
		}
	}
	return out
}

func scanForSubject(rows map[BindingKey]authz.Binding, scope tenant.ID, sub authz.Subject, resourceType string) []authz.Binding {
	var out []authz.Binding
	for k, b := range rows {
		if k.Scope == scope && k.Subject == sub && k.Res.Type == resourceType && k.Res.ID != "" {
			out = append(out, b)
		}
	}
	return out
}

func scanOnResource(rows map[BindingKey]authz.Binding, scope tenant.ID, res authz.Resource) []authz.Binding {
	var out []authz.Binding
	for k, b := range rows {
		if k.Scope == scope && k.Res == res {
			out = append(out, b)
		}
	}
	return out
}

func scanFrom(rows map[BindingKey]authz.Binding, origins map[BindingKey]map[Origin]struct{}, scope tenant.ID, origin Origin) []authz.Binding {
	var out []authz.Binding
	for k, b := range rows {
		if k.Scope != scope {
			continue
		}
		if _, ok := origins[k][origin]; ok {
			out = append(out, b)
		}
	}
	return out
}

// put stores b and records that origin justifies it. The row is written on
// first origin; further origins add to the set.
func put(rows map[BindingKey]authz.Binding, origins map[BindingKey]map[Origin]struct{}, b authz.Binding, origin Origin) error {
	if err := gate(b.Tenant, b.Subject); err != nil {
		return err
	}
	k := keyOf(b)
	rows[k] = b
	set := origins[k]
	if set == nil {
		set = map[Origin]struct{}{}
		origins[k] = set
	}
	set[origin] = struct{}{}
	return nil
}

// drop removes one origin from a row. The row is deleted only when its last
// origin goes. An unknown key or an origin the row does not carry is a no-op:
// a re-sync must not fail because a previous pass already removed the row.
func drop(rows map[BindingKey]authz.Binding, origins map[BindingKey]map[Origin]struct{}, key BindingKey, origin Origin) error {
	if err := gate(key.Scope, key.Subject); err != nil {
		return err
	}
	set, ok := origins[key]
	if !ok {
		return nil
	}
	delete(set, origin)
	if len(set) == 0 {
		delete(origins, key)
		delete(rows, key)
	}
	return nil
}

// cloneOrigins deep-copies the origin sets, so a staged Apply cannot mutate
// the live store's maps through the shared inner maps.
func cloneOrigins(src map[BindingKey]map[Origin]struct{}) map[BindingKey]map[Origin]struct{} {
	dst := make(map[BindingKey]map[Origin]struct{}, len(src))
	for k, v := range src {
		cp := make(map[Origin]struct{}, len(v))
		for o := range v {
			cp[o] = struct{}{}
		}
		dst[k] = cp
	}
	return dst
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
