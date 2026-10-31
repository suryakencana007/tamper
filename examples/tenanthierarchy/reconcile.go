package tenanthierarchy

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/suryakencana007/tamper/authz"
	"github.com/suryakencana007/tamper/tenant"
)

// ErrDrift — the materialized bindings disagree with what intent × parentage
// requires. The guard reports it and stops; repair is SyncGroup, called
// explicitly.
var ErrDrift = errors.New("tenanthierarchy: binding drift")

// Drift is the difference between what intent × parentage requires and what the
// store holds, for the groups that have intent rows. Both directions are
// reported: a missing binding is an access gap, an orphan is access too broad.
type Drift struct {
	// Missing — required by intent, absent from the store.
	Missing []authz.Binding
	// Orphan — present in the store, not justified by any intent.
	Orphan []authz.Binding
}

// Empty reports whether the two sets agree.
func (d Drift) Empty() bool { return len(d.Missing) == 0 && len(d.Orphan) == 0 }

// Reconcile computes the drift of every tenant-group that holds an intent row.
// It does not modify anything.
func (p *Provisioner) Reconcile(ctx context.Context) (Drift, error) {
	groups, err := p.src.IntentGroups(ctx)
	if err != nil {
		return Drift{}, fmt.Errorf("tenanthierarchy: list intent groups: %w", err)
	}
	var out Drift
	for _, group := range groups {
		d, err := p.reconcileGroup(ctx, group)
		if err != nil {
			return Drift{}, err
		}
		out.Missing = append(out.Missing, d.Missing...)
		out.Orphan = append(out.Orphan, d.Orphan...)
	}
	sortBindings(out.Missing)
	sortBindings(out.Orphan)
	return out, nil
}

// SyncGroup makes group's materialized bindings match intent × parentage, in one
// atomic Apply: orphans are removed and missing rows are written, both under
// GroupOrigin(group). It is idempotent — a second call on a converged group
// writes nothing.
//
// It is the explicit repair. The guard never calls it: silent repair hides the
// bug that produced the drift.
func (p *Provisioner) SyncGroup(ctx context.Context, group tenant.ID) error {
	if !group.Valid() || group.IsSingle() {
		return fmt.Errorf("%w: the group is unset or the single tenant", ErrBadMembership)
	}
	d, err := p.reconcileGroup(ctx, group)
	if err != nil {
		return err
	}
	if d.Empty() {
		return nil
	}
	if n := len(d.Missing) + len(d.Orphan); n > p.maxRows {
		return fmt.Errorf("%w: SyncGroup needs %d rows, cap %d", ErrTooManyRows, n, p.maxRows)
	}

	origin := GroupOrigin(group)
	return p.src.Apply(ctx, func(tx Tx) error {
		for _, b := range d.Orphan {
			if err := tx.RevokeFrom(ctx, keyOf(b), origin); err != nil {
				return err
			}
		}
		for _, b := range d.Missing {
			if err := tx.GrantFrom(ctx, b, origin); err != nil {
				return err
			}
		}
		return nil
	})
}

// Guard is the boot/CI check: any drift is an error naming how much and a
// sample, with ErrDrift in the chain. It never repairs — run SyncGroup for that.
func Guard(ctx context.Context, p *Provisioner) error {
	d, err := p.Reconcile(ctx)
	if err != nil {
		return err
	}
	if d.Empty() {
		return nil
	}
	return fmt.Errorf("%w: %d missing, %d orphan (first missing %s, first orphan %s); run SyncGroup",
		ErrDrift, len(d.Missing), len(d.Orphan), first(d.Missing), first(d.Orphan))
}

// reconcileGroup computes the drift for one tenant-group.
//
// Expected: every intent row of the group, translated through RoleMap,
// materialized onto every child of the group (decision 5: status does not
// matter — a suspended org still needs its bindings). Actual: the rows in each
// child's scope carrying GroupOrigin(group). A direct grant carries another
// origin, so it is neither expected nor actual here.
func (p *Provisioner) reconcileGroup(ctx context.Context, group tenant.ID) (Drift, error) {
	origin := GroupOrigin(group)

	intents, err := p.src.BindingsFrom(ctx, group, origin)
	if err != nil {
		return Drift{}, fmt.Errorf("tenanthierarchy: intent rows of %s: %w", group, err)
	}
	children, err := p.hier.ChildrenOf(ctx, group.String())
	if err != nil {
		return Drift{}, fmt.Errorf("tenanthierarchy: children of %s: %w", group, err)
	}

	expected := make(map[BindingKey]authz.Binding, len(intents)*len(children))
	for _, in := range intents {
		mapped, ok := p.roles.translate(in.Role)
		if !ok {
			return Drift{}, fmt.Errorf("%w: %q held on %s", ErrUnmappedRole, in.Role, group)
		}
		for _, id := range children {
			if !usableOrg(id) {
				continue
			}
			b := materializedBinding(in.Subject, id, mapped)
			expected[keyOf(b)] = b
		}
	}

	actual := make(map[BindingKey]authz.Binding)
	for _, id := range children {
		if !usableOrg(id) {
			continue
		}
		rows, err := p.src.BindingsFrom(ctx, tenant.New(id), origin)
		if err != nil {
			return Drift{}, fmt.Errorf("tenanthierarchy: %s bindings in %s: %w", group, id, err)
		}
		for _, b := range rows {
			actual[keyOf(b)] = b
		}
	}

	var d Drift
	for k, b := range expected {
		if _, ok := actual[k]; !ok {
			d.Missing = append(d.Missing, b)
		}
	}
	for k, b := range actual {
		if _, ok := expected[k]; !ok {
			d.Orphan = append(d.Orphan, b)
		}
	}
	sortBindings(d.Missing)
	sortBindings(d.Orphan)
	return d, nil
}

// usableOrg reports whether a child id can carry a binding.
func usableOrg(id string) bool {
	org := tenant.New(id)
	return org.Valid() && !org.IsSingle()
}

// sortBindings orders by key, so drift output and error messages are stable.
func sortBindings(bs []authz.Binding) {
	sort.Slice(bs, func(i, j int) bool { return keyLess(keyOf(bs[i]), keyOf(bs[j])) })
}

func keyLess(a, b BindingKey) bool {
	if a.Scope != b.Scope {
		return a.Scope.String() < b.Scope.String()
	}
	if a.Subject.Type != b.Subject.Type {
		return a.Subject.Type < b.Subject.Type
	}
	if a.Subject.ID != b.Subject.ID {
		return a.Subject.ID < b.Subject.ID
	}
	if a.Subject.Tenant != b.Subject.Tenant {
		return a.Subject.Tenant.String() < b.Subject.Tenant.String()
	}
	if a.Res.Type != b.Res.Type {
		return a.Res.Type < b.Res.Type
	}
	if a.Res.ID != b.Res.ID {
		return a.Res.ID < b.Res.ID
	}
	return a.Role < b.Role
}

func first(bs []authz.Binding) string {
	if len(bs) == 0 {
		return "none"
	}
	return describe(bs[0])
}

func describe(b authz.Binding) string {
	return fmt.Sprintf("%s{%s:%s} %s", b.Resource.Type, b.Subject.Type, b.Subject.ID, b.Role)
}
