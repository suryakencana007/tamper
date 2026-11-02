package oidc

import (
	"context"
	"errors"

	"github.com/suryakencana007/tamper/tenant"
)

// IdP inheritance: a tenant with no enabled providers of its own can serve the
// providers of its nearest ancestor that has some.
//
// See PHASE12-TENANT-INHERITANCE-SKETCH.md §4.2 and §4.2.1. Off unless wired:
// WithInheritance unset is today's behaviour, path for path.

// inheritConfig is the wired form of the feature: the parentage graph and the
// per-group switch, both required for it to do anything.
type inheritConfig struct {
	store tenant.Store
	allow tenant.Inheritance
}

// WithInheritance enables IdP inheritance over the given parentage store.
//
// The switch is asked of the ancestor whose providers are being borrowed — the
// GROUP's setting, not the child's — and only when that ancestor has providers to
// lend. A group that keeps its own IdP without opting in is saying "children
// configure their own", and the walk stops there rather than substituting a
// grandparent's providers.
//
// A nil store or a nil policy leaves the feature OFF, matching the sibling
// options: an unwired manager behaves exactly as it did before. tamper.New
// refuses the half-configured form at boot, so a deployment wired through it gets
// an error rather than a silent no-op.
func WithInheritance(s tenant.Store, allow tenant.Inheritance) ManagerOption {
	return func(m *Manager) {
		if s != nil && allow != nil {
			m.inherit = &inheritConfig{store: s, allow: allow}
		}
	}
}

// recordsFor resolves the records a build will use, and it is called with NO lock
// held — that is its whole reason for existing.
//
// The registry lock is held across the store read on the unwired path, which is
// deliberate (a stampede for one tenant then costs exactly one store read). An
// ancestor walk under that lock would extend the critical section across a second
// store, so every tenant's rebuild would wait behind one slow hierarchy read.
//
// Outcomes:
//
//	own records exist      those, always — a child with providers never consults
//	                       an ancestor, and nothing is merged
//	no ancestry configured today's empty result
//	unknown tenant         empty, not an error: the registry's contract is (nil, nil)
//	                       for a tenant with no providers, and "this tenant does not
//	                       exist" has the same answer
//	dangling parent        ErrHierarchyDangling, propagated: corrupt parentage is a
//	                       data fault, and swallowing it would hide it behind an
//	                       empty registry
//	policy error           propagated, with the bool ignored both ways round
func (m *Manager) recordsFor(ctx context.Context, tenantID tenant.ID) ([]ProviderRecord, error) {
	recs, err := m.listEnabled(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if len(recs) > 0 || m.inherit == nil {
		return recs, nil
	}

	chain, err := tenant.Ancestors(ctx, m.inherit.store, tenantID)
	if err != nil {
		if errors.Is(err, tenant.ErrHierarchyDangling) {
			return nil, err
		}
		if errors.Is(err, tenant.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}

	for _, ancestor := range chain {
		borrowed, err := m.listEnabled(ctx, ancestor)
		if err != nil {
			return nil, err
		}
		if len(borrowed) == 0 {
			// Nothing to lend, so its switch is not asked: a silent middle layer
			// must not block a decision made further up.
			continue
		}
		allowed, err := m.inherit.allow(ctx, ancestor)
		if err != nil {
			// A settings-table-backed policy fails the day that table is
			// unreachable. Reading (false, err) as a refusal would turn that
			// outage into a silent deny, indistinguishable from a group that
			// switched the feature off; reading (true, err) as permission is the
			// obvious bug. Both are avoided by returning the error.
			return nil, err
		}
		if !allowed {
			return nil, nil
		}
		return borrowed, nil
	}
	return nil, nil
}
