package oidc

import (
	"context"
	"fmt"

	"github.com/suryakencana007/tamper/tenant"
)

// IdP inheritance: a tenant with no enabled providers of its own can serve the
// providers of its nearest ancestor that has some.
//
// See ../docs/phases/PHASE12-TENANT-INHERITANCE-SKETCH.md §4.2 and §4.2.1. Off unless wired:
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
// Two costs come with it, both documented rather than discovered: the child pays
// DISCOVERY for the borrowed providers — a network round trip per provider, cached
// in the child's entry for the TTL — and with inheritance wired a provider change
// clears the whole registry cache, so that a group's edit reaches its inheritors on
// their next request. The callback URL is compiled for the child.
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
// The policy rules are tenant.Inherited's, in one place; this function is the OIDC
// half of the wiring.
func (m *Manager) recordsFor(ctx context.Context, tenantID tenant.ID) ([]ProviderRecord, error) {
	if m.inherit == nil {
		return m.listEnabled(ctx, tenantID)
	}
	// The walk can read an ANCESTOR's rows, so a store error has to say whose:
	// "list enabled providers" alone would leave an operator unable to tell which
	// tenant's table failed.
	own := func(ctx context.Context, id tenant.ID) ([]ProviderRecord, error) {
		recs, err := m.listEnabled(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("oidc: tenant %q: %w", id.String(), err)
		}
		return recs, nil
	}
	return tenant.Inherited(ctx, m.inherit.store, m.inherit.allow, tenantID, own)
}
