package saml

import (
	"context"
	"fmt"

	"github.com/suryakencana007/tamper/tenant"
)

// IdP inheritance, for SAML. Identical semantics to the OIDC Manager's
// (oidc/inheritance.go) — the same walk, the same switch, the same outcomes — and
// this file exists rather than a shared helper because the two managers have no
// common type to hang one on. The tests here are the ones that differ: the SAML
// Manager has a second per-tenant seam, the SP metadata URL, which must be
// compiled for the CHILD exactly as the OIDC redirect URL is.
//
// See PHASE12-TENANT-INHERITANCE-SKETCH.md §4.2 and §4.2.1.

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
// their next request. The SP metadata URL is compiled for the child.
//
// A nil store or a nil policy leaves the feature OFF, matching the sibling
// options. tamper.New refuses the half-configured form at boot.
func WithInheritance(s tenant.Store, allow tenant.Inheritance) ManagerOption {
	return func(m *Manager) {
		if s != nil && allow != nil {
			m.inherit = &inheritConfig{store: s, allow: allow}
		}
	}
}

// recordsFor resolves the records a build will use, with NO lock held — the same
// contract as the OIDC Manager's, and for the same reason: the SAML Manager also
// reads the store under mu on the unwired path, so a hierarchy walk there would
// extend the critical section across a second store.
//
// The policy rules are tenant.Inherited's, in one place; this function is the SAML
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
			return nil, fmt.Errorf("saml: tenant %q: %w", id.String(), err)
		}
		return recs, nil
	}
	return tenant.Inherited(ctx, m.inherit.store, m.inherit.allow, tenantID, own)
}
