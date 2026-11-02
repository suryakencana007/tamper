package saml

import (
	"context"
	"errors"

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
			continue
		}
		allowed, err := m.inherit.allow(ctx, ancestor)
		if err != nil {
			return nil, err
		}
		if !allowed {
			return nil, nil
		}
		return borrowed, nil
	}
	return nil, nil
}
