package tenanthierarchy

import "context"

// OrgHierarchy is the app-owned parentage port. It is what turns "the org a
// request is scoped to" into "the tenant-group that owns it" — nothing more.
//
// tamper's own tenant.Store deliberately does not expose this, and never will:
// a Store carries ParentID and resolves nothing through it. Tamper DOES walk the
// same field through tenant.Ancestors (Phase 12 §3.1 — the Phase 7 "nothing
// resolves it" invariant amended; ADR-0001 §5.A narrowed, not overturned). That
// walk answers "who may this tenant inherit from"; it cannot answer "which orgs
// does this group own", which is what provisioning needs, so an application backs
// this port with its own tenant table or cache the same way it backs
// authz.BindingStore.
//
// Implementations MUST be safe for concurrent use and SHOULD be cheap or
// cached: ParentOf is on the request path (espresso's tenant gate resolves an
// org to its group), and both methods are on the provisioning path.
type OrgHierarchy interface {
	// ParentOf returns the tenant-group that owns orgID, and false when
	// orgID has no parent (a root org, or an unknown id — deliberately not
	// distinguished here). An unknown org expands to nothing, which is a
	// deny, not an error.
	ParentOf(ctx context.Context, orgID string) (groupID string, ok bool, err error)

	// ChildrenOf returns every organization id that has groupID as its
	// parent. Empty (non-nil) slice for none. Fuel for provisioning: one
	// materialized binding is written per id.
	ChildrenOf(ctx context.Context, groupID string) (orgIDs []string, err error)
}
