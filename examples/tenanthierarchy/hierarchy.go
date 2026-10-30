package tenanthierarchy

import "context"

// OrgHierarchy is the app-owned parentage port. It is what turns "the org a
// request is scoped to" into "the tenant-group that owns it" — nothing more.
//
// tamper's own tenant.Store deliberately does not expose this: ParentID is
// RESERVED there ("Nothing in tamper resolves it, inherits through it, or
// branches on it", Phase 7 sketch §8 item 3). An application backs this port
// with its own tenant table or cache, the same way it backs
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
