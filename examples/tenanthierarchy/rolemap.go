package tenanthierarchy

import "github.com/suryakencana007/tamper/authz"

// RoleMap translates a role held on a tenant-group into the role it confers
// on each child organization.
//
// It exists because authz role ladders are independent per resource type
// (authz/policy.go): a "tenant_group" ladder and an "organization" ladder are
// unrelated enums even when some names coincide, so an explicit map is safer
// than assuming identical role strings carry the same rank in both.
//
// Keyed by the SOURCE role (as held on the tenant-group); the value is the
// role reported on the expanded organization resource. A role absent from the
// map does NOT expand — fail closed, the same discipline as
// authz.Hierarchy.rank's "unknown role ranks 0". Provisioning treats a missing
// entry as a hard error (ErrUnmappedRole), never a silent skip: a new
// tenant-group role added without updating the map then grants nothing and
// says so, rather than something undefined.
type RoleMap map[authz.Role]authz.Role

// translate returns the mapped role and whether a mapping exists.
func (m RoleMap) translate(r authz.Role) (authz.Role, bool) {
	out, ok := m[r]
	return out, ok
}
