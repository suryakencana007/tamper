package tenanthierarchy

import (
	"net/http"
)

// resolveErrorSentinel is what TenantGroupResolve returns when the
// hierarchy store cannot answer. It can never equal a minted tenant id:
// tokens carry either Single ("") or an application-chosen id, and a
// leading NUL byte is never one. RequireTenant's single equality then
// collapses the request onto its ordinary 401 — fail closed, with no new
// error surface and no distinguishable response.
const resolveErrorSentinel = "\x00tenanthierarchy:resolve-error"

// TenantGroupResolve returns an espresso RequireTenant resolver
// (func(*http.Request) string) that pins a request to the TENANT-GROUP
// owning the organization named by the org path parameter.
//
// This is the app-level bridge ADR-0001 §2 leaves out. RequireTenant
// cross-checks the token's `tid` against the value this function returns
// (espresso/tenantgate.go), so the pin level determines who can reach
// which route:
//
//   - Pin the ORGANIZATION and a tenant-group admin's single `tid` can
//     only ever match one child org — every sibling is a 401 before authz
//     runs, and the ADR's "one group, many orgs" premise is unachievable.
//   - Pin the TENANT-GROUP (this function) and one token reaches every
//     child org; within-org authorization is still decided per-org by the
//     DecisionGate, exactly as ADR-0001 §4a describes.
//
// The hierarchy read is the same app-owned OrgHierarchy port the Store
// expands against — tamper's tenant.Store never walks ParentID. An org
// with no parent (a root org / single-tenant deployment) pins to itself,
// which keeps that case byte-identical to the flat model. An unknown org
// also has no parent and therefore pins to its own id, which no real
// group token matches: the request is rejected at the tenant gate before
// any existence signal, so a miss and a cross-group deny are the same 401.
//
// Callers wire it as:
//
//	RequireTenant(tenanthierarchy.TenantGroupResolve(hier, "org_id"))
//
// NOTE the consequence for audit: RequireTenant stashes this value as the
// request tenant, so an org-scoped mutation audits with tenant_id equal to
// the owning group and the organization in resource_id. That is the
// isolation boundary ADR-0001 §7 assumes, stated here so it is not a
// surprise.
func TenantGroupResolve(hier OrgHierarchy, orgParam string) func(*http.Request) string {
	if hier == nil || orgParam == "" {
		panic("tenanthierarchy: TenantGroupResolve requires a non-nil OrgHierarchy and a non-empty path param — " +
			"a resolver that cannot resolve would be a tenant gate that pins nothing")
	}
	return func(r *http.Request) string {
		orgID := r.PathValue(orgParam)
		if orgID == "" {
			// No org in the route (untenanted / single-tenant surface):
			// return "" so a Single token still matches, byte-identical
			// to the pre-hierarchy behaviour.
			return ""
		}
		groupID, ok, err := hier.ParentOf(r.Context(), orgID)
		if err != nil {
			return resolveErrorSentinel
		}
		if !ok {
			// Root org: pin to itself. Unknown org: also lands here, and
			// no group token will match it.
			return orgID
		}
		return groupID
	}
}
