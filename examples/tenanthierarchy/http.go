package tenanthierarchy

import (
	"net/http"

	"github.com/suryakencana007/tamper/authz"
	"github.com/suryakencana007/tamper/crypto"
	tamperespresso "github.com/suryakencana007/tamper/espresso"
	"github.com/suryakencana007/tamper/tenant"
)

// OrgParam is the path-parameter name the organization id travels in, for both
// the tenant gate and the decision gate.
const OrgParam = "org_id"

// RouteTenant resolves the ORGANIZATION a route is scoped to, from OrgParam. It
// is the resolver RequireTenantAllowEntered takes: the gate pins what this
// returns, and the DecisionGate reads that pinned value through
// TenantFromRoutedContext. Passing TenantFromRoutedContext to THIS gate would be
// circular — nothing has pinned the tenant when it runs — so every request would
// be a 401.
func RouteTenant(r *http.Request) (tenant.ID, bool) {
	org := tenant.New(r.PathValue(OrgParam))
	return org, org.Valid()
}

// OrgGate is the org-scoped HTTP surface: RequireAuth, then
// RequireTenantAllowEntered(RouteTenant), then a DecisionGate whose scope is the
// organization the gate pinned and which accepts a tenant-group admin entered
// into it. The authorization question is asked in exactly one scope — the
// organization — with no cross-scope OR and no wrapper store.
//
// notVisible writes the 404 for an in-group org the subject cannot see; denied
// writes the 403 for a visible but under-ranked role.
func OrgGate(
	jwt *crypto.JWTService,
	engine authz.Authorizer,
	action, visibility authz.Action,
	notVisible, denied tamperespresso.DenyWriter,
) func(http.Handler) http.Handler {
	gate := tamperespresso.RequireDecision(tamperespresso.DecisionGate{
		Authorizer:       engine,
		Label:            "organization role",
		SubjectType:      "user",
		ResourceType:     ResourceOrganization,
		ResourceIDFrom:   OrgParam,
		Action:           action,
		VisibilityAction: visibility,
		WriteNotVisible:  notVisible,
		WriteDenied:      denied,
		Tenant:           tamperespresso.TenantFromRoutedContext,
		AllowEntered:     true,
	})
	return func(next http.Handler) http.Handler {
		return tamperespresso.RequireAuth(jwt)(
			tamperespresso.RequireTenantAllowEntered(RouteTenant)(
				gate(next)))
	}
}
