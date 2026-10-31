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

// OrgGateOption configures OrgGate.
type OrgGateOption func(*orgGateConfig)

type orgGateConfig struct{ subjectType string }

// WithOrgSubjectType sets the authz subject type the org gate builds. It must be
// the same type the bindings were granted with, and the same type Membership is
// configured with (WithUserSubjectType) — otherwise the gate asks about
// {user, id} while the store holds a grant for {staff, id}, and the
// exact-subject match in authz.RBAC denies. The default is
// DefaultUserSubjectType.
func WithOrgSubjectType(subjectType string) OrgGateOption {
	return func(c *orgGateConfig) { c.subjectType = subjectType }
}

// OrgGate is the org-scoped HTTP surface: RequireAuth, then
// RequireTenantAllowEntered(RouteTenant), then a DecisionGate whose scope is the
// organization the gate pinned and which accepts a tenant-group admin entered
// into it. The authorization question is asked in exactly one scope — the
// organization — with no cross-scope OR and no wrapper store.
//
// notVisible writes the 404 for an in-group org the subject cannot see; denied
// writes the 403 for a visible but under-ranked role. Panics on an empty subject
// type: a gate that names none would deny every request (standing rule 4).
func OrgGate(
	jwt *crypto.JWTService,
	engine authz.Authorizer,
	action, visibility authz.Action,
	notVisible, denied tamperespresso.DenyWriter,
	opts ...OrgGateOption,
) func(http.Handler) http.Handler {
	cfg := orgGateConfig{subjectType: DefaultUserSubjectType}
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.subjectType == "" {
		panic("tenanthierarchy: OrgGate requires a non-empty subject type")
	}

	gate := tamperespresso.RequireDecision(tamperespresso.DecisionGate{
		Authorizer:       engine,
		Label:            "organization role",
		SubjectType:      cfg.subjectType,
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

// ResourceSystem is the resource type of the platform (system) scope.
const ResourceSystem = "system"

// PlatformGate is the UNTENANTED platform surface: RequireAuth plus a
// system-scope DecisionGate. This is where "grant a tenant-group admin" lives —
// decision 6: only a platform admin may change a group's grant list, because a
// group admin manages org resources, not its own grant list.
//
// There is no RequireTenant: a platform admin's token is for the platform tenant
// and is not a guest anywhere. A tenant token (home or entered) does not fit the
// platform tenant, so it gets the 401 a wrong tenant always gets; a platform
// admin without the system role gets the 403.
func PlatformGate(
	jwt *crypto.JWTService,
	engine authz.Authorizer,
	platform tenant.ID,
	action authz.Action,
	denied tamperespresso.DenyWriter,
	opts ...OrgGateOption,
) func(http.Handler) http.Handler {
	cfg := orgGateConfig{subjectType: DefaultUserSubjectType}
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.subjectType == "" {
		panic("tenanthierarchy: PlatformGate requires a non-empty subject type")
	}
	if !platform.Valid() || platform.IsSingle() {
		panic("tenanthierarchy: PlatformGate requires a real platform tenant — " +
			"a gate fixed to no tenant would refuse every request")
	}

	gate := tamperespresso.RequireDecision(tamperespresso.DecisionGate{
		Authorizer:     engine,
		Label:          "platform role",
		SubjectType:    cfg.subjectType,
		ResourceType:   ResourceSystem,
		ResourceIDFrom: "", // singleton / system scope
		Action:         action,
		WriteDenied:    denied,
		Tenant:         tamperespresso.FixedRequestTenant(platform),
		AllowEntered:   false,
	})
	return func(next http.Handler) http.Handler {
		return tamperespresso.RequireAuth(jwt)(gate(next))
	}
}
