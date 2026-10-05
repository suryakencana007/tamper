package authz

import (
	"context"

	"github.com/suryakencana007/tamper/tenant"
)

// Binding is one effective role grant: sub holds Role on Resource. A
// Resource with an empty ID is a global (type-level) binding — e.g.
// Barista's users.system_role surfaces as
// {Subject{user,U}, Resource{system,""}, Role("cluster-admin")}.
//
// Tenant is the SCOPE the binding lives in: the tenant whose resource
// it is a grant on. It is not the subject's home tenant, which is
// Subject.Tenant; the two differ for a guest. The RBAC engine drops any
// binding whose Tenant is not the scope it asked about.
type Binding struct {
	Tenant   tenant.ID
	Subject  Subject
	Resource Resource
	Role     Role
}

// BindingStore supplies the RBAC engine with EFFECTIVE role bindings.
//
// Indirection is the store's concern, not the engine's: if the application
// supports group grants (Barista: group_roles + direct group_members rows),
// the store reports them as bindings for the member subject. The engine
// then takes the max rank across everything returned — which reproduces
// Barista's EffectiveRole = max(manual, group-derived) exactly. This
// division is deliberate: Barista's nested groups confer NO effective roles
// today (every effective-role join is scoped member_type='user'), and an
// engine that walked group graphs itself would silently invent inheritance
// the application never had.
//
// Implementations MUST be safe for concurrent use. Queries are read-only;
// how bindings are created/revoked is out of the PDP's scope.
//
// THE ISOLATION CONTRACT. Every method takes tenantID, the scope, and
// returns only bindings that live in it:
//
//   - A binding of another tenant is never returned, whatever the
//     subject or the resource id.
//   - sub is matched whole, home tenant included. A binding granted to
//     {acme, user, u-1} is not returned for {globex, user, u-1}.
//   - A binding returned has Tenant set to tenantID.
//
// authz/tenanttest.RunBindingStoreLeakSuite checks this. Run it against
// your store.
type BindingStore interface {
	// BindingsFor returns every effective binding sub holds on exactly
	// res (same Type AND same ID — an instance binding does not answer a
	// global query, nor the reverse).
	BindingsFor(ctx context.Context, tenantID tenant.ID, sub Subject, res Resource) ([]Binding, error)

	// BindingsForSubject returns every effective binding sub holds on
	// CONCRETE resources (ID != "") of the given type. Fuel for
	// ListResources; global bindings are queried separately via
	// BindingsFor with Resource{Type, ""}.
	BindingsForSubject(ctx context.Context, tenantID tenant.ID, sub Subject, resourceType string) ([]Binding, error)

	// BindingsOnResource returns every subject's effective binding on
	// exactly res. Fuel for ListSubjects; called with Resource{Type, ""}
	// to enumerate global-role holders (the SQL case can enumerate them,
	// which is why the RBAC engine's ListSubjects never reports
	// unbounded).
	BindingsOnResource(ctx context.Context, tenantID tenant.ID, res Resource) ([]Binding, error)
}
