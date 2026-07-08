package authz

import "context"

// Binding is one effective role grant: sub holds Role on Resource. A
// Resource with an empty ID is a global (type-level) binding — e.g.
// Barista's users.system_role surfaces as
// {Subject{user,U}, Resource{system,""}, Role("cluster-admin")}.
type Binding struct {
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
type BindingStore interface {
	// BindingsFor returns every effective binding sub holds on exactly
	// res (same Type AND same ID — an instance binding does not answer a
	// global query, nor the reverse).
	BindingsFor(ctx context.Context, sub Subject, res Resource) ([]Binding, error)

	// BindingsForSubject returns every effective binding sub holds on
	// CONCRETE resources (ID != "") of the given type. Fuel for
	// ListResources; global bindings are queried separately via
	// BindingsFor with Resource{Type, ""}.
	BindingsForSubject(ctx context.Context, sub Subject, resourceType string) ([]Binding, error)

	// BindingsOnResource returns every subject's effective binding on
	// exactly res. Fuel for ListSubjects; called with Resource{Type, ""}
	// to enumerate global-role holders (the SQL case can enumerate them,
	// which is why the RBAC engine's ListSubjects never reports
	// unbounded).
	BindingsOnResource(ctx context.Context, res Resource) ([]Binding, error)
}
