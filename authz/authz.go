// Package authz defines Tamper's Authorizer PDP — the policy decision point
// every Tamper consumer codes against — plus a built-in RBAC engine
// (rbac.go) that evaluates scoped-role bindings supplied by a pluggable
// BindingStore. The interface is the framework's spine: call sites depend on
// it, never on a concrete engine, which is what lets a deployment start on
// SQL-backed RBAC and later swap in Cedar/Casbin (ABAC) or OpenFGA/SpiceDB
// (ReBAC) without touching a single call site.
//
// Phase 1 of the extraction roadmap in ../TAMPER-DESIGN.md. The shapes are
// generalized from Barista's production authz surface (fixed-enum roles at
// four scopes, group→role grants, per-cluster ACLs).
package authz

import (
	"context"
	"errors"
	"fmt"

	"github.com/suryakencana007/tamper/tenant"
)

// ErrTenantRequired — an authorization question was asked without a
// tenant: the scope is the zero tenant.ID, or the subject has no home
// tenant. It is a wiring bug in the caller, said in its own words rather
// than as a quiet deny. Callers treat every error as deny.
//
// A single-tenant deployment passes tenant.Single for both. The zero
// value is not "single tenant"; it is "nobody said".
var ErrTenantRequired = errors.New("authz: tenant is required")

// gate refuses a question that names no scope, and one whose subject
// has no home tenant.
func gate(tenantID tenant.ID, sub Subject) error {
	if !tenantID.Valid() {
		return fmt.Errorf("%w: the scope is unset", ErrTenantRequired)
	}
	if !sub.Tenant.Valid() {
		return fmt.Errorf("%w: subject %s:%s has no home tenant", ErrTenantRequired, sub.Type, sub.ID)
	}
	return nil
}

// Subject identifies WHO is asking. Type and ID are opaque, app-defined
// identifiers — Tamper never hard-codes a principal taxonomy. Barista
// instantiates {"user", <uuid>} and {"service_account", <id>}; groups are
// deliberately NOT subjects here — group indirection is resolved by the
// BindingStore (a group grant surfaces as an effective binding for the
// member), so engines and call sites never walk group graphs themselves.
//
// Small comparable struct rather than a "type:id" string: reverse queries
// return these, and callers need the ID without parsing; comparability
// makes Subjects usable as map keys for bulk dedup.
//
// Tenant is the subject's HOME tenant: the tenant it is stored in. It is
// part of the identity. An id is unique inside one tenant only, so
// {acme, user, u-1} and {globex, user, u-1} are two different subjects,
// and a binding for one is not a binding for the other.
//
// The home tenant is not the scope of a question. A platform admin
// stored in "platform" who has entered "acme" asks with Tenant=platform
// in scope acme, and gets only what was granted to that exact subject
// inside acme. The zero value is refused (ErrTenantRequired);
// single-tenant code sets tenant.Single.
type Subject struct {
	Tenant tenant.ID
	Type   string
	ID     string
}

// Resource identifies WHAT is being acted on. Type is the app-defined
// resource class ("cluster", "project", …); ID is the instance. An empty ID
// means the check is type-level ("may the subject create clusters at all?")
// — bindings scoped to a concrete instance do not satisfy a type-level
// check unless the store reports them as such (e.g. a system-wide role).
//
// A Resource carries no tenant. Whose it is is the scope of the
// question — the tenantID every Authorizer method takes.
type Resource struct {
	Type string
	ID   string
}

// Action is the app-defined verb being attempted. Dotted
// "<resource>.<verb>" convention by Barista precedent ("cluster.deploy",
// "identity_provider.delete"), but the engine treats it as opaque.
type Action string

// Decision is the PDP verdict. Reason is for audit trails and debugging —
// engines fill it on BOTH allow and deny so an audit row can record why —
// and it MUST NOT be used for control flow.
type Decision struct {
	Allowed bool
	Reason  string
}

// CheckRequest is one (subject, action, resource) authorization question.
// A struct rather than positional args so future evolution (e.g. an
// attribute bag for ABAC engines) is an additive, non-breaking field.
type CheckRequest struct {
	Subject  Subject
	Action   Action
	Resource Resource
}

// Authorizer is the policy decision point. Implementations MUST be safe for
// concurrent use.
//
// Deny-by-default is a hard contract: unknown actions, unknown resource
// types, and store errors all resolve to a deny (with error where the
// question could not be evaluated at all). An error return means "could not
// decide" — callers must treat it as deny, never as allow.
//
// Every method takes tenantID, the SCOPE of the question: the tenant
// whose resources are being acted on. Bindings live in a scope and never
// answer a question in another one; there is no binding that spans
// tenants. An unset scope is ErrTenantRequired. A single-tenant
// deployment passes tenant.Single.
type Authorizer interface {
	// Check answers one authorization question.
	Check(ctx context.Context, tenantID tenant.ID, sub Subject, act Action, res Resource) (Decision, error)

	// CheckBulk answers many questions in one round trip. The result slice
	// is index-aligned with reqs. Implementations should batch store access
	// where possible; a failed evaluation fails the whole call (callers
	// deny everything on error).
	//
	// All of reqs are asked in the one scope tenantID.
	CheckBulk(ctx context.Context, tenantID tenant.ID, reqs []CheckRequest) ([]Decision, error)

	// ListResources answers the reverse query "which resources of this
	// type may the subject perform act on?" — the shape UI listings and
	// audit scoping need. It returns the enumerable set of concrete
	// resources. unbounded=true means the subject's access is NOT limited
	// to an enumerable set (e.g. a system-wide role grants the action on
	// every resource of the type); the caller — who owns the resource
	// catalog — must treat that as "all" and skip per-resource filtering.
	// resources may be non-empty alongside unbounded=true; callers should
	// check unbounded first.
	ListResources(ctx context.Context, tenantID tenant.ID, sub Subject, act Action, resourceType string) (resources []Resource, unbounded bool, err error)

	// ListSubjects answers "which subjects may perform act on res?" —
	// access-review and admin-UI surfaces. unbounded=true means subjects
	// beyond the returned set may also have access via grants the store
	// cannot enumerate; stores that can enumerate global-role holders
	// (the common SQL case) return them concretely with unbounded=false.
	//
	// The subjects come back with their home tenant, so a guest from
	// another tenant is visible as one.
	ListSubjects(ctx context.Context, tenantID tenant.ID, act Action, res Resource) (subjects []Subject, unbounded bool, err error)
}
