package authz

import "fmt"

// Role is a named rank within one resource type's ladder. Roles are only
// meaningful relative to a Hierarchy — "admin" on clusters and "admin" on
// orgs are unrelated ranks (Barista precedent: four independent enums that
// never compose).
type Role string

// Hierarchy defines, per resource type, the ordered role ladder from lowest
// to highest rank. Rank comparisons are strictly within one ladder; a role
// absent from its ladder has rank 0 and satisfies nothing (fail-closed,
// mirroring Barista's HasAtLeast semantics for unknown enum values).
type Hierarchy map[string][]Role

// rank returns the 1-based rank of r within resourceType's ladder, or 0
// when the type or role is unknown.
func (h Hierarchy) rank(resourceType string, r Role) int {
	for i, candidate := range h[resourceType] {
		if candidate == r {
			return i + 1
		}
	}
	return 0
}

// Requirement is one way to satisfy an action: holding at least Min on the
// requirement's resource type.
//
// When Type equals the checked resource's type, the subject's bindings on
// that concrete resource instance are consulted. When Type differs, the
// requirement is a GLOBAL alternative: the subject's bindings on the
// singleton Resource{Type: Type, ID: ""} are consulted instead. That is
// exactly how Barista's system-role bypass composes — "cluster.acl.grant"
// is satisfied by cluster-admin ON the cluster, OR by the system-scope
// cluster-admin role held globally — without the engine hard-coding any
// scope-containment graph.
type Requirement struct {
	Type string
	Min  Role
}

// Policy maps each action to the requirements that can satisfy it.
// Requirements compose with OR semantics: any single satisfied requirement
// allows the action. Actions absent from the policy are denied
// (deny-by-default).
//
// Conjunctive gates (Barista's "org membership is a precondition for
// project visibility") are deliberately NOT expressible here — they remain
// the application's composition of two checks. Keeping the policy language
// to OR-of-scoped-minimums is what keeps every rule auditable at a glance.
type Policy map[Action][]Requirement

// validate checks policy/hierarchy consistency so misconfigurations fail at
// construction (boot) rather than as silent per-request denies.
func validate(h Hierarchy, p Policy) error {
	for resourceType, ladder := range h {
		if resourceType == "" {
			return fmt.Errorf("authz: hierarchy has an empty resource type")
		}
		if len(ladder) == 0 {
			return fmt.Errorf("authz: hierarchy for %q has no roles", resourceType)
		}
		seen := make(map[Role]bool, len(ladder))
		for _, r := range ladder {
			if r == "" {
				return fmt.Errorf("authz: hierarchy for %q contains an empty role", resourceType)
			}
			if seen[r] {
				return fmt.Errorf("authz: hierarchy for %q lists role %q twice", resourceType, r)
			}
			seen[r] = true
		}
	}
	for action, reqs := range p {
		if action == "" {
			return fmt.Errorf("authz: policy has an empty action")
		}
		if len(reqs) == 0 {
			return fmt.Errorf("authz: action %q has no requirements (unsatisfiable; remove it instead)", action)
		}
		for _, req := range reqs {
			if _, ok := h[req.Type]; !ok {
				return fmt.Errorf("authz: action %q requires unknown resource type %q", action, req.Type)
			}
			if h.rank(req.Type, req.Min) == 0 {
				return fmt.Errorf("authz: action %q requires role %q not in the %q ladder", action, req.Min, req.Type)
			}
		}
	}
	return nil
}
