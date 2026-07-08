package authz

import (
	"context"
	"fmt"
	"sort"
)

// RBAC is the built-in Authorizer: scoped-role RBAC over a pluggable
// BindingStore. It generalizes Barista's production model — independent
// linear role ladders per resource type, effective role = max rank across
// direct and store-resolved indirect bindings, and global-role bypass
// expressed as OR-requirements — without hard-coding any of Barista's
// taxonomy.
//
// Engines are stateless beyond their configuration; all methods are safe
// for concurrent use as long as the BindingStore is.
type RBAC struct {
	store BindingStore
	h     Hierarchy
	p     Policy
}

var _ Authorizer = (*RBAC)(nil)

// NewRBAC validates the hierarchy + policy and returns the engine.
// Validation failures are construction errors by design: a misconfigured
// policy should fail the host application's boot, not surface as silent
// per-request denies.
func NewRBAC(store BindingStore, h Hierarchy, p Policy) (*RBAC, error) {
	if store == nil {
		return nil, fmt.Errorf("authz: NewRBAC requires a BindingStore")
	}
	if err := validate(h, p); err != nil {
		return nil, err
	}
	return &RBAC{store: store, h: h, p: p}, nil
}

// Check implements Authorizer. Unknown actions deny with a nil error (the
// deny-by-default contract); store failures return an error, which callers
// must also treat as deny.
func (e *RBAC) Check(ctx context.Context, sub Subject, act Action, res Resource) (Decision, error) {
	reqs, ok := e.p[act]
	if !ok {
		return Decision{Allowed: false, Reason: fmt.Sprintf("unknown action %q", act)}, nil
	}
	for _, req := range reqs {
		target := res
		if req.Type != res.Type {
			// Global alternative: consult the singleton resource of the
			// requirement's type (see Requirement docs).
			target = Resource{Type: req.Type}
		}
		role, rank, err := e.effective(ctx, sub, target)
		if err != nil {
			return Decision{}, fmt.Errorf("authz: check %q on %s: %w", act, label(res), err)
		}
		if rank >= e.h.rank(req.Type, req.Min) {
			return Decision{
				Allowed: true,
				Reason:  fmt.Sprintf("role %q on %s satisfies %q (needs >= %q)", role, label(target), act, req.Min),
			}, nil
		}
	}
	return Decision{Allowed: false, Reason: fmt.Sprintf("no requirement of %q satisfied for %s", act, label(res))}, nil
}

// CheckBulk implements Authorizer. Results are index-aligned with reqs; the
// first evaluation error fails the whole call.
func (e *RBAC) CheckBulk(ctx context.Context, reqs []CheckRequest) ([]Decision, error) {
	out := make([]Decision, len(reqs))
	for i, r := range reqs {
		d, err := e.Check(ctx, r.Subject, r.Action, r.Resource)
		if err != nil {
			return nil, err
		}
		out[i] = d
	}
	return out, nil
}

// ListResources implements Authorizer. Unlike Check, an unknown action is
// an error here rather than an empty result: list callers are UI/audit
// surfaces wiring actions statically, and a typo silently rendering an
// empty listing is a worse failure mode than a loud one.
func (e *RBAC) ListResources(ctx context.Context, sub Subject, act Action, resourceType string) ([]Resource, bool, error) {
	reqs, ok := e.p[act]
	if !ok {
		return nil, false, fmt.Errorf("authz: unknown action %q", act)
	}

	// Global alternatives first: a satisfied different-type requirement
	// grants the action on EVERY resource of the asked type — the caller
	// owns the catalog, so report unbounded rather than pretending to
	// enumerate it.
	unbounded := false
	lowest := 0 // lowest satisfying same-type rank (0 = no same-type requirement)
	for _, req := range reqs {
		if req.Type == resourceType {
			if r := e.h.rank(resourceType, req.Min); lowest == 0 || r < lowest {
				lowest = r
			}
			continue
		}
		if unbounded {
			continue
		}
		_, rank, err := e.effective(ctx, sub, Resource{Type: req.Type})
		if err != nil {
			return nil, false, fmt.Errorf("authz: list resources for %q: %w", act, err)
		}
		if rank >= e.h.rank(req.Type, req.Min) {
			unbounded = true
		}
	}
	if lowest == 0 {
		return nil, unbounded, nil
	}

	bs, err := e.store.BindingsForSubject(ctx, sub, resourceType)
	if err != nil {
		return nil, false, fmt.Errorf("authz: list resources for %q: %w", act, err)
	}
	seen := make(map[Resource]bool)
	var out []Resource
	for _, b := range bs {
		if b.Subject != sub || b.Resource.Type != resourceType || b.Resource.ID == "" {
			continue // defensive: hold the store to its contract
		}
		if e.h.rank(resourceType, b.Role) >= lowest && !seen[b.Resource] {
			seen[b.Resource] = true
			out = append(out, b.Resource)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, unbounded, nil
}

// ListSubjects implements Authorizer. Global-role holders are enumerated
// concretely via the store (SQL can list them), so the RBAC engine never
// reports unbounded — the parameter exists for engines that cannot
// enumerate (see the interface docs).
func (e *RBAC) ListSubjects(ctx context.Context, act Action, res Resource) ([]Subject, bool, error) {
	reqs, ok := e.p[act]
	if !ok {
		return nil, false, fmt.Errorf("authz: unknown action %q", act)
	}
	seen := make(map[Subject]bool)
	var out []Subject
	for _, req := range reqs {
		target := res
		if req.Type != res.Type {
			target = Resource{Type: req.Type}
		}
		minRank := e.h.rank(req.Type, req.Min)
		bs, err := e.store.BindingsOnResource(ctx, target)
		if err != nil {
			return nil, false, fmt.Errorf("authz: list subjects for %q: %w", act, err)
		}
		for _, b := range bs {
			if b.Resource != target {
				continue
			}
			if e.h.rank(target.Type, b.Role) >= minRank && !seen[b.Subject] {
				seen[b.Subject] = true
				out = append(out, b.Subject)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].ID < out[j].ID
	})
	return out, false, nil
}

// effective returns the highest-ranked role sub holds on exactly res,
// mirroring Barista's EffectiveRole = max(direct, group-derived) once the
// store has resolved indirection into bindings. Bindings whose role is not
// in res.Type's ladder rank 0 and are ignored (fail closed).
func (e *RBAC) effective(ctx context.Context, sub Subject, res Resource) (Role, int, error) {
	bs, err := e.store.BindingsFor(ctx, sub, res)
	if err != nil {
		return "", 0, err
	}
	best := 0
	var bestRole Role
	for _, b := range bs {
		if b.Subject != sub || b.Resource != res {
			continue // defensive: exact-match contract
		}
		if r := e.h.rank(res.Type, b.Role); r > best {
			best, bestRole = r, b.Role
		}
	}
	return bestRole, best, nil
}

func label(r Resource) string {
	if r.ID == "" {
		return r.Type + " (global)"
	}
	return r.Type + ":" + r.ID
}
