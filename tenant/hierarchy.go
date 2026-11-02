package tenant

import (
	"context"
	"errors"
	"fmt"
)

// Parentage, resolved — the one place in tamper that reads Descriptor.ParentID.
//
// This amends the Phase 7 invariant that said nothing in tamper resolves it
// ("RESERVED. Nothing in tamper resolves it, inherits through it, or branches
// on it"). ADR-0001 §5.A rejected resolving it in core and named its own
// precondition — a Phase 7 sketch amendment — which
// PHASE12-TENANT-INHERITANCE-SKETCH.md §3.1 is. The rejection is narrowed, not
// overturned: §5.A still stands for AUTHORIZATION, where a runtime walk cannot
// substitute for the per-scope bindings the RBAC engine requires. Nothing here
// builds an authorization scope, and nothing here grants a permission.

var (
	// ErrHierarchyCycle — the parentage graph loops back on itself. A tenant
	// that is, directly or transitively, its own ancestor.
	//
	// An error rather than a truncated chain: a cycle means the parentage data
	// is corrupt, and the two silent readings of it — "stop here" and "keep
	// going" — differ in who inherits what. Deny.
	ErrHierarchyCycle = errors.New("tenant: hierarchy cycle")

	// ErrHierarchyDepth — the chain is longer than maxHierarchyDepth.
	//
	// The bound is against corrupt or adversarial data, not a product limit.
	// Real hierarchies are three deep; a deployment that needs more than
	// maxHierarchyDepth has a data-modelling problem whose symptom should be
	// this error rather than a request that reads the store without end.
	ErrHierarchyDepth = errors.New("tenant: hierarchy deeper than the limit")
)

// maxHierarchyDepth is the largest chain Ancestors will walk. See
// ErrHierarchyDepth for why it is a bound rather than a policy.
const maxHierarchyDepth = 32

// Inheritance answers, per tenant and per axis, whether that tenant may inherit
// from its ancestors. It is the application's setting; tamper owns no table for
// it.
//
// Absent policy is deny: a caller that wires no Inheritance gets today's
// behaviour, because nothing asks the question. When one IS wired, three rules
// apply and each is a test:
//
//   - An unset ID denies. Ancestors never yields one, so this is defence in
//     depth — but a bool return is as capable of failing open as an error one.
//   - A false, nil answer refuses THIS ancestor and stops the walk. It is not a
//     "keep looking higher" signal; see the IdP walk in particular.
//   - An error aborts the walk and the bool is ignored, BOTH ways round. A
//     policy backed by a settings table will fail the day that table is
//     unreachable, and reading (false, err) as "refused" would turn that outage
//     into a silent deny indistinguishable from a group that switched the
//     feature off — while reading (true, err) as permission is the obvious bug.
type Inheritance func(ctx context.Context, id ID) (bool, error)

// Ancestors returns the chain of parents above id, nearest first, excluding id
// itself.
//
// Four readings of "no ancestors", and they are deliberately distinct:
//
//	unset ID        nothing, no store call
//	tenant.Single   nothing, no store call
//	root            nothing, after reading the row
//	unknown id      ErrNotFound
//
// The first two are the trap Phase 9 hit. An unset ID means a caller never
// threaded a tenant through, and Single is the explicit single-tenant
// deployment — which has no tenant rows at all (Store's doc), so reading the
// store for it would return ErrNotFound and turn every such call into an error.
// Both deny, for different reasons, and neither is "root".
//
// An unknown id is an error rather than an empty chain: "this tenant does not
// exist" and "this tenant exists with no parent" are different facts, and only
// one of them is worth an operator's attention.
//
// The other failures fail closed too. A parent id that does not resolve is an
// error (matching ErrNotFound, wrapped) rather than a silent root, because a
// dangling pointer is corrupt data and treating it as a root would quietly
// change who inherits what. A cycle is ErrHierarchyCycle and an over-long chain
// is ErrHierarchyDepth. Those sentinels are the operational face of this rule:
// fail-closed means a tenant with corrupt parentage has its gated requests
// denied, which looks like an outage rather than a data fault, so callers must
// not discard the error when they deny.
//
// Every returned id has passed through FromStored, because parentage comes out
// of storage — that is the conversion named for that case. Its "" branch
// returns Single, and that branch is unreachable from here: an empty ParentID
// ends the walk before any conversion, which a test pins.
func Ancestors(ctx context.Context, s Store, id ID) ([]ID, error) {
	if s == nil {
		panic("tenant: Ancestors requires a Store — a nil one would resolve nothing " +
			"and read as \"no ancestors\", which is a hierarchy that silently never inherits")
	}
	if !id.Valid() || id.IsSingle() {
		return []ID{}, nil
	}
	desc, err := s.ByID(ctx, id.String())
	if err != nil {
		return nil, fmt.Errorf("tenant: ancestors of %q: %w", id.String(), err)
	}

	seen := map[ID]struct{}{id: {}}
	chain := []ID{}
	for {
		parent := desc.ParentID
		if parent == "" {
			return chain, nil
		}
		pid := FromStored(parent)
		if _, dup := seen[pid]; dup {
			return nil, fmt.Errorf("%w: %q is its own ancestor", ErrHierarchyCycle, pid.String())
		}
		if len(chain) >= maxHierarchyDepth {
			return nil, fmt.Errorf("%w: %q is more than %d levels below a root",
				ErrHierarchyDepth, id.String(), maxHierarchyDepth)
		}
		seen[pid] = struct{}{}
		chain = append(chain, pid)

		desc, err = s.ByID(ctx, pid.String())
		if err != nil {
			return nil, fmt.Errorf("tenant: ancestors of %q: %w", id.String(), err)
		}
	}
}
