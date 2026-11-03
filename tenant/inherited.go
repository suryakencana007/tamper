package tenant

import (
	"context"
	"errors"
)

// One home for the inheritance policy rules.
//
// The OIDC and SAML provider managers both need "this tenant's own items, or the
// nearest ancestor's that has some, if that ancestor allows it" — and the rules in
// that sentence are security rules, not plumbing: which ancestor's switch is asked,
// where the walk stops, and which errors propagate rather than reading as "nothing".
// Two copies of them is two places to fix, and the divergence would be silent. So
// the rules live here, over a type parameter, and each manager supplies only its own
// lookup and its own record type.

// InheritFunc returns what one tenant has of its own for a single inheritance axis.
// An empty (non-nil) slice means "nothing", which is what invites the walk.
type InheritFunc[T any] func(ctx context.Context, id ID) ([]T, error)

// Inherited resolves one axis for id: its own items, or the nearest ancestor's.
//
// The rules, each of which has a test:
//
//   - Own items win ENTIRELY. Nothing is merged: two records sharing an id would
//     make a later lookup ambiguous, and the tenant that configured its own is
//     saying it does not want the ancestor's.
//   - An ancestor with nothing to lend is passed over WITHOUT asking its switch.
//     A silent middle layer — one that has configured nothing either way — must not
//     block a decision made further up.
//   - The first ancestor WITH items decides, by its switch, and the walk STOPS
//     there. A false answer is not "keep looking higher": a group that keeps its own
//     configuration and has not opted in is saying its children configure their own,
//     and substituting a grandparent's answer would overrule a decision it made.
//   - A policy error ABORTS the walk with the bool ignored both ways round. A
//     settings-table-backed policy fails the day that table is unreachable, and
//     reading (false, err) as a refusal would turn that outage into a silent deny,
//     indistinguishable from a group that switched the feature off.
//   - A nil store or a nil policy means the feature is unwired: id keeps its own
//     answer, and nothing walks.
//   - An unknown id returns nothing, NOT an error — the caller's own contract for
//     "this tenant has nothing" is what an unknown tenant looks like too. Corrupt
//     parentage is the opposite: it propagates, because swallowing it would hide a
//     data fault behind an empty answer.
//
// s and allow may both be nil; own may not, and a nil own panics rather than
// resolving every tenant to nothing.
func Inherited[T any](ctx context.Context, s Store, allow Inheritance, id ID, own InheritFunc[T]) ([]T, error) {
	if own == nil {
		panic("tenant: Inherited requires a lookup — a nil one would resolve every tenant to nothing")
	}
	items, err := own(ctx, id)
	if err != nil {
		return nil, err
	}
	if len(items) > 0 || s == nil || allow == nil {
		return items, nil
	}

	chain, err := Ancestors(ctx, s, id)
	if err != nil {
		if errors.Is(err, ErrHierarchyDangling) {
			return nil, err
		}
		if errors.Is(err, ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}

	for _, ancestor := range chain {
		lent, err := own(ctx, ancestor)
		if err != nil {
			return nil, err
		}
		if len(lent) == 0 {
			continue
		}
		allowed, err := allow(ctx, ancestor)
		if err != nil {
			return nil, err
		}
		if !allowed {
			return nil, nil
		}
		return lent, nil
	}
	return nil, nil
}
