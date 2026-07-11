package scim

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErrCyclicGroup is the sentinel every *NestingError wraps when the
// candidate addition would close a cycle in the group_members graph.
// Callers reach for errors.Is(err, scim.ErrCyclicGroup) and translate
// to the SCIM CIRCULAR_GROUP_REFERENCE response (HTTP 400, scimType=
// invalidValue) so the IdP knows to drop the offending member from
// its push.
//
// v1.13 Sprint 1 task 03 addition. Mirrors the FilterError /
// ErrInvalidFilter shape from filter.go so the two SCIM-side error
// envelopes feel structurally identical to handlers downstream.
var ErrCyclicGroup = errors.New("scim nesting: cyclic group reference")

// NestingError is the envelope handlers convert into the RFC 7644
// CIRCULAR_GROUP_REFERENCE error response. Carries the closure point
// (the parent->candidate edge that closed the cycle) so the audit
// event detail captures which add was rejected.
//
// The error wraps a sentinel (ErrCyclicGroup) so callers reach for
// errors.Is rather than type-asserting at every catch site.
type NestingError struct {
	Message   string
	Parent    string // group that would receive the new member
	Candidate string // would-be Group-typed member
	cause     error
}

// Error implements the error interface.
func (e *NestingError) Error() string {
	if e == nil {
		return ""
	}
	if e.cause != nil {
		return fmt.Sprintf("scim nesting: %s (parent=%q candidate=%q): %v", e.Message, e.Parent, e.Candidate, e.cause)
	}
	return fmt.Sprintf("scim nesting: %s (parent=%q candidate=%q)", e.Message, e.Parent, e.Candidate)
}

// Unwrap returns the wrapped cause so errors.Is can chase the chain.
// When no concrete cause was supplied (the typical case for a
// cycle-detected error), Unwrap returns the ErrCyclicGroup sentinel
// directly.
func (e *NestingError) Unwrap() error {
	if e == nil || e.cause == nil {
		return ErrCyclicGroup
	}
	return e.cause
}

// Is reports whether err is a *NestingError or the sentinel itself.
// Lets callers write errors.Is(err, scim.ErrCyclicGroup) regardless
// of whether they received the typed envelope or the bare sentinel.
func (e *NestingError) Is(target error) bool {
	return target == ErrCyclicGroup
}

// GroupMemberQueries is the minimal store-side surface DetectCycle
// consumes. The sqlite.Queries struct satisfies this interface
// natively; tests can swap a fake without pulling in a SQLite file.
//
// The parameter signature mirrors sqlc's generated shape exactly
// (sql.NullString in, []string out) so callers pass the generated
// function directly without an adapter.
type GroupMemberQueries interface {
	ListParentGroupsOf(ctx context.Context, memberGroupID sql.NullString) ([]string, error)
}

// DetectCycle returns *NestingError (wrapping ErrCyclicGroup) if
// adding (parent, candidate) as a Group-typed group_members row
// would create a cycle.
//
// Graph semantics: edges go parent -> child (parent CONTAINS child
// as a member). Row `(group_id=A, member_group_id=B)` encodes A -> B.
// `ListParentGroupsOf(B)` returns the set {A : A -> B exists}.
//
// Cycle rule: adding `parent -> candidate` closes a cycle iff
// `candidate` is already an ANCESTOR of `parent` in the existing
// graph (i.e., candidate -> ... -> parent exists, so the new edge
// candidate -> ... -> parent -> candidate forms a loop). Equivalently,
// walking UPWARD from `parent` (parents-of-parent, transitively),
// we reach `candidate`.
//
// Walking upward from `parent` (NOT from `candidate`) is the load-
// bearing direction: candidate's downward subtree could be huge
// (many leaves under candidate), but parent's ancestor chain is
// bounded by the depth of the tree. Typical IdP-pushed lattices
// are narrow + deep; upward walk from the small side wins.
//
// The addition itself is NOT persisted by this function -- caller
// decides whether to INSERT after the check passes.
//
// Self-reference (parent == candidate) is the trivial cycle and
// short-circuits without graph traversal.
func DetectCycle(ctx context.Context, q GroupMemberQueries, parent, candidate string) error {
	if q == nil {
		return errors.New("scim nesting: nil GroupMemberQueries")
	}
	if parent == "" || candidate == "" {
		return errors.New("scim nesting: parent and candidate are required")
	}
	if parent == candidate {
		return &NestingError{Message: "self-reference", Parent: parent, Candidate: candidate}
	}

	// BFS upward from `parent`. If we reach `candidate`, candidate
	// is an ancestor of parent and adding parent -> candidate closes
	// the loop. visited prevents revisiting on diamond-shaped graphs
	// (P has two distinct parents both reaching the same grandparent).
	visited := map[string]bool{parent: true}
	queue := []string{parent}
	for len(queue) > 0 {
		next := queue[0]
		queue = queue[1:]
		parents, err := q.ListParentGroupsOf(ctx, sql.NullString{String: next, Valid: true})
		if err != nil {
			return fmt.Errorf("scim nesting: list parents of %q: %w", next, err)
		}
		for _, p := range parents {
			if p == candidate {
				// candidate is an ancestor of parent; adding
				// parent -> candidate closes a cycle
				// candidate -> ... -> parent -> candidate.
				return &NestingError{
					Message:   "adding member would close a cycle",
					Parent:    parent,
					Candidate: candidate,
				}
			}
			if !visited[p] {
				visited[p] = true
				queue = append(queue, p)
			}
		}
	}
	return nil
}
