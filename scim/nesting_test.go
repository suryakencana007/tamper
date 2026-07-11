package scim

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

// fakeQ is a tiny GroupMemberQueries stub. parentsOf maps a member
// to its direct parents in the synthetic graph.
type fakeQ struct {
	parentsOf map[string][]string
	calls     int
}

func (f *fakeQ) ListParentGroupsOf(_ context.Context, m sql.NullString) ([]string, error) {
	f.calls++
	if !m.Valid {
		return nil, nil
	}
	return f.parentsOf[m.String], nil
}

func TestDetectCycle_NoCycle_Linear(t *testing.T) {
	// Graph: A -> B -> C. ListParentGroupsOf(C) = [B];
	// ListParentGroupsOf(B) = [A]; ListParentGroupsOf(A) = nil.
	q := &fakeQ{parentsOf: map[string][]string{
		"C": {"B"},
		"B": {"A"},
	}}
	// Adding A -> D where D has no parents: no cycle.
	if err := DetectCycle(context.Background(), q, "A", "D"); err != nil {
		t.Errorf("DetectCycle(A, D) = %v, want nil", err)
	}
}

func TestDetectCycle_DirectCycle(t *testing.T) {
	// Graph: A -> B (so B has parent A).
	q := &fakeQ{parentsOf: map[string][]string{
		"B": {"A"},
	}}
	// Adding B -> A would close A->B->A.
	err := DetectCycle(context.Background(), q, "B", "A")
	if err == nil {
		t.Fatalf("DetectCycle = nil, want cycle error")
	}
	if !errors.Is(err, ErrCyclicGroup) {
		t.Errorf("err = %v, want errors.Is ErrCyclicGroup", err)
	}
}

func TestDetectCycle_TransitiveCycle(t *testing.T) {
	// Graph: A -> B -> C. Adding C -> A closes A->B->C->A.
	q := &fakeQ{parentsOf: map[string][]string{
		"C": {"B"},
		"B": {"A"},
	}}
	err := DetectCycle(context.Background(), q, "C", "A")
	if err == nil {
		t.Fatalf("DetectCycle = nil, want cycle error")
	}
	if !errors.Is(err, ErrCyclicGroup) {
		t.Errorf("err = %v, want ErrCyclicGroup", err)
	}
}

func TestDetectCycle_SelfReference(t *testing.T) {
	q := &fakeQ{parentsOf: map[string][]string{}}
	err := DetectCycle(context.Background(), q, "A", "A")
	if !errors.Is(err, ErrCyclicGroup) {
		t.Errorf("self-reference err = %v, want ErrCyclicGroup", err)
	}
}

func TestDetectCycle_DiamondNoCycle(t *testing.T) {
	// Graph: X -> A, X -> B, A -> C, B -> C. (X transitively reaches
	// C via two paths; the existing structure is a DAG, not a tree.)
	// Adding X -> C is a redundant edge but not a cycle -- X is
	// already an ancestor of C in the existing graph.
	q := &fakeQ{parentsOf: map[string][]string{
		"C": {"A", "B"},
		"A": {"X"},
		"B": {"X"},
	}}
	if err := DetectCycle(context.Background(), q, "X", "C"); err != nil {
		t.Errorf("diamond DAG add err = %v, want nil", err)
	}
	// But adding C -> X DOES cycle (C is descendant of X; new edge
	// C -> X closes X -> A -> C -> X).
	err := DetectCycle(context.Background(), q, "C", "X")
	if !errors.Is(err, ErrCyclicGroup) {
		t.Errorf("C -> X err = %v, want ErrCyclicGroup", err)
	}
}

func TestDetectCycle_VisitedSetBounded(t *testing.T) {
	// Same diamond shape; assert visited de-duplicates X across the
	// A + B branches (BFS up from C). C's parents=[A,B]; A's parents
	// =[X]; B's parents=[X]; X enqueued once via A, not again via B.
	q := &fakeQ{parentsOf: map[string][]string{
		"C": {"A", "B"},
		"A": {"X"},
		"B": {"X"},
	}}
	_ = DetectCycle(context.Background(), q, "C", "Z")
	// 4 expected ListParentGroupsOf calls: C, A, B, X. X is enqueued
	// once. Without visited it would be 5+ (X via A and X via B).
	if q.calls > 4 {
		t.Errorf("BFS visited %d nodes; want at most 4 (visited-set should de-dupe)", q.calls)
	}
}

func TestDetectCycle_NilQueries(t *testing.T) {
	err := DetectCycle(context.Background(), nil, "A", "B")
	if err == nil {
		t.Errorf("DetectCycle(nil queries) = nil, want error")
	}
}
