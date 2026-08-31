package audit

import (
	"bytes"
	"testing"
	"time"
)

func testEventForHash(version int) Event {
	e := Event{
		ID:               "evt-1",
		At:               time.Unix(1700000000, 0).UTC(),
		Actor:            Actor{Type: ActorTypeUser, UserID: "u-1"},
		Action:           Action("project.create"),
		ResourceType:     ResourceType("project"),
		ResourceID:       "p-1",
		CanonicalVersion: version,
	}
	if version == CanonicalVersion4 {
		e.TenantID = "acme"
		e.RowSalt = bytes.Repeat([]byte{9}, RowSaltSize)
		e.Commitments = ComputeCommitments(e.RowSalt, e)
	}
	return e
}

// TestComputeHash_MatchesLoggersOwnComputation is the property that
// actually matters for a bring-your-own-store Logger: whatever
// ComputeHash returns must be byte-for-byte what SQLiteLogger.Log would
// have stored for the same event, or two Loggers backed by different
// stores would fork the chain the moment either one's rows were
// compared or migrated onto the other's storage.
func TestComputeHash_MatchesLoggersOwnComputation(t *testing.T) {
	prevHash := bytes.Repeat([]byte{1}, HashSize)
	for _, version := range []int{CanonicalVersion3, CanonicalVersion4} {
		e := testEventForHash(version)
		got, err := ComputeHash(e, prevHash)
		if err != nil {
			t.Fatalf("version %d: ComputeHash: %v", version, err)
		}
		want := computeHash(prevHash, e, version)
		if !bytes.Equal(got, want) {
			t.Errorf("version %d: ComputeHash = %x, want %x (Logger's own internal computation)", version, got, want)
		}
	}
}

// TestComputeHash_DifferentEventsHashDifferently is a basic sanity
// check that this isn't a constant-output stub — changing the event
// must change the hash.
func TestComputeHash_DifferentEventsHashDifferently(t *testing.T) {
	prevHash := make([]byte, HashSize)
	e1 := testEventForHash(CanonicalVersion4)
	e2 := testEventForHash(CanonicalVersion4)
	e2.ResourceID = "p-2"

	h1, err := ComputeHash(e1, prevHash)
	if err != nil {
		t.Fatalf("ComputeHash(e1): %v", err)
	}
	h2, err := ComputeHash(e2, prevHash)
	if err != nil {
		t.Fatalf("ComputeHash(e2): %v", err)
	}
	if bytes.Equal(h1, h2) {
		t.Error("two events differing only in ResourceID hashed identically")
	}
}

func TestComputeHash_RequiresIDAtAction(t *testing.T) {
	base := testEventForHash(CanonicalVersion4)
	prevHash := make([]byte, HashSize)

	cases := []struct {
		name    string
		mutate  func(*Event)
		wantErr bool
	}{
		{"missing id", func(e *Event) { e.ID = "" }, true},
		{"missing at", func(e *Event) { e.At = time.Time{} }, true},
		{"missing action", func(e *Event) { e.Action = "" }, true},
		{"all present", func(*Event) {}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := base
			tc.mutate(&e)
			_, err := ComputeHash(e, prevHash)
			if (err != nil) != tc.wantErr {
				t.Errorf("ComputeHash err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

// TestComputeHash_RejectsUnsetOrLegacyCanonicalVersion locks in the one
// deliberate behavior difference from Logger.Log: no defaulting.
func TestComputeHash_RejectsUnsetOrLegacyCanonicalVersion(t *testing.T) {
	prevHash := make([]byte, HashSize)
	for _, version := range []int{0, CanonicalVersion1, CanonicalVersion2, 99} {
		e := testEventForHash(CanonicalVersion4) // valid Event shape otherwise
		e.CanonicalVersion = version
		if _, err := ComputeHash(e, prevHash); err == nil {
			t.Errorf("ComputeHash with CanonicalVersion=%d succeeded, want an error (ComputeHash does not default a zero/legacy version the way Logger.Log does)", version)
		}
	}
}
