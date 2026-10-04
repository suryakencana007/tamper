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
	e := testEventForHash(CanonicalVersion4)
	got, err := ComputeHash(e, prevHash)
	if err != nil {
		t.Fatalf("ComputeHash: %v", err)
	}
	want := hashChainLink(prevHash, canonicalPayloadV4(e, prevHash))
	if !bytes.Equal(got, want) {
		t.Errorf("ComputeHash = %x, want %x (Logger's own internal computation)", got, want)
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

// TestComputeHash_RejectsEveryVersionButV4 locks in the one deliberate
// behavior difference from Logger.Log: no defaulting of a zero version.
func TestComputeHash_RejectsEveryVersionButV4(t *testing.T) {
	prevHash := make([]byte, HashSize)
	for _, version := range []int{0, 1, 2, 3, 99} {
		e := testEventForHash(CanonicalVersion4) // valid Event shape otherwise
		e.CanonicalVersion = version
		if _, err := ComputeHash(e, prevHash); err == nil {
			t.Errorf("ComputeHash with CanonicalVersion=%d succeeded, want an error (ComputeHash does not default a zero version the way Logger.Log does)", version)
		}
	}
}

// TestComputeHash_RejectsWrongLengthPrevHash guards the review finding
// that a nil/short/long prevHash silently hashed to something other
// than what the documented HashSize-zero-byte genesis convention (or
// any real prior Hash) would produce, with no error at all.
func TestComputeHash_RejectsWrongLengthPrevHash(t *testing.T) {
	e := testEventForHash(CanonicalVersion4)
	for name, prevHash := range map[string][]byte{
		"nil":          nil,
		"empty":        {},
		"one short":    bytes.Repeat([]byte{1}, HashSize-1),
		"one long":     bytes.Repeat([]byte{1}, HashSize+1),
		"way too long": bytes.Repeat([]byte{1}, HashSize*2),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ComputeHash(e, prevHash); err == nil {
				t.Errorf("ComputeHash with %d-byte prevHash succeeded, want an error", len(prevHash))
			}
		})
	}
}

// TestComputeHash_RejectsV4EventWithUnpopulatedOrRedactedSalt guards
// the review finding that a CanonicalVersion4 event with a nil,
// wrong-length, or all-zero RowSalt silently hashed successfully —
// indistinguishable, from the outside, from a row whose PII was
// legitimately erased, permanently defeating tamper-evidence on PII
// with no error ever raised.
//
// Commitments is deliberately RE-DERIVED from the same bad salt in
// every case (rather than left at the fixture's valid value), so this
// test isolates the standalone RowSalt shape check from the separate
// Commitments-consistency check: ComputeCommitments happily hashes a
// nil/short/all-zero salt without error, so a caller who consistently
// (mis)uses one of these as RowSalt everywhere would still pass a
// bare equality check — confirmed by first writing this test with
// Commitments left at the fixture's value, which passed even with the
// RowSalt check removed, because the untouched Commitments no longer
// matched ComputeCommitments(badSalt, e) either. Only re-deriving
// Commitments from the SAME bad salt proves the RowSalt check earns
// its keep independently.
func TestComputeHash_RejectsV4EventWithUnpopulatedOrRedactedSalt(t *testing.T) {
	prevHash := make([]byte, HashSize)
	for name, salt := range map[string][]byte{
		"nil":          nil,
		"empty":        {},
		"wrong length": bytes.Repeat([]byte{9}, RowSaltSize-1),
		"all zero":     make([]byte, RowSaltSize), // legitimate shape for an ERASED row, not a new one
	} {
		t.Run(name, func(t *testing.T) {
			e := testEventForHash(CanonicalVersion4)
			e.RowSalt = salt
			e.Commitments = ComputeCommitments(salt, e) // self-consistent with the bad salt
			if _, err := ComputeHash(e, prevHash); err == nil {
				t.Errorf("ComputeHash with %s RowSalt (and self-consistent Commitments) succeeded, want an error", name)
			}
		})
	}
}

// TestComputeHash_RejectsV4EventWithCommitmentsNotDerivedFromItsOwnSalt
// is the highest-severity review finding: ComputeHash must not hash a
// CanonicalVersion4 event whose Commitments don't actually correspond
// to ComputeCommitments(e.RowSalt, e) — otherwise two events differing
// only in PII (e.g. Actor.Email) can hash identically, silently
// committing to no PII at all.
func TestComputeHash_RejectsV4EventWithCommitmentsNotDerivedFromItsOwnSalt(t *testing.T) {
	prevHash := make([]byte, HashSize)

	t.Run("zero-value Commitments", func(t *testing.T) {
		e := testEventForHash(CanonicalVersion4)
		e.Commitments = Commitments{}
		if _, err := ComputeHash(e, prevHash); err == nil {
			t.Error("ComputeHash with zero-value Commitments succeeded, want an error")
		}
	})

	t.Run("Commitments from a different salt", func(t *testing.T) {
		e := testEventForHash(CanonicalVersion4)
		otherSalt := bytes.Repeat([]byte{7}, RowSaltSize)
		e.Commitments = ComputeCommitments(otherSalt, e) // derived from otherSalt, not e.RowSalt
		if _, err := ComputeHash(e, prevHash); err == nil {
			t.Error("ComputeHash with Commitments derived from a different salt succeeded, want an error")
		}
	})

	t.Run("Commitments stale after editing PII", func(t *testing.T) {
		e := testEventForHash(CanonicalVersion4)
		e.Actor.Email = "changed@example.com" // Commitments still reflects the original fixture email
		if _, err := ComputeHash(e, prevHash); err == nil {
			t.Error("ComputeHash with Commitments stale relative to the event's own PII succeeded, want an error")
		}
	})

	t.Run("correctly derived Commitments still succeeds", func(t *testing.T) {
		e := testEventForHash(CanonicalVersion4) // fixture already derives Commitments from e.RowSalt
		if _, err := ComputeHash(e, prevHash); err != nil {
			t.Errorf("ComputeHash with correctly derived Commitments failed: %v", err)
		}
	})
}
