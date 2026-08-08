package audit

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

// Commitment-based redaction — how a v4 row survives an erasure request
// without breaking the chain.
//
// THE PROBLEM. A hash chain and a right-to-erasure are natural enemies:
// the chain's whole value is that nothing in it can change, and erasure
// demands that something in it change. Deleting the row breaks the
// chain. Rewriting the row breaks the chain. Keeping the row denies the
// request.
//
// THE SHAPE OF THE ANSWER. Hash the PII once, at write time, into a
// salted commitment; put the COMMITMENT in the canonical payload and
// keep the plaintext in an ordinary column beside it. Erasure then
// means: null the plaintext, zero the salt, keep the 32 bytes. The
// canonical payload is unchanged because it never contained the
// plaintext, so the chain verifies straight through a redacted row and
// the value is gone.
//
// WHY THE SALT. Without one, H("alice@example.com") is a rainbow-table
// lookup and the "redacted" row still identifies its subject. The salt
// is per row, so two rows about the same person do not even correlate.
// Zeroing it on redaction is what makes the erasure irreversible rather
// than merely inconvenient: with the salt gone, the commitment is not
// invertible even by someone holding a candidate address.
//
// WHAT THIS COSTS, STATED PLAINLY. Under v3 the chain hash covered the
// plaintext, so editing an email broke the chain. Under v4 the chain
// hash covers the commitment, so editing the plaintext alone does NOT
// break it. That is not a weakening ONLY because VerifyCommitments
// exists and is run alongside the chain walk — it is the check that
// re-binds plaintext to commitment while the salt is still present. A
// deployment that walks the chain and skips VerifyCommitments has
// strictly less tamper-evidence on PII than it had at v3.

// CommitmentSize is the length of a field commitment, in bytes.
const CommitmentSize = sha256.Size

// RowSaltSize is the length of a per-row commitment salt, in bytes.
const RowSaltSize = 32

// ErrCommitmentMismatch is returned when a row's stored plaintext does
// not hash to its stored commitment — the PII-tamper signal.
var ErrCommitmentMismatch = errors.New("audit: field commitment does not match stored value")

// Commitments carries the salted hashes of an event's PII fields.
//
// These are what canonicalPayloadV4 hashes. Each is CommitmentSize
// bytes on a v4 row, or nil on a row that predates v4.
type Commitments struct {
	ActorEmail []byte
	ActorName  []byte
	ActorIP    []byte
	Before     []byte
	After      []byte
}

// commitmentFieldNames are the canonical names mixed into each
// commitment. Domain separation: without the name in the hash, a value
// moved from actor.name to actor.email would keep its commitment and
// the swap would be invisible to both the chain and VerifyCommitments.
const (
	fieldActorEmail = "actor.email"
	fieldActorName  = "actor.name"
	fieldActorIP    = "actor.ip"
	fieldBefore     = "before"
	fieldAfter      = "after"
)

// NewRowSalt returns a fresh per-row commitment salt.
func NewRowSalt() ([]byte, error) {
	salt := make([]byte, RowSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("audit: read random salt: %w", err)
	}
	return salt, nil
}

// commit computes H(salt || LP(field) || LP(value)).
//
// Both the name and the value are length-prefixed, so no (field, value)
// pair can be confused with a different one by concatenation — the same
// reasoning as the length-prefixed canonical payload itself.
func commit(salt []byte, field string, value []byte) []byte {
	h := sha256.New()
	h.Write(salt)
	var lp []byte
	lp = appendLP(lp, []byte(field))
	lp = appendLP(lp, value)
	h.Write(lp)
	return h.Sum(nil)
}

// ComputeCommitments derives the full commitment set for an event under
// a given salt.
//
// Called exactly once per row, at write time. The verify path does NOT
// call this to reconstruct the payload — it reads the stored
// commitments — because a row whose plaintext has been erased can no
// longer reproduce them, which is the entire point.
func ComputeCommitments(salt []byte, e Event) Commitments {
	return Commitments{
		ActorEmail: commit(salt, fieldActorEmail, []byte(e.Actor.Email)),
		ActorName:  commit(salt, fieldActorName, []byte(e.Actor.Name)),
		ActorIP:    commit(salt, fieldActorIP, []byte(e.Actor.IP)),
		Before:     commit(salt, fieldBefore, []byte(e.Before)),
		After:      commit(salt, fieldAfter, []byte(e.After)),
	}
}

// IsRedacted reports whether a row's salt has been zeroed — the marker
// that its plaintext was erased and its commitments can no longer be
// re-derived.
//
// An all-zero salt, not a missing one, so the column stays NOT NULL and
// a redaction is a visible state rather than an absence. A row that
// never had a salt (pre-v4) is also reported as redacted here, and that
// is correct for the only use this has: "do not try to re-derive the
// commitments for this row."
func IsRedacted(salt []byte) bool {
	for _, b := range salt {
		if b != 0 {
			return false
		}
	}
	return true
}

// VerifyCommitments re-binds an event's stored plaintext to its stored
// commitments.
//
// RUN THIS ALONGSIDE THE CHAIN WALK, not instead of it. The two checks
// answer different questions and neither implies the other:
//
//   - the chain walk proves the row is in its original position and its
//     non-PII fields are unedited;
//   - this proves the PII plaintext still matches what was committed to
//     when the row was written.
//
// Returns (false, nil) — "not checkable", not "failed" — for any row
// that cannot be re-derived: a pre-v4 row, or a redacted one whose salt
// is zeroed. A redacted row is not a tampered row, and reporting it as
// one would make every erasure look like an attack.
func VerifyCommitments(e Event) (checked bool, err error) {
	if e.CanonicalVersion != CanonicalVersion4 {
		return false, nil
	}
	if IsRedacted(e.RowSalt) {
		return false, nil
	}
	want := ComputeCommitments(e.RowSalt, e)
	for _, c := range []struct {
		field       string
		stored, got []byte
	}{
		{fieldActorEmail, e.Commitments.ActorEmail, want.ActorEmail},
		{fieldActorName, e.Commitments.ActorName, want.ActorName},
		{fieldActorIP, e.Commitments.ActorIP, want.ActorIP},
		{fieldBefore, e.Commitments.Before, want.Before},
		{fieldAfter, e.Commitments.After, want.After},
	} {
		if !bytesEqual(c.stored, c.got) {
			return true, fmt.Errorf("%w: event %s field %s", ErrCommitmentMismatch, e.ID, c.field)
		}
	}
	return true, nil
}

// Redact erases an event's PII in place: plaintext cleared, salt zeroed,
// commitments untouched.
//
// This is the in-memory half; persisting it is the store's job (see
// SQLiteLogger.RedactEvent). The commitments are deliberately left
// alone — they are what the chain hashed, so changing them would break
// the chain in exactly the way this mechanism exists to avoid.
//
// IRREVERSIBLE by construction. Once the salt is zeroed the commitment
// cannot be re-derived even by someone who guesses the original value,
// which is what distinguishes this from hiding a column behind a view.
func Redact(e *Event) {
	if e == nil {
		return
	}
	e.Actor.Email = ""
	e.Actor.Name = ""
	e.Actor.IP = ""
	e.Before = nil
	e.After = nil
	if len(e.RowSalt) > 0 {
		for i := range e.RowSalt {
			e.RowSalt[i] = 0
		}
	}
}

// RedactEvent erases a v4 row's PII in place and persists it.
//
// The chain still verifies afterwards: the canonical payload hashed the
// COMMITMENTS, and those are left exactly as they were. What changes is
// only what the commitments were computed FROM, plus the salt that made
// them un-invertible — which is what makes the erasure irreversible
// rather than a column hidden behind a view.
//
// Returns (false, nil) for a row that is absent or not v4. A pre-v4 row
// hashed its PII directly, so it cannot be redacted without breaking its
// hash; that is the honest residual recorded in sketch §8 item 1, and it
// closes only by those rows ageing out through PruneOlderThan. Reporting
// it as "not redacted" rather than erroring is deliberate: a caller
// sweeping a subject's rows should learn which ones it could not reach,
// not abort halfway through.
//
// IDEMPOTENT. Re-redacting an already-redacted row rewrites the same
// empty values over themselves and leaves the commitments alone.
func (l *SQLiteLogger) RedactEvent(ctx context.Context, id string) (bool, error) {
	if l == nil || l.store == nil {
		return false, nil
	}
	before, err := l.store.Queries.GetEventByID(ctx, id)
	if err != nil {
		// Absent is not an error here — see the doc comment.
		return false, nil //nolint:nilerr // a missing row is "nothing redacted", not a failure
	}
	if before.CanonicalVersion != int64(CanonicalVersion4) {
		return false, nil
	}
	if err := l.store.Queries.RedactEventPII(ctx, id); err != nil {
		return false, fmt.Errorf("audit: redact event %s: %w", id, err)
	}
	return true, nil
}
