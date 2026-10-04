package audit

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// canonical_version=4: the tenant is inside the hash, and PII is hashed
// as salted commitments so a row can be redacted without breaking the
// chain.

// v4Logger builds a logger over a fresh DB and returns the concrete type.
func v4Logger(t *testing.T) *SQLiteLogger {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	l, err := NewSQLiteLogger(dbPath, SQLiteLoggerOptions{})
	if err != nil {
		t.Fatalf("NewSQLiteLogger: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	sl, ok := l.(*SQLiteLogger)
	if !ok {
		t.Fatalf("NewSQLiteLogger returned %T", l)
	}
	return sl
}

func tenantEvent(id string, at time.Time, tenantID string) Event {
	return Event{
		ID:           id,
		At:           at,
		Actor:        Actor{UserID: "u-1", Email: "alice@example.com", Name: "Alice", IP: "10.0.0.1"},
		Action:       Action("user.update"),
		ResourceType: ResourceType("user"),
		ResourceID:   "u-1",
		TenantID:     tenantID,
	}
}

// TestV4_TenantIsInsideTheHash is the reason the tenant is in the payload.
// An unhashed tenant column could be re-attributed from one customer to
// another without breaking anything — and evidence that can be silently
// re-attributed is not evidence.
func TestV4_TenantIsInsideTheHash(t *testing.T) {
	mk := func(eventTenant, actorTenant string) []byte {
		e := Event{
			ID: "x", At: time.Unix(1700000000, 0).UTC(),
			Actor:            Actor{Type: ActorTypeUser, UserID: "u-1", TenantID: actorTenant},
			Action:           Action("user.update"),
			CanonicalVersion: CanonicalVersion4,
			TenantID:         eventTenant,
		}
		e.Commitments = ComputeCommitments(bytes.Repeat([]byte{7}, RowSaltSize), e)
		prev := make([]byte, HashSize)
		return hashChainLink(prev, canonicalPayloadV4(e, prev))
	}
	acme := mk("acme", "acme")
	if bytes.Equal(acme, mk("globex", "acme")) {
		t.Error("re-attributing the EVENT tenant left the hash unchanged; a row " +
			"can be moved between customers without breaking the chain")
	}
	if bytes.Equal(acme, mk("acme", "globex")) {
		t.Error("re-attributing the ACTOR tenant left the hash unchanged")
	}
}

// TestV4_PayloadFieldOrderIsFrozen pins the v4 layout: every field
// name, in order, exactly once.
//
// This replaced a test that asserted "the event tenant and the actor
// tenant are distinct fields" by swapping their values and expecting a
// different hash. That test could not fail. The payload is
// length-prefixed and positional, so swapping two values changes the
// bytes whatever the fields are called — it was asserting a property of
// the encoding rather than of this encoder, and its mutation stayed
// green.
//
// What IS worth guarding is the thing the design says is frozen: v4's
// field sequence. A reorder, a rename, an insertion or a removal all
// silently invalidate every v4 row already on disk, and none of them
// look like a breaking change at review time. Changing this list is a
// v5, not an edit — so the list itself is the artifact under test.
func TestV4_PayloadFieldOrderIsFrozen(t *testing.T) {
	e := Event{
		ID: "x", At: time.Unix(1700000000, 0).UTC(),
		Actor:            Actor{Type: ActorTypeUser, UserID: "u-1", TenantID: "vendor"},
		Action:           Action("user.update"),
		CanonicalVersion: CanonicalVersion4,
		TenantID:         "acme",
	}
	e.Commitments = ComputeCommitments(bytes.Repeat([]byte{7}, RowSaltSize), e)
	payload := canonicalPayloadV4(e, make([]byte, HashSize))

	want := []string{
		"id", "at", "actor.user_id", "actor.email", "actor.name", "actor.ip",
		"actor.type", "action", "resource_type", "resource_id", "request_id",
		"tenant_id", "actor.tenant_id", "before", "after", "prev_hash",
	}
	// Walk the length-prefixed stream and collect the field names, which
	// is stricter than substring matching: it proves each name appears
	// exactly once, in a field-name position, in this order.
	got := readV4FieldNames(t, payload)
	if len(got) != len(want) {
		t.Fatalf("v4 payload has %d fields, want %d:\n got %v\nwant %v",
			len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("v4 field %d is %q, want %q.\n\nThe v4 field sequence is "+
				"frozen: every v4 row already written verifies under the old "+
				"order. If this change is intended it is canonical_version=5, "+
				"not an edit to v4.\n got %v\nwant %v", i, got[i], want[i], got, want)
		}
	}

	// And the two tenant fields carry DIFFERENT sources — the correctness
	// bug the manifest names. Reading e.TenantID into both slots is the
	// realistic mistake, and it is invisible to a same-tenant fixture.
	if !bytes.Contains(payload, append(lpOf("tenant_id"), lpOf("acme")...)) {
		t.Error("tenant_id does not carry Event.TenantID")
	}
	if !bytes.Contains(payload, append(lpOf("actor.tenant_id"), lpOf("vendor")...)) {
		t.Error("actor.tenant_id does not carry Actor.TenantID; both slots read " +
			"the same source, so an actor's home tenant is unrecorded")
	}
}

// lpOf renders a length-prefixed field the way the encoder does.
func lpOf(s string) []byte { return appendLP(nil, []byte(s)) }

// readV4FieldNames walks the length-prefixed payload and returns the
// name of each field, in order. Fields alternate name, value.
func readV4FieldNames(t *testing.T, payload []byte) []string {
	t.Helper()
	var names []string
	for i, off := 0, 0; off < len(payload); i++ {
		val, next, ok := readLP(payload, off)
		if !ok {
			t.Fatalf("payload truncated at offset %d", off)
		}
		if i%2 == 0 {
			names = append(names, string(val))
		}
		off = next
	}
	return names
}

// readLP reads one length-prefixed chunk at off, returning it and the
// next offset.
func readLP(b []byte, off int) ([]byte, int, bool) {
	if off+4 > len(b) {
		return nil, 0, false
	}
	n := int(binary.BigEndian.Uint32(b[off : off+4]))
	off += 4
	if off+n > len(b) {
		return nil, 0, false
	}
	return b[off : off+n], off + n, true
}

// --- mixed-version chains -----------------------------------------------

// TestV4_TamperedRowIsDetected: editing a v4 row's non-PII field in
// place must break the walk.
func TestV4_TamperedRowIsDetected(t *testing.T) {
	ctx := context.Background()
	l := v4Logger(t)
	base := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)

	for i, id := range []string{"a", "b", "c"} {
		if _, err := l.Log(ctx, tenantEvent(id, base.Add(time.Duration(i+1)*time.Second), "acme")); err != nil {
			t.Fatalf("Log %s: %v", id, err)
		}
	}
	if _, err := verifyChainPostMigrationStore(ctx, l); err != nil {
		t.Fatalf("clean v4 chain failed to verify: %v", err)
	}

	// Re-attribute row "b" to another tenant, in place.
	if _, err := l.store.DB.ExecContext(ctx,
		`UPDATE events SET tenant_id = 'globex' WHERE id = 'b'`); err != nil {
		t.Fatalf("tamper update: %v", err)
	}
	if _, err := verifyChainPostMigrationStore(ctx, l); err == nil {
		t.Error("re-attributing a v4 row to another tenant did not break the chain; " +
			"the tenant is not inside the hash and v4 has no reason to exist")
	}
}

// TestV4_PIITamperIsDetectedByCommitments: the chain hash covers the
// commitment, not the plaintext, so the chain walk alone does not notice
// an edited email. VerifyCommitments is the check that does, and this
// pins that it fires.
func TestV4_PIITamperIsDetectedByCommitments(t *testing.T) {
	ctx := context.Background()
	l := v4Logger(t)
	base := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)

	if _, err := l.Log(ctx, tenantEvent("a", base.Add(time.Second), "acme")); err != nil {
		t.Fatalf("Log: %v", err)
	}
	if _, err := l.store.DB.ExecContext(ctx,
		`UPDATE events SET actor_email = 'mallory@evil.example' WHERE id = 'a'`); err != nil {
		t.Fatalf("tamper update: %v", err)
	}

	// The CHAIN still walks — that is the honest cost of commitment
	// hashing, and pinning it here stops anyone assuming otherwise.
	if _, err := verifyChainPostMigrationStore(ctx, l); err != nil {
		t.Fatalf("the chain broke on a PII edit; commitments are not being used: %v", err)
	}

	// The COMMITMENT check is what catches it.
	row, err := l.store.Queries.GetEventByID(ctx, "a")
	if err != nil {
		t.Fatalf("GetEventByID: %v", err)
	}
	checked, err := VerifyCommitments(fromRow(row))
	if !checked {
		t.Fatal("VerifyCommitments skipped a live v4 row")
	}
	if !errors.Is(err, ErrCommitmentMismatch) {
		t.Errorf("VerifyCommitments err = %v, want ErrCommitmentMismatch — an edited "+
			"email is invisible to BOTH checks", err)
	}
}

// TestV4_CommitmentsAreFieldSeparated: a value moved from actor.name to
// actor.email must not keep its commitment. Without the field name in
// the hash the swap is invisible to both checks.
func TestV4_CommitmentsAreFieldSeparated(t *testing.T) {
	salt := bytes.Repeat([]byte{3}, RowSaltSize)
	c := ComputeCommitments(salt, Event{
		Actor: Actor{Email: "same", Name: "same", IP: "same"},
	})
	if bytes.Equal(c.ActorEmail, c.ActorName) || bytes.Equal(c.ActorName, c.ActorIP) {
		t.Error("identical values in different fields produced identical commitments; " +
			"a field swap would be invisible")
	}
}

// TestV4_CommitmentsAreSalted: two rows about the same person must not
// correlate. An unsalted commitment is a rainbow-table lookup and the
// "redacted" row still identifies its subject.
func TestV4_CommitmentsAreSalted(t *testing.T) {
	e := Event{Actor: Actor{Email: "alice@example.com"}}
	a := ComputeCommitments(bytes.Repeat([]byte{1}, RowSaltSize), e)
	b := ComputeCommitments(bytes.Repeat([]byte{2}, RowSaltSize), e)
	if bytes.Equal(a.ActorEmail, b.ActorEmail) {
		t.Error("the same value under two salts produced the same commitment; " +
			"the salt is not reaching the hash")
	}
}

// --- redaction ----------------------------------------------------------

// TestV4_RedactionKeepsTheChainVerifiable is the property the whole
// commitment scheme exists for: erase the PII, and the chain still
// walks.
func TestV4_RedactionKeepsTheChainVerifiable(t *testing.T) {
	ctx := context.Background()
	l := v4Logger(t)
	base := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)

	for i, id := range []string{"a", "b", "c"} {
		if _, err := l.Log(ctx, tenantEvent(id, base.Add(time.Duration(i+1)*time.Second), "acme")); err != nil {
			t.Fatalf("Log %s: %v", id, err)
		}
	}
	beforeRes, err := verifyChainPostMigrationStore(ctx, l)
	if err != nil {
		t.Fatalf("pre-redaction verify: %v", err)
	}

	redacted, err := l.RedactEvent(ctx, "b")
	if err != nil {
		t.Fatalf("RedactEvent: %v", err)
	}
	if !redacted {
		t.Fatal("RedactEvent reported nothing redacted for a live v4 row")
	}

	afterRes, err := verifyChainPostMigrationStore(ctx, l)
	if err != nil {
		t.Fatalf("THE CHAIN BROKE ON REDACTION — the commitment scheme is not "+
			"doing its job: %v", err)
	}
	if afterRes.Count != beforeRes.Count {
		t.Errorf("row count changed across redaction: %d → %d", beforeRes.Count, afterRes.Count)
	}

	// The value is actually gone, and the salt with it.
	row, err := l.store.Queries.GetEventByID(ctx, "b")
	if err != nil {
		t.Fatalf("GetEventByID: %v", err)
	}
	if row.ActorEmail != "" || row.ActorName != "" || row.ActorIp != "" {
		t.Errorf("redaction left PII behind: email=%q name=%q ip=%q",
			row.ActorEmail, row.ActorName, row.ActorIp)
	}
	if !IsRedacted(row.RowSalt) {
		t.Error("the salt survived redaction; the commitment is still invertible " +
			"by anyone holding a candidate value")
	}
	if len(row.CActorEmail) != CommitmentSize {
		t.Errorf("the commitment was destroyed (%d bytes); that is what the chain "+
			"hashed", len(row.CActorEmail))
	}

	// A redacted row is not a tampered row.
	checked, cerr := VerifyCommitments(fromRow(row))
	if checked {
		t.Error("VerifyCommitments tried to re-derive a redacted row; every erasure " +
			"would report as tamper")
	}
	if cerr != nil {
		t.Errorf("VerifyCommitments errored on a redacted row: %v", cerr)
	}
}

// TestV4_RedactIsIdempotentAndScoped: re-redacting is a no-op, and an
// absent row reports "not redacted" rather than erroring — a caller
// sweeping a subject's rows needs to learn which it could not reach, not
// abort halfway.
func TestV4_RedactIsIdempotentAndScoped(t *testing.T) {
	ctx := context.Background()
	l := v4Logger(t)
	base := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)

	if _, err := l.Log(ctx, tenantEvent("a", base.Add(time.Second), "acme")); err != nil {
		t.Fatalf("Log: %v", err)
	}
	if _, err := l.RedactEvent(ctx, "a"); err != nil {
		t.Fatalf("first redact: %v", err)
	}
	if _, err := l.RedactEvent(ctx, "a"); err != nil {
		t.Errorf("second redact errored: %v", err)
	}
	if _, err := verifyChainPostMigrationStore(ctx, l); err != nil {
		t.Errorf("double redaction broke the chain: %v", err)
	}
	if ok, err := l.RedactEvent(ctx, "no-such-row"); ok || err != nil {
		t.Errorf("RedactEvent(missing) = (%v, %v), want (false, nil)", ok, err)
	}
}

// TestV4_GoldenVector pins the encoder to bytes, not to itself. Every
// other test compares Log against canonicalPayloadV4, so a reordered or
// renamed field would pass them all while making every stored chain
// read as tamper. This one fails.
//
// If it fails, the encoding changed. That is a new canonical version,
// not an edit: do not update the constant.
func TestV4_GoldenVector(t *testing.T) {
	e := Event{
		ID: "evt-golden",
		At: time.Unix(1700000000, 123456789).UTC(),
		Actor: Actor{
			Type: ActorTypeServiceAccount, UserID: "sa-1", Email: "svc@example.com",
			Name: "provisioner", IP: "203.0.113.7", TenantID: "vendor",
		},
		Action:       Action("user.update"),
		ResourceType: ResourceUser,
		ResourceID:   "u-42",
		RequestID:    "req-7",
		ClusterID:    "c-1", // not hashed
		TenantID:     "acme",
		Before:       []byte(`{"active":true}`),
		After:        []byte(`{"active":false}`),
	}
	e.RowSalt = bytes.Repeat([]byte{0xA5}, RowSaltSize)
	e.Commitments = ComputeCommitments(e.RowSalt, e)
	prev := bytes.Repeat([]byte{0x11}, HashSize)

	// Computed once by this package and once by an independent
	// implementation of the layout documented on canonicalPayloadV4 and
	// commit (sha256, BigEndian u32 length prefixes); both agreed.
	const want = "1d4cfb62d296120a4622a605d547e194f25c229207421369c78ec57b87423c17"
	if got := HashHex(hashChainLink(prev, canonicalPayloadV4(e, prev))); got != want {
		t.Fatalf("v4 hash = %s, want %s", got, want)
	}
}
