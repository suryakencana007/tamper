package audit

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// Slice 7i-1 — canonical_version=4.
//
// The bar for this slice is not "v4 works". It is "v4 exists and NOTHING
// ELSE MOVED": every pre-existing row keeps its own canonical_version
// and its own hash byte-for-byte, a tenancy-disabled deployment never
// writes a v4 row at all, and the mixed chain still walks.

// v4Logger builds a tenancy-configured logger over a fresh DB.
func v4Logger(t *testing.T) *SQLiteLogger {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	l, err := NewSQLiteLogger(dbPath, SQLiteLoggerOptions{Tenancy: true})
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

// v3Logger is the same, tenancy OFF — the "" path.
func v3Logger(t *testing.T) *SQLiteLogger {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	l, err := NewSQLiteLogger(dbPath, SQLiteLoggerOptions{})
	if err != nil {
		t.Fatalf("NewSQLiteLogger: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	sl, _ := l.(*SQLiteLogger)
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

// --- the "" path does not move ------------------------------------------

// TestV4_TenancyOffStillWritesV3 is invariant 1 for this slice, and it
// is satisfied by NOT PARTICIPATING rather than by careful equivalence:
// a single-tenant deployment never emits a v4 row, so there is no
// equivalence to get wrong.
func TestV4_TenancyOffStillWritesV3(t *testing.T) {
	ctx := context.Background()
	l := v3Logger(t)
	base := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)

	got, err := l.Log(ctx, makeEvent("e-1", base, Action("auth.login")))
	if err != nil {
		t.Fatalf("Log: %v", err)
	}
	if got.CanonicalVersion != CanonicalVersion3 {
		t.Errorf("canonical_version = %d, want 3 — a tenancy-disabled logger "+
			"started writing v4 rows", got.CanonicalVersion)
	}
	if len(got.RowSalt) != 0 {
		t.Errorf("a v3 row carries a %d-byte salt; the '' path gained state it "+
			"never had", len(got.RowSalt))
	}
	if len(got.Commitments.ActorEmail) != 0 {
		t.Error("a v3 row carries commitments")
	}
}

// TestV4_V3HashIsUnchangedByThisSlice is the byte-parity proof, pinned
// as a literal. If any edit in this slice perturbed the v3 encoder — a
// reordered field, an extra append, a changed default — this constant
// stops matching and the whole pre-existing chain on every deployed DB
// becomes unverifiable.
//
// The value was captured by BUILDING THE PRE-SLICE COMMIT and running
// the v3 encoder there, not by printing what this branch computes. That
// distinction is the whole reason the pin can witness a regression: a
// constant copied from the code under test agrees with it by
// construction and proves nothing.
func TestV4_V3HashIsUnchangedByThisSlice(t *testing.T) {
	e := Event{
		ID:               "pin-1",
		At:               time.Unix(1700000000, 0).UTC(),
		Actor:            Actor{Type: ActorTypeUser, UserID: "u-1", Email: "alice@example.com", Name: "Alice", IP: "10.0.0.1"},
		Action:           Action("auth.login"),
		ResourceType:     ResourceType("user"),
		ResourceID:       "u-1",
		RequestID:        "req-1",
		CanonicalVersion: CanonicalVersion3,
		// Set, and deliberately IGNORED by the v3 encoder. If v3 ever
		// started reading these the pin would move.
		TenantID: "acme",
	}
	e.Actor.TenantID = "acme"
	prev := make([]byte, HashSize)

	const want = "d01d0a06f109bb033e5a42981d04536454b8680085fd19f0b60daee01d91daee"
	got := hex.EncodeToString(computeHash(prev, e, CanonicalVersion3))
	if got != want {
		t.Errorf("the v3 canonical hash MOVED.\n got: %s\nwant: %s\n\n"+
			"Every v3 row on every deployed audit DB verifies under the old "+
			"value. If this change was intentional it is a new canonical "+
			"version, not an edit to v3.", got, want)
	}
}

// TestV4_TenantIsInsideTheHash is the justification for v4 existing.
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
		return computeHash(make([]byte, HashSize), e, CanonicalVersion4)
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

// TestV4_MixedV3V4ChainVerifies. Per-row canonical_version dispatch,
// exactly as v2/v3 already do. The v4 anchor lands first so the walk
// root and encoder version are right for the rows that follow.
func TestV4_MixedV3V4ChainVerifies(t *testing.T) {
	ctx := context.Background()
	l := v3Logger(t) // start tenancy-OFF so the first rows are genuinely v3
	base := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)

	for i, id := range []string{"v3-a", "v3-b"} {
		if _, err := l.Log(ctx, makeEvent(id, base.Add(time.Duration(i)*time.Second), Action("auth.login"))); err != nil {
			t.Fatalf("Log %s: %v", id, err)
		}
	}

	// Flip the same DB to tenancy and emit the anchor, then v4 rows.
	l.opts.Tenancy = true
	emitted, err := l.BootstrapChainV4(ctx, base.Add(10*time.Second), "v4-anchor")
	if err != nil {
		t.Fatalf("BootstrapChainV4: %v", err)
	}
	if !emitted {
		t.Fatal("BootstrapChainV4 emitted nothing on a DB with no v4 anchor")
	}
	for i, id := range []string{"v4-a", "v4-b"} {
		if _, err := l.Log(ctx, tenantEvent(id, base.Add(time.Duration(20+i)*time.Second), "acme")); err != nil {
			t.Fatalf("Log %s: %v", id, err)
		}
	}

	res, err := verifyChainPostMigrationStore(ctx, l)
	if err != nil {
		t.Fatalf("mixed v3/v4 chain failed to verify: %v", err)
	}
	if res.Count != 5 {
		t.Errorf("walked %d rows, want 5", res.Count)
	}

	// And the versions really are mixed — otherwise this test proves
	// only that a uniform chain verifies.
	rows, err := l.store.Queries.ListEventsForVerify(ctx)
	if err != nil {
		t.Fatalf("ListEventsForVerify: %v", err)
	}
	seen := map[int64]int{}
	for _, r := range rows {
		seen[r.CanonicalVersion]++
	}
	if seen[int64(CanonicalVersion3)] != 2 || seen[int64(CanonicalVersion4)] != 3 {
		t.Errorf("version mix = %v, want 2×v3 and 3×v4 (anchor + 2 rows)", seen)
	}
}

// TestV4_PreExistingRowsKeepTheirHash is the byte-parity DoD line at the
// row level: introducing v4 must not perturb a single stored hash.
func TestV4_PreExistingRowsKeepTheirHash(t *testing.T) {
	ctx := context.Background()
	l := v3Logger(t)
	base := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)

	before := map[string]string{}
	for i, id := range []string{"r-1", "r-2", "r-3"} {
		got, err := l.Log(ctx, makeEvent(id, base.Add(time.Duration(i)*time.Second), Action("auth.login")))
		if err != nil {
			t.Fatalf("Log %s: %v", id, err)
		}
		before[id] = hex.EncodeToString(got.Hash)
	}

	l.opts.Tenancy = true
	if _, err := l.BootstrapChainV4(ctx, base.Add(time.Minute), "v4-anchor"); err != nil {
		t.Fatalf("BootstrapChainV4: %v", err)
	}
	if _, err := l.Log(ctx, tenantEvent("v4-a", base.Add(2*time.Minute), "acme")); err != nil {
		t.Fatalf("Log v4-a: %v", err)
	}

	rows, err := l.store.Queries.ListEventsForVerify(ctx)
	if err != nil {
		t.Fatalf("ListEventsForVerify: %v", err)
	}
	for _, r := range rows {
		want, ok := before[r.ID]
		if !ok {
			continue
		}
		if got := hex.EncodeToString(r.Hash); got != want {
			t.Errorf("row %s hash CHANGED across the v4 migration:\n got %s\nwant %s",
				r.ID, got, want)
		}
		if r.CanonicalVersion != int64(CanonicalVersion3) {
			t.Errorf("row %s canonical_version = %d, want 3 — an existing row was "+
				"re-canonicalised", r.ID, r.CanonicalVersion)
		}
	}
}

// --- tamper detection ----------------------------------------------------

// TestV4_TamperedRowIsDetected: editing a v4 row's non-PII field in
// place must break the walk.
func TestV4_TamperedRowIsDetected(t *testing.T) {
	ctx := context.Background()
	l := v4Logger(t)
	base := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)

	if _, err := l.BootstrapChainV4(ctx, base, "v4-anchor"); err != nil {
		t.Fatalf("BootstrapChainV4: %v", err)
	}
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

// TestV4_PIITamperIsDetectedByCommitments is the check that keeps v4
// from being WEAKER than v3 on the PII fields. Under v3 the chain hash
// covered the plaintext, so editing an email broke the chain; under v4
// it covers the commitment, so the chain alone no longer notices. This
// is the check that re-binds the two.
func TestV4_PIITamperIsDetectedByCommitments(t *testing.T) {
	ctx := context.Background()
	l := v4Logger(t)
	base := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)

	if _, err := l.BootstrapChainV4(ctx, base, "v4-anchor"); err != nil {
		t.Fatalf("BootstrapChainV4: %v", err)
	}
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
			"email is invisible to BOTH checks, so v4 is weaker than v3 here", err)
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

	if _, err := l.BootstrapChainV4(ctx, base, "v4-anchor"); err != nil {
		t.Fatalf("BootstrapChainV4: %v", err)
	}
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

// TestV4_RedactIsIdempotentAndScoped: re-redacting is a no-op, and a
// pre-v4 row reports "not redacted" rather than erroring — a caller
// sweeping a subject's rows needs to learn which it could not reach, not
// abort halfway.
func TestV4_RedactIsIdempotentAndScoped(t *testing.T) {
	ctx := context.Background()
	l := v4Logger(t)
	base := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)

	if _, err := l.BootstrapChainV4(ctx, base, "v4-anchor"); err != nil {
		t.Fatalf("BootstrapChainV4: %v", err)
	}
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

// TestV4_PreV4RowCannotBeRedacted pins the honest residual recorded in
// sketch §8: a v3 row hashed its PII directly, so it cannot be redacted
// without breaking its hash. Stated as a test so nobody later "fixes"
// it by redacting one anyway.
func TestV4_PreV4RowCannotBeRedacted(t *testing.T) {
	ctx := context.Background()
	l := v3Logger(t)
	base := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	if _, err := l.Log(ctx, makeEvent("v3-row", base, Action("auth.login"))); err != nil {
		t.Fatalf("Log: %v", err)
	}
	ok, err := l.RedactEvent(ctx, "v3-row")
	if err != nil {
		t.Fatalf("RedactEvent: %v", err)
	}
	if ok {
		t.Error("a v3 row reported as redacted; its PII is inside its hash, so " +
			"erasing it would break the chain")
	}
}

// --- the anchor ---------------------------------------------------------

// TestV4_AnchorCarriesTheRealLatestHash. The zero sentinel is true only
// on an empty table; writing it onto a populated DB produces a row whose
// linkage fails at the next boot — the migration breaking the guarantee
// it is migrating.
func TestV4_AnchorCarriesTheRealLatestHash(t *testing.T) {
	ctx := context.Background()
	l := v3Logger(t)
	base := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)

	last, err := l.Log(ctx, makeEvent("v3-a", base, Action("auth.login")))
	if err != nil {
		t.Fatalf("Log: %v", err)
	}

	l.opts.Tenancy = true
	if _, err := l.BootstrapChainV4(ctx, base.Add(time.Second), "v4-anchor"); err != nil {
		t.Fatalf("BootstrapChainV4: %v", err)
	}
	row, err := l.store.Queries.GetEventByID(ctx, "v4-anchor")
	if err != nil {
		t.Fatalf("GetEventByID: %v", err)
	}
	if !bytes.Equal(row.PrevHash, last.Hash) {
		t.Errorf("anchor prev_hash = %x, want the real latest hash %x",
			row.PrevHash, last.Hash)
	}
	if IsRedacted(row.PrevHash) {
		t.Error("the anchor carries the zero sentinel on a populated DB; the next " +
			"boot's linkage check fails")
	}
}

// TestV4_BootstrapIsIdempotentAndGated. Two boots produce one anchor,
// and a tenancy-disabled logger produces none — the latter being what
// keeps a single-tenant DB byte-identical.
func TestV4_BootstrapIsIdempotentAndGated(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)

	t.Run("idempotent", func(t *testing.T) {
		l := v4Logger(t)
		first, err := l.BootstrapChainV4(ctx, base, "anchor-1")
		if err != nil || !first {
			t.Fatalf("first bootstrap = (%v, %v), want (true, nil)", first, err)
		}
		second, err := l.BootstrapChainV4(ctx, base.Add(time.Hour), "anchor-2")
		if err != nil {
			t.Fatalf("second bootstrap: %v", err)
		}
		if second {
			t.Error("a second boot emitted another v4 anchor; every restart would " +
				"add a chain segment")
		}
		n, err := l.store.Queries.CountEvents(ctx)
		if err != nil {
			t.Fatalf("CountEvents: %v", err)
		}
		if n != 1 {
			t.Errorf("event count = %d, want 1", n)
		}
	})

	t.Run("gated on tenancy", func(t *testing.T) {
		l := v3Logger(t)
		emitted, err := l.BootstrapChainV4(ctx, base, "anchor-1")
		if err != nil {
			t.Fatalf("BootstrapChainV4: %v", err)
		}
		if emitted {
			t.Error("a tenancy-DISABLED logger emitted a v4 anchor; the '' path's " +
				"audit DB is no longer byte-identical")
		}
	})
}

// TestV4_AnchorCarriesNoTenant: the anchor is a property of the chain,
// not of any customer. Giving it one would put a chain-machinery row
// inside a tenant's export.
func TestV4_AnchorCarriesNoTenant(t *testing.T) {
	ctx := context.Background()
	l := v4Logger(t)
	base := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	if _, err := l.BootstrapChainV4(ctx, base, "v4-anchor"); err != nil {
		t.Fatalf("BootstrapChainV4: %v", err)
	}
	row, err := l.store.Queries.GetEventByID(ctx, "v4-anchor")
	if err != nil {
		t.Fatalf("GetEventByID: %v", err)
	}
	if row.TenantID != "" {
		t.Errorf("the v4 anchor carries tenant %q", row.TenantID)
	}
}
