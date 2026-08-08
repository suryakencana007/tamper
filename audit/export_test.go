package audit

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Slice 7i-1 — the tenant-scoped export.
//
// Two things to get right, and the second is the one that ships broken:
// the slice must contain no other tenant's rows, and it must not CLAIM
// more than a slice of a shared chain can prove.

// seedThreeTenants writes an interleaved chain across three tenants and
// returns the logger. Interleaved on purpose: a filter that returned a
// contiguous block would pass against tenant-grouped fixtures and fail
// on any real DB.
func seedThreeTenants(t *testing.T) *SQLiteLogger {
	t.Helper()
	ctx := context.Background()
	l := v4Logger(t)
	base := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	if _, err := l.BootstrapChainV4(ctx, base, "v4-anchor"); err != nil {
		t.Fatalf("BootstrapChainV4: %v", err)
	}
	for i, tenantID := range []string{"acme", "globex", "acme", "initech", "globex", "acme"} {
		e := tenantEvent(string(rune('a'+i)), base.Add(time.Duration(i+1)*time.Second), tenantID)
		e.Actor.Email = tenantID + "-user@example.com"
		if _, err := l.Log(ctx, e); err != nil {
			t.Fatalf("Log %d: %v", i, err)
		}
	}
	return l
}

// TestExport_ContainsNoOtherTenantsRows is the manifest's line and the
// one that would be a cross-customer disclosure if it regressed.
func TestExport_ContainsNoOtherTenantsRows(t *testing.T) {
	ctx := context.Background()
	l := seedThreeTenants(t)

	exp, err := l.ExportForTenant(ctx, "acme")
	if err != nil {
		t.Fatalf("ExportForTenant: %v", err)
	}
	if len(exp.Events) != 3 {
		t.Fatalf("exported %d rows, want 3 (acme's)", len(exp.Events))
	}
	for _, e := range exp.Events {
		if e.TenantID != "acme" {
			t.Errorf("event %s belongs to tenant %q", e.ID, e.TenantID)
		}
	}

	// Scan the SERIALISED export for any other tenant's identifiers, not
	// just the TenantID field. A leak through actor email, a before/after
	// snapshot or a future field would pass a field-only check.
	blob, err := json.Marshal(exp)
	if err != nil {
		t.Fatalf("marshal export: %v", err)
	}
	for _, foreign := range []string{"globex", "initech"} {
		if strings.Contains(string(blob), foreign) {
			t.Errorf("acme's export mentions %q somewhere in its payload:\n%s",
				foreign, blob)
		}
	}
}

// TestExport_ExcludesTheChainAnchor: the v4 anchor is a property of the
// chain, not of a customer, and a chain-machinery row inside a customer
// export is noise at best and a hint about the pool at worst.
func TestExport_ExcludesTheChainAnchor(t *testing.T) {
	ctx := context.Background()
	l := seedThreeTenants(t)
	exp, err := l.ExportForTenant(ctx, "acme")
	if err != nil {
		t.Fatalf("ExportForTenant: %v", err)
	}
	for _, e := range exp.Events {
		if isChainAnchorAction(e.Action) {
			t.Errorf("the export contains chain-machinery row %s (%s)", e.ID, e.Action)
		}
	}
}

// TestExport_FiltersOnEventTenantNotActorTenant is the correctness bug
// the manifest calls out by name. A support engineer belonging to tenant
// A acting on tenant B's resource has actor-tenant A and event-tenant B.
// Filtering on the ACTOR's tenant silently omits exactly the
// cross-tenant administrative actions a customer most wants to see — and
// it passes every test written with same-tenant fixtures, which is how
// it ships.
func TestExport_FiltersOnEventTenantNotActorTenant(t *testing.T) {
	ctx := context.Background()
	l := v4Logger(t)
	base := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	if _, err := l.BootstrapChainV4(ctx, base, "v4-anchor"); err != nil {
		t.Fatalf("BootstrapChainV4: %v", err)
	}

	// A support engineer whose home tenant is "vendor", acting INSIDE
	// acme's tenant. This row belongs in acme's log.
	crossTenant := tenantEvent("support-action", base.Add(time.Second), "acme")
	crossTenant.Actor = Actor{
		Type: ActorTypeUser, UserID: "support-1",
		Email: "support@vendor.example", TenantID: "vendor",
	}
	if _, err := l.Log(ctx, crossTenant); err != nil {
		t.Fatalf("Log: %v", err)
	}
	// And an ordinary acme row, so a filter that returned nothing at all
	// could not pass by accident.
	if _, err := l.Log(ctx, tenantEvent("own-action", base.Add(2*time.Second), "acme")); err != nil {
		t.Fatalf("Log: %v", err)
	}

	exp, err := l.ExportForTenant(ctx, "acme")
	if err != nil {
		t.Fatalf("ExportForTenant: %v", err)
	}
	var sawSupport bool
	for _, e := range exp.Events {
		if e.ID == "support-action" {
			sawSupport = true
		}
	}
	if !sawSupport {
		t.Error("acme's export OMITS an action taken inside acme by an actor from " +
			"another tenant; the filter is on Actor.TenantID, so every " +
			"cross-tenant admin action is invisible to the customer it happened to")
	}
	if len(exp.Events) != 2 {
		t.Errorf("exported %d rows, want 2", len(exp.Events))
	}

	// The converse: the vendor's own export must not pick up the row
	// just because their engineer performed it.
	vendorExp, err := l.ExportForTenant(ctx, "vendor")
	if err != nil {
		t.Fatalf("ExportForTenant(vendor): %v", err)
	}
	if len(vendorExp.Events) != 0 {
		t.Errorf("the vendor's export contains %d rows scoped to another tenant",
			len(vendorExp.Events))
	}
}

// TestExport_DoesNotRenumberOrRehash: the export is a projection of the
// chain, not a new one. Re-hashing a slice into something self-consistent
// would manufacture evidence the original never contained.
func TestExport_DoesNotRenumberOrRehash(t *testing.T) {
	ctx := context.Background()
	l := seedThreeTenants(t)

	stored := map[string][]byte{}
	rows, err := l.store.Queries.ListEventsForVerify(ctx)
	if err != nil {
		t.Fatalf("ListEventsForVerify: %v", err)
	}
	for _, r := range rows {
		stored[r.ID] = r.Hash
	}

	exp, err := l.ExportForTenant(ctx, "acme")
	if err != nil {
		t.Fatalf("ExportForTenant: %v", err)
	}
	for _, e := range exp.Events {
		if want := stored[e.ID]; !bytesEqual(e.Hash, want) {
			t.Errorf("event %s was re-hashed for export:\n got %x\nwant %x",
				e.ID, e.Hash, want)
		}
		if len(e.PrevHash) == 0 {
			t.Errorf("event %s lost its prev_hash; the row can no longer be "+
				"recomputed on its own", e.ID)
		}
	}
}

// TestExport_AdmitsWhatItCannotProve. Under one chain, consecutive rows
// of one tenant are not chain-adjacent — the links run through other
// tenants' rows. A consumer that believed otherwise would read an
// ordinary gap as tampering, or an absence as innocence.
func TestExport_AdmitsWhatItCannotProve(t *testing.T) {
	ctx := context.Background()
	l := seedThreeTenants(t)
	exp, err := l.ExportForTenant(ctx, "acme")
	if err != nil {
		t.Fatalf("ExportForTenant: %v", err)
	}
	if exp.IsChain {
		t.Error("the export claims to be a chain; its rows do not link to each other")
	}
	if exp.Completeness != CompletenessIssuerAttested {
		t.Errorf("completeness = %q, want %q", exp.Completeness, CompletenessIssuerAttested)
	}

	// Both must survive serialisation: a consumer that finds no such
	// field cannot tell "not a chain" from "this export predates the
	// question", so omitempty on either would be a silent downgrade.
	blob, err := json.Marshal(exp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{`"is_chain":false`, `"completeness":"issuer-attested"`} {
		if !strings.Contains(string(blob), want) {
			t.Errorf("serialised export is missing %s:\n%s", want, blob)
		}
	}

	// And the rows really are non-adjacent, or this test is asserting a
	// disclaimer about a situation that never arises.
	adjacent := true
	for i := 1; i < len(exp.Events); i++ {
		if !bytesEqual(exp.Events[i].PrevHash, exp.Events[i-1].Hash) {
			adjacent = false
			break
		}
	}
	if adjacent {
		t.Error("the fixture's tenant rows happen to be chain-adjacent, so this " +
			"test proves nothing about the interleaved case")
	}
}

// TestExport_EmptyTenantExportsNothing: deny by default extends here.
// "" is the single-tenant scope, and an unscoped export is a different
// operation that should be spelled differently rather than reached by
// forgetting an argument.
func TestExport_EmptyTenantExportsNothing(t *testing.T) {
	ctx := context.Background()
	l := seedThreeTenants(t)
	exp, err := l.ExportForTenant(ctx, "")
	if err != nil {
		t.Fatalf("ExportForTenant(\"\"): %v", err)
	}
	if len(exp.Events) != 0 {
		t.Errorf("an empty tenant exported %d rows; a forgotten argument dumps "+
			"the pool", len(exp.Events))
	}
}

// TestExport_UnknownTenantIsEmptyNotError: a tenant with no rows and a
// tenant that does not exist are the same answer. Distinguishing them
// would make the export endpoint a tenant-existence oracle.
func TestExport_UnknownTenantIsEmptyNotError(t *testing.T) {
	ctx := context.Background()
	l := seedThreeTenants(t)
	exp, err := l.ExportForTenant(ctx, "never-heard-of")
	if err != nil {
		t.Fatalf("ExportForTenant: %v", err)
	}
	if len(exp.Events) != 0 {
		t.Errorf("unknown tenant exported %d rows", len(exp.Events))
	}
	if exp.Events == nil {
		t.Error("Events is nil; it serialises as null rather than [], which a " +
			"consumer will read as a missing field")
	}
}

// TestExport_RedactedRowsStillExport: an erasure must not silently drop
// the row from the customer's own log. The event still happened; only
// the personal data is gone.
func TestExport_RedactedRowsStillExport(t *testing.T) {
	ctx := context.Background()
	l := seedThreeTenants(t)
	exp, err := l.ExportForTenant(ctx, "acme")
	if err != nil {
		t.Fatalf("ExportForTenant: %v", err)
	}
	target := exp.Events[0].ID
	if _, err := l.RedactEvent(ctx, target); err != nil {
		t.Fatalf("RedactEvent: %v", err)
	}

	after, err := l.ExportForTenant(ctx, "acme")
	if err != nil {
		t.Fatalf("ExportForTenant post-redaction: %v", err)
	}
	if len(after.Events) != len(exp.Events) {
		t.Errorf("redaction changed the export size %d → %d; the event itself "+
			"disappeared from the customer's log", len(exp.Events), len(after.Events))
	}
	for _, e := range after.Events {
		if e.ID == target && e.Actor.Email != "" {
			t.Errorf("redacted row still carries an email: %q", e.Actor.Email)
		}
	}
}
