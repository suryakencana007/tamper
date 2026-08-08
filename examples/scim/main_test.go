package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	espresso "github.com/suryakencana007/espresso/v2"

	"github.com/suryakencana007/tamper/audit"
	tamperespresso "github.com/suryakencana007/tamper/espresso"
)

// This test IS the IdP: it drives the SCIM server exactly as Okta / Entra
// would — a service-account bearer token on every call, RFC-7644 JSON bodies —
// and asserts the two things this example exists to demonstrate:
//   1. every route fails closed without a valid service-account token, and
//   2. the AUDIT CROSSING (A3): the STORE emits the rows, attributed to the
//      service account the gate stashed — the transport emits nothing.

const testSAToken = "demo-service-account-token"

// scimClient is the IdP side of the wire.
type scimClient struct {
	t     *testing.T
	r     *espresso.Router
	token string // "" => send no Authorization header
}

func (c *scimClient) do(method, path string, body any) *httptest.ResponseRecorder {
	c.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			c.t.Fatalf("marshal request body: %v", err)
		}
		rdr = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rdr)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Content-Type", tamperespresso.ContentTypeSCIM)
	rec := httptest.NewRecorder()
	c.r.ServeHTTP(rec, req)
	return rec
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %T: %v (body=%s)", v, err, rec.Body.String())
	}
	return v
}

func mustStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("status = %d, want %d (body=%s)", rec.Code, want, rec.Body.String())
	}
}

// usersFilter percent-encodes a SCIM filter into a /Users query URL, exactly
// as a real IdP would put it on the wire (the raw filter carries spaces + quotes).
func usersFilter(filter string) string {
	return "/scim/v2/Users?" + url.Values{"filter": {filter}}.Encode()
}

// userBody builds an RFC 7643 §4.1 core:User payload.
func userBody(userName, family, given string, active bool) map[string]any {
	return map[string]any{
		"schemas":  []string{tamperespresso.SchemaUser},
		"userName": userName,
		"name":     map[string]any{"familyName": family, "givenName": given},
		"active":   active,
	}
}

func TestSCIM_EndToEnd(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	router, provider, users, groups, err := buildHandler(dbPath, "test-jwt-secret", testSAToken)
	if err != nil {
		t.Fatalf("buildHandler: %v", err)
	}
	defer func() { _ = provider.Close() }()

	idp := &scimClient{t: t, r: router, token: testSAToken}
	anon := &scimClient{t: t, r: router, token: ""}

	// --- 1. The gate fails closed (this is the whole point of a SCIM server) ---
	mustStatus(t, anon.do(http.MethodGet, "/scim/v2/Users", nil), http.StatusUnauthorized)
	mustStatus(t, (&scimClient{t: t, r: router, token: "wrong-token"}).
		do(http.MethodGet, "/scim/v2/Users", nil), http.StatusUnauthorized)

	// --- 2. Discovery advertises the injected caps verbatim ---
	spc := decode[tamperespresso.ServiceProviderConfig](t, idp.do(http.MethodGet, "/scim/v2/ServiceProviderConfig", nil))
	if !spc.Filter.Supported || spc.Filter.MaxResults != 100 {
		t.Errorf("filter = %+v, want supported + maxResults 100", spc.Filter)
	}
	if spc.Bulk.MaxOperations != 50 {
		t.Errorf("bulk.maxOperations = %d, want the injected 50", spc.Bulk.MaxOperations)
	}

	// --- 3. Create a user (Okta pushing a new hire) ---
	rec := idp.do(http.MethodPost, "/scim/v2/Users", userBody("alice@corp.example", "Anderson", "Alice", true))
	mustStatus(t, rec, http.StatusCreated)
	alice := decode[tamperespresso.UserResource](t, rec)
	if alice.ID == "" || alice.UserName != "alice@corp.example" {
		t.Fatalf("create returned %+v", alice)
	}
	if loc := rec.Header().Get("Location"); loc == "" {
		t.Error("create must set a Location header (RFC 7644 §3.3)")
	}
	if users.Count() != 1 {
		t.Errorf("user store count = %d, want 1", users.Count())
	}
	aliceURL := "/scim/v2/Users/" + alice.ID

	// --- 4. Read it back ---
	got := decode[tamperespresso.UserResource](t, idp.do(http.MethodGet, aliceURL, nil))
	if got.Name == nil || got.Name.FamilyName != "Anderson" {
		t.Fatalf("GET name = %+v, want familyName Anderson", got.Name)
	}

	// --- 5. Filter: the one supported clause matches; others are 400 ---
	list := decode[tamperespresso.ListResponse](t, idp.do(http.MethodGet, usersFilter(`userName eq "alice@corp.example"`), nil))
	if list.TotalResults != 1 {
		t.Errorf("filtered totalResults = %d, want 1", list.TotalResults)
	}
	mustStatus(t, idp.do(http.MethodGet, usersFilter(`displayName eq "x"`), nil), http.StatusBadRequest)
	// No filter param => the store's match-all branch, one user.
	all := decode[tamperespresso.ListResponse](t, idp.do(http.MethodGet, "/scim/v2/Users", nil))
	if all.TotalResults != 1 {
		t.Errorf("unfiltered totalResults = %d, want 1", all.TotalResults)
	}

	// --- 6. PATCH active=false MUST preserve the name (the SavePatch contract) ---
	patch := map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{{"op": "replace", "value": map[string]any{"active": false}}},
	}
	mustStatus(t, idp.do(http.MethodPatch, aliceURL, patch), http.StatusOK)
	afterPatch := decode[tamperespresso.UserResource](t, idp.do(http.MethodGet, aliceURL, nil))
	if afterPatch.Active {
		t.Error("PATCH active=false did not disable the user")
	}
	if afterPatch.Name == nil || afterPatch.Name.FamilyName != "Anderson" {
		t.Errorf("PATCH wiped the name: %+v — SavePatch must be a partial update", afterPatch.Name)
	}

	// --- 7. PUT (full replace) re-enables + is a full overwrite ---
	replaced := decode[tamperespresso.UserResource](t, idp.do(http.MethodPut, aliceURL,
		userBody("alice@corp.example", "Anderson", "Alice", true)))
	if !replaced.Active {
		t.Error("PUT active=true did not re-enable the user")
	}

	// --- 8. Groups: member validation, then a real cycle is rejected ---
	teamA := decode[tamperespresso.GroupResource](t, idp.do(http.MethodPost, "/scim/v2/Groups", map[string]any{
		"schemas":     []string{tamperespresso.SchemaGroup},
		"displayName": "Team A",
		"members":     []map[string]any{{"value": alice.ID, "type": "User"}},
	}))
	if len(teamA.Members) != 1 || teamA.Members[0].Value != alice.ID {
		t.Fatalf("group members = %+v, want alice", teamA.Members)
	}
	teamB := decode[tamperespresso.GroupResource](t, idp.do(http.MethodPost, "/scim/v2/Groups", map[string]any{
		"schemas":     []string{tamperespresso.SchemaGroup},
		"displayName": "Team B",
		"members":     []map[string]any{{"value": teamA.ID, "type": "Group"}}, // B ⊇ A
	}))
	// Now make A ⊇ B — that closes A ⊇ B ⊇ A. Must be a 400 CIRCULAR_GROUP_REFERENCE.
	cycleRec := idp.do(http.MethodPut, "/scim/v2/Groups/"+teamA.ID, map[string]any{
		"schemas":     []string{tamperespresso.SchemaGroup},
		"displayName": "Team A",
		"members":     []map[string]any{{"value": teamB.ID, "type": "Group"}},
	})
	mustStatus(t, cycleRec, http.StatusBadRequest)
	if scimErr := decode[tamperespresso.SCIMError](t, cycleRec); !bytes.Contains([]byte(scimErr.Detail), []byte("CIRCULAR")) {
		t.Errorf("cycle detail = %q, want a CIRCULAR_GROUP_REFERENCE marker", scimErr.Detail)
	}

	// --- 9. Delete removes it; the row is gone ---
	mustStatus(t, idp.do(http.MethodDelete, aliceURL, nil), http.StatusNoContent)
	mustStatus(t, idp.do(http.MethodGet, aliceURL, nil), http.StatusNotFound)

	// --- 10. Bulk: creates in one envelope, each dispatched under the SA context ---
	// The /Groups op matters: GroupsCreate calls MustGetPrincipal(ctx), so it
	// panics unless the bulk sub-request carries the gate-stashed principal —
	// this is the runtime proof that bulk.go's .WithContext(r.Context()) works.
	bulk := map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:BulkRequest"},
		"Operations": []map[string]any{
			{"method": "POST", "path": "/Users", "bulkId": "b1", "data": userBody("bob@corp.example", "Baker", "Bob", true)},
			{"method": "POST", "path": "/Users", "bulkId": "b2", "data": userBody("carol@corp.example", "Cole", "Carol", true)},
			{"method": "POST", "path": "/Groups", "bulkId": "b3", "data": map[string]any{
				"schemas": []string{tamperespresso.SchemaGroup}, "displayName": "Bulk Team", "members": []map[string]any{},
			}},
		},
	}
	bulkRec := idp.do(http.MethodPost, "/scim/v2/Bulk", bulk)
	mustStatus(t, bulkRec, http.StatusOK)
	br := decode[bulkResponse](t, bulkRec)
	if len(br.Operations) != 3 {
		t.Fatalf("bulk returned %d results, want 3", len(br.Operations))
	}
	for _, op := range br.Operations {
		if op.Status != "201" {
			t.Errorf("bulk op %s status = %q, want 201", op.BulkID, op.Status)
		}
	}
	// alice was deleted (§9); bob + carol were bulk-created (§10) => 2 users.
	if users.Count() != 2 {
		t.Errorf("user store count = %d, want 2 (bob+carol; alice deleted)", users.Count())
	}
	// Team A + Team B (§8) + the bulk-created "Bulk Team" => 3 groups.
	if groups.Count() != 3 {
		t.Errorf("group store count = %d, want 3", groups.Count())
	}

	// --- 11. THE AUDIT CROSSING (A3): the store emitted, attributed to the SA ---
	assertAudit(t, provider.Audit)
}

// assertAudit walks the hash-chained audit log and proves the store — not the
// transport — emitted the mutation rows, each attributed to the service
// account the gate stashed (Actor.Type=service_account, Name from the Principal).
func assertAudit(t *testing.T, logger audit.Logger) {
	t.Helper()
	page, err := logger.List(context.Background(), audit.Filter{Limit: 1000})
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}

	seen := map[audit.Action]bool{}
	for _, ev := range page.Events {
		seen[ev.Action] = true
		// Every SCIM-emitted row must carry the service-account actor.
		switch ev.Action {
		case actionUserCreate, actionUserPatch, actionUserDelete, actionGroupCreate, actionBulk:
			if ev.Actor.Type != audit.ActorTypeServiceAccount {
				t.Errorf("action %q actor type = %q, want service_account", ev.Action, ev.Actor.Type)
			}
			if ev.Actor.Name != "demo-idp" || ev.Actor.UserID != "sa-demo" {
				t.Errorf("action %q actor = {name:%q id:%q}, want the demo-idp SA", ev.Action, ev.Actor.Name, ev.Actor.UserID)
			}
		}
	}

	// The flow above exercised each of these at least once.
	for _, want := range []audit.Action{actionUserCreate, actionUserPatch, actionUserDelete, actionUserList, actionGroupCreate, actionBulk} {
		if !seen[want] {
			t.Errorf("audit chain missing a %q row — the store isn't emitting it", want)
		}
	}
}

// TestSCIM_RateLimited proves the limiter is actually MOUNTED, not merely
// available. Slice 7k-1 wires it in main.go; without a test that drives
// the router past the burst, deleting the two lines that install it
// leaves this whole suite green — which is exactly how the exit-3 chain
// guard went quietly missing in Phase 0c.
//
// A connector is a machine on a loop. It does not get tired and it does
// not back off unless told to, so "someone would notice" is not a
// control.
func TestSCIM_RateLimited(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	router, provider, _, _, err := buildHandler(dbPath, "test-jwt-secret", testSAToken)
	if err != nil {
		t.Fatalf("buildHandler: %v", err)
	}
	defer func() { _ = provider.Close() }()

	idp := &scimClient{t: t, r: router, token: testSAToken}

	// The demo bucket is burst 20, refilling 10/s. Sixty back-to-back
	// reads outrun it comfortably; the loop takes far less than the two
	// seconds it would take to earn them back.
	var limited *httptest.ResponseRecorder
	for range 60 {
		rec := idp.do(http.MethodGet, "/scim/v2/Users", nil)
		if rec.Code == http.StatusTooManyRequests {
			limited = rec
			break
		}
	}
	if limited == nil {
		t.Fatal("60 back-to-back SCIM reads were never rate limited; the throttle " +
			"is not mounted on the SCIM surface")
	}

	// A connector fail-closes on an app-branded body, so the refusal must
	// arrive in the RFC 7644 §3.12 envelope.
	if ct := limited.Header().Get("Content-Type"); ct != "application/scim+json" {
		t.Errorf("content-type = %q, want application/scim+json — a SCIM client "+
			"cannot parse this refusal", ct)
	}
	if body := limited.Body.String(); !bytes.Contains([]byte(body), []byte(tamperespresso.SchemaError)) {
		t.Errorf("429 body is not a SCIM error envelope: %s", body)
	}
	if ra := limited.Header().Get("Retry-After"); ra == "" {
		t.Error("429 carries no Retry-After; a connector that cannot tell how long " +
			"to wait will hot-loop on the refusal")
	}
}

// TestSCIM_ThrottleRunsInsideTheAuthGate pins the composition order. With
// the limiter OUTSIDE RequireServiceAccount there is no principal yet, so
// every request keys as unauthenticated, one global bucket limits every
// tenant, and an unauthenticated flood can lock out real connectors. The
// symptom is invisible in a single-tenant demo, which is why it is
// asserted rather than left to a comment.
func TestSCIM_ThrottleRunsInsideTheAuthGate(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	router, provider, _, _, err := buildHandler(dbPath, "test-jwt-secret", testSAToken)
	if err != nil {
		t.Fatalf("buildHandler: %v", err)
	}
	defer func() { _ = provider.Close() }()

	// Exhaust the anonymous budget many times over. Every one of these is
	// rejected by the auth gate before the limiter is ever consulted.
	anon := &scimClient{t: t, r: router, token: ""}
	for range 100 {
		if rec := anon.do(http.MethodGet, "/scim/v2/Users", nil); rec.Code != http.StatusUnauthorized {
			t.Fatalf("anonymous request status = %d, want 401", rec.Code)
		}
	}

	// The authenticated connector still has its full budget.
	idp := &scimClient{t: t, r: router, token: testSAToken}
	rec := idp.do(http.MethodGet, "/scim/v2/Users", nil)
	if rec.Code == http.StatusTooManyRequests {
		t.Error("an unauthenticated flood consumed the authenticated connector's " +
			"budget; the limiter is mounted outside the service-account gate, so " +
			"every caller shares one bucket")
	}
}
