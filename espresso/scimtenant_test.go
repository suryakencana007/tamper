package espresso

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/suryakencana007/tamper/audit"
	scim "github.com/suryakencana007/tamper/scim"
	"github.com/suryakencana007/tamper/tenant"
)

// SCIM principal tenancy (B5). Tenant A's token must not
// touch tenant B's directory on ANY verb, and the refusal must be
// byte-identical to a genuine miss.

const (
	tenantA = "acme"
	tenantB = "globex"
)

// tenantSCIMStore is a two-tenant SCIM store. Rows are filed under a
// tenant in the STORE, because tamper names no column — the tenant
// reaches it only as an argument.
type tenantSCIMStore struct {
	users  map[string]map[string]scim.UserRecord // tenant -> id -> rec
	groups map[string]map[string]scim.GroupRecord
	// calls records the tenant every scoped method was invoked with, so a
	// test can prove WHICH tenant the handler passed down.
	calls []string
}

var _ scim.UserStore = (*tenantSCIMStore)(nil)

func newTenantSCIMStore() *tenantSCIMStore {
	s := &tenantSCIMStore{
		users:  map[string]map[string]scim.UserRecord{tenantA: {}, tenantB: {}},
		groups: map[string]map[string]scim.GroupRecord{tenantA: {}, tenantB: {}},
	}
	s.users[tenantA]["u-a"] = scim.UserRecord{ID: "u-a", UserName: "a@acme.test", Active: true}
	s.users[tenantB]["u-b"] = scim.UserRecord{ID: "u-b", UserName: "b@globex.test", Active: true}
	s.groups[tenantA]["g-a"] = scim.GroupRecord{ID: "g-a", DisplayName: "A team"}
	s.groups[tenantB]["g-b"] = scim.GroupRecord{ID: "g-b", DisplayName: "B team"}
	return s
}

func (s *tenantSCIMStore) note(t tenant.ID) { s.calls = append(s.calls, t.String()) }

// --- tenant-scoped users ---

func (s *tenantSCIMStore) Create(_ context.Context, t tenant.ID, w scim.UserWrite, _ scim.WriteMeta) (scim.UserRecord, error) {
	s.note(t)
	rec := scim.UserRecord{ID: "new-" + t.String(), UserName: w.UserName, Active: true}
	s.users[t.String()][rec.ID] = rec
	return rec, nil
}

func (s *tenantSCIMStore) Get(_ context.Context, t tenant.ID, id string) (scim.UserRecord, error) {
	s.note(t)
	rec, ok := s.users[t.String()][id]
	if !ok {
		return scim.UserRecord{}, scim.ErrNotFound
	}
	return rec, nil
}

func (s *tenantSCIMStore) Replace(_ context.Context, t tenant.ID, id string, w scim.UserWrite, _ scim.WriteMeta) (scim.UserRecord, error) {
	s.note(t)
	if _, ok := s.users[t.String()][id]; !ok {
		return scim.UserRecord{}, scim.ErrNotFound
	}
	rec := scim.UserRecord{ID: id, UserName: w.UserName, Active: true}
	s.users[t.String()][id] = rec
	return rec, nil
}

func (s *tenantSCIMStore) Delete(_ context.Context, t tenant.ID, id string, _ scim.WriteMeta) error {
	s.note(t)
	if _, ok := s.users[t.String()][id]; !ok {
		return scim.ErrNotFound
	}
	delete(s.users[t.String()], id)
	return nil
}

func (s *tenantSCIMStore) SavePatch(_ context.Context, t tenant.ID, id string, w scim.UserWrite, _ []scim.Operation) (scim.UserRecord, error) {
	s.note(t)
	if _, ok := s.users[t.String()][id]; !ok {
		return scim.UserRecord{}, scim.ErrNotFound
	}
	rec := scim.UserRecord{ID: id, UserName: w.UserName, Active: w.Active}
	s.users[t.String()][id] = rec
	return rec, nil
}

func (s *tenantSCIMStore) ListFiltered(_ context.Context, t tenant.ID, _, _ int, _ string) (scim.UserPage, error) {
	s.note(t)
	return s.userPage(t.String()), nil
}

func (s *tenantSCIMStore) userPage(t string) scim.UserPage {
	out := make([]scim.UserRecord, 0, len(s.users[t]))
	for _, r := range s.users[t] {
		out = append(out, r)
	}
	return scim.UserPage{Users: out, Total: len(out)}
}

// --- tenant-scoped groups ---

func (s *tenantSCIMStore) groupCreate(t string, w scim.GroupWrite) scim.GroupRecord {
	rec := scim.GroupRecord{ID: "newg-" + t, DisplayName: w.DisplayName}
	s.groups[t][rec.ID] = rec
	return rec
}

func (s *tenantSCIMStore) groupPage(t string) scim.GroupPage {
	out := make([]scim.GroupRecord, 0, len(s.groups[t]))
	for _, r := range s.groups[t] {
		out = append(out, r)
	}
	return scim.GroupPage{Groups: out, Total: len(out)}
}

// groupSide adapts the same backing maps to the Group port. Separate
// type because Go cannot have two methods with one name on one type.
type groupSide struct{ s *tenantSCIMStore }

var _ scim.GroupStore = groupSide{}

func (g groupSide) Create(_ context.Context, t tenant.ID, w scim.GroupWrite, _ scim.GroupWriteMeta) (scim.GroupRecord, error) {
	g.s.note(t)
	return g.s.groupCreate(t.String(), w), nil
}
func (g groupSide) Get(_ context.Context, t tenant.ID, id string) (scim.GroupRecord, error) {
	g.s.note(t)
	rec, ok := g.s.groups[t.String()][id]
	if !ok {
		return scim.GroupRecord{}, scim.ErrNotFound
	}
	return rec, nil
}
func (g groupSide) Replace(_ context.Context, t tenant.ID, id string, w scim.GroupWrite, _ scim.GroupWriteMeta) (scim.GroupRecord, error) {
	g.s.note(t)
	if _, ok := g.s.groups[t.String()][id]; !ok {
		return scim.GroupRecord{}, scim.ErrNotFound
	}
	rec := scim.GroupRecord{ID: id, DisplayName: w.DisplayName}
	g.s.groups[t.String()][id] = rec
	return rec, nil
}
func (g groupSide) Delete(_ context.Context, t tenant.ID, id string, _ scim.GroupWriteMeta) error {
	g.s.note(t)
	if _, ok := g.s.groups[t.String()][id]; !ok {
		return scim.ErrNotFound
	}
	delete(g.s.groups[t.String()], id)
	return nil
}
func (g groupSide) SavePatch(_ context.Context, t tenant.ID, id string, w scim.GroupWrite, _ []scim.Operation) (scim.GroupRecord, error) {
	g.s.note(t)
	if _, ok := g.s.groups[t.String()][id]; !ok {
		return scim.GroupRecord{}, scim.ErrNotFound
	}
	rec := scim.GroupRecord{ID: id, DisplayName: w.DisplayName}
	g.s.groups[t.String()][id] = rec
	return rec, nil
}
func (g groupSide) ValidateMembers(_ context.Context, t tenant.ID, members []scim.MemberRef) error {
	g.s.note(t)
	// The dangerous one: a member must belong to THIS tenant.
	for _, m := range members {
		if _, ok := g.s.users[t.String()][m.Value]; !ok {
			return scim.ErrInvalidInput
		}
	}
	return nil
}
func (g groupSide) ListFiltered(_ context.Context, t tenant.ID, _, _ int, _ string) (scim.GroupPage, error) {
	g.s.note(t)
	return g.s.groupPage(t.String()), nil
}

// --- harness ----------------------------------------------------------

func tenantSCIM(t *testing.T) (*SCIMRoutes, *tenantSCIMStore) {
	t.Helper()
	store := newTenantSCIMStore()
	rt, err := NewSCIMRoutes(SCIMConfig{
		Prefix: "/scim/v2", BaseURL: "https://panel.test", MaxResults: 100,
	}, store, groupSide{s: store})
	if err != nil {
		t.Fatalf("NewSCIMRoutes: %v", err)
	}
	return rt, store
}

// asTenant runs a handler with a validated principal for tenantID —
// exactly what RequireServiceAccount stashes.
func asTenant(h http.HandlerFunc, tenantID, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/scim+json")
	ctx := context.WithValue(req.Context(), principalKey{},
		Principal{ID: "sa-1", TenantID: tenantID, Name: "provisioner", CreatedAt: time.Unix(0, 0)})
	rec := httptest.NewRecorder()
	h(rec, req.WithContext(ctx))
	return rec
}

func bodyOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	b, _ := io.ReadAll(rec.Result().Body)
	return string(b)
}

// --- every verb, both resources ---------------------------------------

// TestSCIMTenancy_CrossTenantDeniedOnEveryVerb is the B5 guard. Tenant
// A's token addresses tenant B's resource by its real id on every verb.
// Each must 404 — and 404 rather than 403, so the response cannot be
// used to discover that the resource exists in another tenant.
func TestSCIMTenancy_CrossTenantDeniedOnEveryVerb(t *testing.T) {
	rt, _ := tenantSCIM(t)

	for _, tc := range []struct {
		name, method, path, body string
		h                        http.HandlerFunc
	}{
		{"users GET", http.MethodGet, "/scim/v2/Users/u-b", "", rt.UsersGet},
		{"users PUT", http.MethodPut, "/scim/v2/Users/u-b", `{"userName":"x@acme.test"}`, rt.UsersReplace},
		{"users PATCH", http.MethodPatch, "/scim/v2/Users/u-b",
			`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`, rt.UsersPatch},
		{"users DELETE", http.MethodDelete, "/scim/v2/Users/u-b", "", rt.UsersDelete},
		{"groups GET", http.MethodGet, "/scim/v2/Groups/g-b", "", rt.GroupsGet},
		{"groups PUT", http.MethodPut, "/scim/v2/Groups/g-b", `{"displayName":"stolen"}`, rt.GroupsReplace},
		{"groups PATCH", http.MethodPatch, "/scim/v2/Groups/g-b",
			`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"stolen"}]}`, rt.GroupsPatch},
		{"groups DELETE", http.MethodDelete, "/scim/v2/Groups/g-b", "", rt.GroupsDelete},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := asTenant(tc.h, tenantA, tc.method, tc.path, tc.body)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404 — tenant %s reached tenant %s's resource. "+
					"Body: %s", rec.Code, tenantA, tenantB, bodyOf(t, rec))
			}
			if strings.Contains(bodyOf(t, rec), "globex") {
				t.Errorf("the refusal disclosed the other tenant: %s", bodyOf(t, rec))
			}
		})
	}
}

// TestSCIMTenancy_404IsByteIdenticalToAGenuineMiss is the DoD line. A
// cross-tenant refusal and a plain not-found must be the same bytes, or
// the difference is an existence oracle for another customer's directory.
func TestSCIMTenancy_404IsByteIdenticalToAGenuineMiss(t *testing.T) {
	rt, _ := tenantSCIM(t)

	for _, tc := range []struct {
		name          string
		h             http.HandlerFunc
		crossID, miss string
		prefix        string
	}{
		{"users", rt.UsersGet, "u-b", "does-not-exist", "/scim/v2/Users/"},
		{"groups", rt.GroupsGet, "g-b", "does-not-exist", "/scim/v2/Groups/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cross := asTenant(tc.h, tenantA, http.MethodGet, tc.prefix+tc.crossID, "")
			miss := asTenant(tc.h, tenantA, http.MethodGet, tc.prefix+tc.miss, "")

			if cross.Code != miss.Code {
				t.Fatalf("status differs: cross-tenant %d, genuine miss %d", cross.Code, miss.Code)
			}
			if got, want := bodyOf(t, cross), bodyOf(t, miss); got != want {
				t.Errorf("bodies differ:\n cross: %s\n  miss: %s", got, want)
			}
			if got, want := cross.Header().Get("Content-Type"), miss.Header().Get("Content-Type"); got != want {
				t.Errorf("content-type differs: %q vs %q", got, want)
			}
		})
	}
}

// TestSCIMTenancy_OwnTenantStillWorks: the denial is not achieved by
// denying everything.
func TestSCIMTenancy_OwnTenantStillWorks(t *testing.T) {
	rt, _ := tenantSCIM(t)
	for _, tc := range []struct {
		name, path string
		h          http.HandlerFunc
	}{
		{"users", "/scim/v2/Users/u-a", rt.UsersGet},
		{"groups", "/scim/v2/Groups/g-a", rt.GroupsGet},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := asTenant(tc.h, tenantA, http.MethodGet, tc.path, "")
			if rec.Code != http.StatusOK {
				t.Errorf("status = %d, want 200 — tenant A cannot read its OWN resource. Body: %s",
					rec.Code, bodyOf(t, rec))
			}
		})
	}
}

// TestSCIMTenancy_ListsAreScoped: a page that included another tenant's
// rows would leak on the first unfiltered request an integration makes.
func TestSCIMTenancy_ListsAreScoped(t *testing.T) {
	rt, _ := tenantSCIM(t)
	for _, tc := range []struct {
		name, path, foreign string
		h                   http.HandlerFunc
	}{
		{"users", "/scim/v2/Users", "b@globex.test", rt.UsersList},
		{"groups", "/scim/v2/Groups", "B team", rt.GroupsList},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := asTenant(tc.h, tenantA, http.MethodGet, tc.path, "")
			if body := bodyOf(t, rec); strings.Contains(body, tc.foreign) {
				t.Errorf("the list leaked another tenant's row: %s", body)
			}
		})
	}
}

// TestSCIMTenancy_EveryCallCarriesThePrincipalsTenant is the structural
// half. The fixture records the tenant each store method was handed;
// every one must be the principal's. This catches a handler that names
// a tenant from anywhere else, which no behavioural assertion would
// notice while the fixture happens to answer correctly.
func TestSCIMTenancy_EveryCallCarriesThePrincipalsTenant(t *testing.T) {
	rt, store := tenantSCIM(t)

	calls := []struct {
		method, path, body string
		h                  http.HandlerFunc
	}{
		{http.MethodPost, "/scim/v2/Users", `{"userName":"n@acme.test"}`, rt.UsersCreate},
		{http.MethodGet, "/scim/v2/Users/u-a", "", rt.UsersGet},
		{http.MethodPut, "/scim/v2/Users/u-a", `{"userName":"n@acme.test"}`, rt.UsersReplace},
		{http.MethodPatch, "/scim/v2/Users/u-a",
			`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`, rt.UsersPatch},
		{http.MethodDelete, "/scim/v2/Users/u-a", "", rt.UsersDelete},
		{http.MethodGet, "/scim/v2/Users", "", rt.UsersList},
		{http.MethodPost, "/scim/v2/Groups", `{"displayName":"New"}`, rt.GroupsCreate},
		{http.MethodGet, "/scim/v2/Groups/g-a", "", rt.GroupsGet},
		{http.MethodPut, "/scim/v2/Groups/g-a", `{"displayName":"New"}`, rt.GroupsReplace},
		{http.MethodPatch, "/scim/v2/Groups/g-a",
			`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"renamed"}]}`, rt.GroupsPatch},
		{http.MethodDelete, "/scim/v2/Groups/g-a", "", rt.GroupsDelete},
		{http.MethodGet, "/scim/v2/Groups", "", rt.GroupsList},
	}
	for _, c := range calls {
		if rec := asTenant(c.h, tenantA, c.method, c.path, c.body); rec.Code >= 400 {
			t.Fatalf("%s %s: status %d (%s) — the call did not reach its store method", c.method, c.path, rec.Code, bodyOf(t, rec))
		}
	}

	for _, got := range store.calls {
		if got != tenantA {
			t.Errorf("a handler passed tenant %q, want %q — the tenant did not come from the "+
				"principal; trace: %v", got, tenantA, store.calls)
		}
	}
	if len(store.calls) == 0 {
		t.Fatal("no store calls recorded; the test proved nothing")
	}
}

// --- the audit actor --------------------------------------------------

// TestSCIMTenancy_ActorCarriesTheTenant: the actor's existing fields keep
// their meaning; the tenant is added, not substituted.
func TestSCIMTenancy_ActorCarriesTheTenant(t *testing.T) {
	var got audit.Actor
	h := RequireServiceAccount(ValidatorFunc(func(context.Context, string) (Principal, error) {
		return Principal{ID: "sa-1", TenantID: tenantB, Name: "provisioner"}, nil
	}))(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = audit.ActorFromContext(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	req.Header.Set("Authorization", "Bearer tok")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if got.TenantID != tenantB {
		t.Errorf("actor TenantID = %q, want %q", got.TenantID, tenantB)
	}
	if got.UserID != "sa-1" || got.Name != "provisioner" {
		t.Errorf("existing actor fields changed meaning: %+v", got)
	}
}

// TestSCIMTenancy_ValidateMembersIsScoped guards the method most likely
// to be left untenanted. Without the tenant, tenant A nests tenant B's
// user into an A group — a cross-tenant WRITE that touches no
// tenant-scoped read path.
func TestSCIMTenancy_ValidateMembersIsScoped(t *testing.T) {
	store := newTenantSCIMStore()
	g := groupSide{s: store}
	ctx := context.Background()

	if err := g.ValidateMembers(ctx, tenant.New(tenantA), []scim.MemberRef{{Value: "u-a"}}); err != nil {
		t.Fatalf("tenant A rejected its own member: %v", err)
	}
	err := g.ValidateMembers(ctx, tenant.New(tenantA), []scim.MemberRef{{Value: "u-b"}})
	if !errors.Is(err, scim.ErrInvalidInput) {
		t.Errorf("tenant A nested tenant B's user into an A group: err = %v", err)
	}
}
