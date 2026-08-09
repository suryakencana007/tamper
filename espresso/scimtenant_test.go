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
)

// Slice 7g-1 — SCIM principal tenancy (B5). Tenant A's token must not
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

var _ scim.TenantScopedUserStore = (*tenantSCIMStore)(nil)

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

func (s *tenantSCIMStore) note(t string) { s.calls = append(s.calls, t) }

// --- tenant-scoped users ---

func (s *tenantSCIMStore) CreateInTenant(_ context.Context, t string, w scim.UserWrite, _ scim.WriteMeta) (scim.UserRecord, error) {
	s.note(t)
	rec := scim.UserRecord{ID: "new-" + t, UserName: w.UserName, Active: true}
	s.users[t][rec.ID] = rec
	return rec, nil
}

func (s *tenantSCIMStore) GetInTenant(_ context.Context, t, id string) (scim.UserRecord, error) {
	s.note(t)
	rec, ok := s.users[t][id]
	if !ok {
		return scim.UserRecord{}, scim.ErrNotFound
	}
	return rec, nil
}

func (s *tenantSCIMStore) ReplaceInTenant(_ context.Context, t, id string, w scim.UserWrite, _ scim.WriteMeta) (scim.UserRecord, error) {
	s.note(t)
	if _, ok := s.users[t][id]; !ok {
		return scim.UserRecord{}, scim.ErrNotFound
	}
	rec := scim.UserRecord{ID: id, UserName: w.UserName, Active: true}
	s.users[t][id] = rec
	return rec, nil
}

func (s *tenantSCIMStore) DeleteInTenant(_ context.Context, t, id string, _ scim.WriteMeta) error {
	s.note(t)
	if _, ok := s.users[t][id]; !ok {
		return scim.ErrNotFound
	}
	delete(s.users[t], id)
	return nil
}

func (s *tenantSCIMStore) SavePatchInTenant(_ context.Context, t, id string, w scim.UserWrite, _ []scim.Operation) (scim.UserRecord, error) {
	s.note(t)
	if _, ok := s.users[t][id]; !ok {
		return scim.UserRecord{}, scim.ErrNotFound
	}
	rec := scim.UserRecord{ID: id, UserName: w.UserName, Active: w.Active}
	s.users[t][id] = rec
	return rec, nil
}

func (s *tenantSCIMStore) ListInTenant(_ context.Context, t string, _, _ int) (scim.UserPage, error) {
	s.note(t)
	return s.userPage(t), nil
}

func (s *tenantSCIMStore) ListFilteredInTenant(_ context.Context, t string, _, _ int, _ string) (scim.UserPage, error) {
	s.note(t)
	return s.userPage(t), nil
}

func (s *tenantSCIMStore) userPage(t string) scim.UserPage {
	out := make([]scim.UserRecord, 0, len(s.users[t]))
	for _, r := range s.users[t] {
		out = append(out, r)
	}
	return scim.UserPage{Users: out, Total: len(out)}
}

// --- tenant-scoped groups ---

func (s *tenantSCIMStore) groupCreateInTenant(t string, w scim.GroupWrite) scim.GroupRecord {
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

// --- the untenanted halves, required by the embedded base interfaces ---
// They are never reached with Tenancy on; a test below proves it.

func (s *tenantSCIMStore) Create(context.Context, scim.UserWrite, scim.WriteMeta) (scim.UserRecord, error) {
	s.note("UNSCOPED")
	return scim.UserRecord{ID: "leaked"}, nil
}
func (s *tenantSCIMStore) Get(context.Context, string) (scim.UserRecord, error) {
	s.note("UNSCOPED")
	return scim.UserRecord{ID: "leaked"}, nil
}
func (s *tenantSCIMStore) Replace(context.Context, string, scim.UserWrite, scim.WriteMeta) (scim.UserRecord, error) {
	s.note("UNSCOPED")
	return scim.UserRecord{ID: "leaked"}, nil
}
func (s *tenantSCIMStore) Delete(context.Context, string, scim.WriteMeta) error {
	s.note("UNSCOPED")
	return nil
}
func (s *tenantSCIMStore) SavePatch(context.Context, string, scim.UserWrite, []scim.Operation) (scim.UserRecord, error) {
	s.note("UNSCOPED")
	return scim.UserRecord{ID: "leaked"}, nil
}
func (s *tenantSCIMStore) List(context.Context, int, int) (scim.UserPage, error) {
	s.note("UNSCOPED")
	return scim.UserPage{}, nil
}
func (s *tenantSCIMStore) ListFiltered(context.Context, int, int, string) (scim.UserPage, error) {
	s.note("UNSCOPED")
	return scim.UserPage{}, nil
}

// groupSide adapts the same backing maps to the Group port. Separate
// type because Go cannot have two methods with one name on one type.
type groupSide struct{ s *tenantSCIMStore }

var _ scim.TenantScopedGroupStore = groupSide{}

func (g groupSide) CreateInTenant(_ context.Context, t string, w scim.GroupWrite, _ scim.GroupWriteMeta) (scim.GroupRecord, error) {
	g.s.note(t)
	return g.s.groupCreateInTenant(t, w), nil
}
func (g groupSide) GetInTenant(_ context.Context, t, id string) (scim.GroupRecord, error) {
	g.s.note(t)
	rec, ok := g.s.groups[t][id]
	if !ok {
		return scim.GroupRecord{}, scim.ErrNotFound
	}
	return rec, nil
}
func (g groupSide) ReplaceInTenant(_ context.Context, t, id string, w scim.GroupWrite, _ scim.GroupWriteMeta) (scim.GroupRecord, error) {
	g.s.note(t)
	if _, ok := g.s.groups[t][id]; !ok {
		return scim.GroupRecord{}, scim.ErrNotFound
	}
	rec := scim.GroupRecord{ID: id, DisplayName: w.DisplayName}
	g.s.groups[t][id] = rec
	return rec, nil
}
func (g groupSide) DeleteInTenant(_ context.Context, t, id string, _ scim.GroupWriteMeta) error {
	g.s.note(t)
	if _, ok := g.s.groups[t][id]; !ok {
		return scim.ErrNotFound
	}
	delete(g.s.groups[t], id)
	return nil
}
func (g groupSide) SavePatchInTenant(_ context.Context, t, id string, w scim.GroupWrite, _ []scim.Operation) (scim.GroupRecord, error) {
	g.s.note(t)
	if _, ok := g.s.groups[t][id]; !ok {
		return scim.GroupRecord{}, scim.ErrNotFound
	}
	rec := scim.GroupRecord{ID: id, DisplayName: w.DisplayName}
	g.s.groups[t][id] = rec
	return rec, nil
}
func (g groupSide) ValidateMembersInTenant(_ context.Context, t string, members []scim.MemberRef) error {
	g.s.note(t)
	// The dangerous one: a member must belong to THIS tenant.
	for _, m := range members {
		if _, ok := g.s.users[t][m.Value]; !ok {
			return scim.ErrInvalidInput
		}
	}
	return nil
}
func (g groupSide) ListInTenant(_ context.Context, t string, _, _ int) (scim.GroupPage, error) {
	g.s.note(t)
	return g.s.groupPage(t), nil
}
func (g groupSide) ListFilteredInTenant(_ context.Context, t string, _, _ int, _ string) (scim.GroupPage, error) {
	g.s.note(t)
	return g.s.groupPage(t), nil
}
func (g groupSide) Create(context.Context, scim.GroupWrite, scim.GroupWriteMeta) (scim.GroupRecord, error) {
	g.s.note("UNSCOPED")
	return scim.GroupRecord{ID: "leaked"}, nil
}
func (g groupSide) Get(context.Context, string) (scim.GroupRecord, error) {
	g.s.note("UNSCOPED")
	return scim.GroupRecord{ID: "leaked"}, nil
}
func (g groupSide) Replace(context.Context, string, scim.GroupWrite, scim.GroupWriteMeta) (scim.GroupRecord, error) {
	g.s.note("UNSCOPED")
	return scim.GroupRecord{ID: "leaked"}, nil
}
func (g groupSide) Delete(context.Context, string, scim.GroupWriteMeta) error {
	g.s.note("UNSCOPED")
	return nil
}
func (g groupSide) SavePatch(context.Context, string, scim.GroupWrite, []scim.Operation) (scim.GroupRecord, error) {
	g.s.note("UNSCOPED")
	return scim.GroupRecord{ID: "leaked"}, nil
}
func (g groupSide) ValidateMembers(context.Context, []scim.MemberRef) error {
	g.s.note("UNSCOPED")
	return nil
}
func (g groupSide) List(context.Context, int, int) (scim.GroupPage, error) {
	g.s.note("UNSCOPED")
	return scim.GroupPage{}, nil
}
func (g groupSide) ListFiltered(context.Context, int, int, string) (scim.GroupPage, error) {
	g.s.note("UNSCOPED")
	return scim.GroupPage{}, nil
}

// --- harness ----------------------------------------------------------

func tenantSCIM(t *testing.T) (*SCIMRoutes, *tenantSCIMStore) {
	t.Helper()
	store := newTenantSCIMStore()
	rt, err := NewSCIMRoutes(SCIMConfig{
		Prefix: "/scim/v2", BaseURL: "https://panel.test", MaxResults: 100, Tenancy: true,
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

// TestSCIMTenancy_NeverReachesTheUnscopedStore is the structural half.
// The fixture's untenanted methods record "UNSCOPED"; with Tenancy on,
// not one of them may be called. This catches a handler that was never
// repointed at a shim, which no behavioural assertion would notice while
// the fixture happens to answer correctly.
func TestSCIMTenancy_NeverReachesTheUnscopedStore(t *testing.T) {
	rt, store := tenantSCIM(t)

	calls := []struct {
		method, path, body string
		h                  http.HandlerFunc
	}{
		{http.MethodPost, "/scim/v2/Users", `{"userName":"n@acme.test"}`, rt.UsersCreate},
		{http.MethodGet, "/scim/v2/Users/u-a", "", rt.UsersGet},
		{http.MethodPut, "/scim/v2/Users/u-a", `{"userName":"n@acme.test"}`, rt.UsersReplace},
		{http.MethodDelete, "/scim/v2/Users/u-a", "", rt.UsersDelete},
		{http.MethodGet, "/scim/v2/Users", "", rt.UsersList},
		{http.MethodPost, "/scim/v2/Groups", `{"displayName":"New"}`, rt.GroupsCreate},
		{http.MethodGet, "/scim/v2/Groups/g-a", "", rt.GroupsGet},
		{http.MethodPut, "/scim/v2/Groups/g-a", `{"displayName":"New"}`, rt.GroupsReplace},
		{http.MethodDelete, "/scim/v2/Groups/g-a", "", rt.GroupsDelete},
		{http.MethodGet, "/scim/v2/Groups", "", rt.GroupsList},
	}
	for _, c := range calls {
		_ = asTenant(c.h, tenantA, c.method, c.path, c.body)
	}

	for _, got := range store.calls {
		if got == "UNSCOPED" {
			t.Fatalf("a handler reached the UNSCOPED store with tenancy on; call trace: %v", store.calls)
		}
		if got != tenantA {
			t.Errorf("a handler passed tenant %q, want %q — the tenant did not come from the "+
				"principal; trace: %v", got, tenantA, store.calls)
		}
	}
	if len(store.calls) == 0 {
		t.Fatal("no store calls recorded; the test proved nothing")
	}
}

// --- the boot guard ---------------------------------------------------

func TestSCIMTenancy_BootGuardNamesTheConcreteType(t *testing.T) {
	_, err := NewSCIMRoutes(SCIMConfig{Prefix: "/scim/v2", MaxResults: 100, Tenancy: true},
		stubUserStore{}, stubGroupStore{})
	if err == nil {
		t.Fatal("NewSCIMRoutes accepted stores that cannot scope by tenant")
	}
	if !strings.Contains(err.Error(), "TenantScopedUserStore") {
		t.Errorf("error does not name the required interface: %v", err)
	}
	if !strings.Contains(err.Error(), "stubUserStore") {
		t.Errorf("error does not name the concrete type: %v", err)
	}
}

func TestSCIMTenancy_BootGuardChecksGroupsToo(t *testing.T) {
	store := newTenantSCIMStore()
	// Users can scope; groups cannot.
	_, err := NewSCIMRoutes(SCIMConfig{Prefix: "/scim/v2", MaxResults: 100, Tenancy: true},
		store, stubGroupStore{})
	if err == nil {
		t.Fatal("NewSCIMRoutes accepted a GroupStore that cannot scope by tenant")
	}
	if !strings.Contains(err.Error(), "TenantScopedGroupStore") {
		t.Errorf("error does not name the group interface: %v", err)
	}
}

// TestSCIMTenancy_DisabledAcceptsPlainStores: the compatibility path.
func TestSCIMTenancy_DisabledAcceptsPlainStores(t *testing.T) {
	rt, err := NewSCIMRoutes(SCIMConfig{Prefix: "/scim/v2", MaxResults: 100},
		stubUserStore{}, stubGroupStore{})
	if err != nil {
		t.Fatalf("tenancy off rejected plain stores: %v", err)
	}
	if rt.tenantUsers != nil || rt.tenantGroups != nil {
		t.Error("tenancy-off routes captured scoped stores")
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

	if err := g.ValidateMembersInTenant(ctx, tenantA, []scim.MemberRef{{Value: "u-a"}}); err != nil {
		t.Fatalf("tenant A rejected its own member: %v", err)
	}
	err := g.ValidateMembersInTenant(ctx, tenantA, []scim.MemberRef{{Value: "u-b"}})
	if !errors.Is(err, scim.ErrInvalidInput) {
		t.Errorf("tenant A nested tenant B's user into an A group: err = %v", err)
	}
}
