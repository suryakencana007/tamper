package espresso

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	scim "github.com/suryakencana007/tamper/scim"
)

// TD-15 — the SCIM surface built with the DEFAULT config (Tenancy unset)
// and handed a tenant-bound credential. The unscoped store methods take no
// tenant, so before the guard this compiled, booted, and served tenant A's
// service account every tenant's directory. It must refuse instead, before
// the store is touched, and leave the single-tenant path exactly alone.

// untenantedSCIM builds the surface the way a pooled deployment that
// forgot the flag would: stores that COULD scope by tenant, and a config
// that never asked them to.
func untenantedSCIM(t *testing.T) (*SCIMRoutes, *tenantSCIMStore) {
	t.Helper()
	store := newTenantSCIMStore()
	rt, err := NewSCIMRoutes(SCIMConfig{
		Prefix: "/scim/v2", BaseURL: "https://panel.test", MaxResults: 100,
		// Tenancy left at its default.
	}, store, groupSide{s: store})
	if err != nil {
		t.Fatalf("NewSCIMRoutes: %v", err)
	}
	return rt, store
}

const (
	userPatchBody  = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`
	groupPatchBody = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"renamed"}]}`
)

// scimVerb is one request against the surface. Every body is VALID, so a
// request is never turned away by the wire parse before it reaches a shim —
// a 400 for a malformed body would pass a "was it refused" assertion while
// proving nothing about the guard.
type scimVerb struct {
	name, method, path, body string
	h                        http.HandlerFunc
	// singleStatus and singleCalls are what the same request does on a
	// single-tenant deployment: its status, and how many store methods the
	// handler runs to get there.
	singleStatus, singleCalls int
}

// scimEveryVerb is the whole resource surface: six verbs, both resources.
// The ids are tenant B's, so a tenant-A principal is asking for another
// customer's rows on every line.
func scimEveryVerb(rt *SCIMRoutes) []scimVerb {
	return []scimVerb{
		{"users CREATE", http.MethodPost, "/scim/v2/Users", `{"userName":"n@acme.test"}`, rt.UsersCreate, http.StatusCreated, 1},
		{"users GET", http.MethodGet, "/scim/v2/Users/u-b", "", rt.UsersGet, http.StatusOK, 1},
		{"users PUT", http.MethodPut, "/scim/v2/Users/u-b", `{"userName":"x@acme.test"}`, rt.UsersReplace, http.StatusOK, 2},
		{"users PATCH", http.MethodPatch, "/scim/v2/Users/u-b", userPatchBody, rt.UsersPatch, http.StatusOK, 2},
		{"users DELETE", http.MethodDelete, "/scim/v2/Users/u-b", "", rt.UsersDelete, http.StatusNoContent, 2},
		{"users LIST", http.MethodGet, "/scim/v2/Users", "", rt.UsersList, http.StatusOK, 1},
		{"groups CREATE", http.MethodPost, "/scim/v2/Groups", `{"displayName":"New","members":[{"value":"u-b"}]}`, rt.GroupsCreate, http.StatusCreated, 1},
		{"groups GET", http.MethodGet, "/scim/v2/Groups/g-b", "", rt.GroupsGet, http.StatusOK, 1},
		{"groups PUT", http.MethodPut, "/scim/v2/Groups/g-b", `{"displayName":"stolen","members":[{"value":"u-b"}]}`, rt.GroupsReplace, http.StatusOK, 3},
		{"groups PATCH", http.MethodPatch, "/scim/v2/Groups/g-b", groupPatchBody, rt.GroupsPatch, http.StatusOK, 2},
		{"groups DELETE", http.MethodDelete, "/scim/v2/Groups/g-b", "", rt.GroupsDelete, http.StatusNoContent, 2},
		{"groups LIST", http.MethodGet, "/scim/v2/Groups", "", rt.GroupsList, http.StatusOK, 1},
	}
}

// TestSCIMTenancyOff_TenantBoundCredentialIsRefusedOnEveryVerb is the
// TD-15 regression. Default config, tenant A's principal, tenant B's
// resources: every verb must answer the CONFIG_ERROR envelope and no store
// method — scoped or unscoped — may run.
func TestSCIMTenancyOff_TenantBoundCredentialIsRefusedOnEveryVerb(t *testing.T) {
	rt, store := untenantedSCIM(t)

	var first string
	for _, tc := range scimEveryVerb(rt) {
		t.Run(tc.name, func(t *testing.T) {
			rec := asTenant(tc.h, tenantA, tc.method, tc.path, tc.body)
			body := bodyOf(t, rec)

			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500 — a tenant-bound credential was served by a "+
					"surface that cannot scope it. Body: %s", rec.Code, body)
			}
			if got := rec.Header().Get("Content-Type"); got != ContentTypeSCIM {
				t.Errorf("Content-Type = %q, want %q", got, ContentTypeSCIM)
			}
			var env SCIMError
			if err := json.Unmarshal([]byte(body), &env); err != nil {
				t.Fatalf("the refusal is not a SCIM envelope: %v (body %s)", err, body)
			}
			if len(env.Schemas) != 1 || env.Schemas[0] != SchemaError || env.Status != "500" {
				t.Errorf("not the RFC 7644 §3.12 error shape: %+v", env)
			}
			// The operator reads this in their IdP's provisioning log; it
			// has to say what is wrong and which setting fixes it.
			for _, want := range []string{"CONFIG_ERROR", "not tenant-scoped", "SCIMConfig.Tenancy"} {
				if !strings.Contains(env.Detail, want) {
					t.Errorf("detail %q does not mention %q", env.Detail, want)
				}
			}
			// And it must say nothing else: no tenant, no row.
			for _, leak := range []string{tenantA, tenantB, "leaked", "u-b", "g-b"} {
				if strings.Contains(body, leak) {
					t.Errorf("the refusal disclosed %q: %s", leak, body)
				}
			}
			// One answer for every verb and every id. A refusal that varied
			// with the resource would be an existence oracle.
			if first == "" {
				first = body
			}
			if body != first {
				t.Errorf("the refusal differs between verbs:\n first: %s\n  this: %s", first, body)
			}
		})
	}

	for _, got := range store.calls {
		if got == "UNSCOPED" {
			t.Fatalf("the default SCIMConfig reached the UNSCOPED store with a tenant-bound "+
				"credential: calls = %v (the principal's tenant %q was never passed down)",
				store.calls, tenantA)
		}
	}
	if len(store.calls) != 0 {
		t.Fatalf("a refused request still reached the store: calls = %v", store.calls)
	}
}

// TestSCIMTenancyOff_RefusalDoesNotDependOnTheResource: a real id in
// another tenant, a real id in the caller's own tenant, and an id that
// exists nowhere must be indistinguishable.
func TestSCIMTenancyOff_RefusalDoesNotDependOnTheResource(t *testing.T) {
	rt, _ := untenantedSCIM(t)

	for _, tc := range []struct {
		name, prefix string
		h            http.HandlerFunc
		ids          []string
	}{
		{"users", "/scim/v2/Users/", rt.UsersGet, []string{"u-b", "u-a", "does-not-exist"}},
		{"groups", "/scim/v2/Groups/", rt.GroupsGet, []string{"g-b", "g-a", "does-not-exist"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var code int
			var body string
			for i, id := range tc.ids {
				rec := asTenant(tc.h, tenantA, http.MethodGet, tc.prefix+id, "")
				if i == 0 {
					code, body = rec.Code, bodyOf(t, rec)
					// Pinned, or three identical 200s would pass.
					if code != http.StatusInternalServerError {
						t.Fatalf("status = %d, want 500. Body: %s", code, body)
					}
					continue
				}
				if rec.Code != code || bodyOf(t, rec) != body {
					t.Errorf("id %q answered %d %s, but %q answered %d %s",
						id, rec.Code, bodyOf(t, rec), tc.ids[0], code, body)
				}
			}
		})
	}
}

// TestSCIMTenancyOff_EveryShimRefusesATenantBoundCredential guards the
// shims the handler test cannot reach. A handler stops at its FIRST
// refusal — PUT never gets past its Get, a Group PUT never past
// ValidateMembers — so the guards on Replace, Delete and SavePatch sit
// behind one that already fired. They are not redundant: the day a handler
// is reordered, or a new one calls a write shim directly, they are the
// only thing in the way. So each shim is called on its own.
func TestSCIMTenancyOff_EveryShimRefusesATenantBoundCredential(t *testing.T) {
	rt, store := untenantedSCIM(t)
	ctx := context.WithValue(context.Background(), principalKey{},
		Principal{ID: "sa-1", TenantID: tenantA})

	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"userCreate", func() error { _, err := rt.userCreate(ctx, scim.UserWrite{}, scim.WriteMeta{}); return err }},
		{"userGet", func() error { _, err := rt.userGet(ctx, "u-b"); return err }},
		{"userReplace", func() error { _, err := rt.userReplace(ctx, "u-b", scim.UserWrite{}, scim.WriteMeta{}); return err }},
		{"userDelete", func() error { return rt.userDelete(ctx, "u-b", scim.WriteMeta{}) }},
		{"userSavePatch", func() error { _, err := rt.userSavePatch(ctx, "u-b", scim.UserWrite{}, nil); return err }},
		{"userListFiltered", func() error { _, err := rt.userListFiltered(ctx, 1, 20, ""); return err }},
		{"groupCreate", func() error { _, err := rt.groupCreate(ctx, scim.GroupWrite{}, scim.GroupWriteMeta{}); return err }},
		{"groupGet", func() error { _, err := rt.groupGet(ctx, "g-b"); return err }},
		{"groupReplace", func() error {
			_, err := rt.groupReplace(ctx, "g-b", scim.GroupWrite{}, scim.GroupWriteMeta{})
			return err
		}},
		{"groupDelete", func() error { return rt.groupDelete(ctx, "g-b", scim.GroupWriteMeta{}) }},
		{"groupSavePatch", func() error { _, err := rt.groupSavePatch(ctx, "g-b", scim.GroupWrite{}, nil); return err }},
		// The one most likely to be left open: it returns only an error, so
		// an unguarded call "succeeds" and tenant B's user is nested into
		// an A group by the write that follows.
		{"groupValidateMembers", func() error {
			return rt.groupValidateMembers(ctx, []scim.MemberRef{{Value: "u-b"}})
		}},
		{"groupListFiltered", func() error { _, err := rt.groupListFiltered(ctx, 1, 20, ""); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := len(store.calls)
			err := tc.call()
			if !errors.Is(err, errSCIMNotTenantScoped) {
				t.Errorf("err = %v, want errSCIMNotTenantScoped", err)
			}
			if got := store.calls[before:]; len(got) != 0 {
				t.Errorf("the shim reached the store before refusing: %v", got)
			}
		})
	}
}

// TestSCIMTenancyOff_SingleTenantPrincipalStillReachesTheUnscopedStore is
// standing rule 1 for this guard, and the proof it is not achieved by
// refusing everything. A principal with an EMPTY TenantID is the
// single-tenant deployment — Barista's shape — and must get exactly what it
// got before: the same status, from the same unscoped store methods, the
// same number of them.
func TestSCIMTenancyOff_SingleTenantPrincipalStillReachesTheUnscopedStore(t *testing.T) {
	rt, store := untenantedSCIM(t)

	for _, tc := range scimEveryVerb(rt) {
		t.Run(tc.name, func(t *testing.T) {
			before := len(store.calls)
			rec := asTenant(tc.h, "", tc.method, tc.path, tc.body)

			if rec.Code != tc.singleStatus {
				t.Fatalf("status = %d, want %d — the guard changed the single-tenant path. "+
					"Body: %s", rec.Code, tc.singleStatus, bodyOf(t, rec))
			}
			calls := store.calls[before:]
			if len(calls) != tc.singleCalls {
				t.Errorf("store calls = %v, want %d of them", calls, tc.singleCalls)
			}
			for _, got := range calls {
				if got != "UNSCOPED" {
					t.Errorf("a single-tenant request was routed to a scoped method with "+
						"tenant %q; calls = %v", got, calls)
				}
			}
		})
	}
}

// TestRequireUntenanted pins the predicate itself, including the two edges
// a rewrite is most likely to move.
func TestRequireUntenanted(t *testing.T) {
	with := func(p Principal) context.Context {
		return context.WithValue(context.Background(), principalKey{}, p)
	}
	for _, tc := range []struct {
		name   string
		ctx    context.Context
		refuse bool
	}{
		// No principal: the pre-guard behaviour, untouched. A MustGetPrincipal
		// here would turn every unauthenticated mount into a panic.
		{"no principal", context.Background(), false},
		{"single-tenant principal", with(Principal{ID: "sa-1"}), false},
		{"tenant-bound principal", with(Principal{ID: "sa-1", TenantID: tenantA}), true},
		// GetPrincipal reports ok=false for an empty ID. A guard that
		// trusted ok would wave this one through.
		{"tenant-bound principal with no ID", with(Principal{TenantID: tenantA}), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := requireUntenanted(tc.ctx)
			if tc.refuse && !errors.Is(err, errSCIMNotTenantScoped) {
				t.Errorf("err = %v, want errSCIMNotTenantScoped", err)
			}
			if !tc.refuse && err != nil {
				t.Errorf("err = %v, want nil", err)
			}
		})
	}
}

// TestSCIMTenancyOff_DiscoveryIsNotGuarded: ServiceProviderConfig,
// ResourceTypes and Schemas touch no store, so there is nothing for the
// guard to protect and nothing for it to break. They are commonly mounted
// unauthenticated; both that and a tenant-bound caller must get the same
// document they always did.
func TestSCIMTenancyOff_DiscoveryIsNotGuarded(t *testing.T) {
	rt, store := untenantedSCIM(t)

	for _, tc := range []struct {
		name, path string
		h          http.HandlerFunc
	}{
		{"ServiceProviderConfig", "/scim/v2/ServiceProviderConfig", rt.ServiceProviderConfig},
		{"ResourceTypes", "/scim/v2/ResourceTypes", rt.ResourceTypes},
		{"Schemas", "/scim/v2/Schemas", rt.Schemas},
	} {
		t.Run(tc.name, func(t *testing.T) {
			anon := httptest.NewRecorder()
			tc.h(anon, httptest.NewRequest(http.MethodGet, tc.path, nil))
			bound := asTenant(tc.h, tenantA, http.MethodGet, tc.path, "")

			if anon.Code != http.StatusOK || bound.Code != http.StatusOK {
				t.Fatalf("statuses = %d (unauthenticated) / %d (tenant-bound), want 200 / 200",
					anon.Code, bound.Code)
			}
			if got, want := bodyOf(t, bound), bodyOf(t, anon); got != want {
				t.Errorf("discovery differs for a tenant-bound caller:\n anon: %s\n bound: %s", want, got)
			}
		})
	}
	if len(store.calls) != 0 {
		t.Errorf("discovery reached the store: %v", store.calls)
	}
}
