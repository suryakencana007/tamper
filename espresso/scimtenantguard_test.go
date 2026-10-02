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
// request is never turned away by the wire parse before it reaches a store —
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
			for _, want := range []string{"CONFIG_ERROR", "not tenant-scoped", "SCIMConfig.Tenancy", "SCIMConfig.TenantBoundStores"} {
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

// portCall is one method of an unscoped port, called through whatever
// store value a SCIMRoutes holds.
type portCall struct {
	name string
	call func(context.Context) error
}

// everyPortMethod is EVERY method of scim.UserStore and scim.GroupStore —
// seven and eight — not just the ones a handler happens to call. It
// includes the plain List, which has no transport caller, and
// ValidateMembers, which returns only an error and so "succeeds" when left
// open.
func everyPortMethod(users scim.UserStore, groups scim.GroupStore) []portCall {
	return []portCall{
		{"users.Create", func(ctx context.Context) error {
			_, err := users.Create(ctx, scim.UserWrite{}, scim.WriteMeta{})
			return err
		}},
		{"users.Get", func(ctx context.Context) error { _, err := users.Get(ctx, "u-b"); return err }},
		{"users.Replace", func(ctx context.Context) error {
			_, err := users.Replace(ctx, "u-b", scim.UserWrite{}, scim.WriteMeta{})
			return err
		}},
		{"users.Delete", func(ctx context.Context) error { return users.Delete(ctx, "u-b", scim.WriteMeta{}) }},
		{"users.SavePatch", func(ctx context.Context) error {
			_, err := users.SavePatch(ctx, "u-b", scim.UserWrite{}, nil)
			return err
		}},
		{"users.List", func(ctx context.Context) error { _, err := users.List(ctx, 1, 20); return err }},
		{"users.ListFiltered", func(ctx context.Context) error {
			_, err := users.ListFiltered(ctx, 1, 20, "")
			return err
		}},
		{"groups.Create", func(ctx context.Context) error {
			_, err := groups.Create(ctx, scim.GroupWrite{}, scim.GroupWriteMeta{})
			return err
		}},
		{"groups.Get", func(ctx context.Context) error { _, err := groups.Get(ctx, "g-b"); return err }},
		{"groups.Replace", func(ctx context.Context) error {
			_, err := groups.Replace(ctx, "g-b", scim.GroupWrite{}, scim.GroupWriteMeta{})
			return err
		}},
		{"groups.Delete", func(ctx context.Context) error {
			return groups.Delete(ctx, "g-b", scim.GroupWriteMeta{})
		}},
		{"groups.SavePatch", func(ctx context.Context) error {
			_, err := groups.SavePatch(ctx, "g-b", scim.GroupWrite{}, nil)
			return err
		}},
		{"groups.ValidateMembers", func(ctx context.Context) error {
			return groups.ValidateMembers(ctx, []scim.MemberRef{{Value: "u-b"}})
		}},
		{"groups.List", func(ctx context.Context) error { _, err := groups.List(ctx, 1, 20); return err }},
		{"groups.ListFiltered", func(ctx context.Context) error {
			_, err := groups.ListFiltered(ctx, 1, 20, "")
			return err
		}},
	}
}

// TestSCIMTenantGuard_GuardsEveryMethodOfBothPorts is the half the handler
// test cannot reach. A handler stops at its FIRST refusal — PUT never gets
// past its Get, a Group PUT never past ValidateMembers — so the guards on
// Replace, Delete and SavePatch sit behind one that already fired, and
// List sits behind no handler at all.
//
// It calls the stores the ROUTES hold (rt.users / rt.groups), not a guard
// built by hand, so it proves what a handler written tomorrow would get
// from those fields: every method refuses a tenant-bound credential before
// the application's store runs, and every method still delegates — once —
// for a single-tenant one.
func TestSCIMTenantGuard_GuardsEveryMethodOfBothPorts(t *testing.T) {
	rt, store := untenantedSCIM(t)
	bound := context.WithValue(context.Background(), principalKey{},
		Principal{ID: "sa-1", TenantID: tenantA})
	single := context.WithValue(context.Background(), principalKey{},
		Principal{ID: "sa-1"})

	methods := everyPortMethod(rt.users, rt.groups)
	if len(methods) != 15 {
		t.Fatalf("%d port methods listed, want 15 (7 on UserStore, 8 on GroupStore)", len(methods))
	}
	for _, tc := range methods {
		t.Run(tc.name, func(t *testing.T) {
			before := len(store.calls)
			if err := tc.call(bound); !errors.Is(err, errSCIMNotTenantScoped) {
				t.Errorf("tenant-bound: err = %v, want errSCIMNotTenantScoped", err)
			}
			if got := store.calls[before:]; len(got) != 0 {
				t.Errorf("tenant-bound: the guard reached the store before refusing: %v", got)
			}

			before = len(store.calls)
			if err := tc.call(single); err != nil {
				t.Errorf("single-tenant: err = %v, want nil — the guard refuses everything", err)
			}
			if got := store.calls[before:]; len(got) != 1 || got[0] != "UNSCOPED" {
				t.Errorf("single-tenant: store calls = %v, want exactly one UNSCOPED — the "+
					"guard did not delegate to the method it wraps", got)
			}
		})
	}
}

// TestSCIMTenantGuard_RoutesHoldTheGuardedStores is the structural half:
// the guard is only worth anything if it is what s.users / s.groups
// actually hold. If NewSCIMRoutes ever stores the application's store
// directly again, every handler — present and future — is back to calling
// an unguarded store, and no behavioural test of today's handlers is
// obliged to notice a handler that does not exist yet.
func TestSCIMTenantGuard_RoutesHoldTheGuardedStores(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  SCIMConfig
	}{
		{"tenancy off", SCIMConfig{Prefix: "/scim/v2", MaxResults: 100}},
		// With Tenancy on no shim calls these fields, and they are guarded
		// all the same.
		{"tenancy on", SCIMConfig{Prefix: "/scim/v2", MaxResults: 100, Tenancy: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newTenantSCIMStore()
			groups := groupSide{s: store}
			rt, err := NewSCIMRoutes(tc.cfg, store, groups)
			if err != nil {
				t.Fatalf("NewSCIMRoutes: %v", err)
			}
			gu, ok := rt.users.(guardedUserStore)
			if !ok {
				t.Fatalf("rt.users is %T, want guardedUserStore — the routes hold an "+
					"unguarded UserStore", rt.users)
			}
			gg, ok := rt.groups.(guardedGroupStore)
			if !ok {
				t.Fatalf("rt.groups is %T, want guardedGroupStore — the routes hold an "+
					"unguarded GroupStore", rt.groups)
			}
			// And the guard is around the application's store, not around
			// nothing or another guard.
			if gu.next != scim.UserStore(store) {
				t.Errorf("the user guard wraps %T, want the application's store", gu.next)
			}
			if gg.next != scim.GroupStore(groups) {
				t.Errorf("the group guard wraps %T, want the application's store", gg.next)
			}
		})
	}

	// The guard must not be what the TenantScoped* assertion sees. If it
	// were, a store that CAN scope would be reported as one that cannot.
	if _, ok := scim.UserStore(guardedUserStore{}).(scim.TenantScopedUserStore); ok {
		t.Error("guardedUserStore satisfies TenantScopedUserStore; it must stay the unscoped port only")
	}
	if _, ok := scim.GroupStore(guardedGroupStore{}).(scim.TenantScopedGroupStore); ok {
		t.Error("guardedGroupStore satisfies TenantScopedGroupStore; it must stay the unscoped port only")
	}
}

// --- the opt-out -------------------------------------------------------

// tenantBoundSCIM is a deployment that DECLARED its unscoped stores safe.
// The fixture's stores are in fact shared by two tenants, which is exactly
// the misuse the flag's doc warns about — and what makes it a usable
// probe: "UNSCOPED" in the trace is the proof the guard stood down.
func tenantBoundSCIM(t *testing.T) (*SCIMRoutes, *tenantSCIMStore) {
	t.Helper()
	store := newTenantSCIMStore()
	rt, err := NewSCIMRoutes(SCIMConfig{
		Prefix: "/scim/v2", BaseURL: "https://panel.test", MaxResults: 100,
		TenantBoundStores: true,
	}, store, groupSide{s: store})
	if err != nil {
		t.Fatalf("NewSCIMRoutes: %v", err)
	}
	return rt, store
}

// TestSCIMTenantBoundStores_TenantBoundCredentialIsServed: with the
// declaration made, a tenant-bound principal gets what a single-tenant one
// gets on every verb — same status, same unscoped store methods, same
// number of them. A deployment that isolates its directory another way,
// and sets Principal.TenantID for entitlements or throttling, must not be
// answered 500 on every request.
func TestSCIMTenantBoundStores_TenantBoundCredentialIsServed(t *testing.T) {
	rt, store := tenantBoundSCIM(t)

	for _, tc := range scimEveryVerb(rt) {
		t.Run(tc.name, func(t *testing.T) {
			before := len(store.calls)
			rec := asTenant(tc.h, tenantA, tc.method, tc.path, tc.body)

			if rec.Code != tc.singleStatus {
				t.Fatalf("status = %d, want %d — TenantBoundStores did not lift the refusal. "+
					"Body: %s", rec.Code, tc.singleStatus, bodyOf(t, rec))
			}
			calls := store.calls[before:]
			if len(calls) != tc.singleCalls {
				t.Errorf("store calls = %v, want %d of them", calls, tc.singleCalls)
			}
			for _, got := range calls {
				if got != "UNSCOPED" {
					t.Errorf("an opted-out request was routed to a scoped method with "+
						"tenant %q; calls = %v", got, calls)
				}
			}
		})
	}
}

// TestSCIMTenantBoundStores_KeepsTheStoresBare: the declared path is the
// pre-guard code with nothing in between — not a guard switched off.
func TestSCIMTenantBoundStores_KeepsTheStoresBare(t *testing.T) {
	rt, store := tenantBoundSCIM(t)
	if rt.users != scim.UserStore(store) {
		t.Errorf("rt.users is %T, want the application's own store", rt.users)
	}
	if rt.groups != scim.GroupStore(groupSide{s: store}) {
		t.Errorf("rt.groups is %T, want the application's own store", rt.groups)
	}
}

// TestSCIMTenantBoundStores_ContradictsTenancy is standing rule 4: the two
// flags answer the same question in opposite ways, and that must fail at
// New — not be resolved quietly in favour of one of them.
func TestSCIMTenantBoundStores_ContradictsTenancy(t *testing.T) {
	// Stores that CAN scope, so the only thing wrong with this config is
	// the contradiction; a store-type error would pass a bare err != nil.
	store := newTenantSCIMStore()
	rt, err := NewSCIMRoutes(SCIMConfig{
		Prefix: "/scim/v2", MaxResults: 100, Tenancy: true, TenantBoundStores: true,
	}, store, groupSide{s: store})
	if err == nil {
		t.Fatal("NewSCIMRoutes accepted Tenancy together with TenantBoundStores")
	}
	if rt != nil {
		t.Error("NewSCIMRoutes returned routes alongside the error")
	}
	for _, want := range []string{"SCIMConfig.Tenancy", "SCIMConfig.TenantBoundStores"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not name %s: %v", want, err)
		}
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
