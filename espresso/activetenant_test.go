package espresso

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/suryakencana007/tamper/tenant"
)

var (
	tidAcme   = tenant.New("acme")
	tidGlobex = tenant.New("globex")
)

// statusStore is a tenant.Store whose answers the test controls.
type statusStore struct {
	byID map[string]tenant.Descriptor
	err  error
	// calls records every lookup, so a test can prove the store was not
	// consulted (the single-tenant case).
	calls []string
}

func (s *statusStore) ByID(_ context.Context, id string) (tenant.Descriptor, error) {
	s.calls = append(s.calls, id)
	if s.err != nil {
		return tenant.Descriptor{}, s.err
	}
	if d, ok := s.byID[id]; ok {
		return d, nil
	}
	return tenant.Descriptor{}, tenant.ErrNotFound
}

func (s *statusStore) BySlug(context.Context, string) (tenant.Descriptor, error) {
	return tenant.Descriptor{}, tenant.ErrNotFound
}

// doubleWriter writes a distinct status+body per writer, so a test can tell
// which one ran.
func doubleWriter(code int, body string) DenyWriter {
	return func(w http.ResponseWriter) {
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}
}

const (
	missBody  = "not found"
	errorBody = "internal"
)

// chain mounts the gate the way the sketch requires: behind a tenant pin.
func chain(id tenant.ID, g ActiveTenantGate, next http.Handler) http.Handler {
	return PinTenant(FixedRequestTenant(id))(RequireActiveTenant(g)(next))
}

// okNext is the terminal handler: it records that it ran.
func okNext() (http.Handler, *bool) {
	reached := false
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusNoContent)
	})
	return h, &reached
}

func serve(t *testing.T, h http.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func activeGate(store tenant.Store) ActiveTenantGate {
	return ActiveTenantGate{
		Store:          store,
		Label:          "tenant status",
		WriteNotActive: doubleWriter(http.StatusNotFound, missBody),
		WriteError:     doubleWriter(http.StatusInternalServerError, errorBody),
	}
}

// ---------------------------------------------------------------------
// The decision table
// ---------------------------------------------------------------------

func TestRequireActiveTenant_AllowsActive(t *testing.T) {
	store := &statusStore{byID: map[string]tenant.Descriptor{
		"acme": {ID: "acme", Status: tenant.StatusActive},
	}}
	next, reached := okNext()
	h := chain(tidAcme, activeGate(store), next)
	if code := serve(t, h, "/acme/x").Code; code != http.StatusNoContent {
		t.Fatalf("active tenant = %d, want 204", code)
	}
	if !*reached {
		t.Fatal("the handler was not reached for an active tenant")
	}
}

func TestRequireActiveTenant_RefusesEveryNonActiveStatus(t *testing.T) {
	for _, status := range []tenant.Status{
		tenant.StatusSuspended,
		tenant.StatusPending,
		tenant.Status("held"), // a status this version has never seen
	} {
		t.Run(string(status), func(t *testing.T) {
			store := &statusStore{byID: map[string]tenant.Descriptor{
				"acme": {ID: "acme", Status: status},
			}}
			next, reached := okNext()
			h := chain(tidAcme, activeGate(store), next)
			rec := serve(t, h, "/acme/x")
			if rec.Code != http.StatusNotFound {
				t.Fatalf("status %q = %d, want 404", status, rec.Code)
			}
			if *reached {
				t.Fatalf("status %q reached the handler", status)
			}
			if got := rec.Body.String(); got != missBody {
				t.Fatalf("body = %q, want the miss writer's", got)
			}
		})
	}
}

func TestRequireActiveTenant_UnknownTenantIsAMiss(t *testing.T) {
	store := &statusStore{} // empty: everything is ErrNotFound
	next, _ := okNext()
	h := chain(tidAcme, activeGate(store), next)
	rec := serve(t, h, "/acme/x")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown tenant = %d, want 404", rec.Code)
	}
	if got := rec.Body.String(); got != missBody {
		t.Fatalf("body = %q, want the miss writer's", got)
	}
}

// Suspended and unknown must be indistinguishable on the wire.
func TestRequireActiveTenant_SuspendedLooksLikeUnknown(t *testing.T) {
	unknown := &statusStore{}
	suspended := &statusStore{byID: map[string]tenant.Descriptor{
		"acme": {ID: "acme", Status: tenant.StatusSuspended},
	}}

	nextUnknown, _ := okNext()
	nextSuspended, _ := okNext()
	gotUnknown := serve(t, chain(tidAcme, activeGate(unknown), nextUnknown), "/acme/x")
	gotSuspended := serve(t, chain(tidAcme, activeGate(suspended), nextSuspended), "/acme/x")

	if gotUnknown.Code != gotSuspended.Code {
		t.Fatalf("status codes differ: unknown %d, suspended %d", gotUnknown.Code, gotSuspended.Code)
	}
	if gotUnknown.Body.String() != gotSuspended.Body.String() {
		t.Fatalf("bodies differ: unknown %q, suspended %q",
			gotUnknown.Body.String(), gotSuspended.Body.String())
	}
	if len(gotUnknown.Body.Bytes()) != len(gotSuspended.Body.Bytes()) {
		t.Fatalf("body lengths differ: %d vs %d", len(gotUnknown.Body.Bytes()), len(gotSuspended.Body.Bytes()))
	}
}

func TestRequireActiveTenant_StoreErrorIsNotAMissAndNotAnAllow(t *testing.T) {
	store := &statusStore{err: errors.New("tenants table down")}
	next, reached := okNext()
	h := chain(tidAcme, activeGate(store), next)

	rec := serve(t, h, "/acme/x")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("store outage = %d, want the error writer's 500", rec.Code)
	}
	if got := rec.Body.String(); got != errorBody {
		t.Fatalf("body = %q, want the error writer's (not a miss)", got)
	}
	if *reached {
		t.Fatal("a store outage allowed the request through")
	}
}

func TestRequireActiveTenant_WrappedErrNotFoundIsStillAMiss(t *testing.T) {
	store := &statusStore{err: errors.Join(errors.New("lookup"), tenant.ErrNotFound)}
	next, _ := okNext()
	h := chain(tidAcme, activeGate(store), next)
	rec := serve(t, h, "/acme/x")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("wrapped ErrNotFound = %d, want 404", rec.Code)
	}
	if got := rec.Body.String(); got != missBody {
		t.Fatalf("body = %q, want the miss writer's", got)
	}
}

// A single-tenant deployment has no row to find, so the gate must not look.
func TestRequireActiveTenant_SingleTenantPassesWithoutLookup(t *testing.T) {
	store := &statusStore{} // would answer ErrNotFound for ""
	next, reached := okNext()
	h := chain(tenant.Single, activeGate(store), next)

	rec := serve(t, h, "/x")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("single tenant = %d, want 204", rec.Code)
	}
	if !*reached {
		t.Fatal("single tenant did not reach the handler")
	}
	if len(store.calls) != 0 {
		t.Fatalf("the store was consulted for tenant.Single: %v", store.calls)
	}
}

// It reads the pinned tenant, never a tenant of its own choosing.
func TestRequireActiveTenant_AnswersForThePinnedTenantOnly(t *testing.T) {
	store := &statusStore{byID: map[string]tenant.Descriptor{
		"globex": {ID: "globex", Status: tenant.StatusActive},
		"acme":   {ID: "acme", Status: tenant.StatusSuspended},
	}}
	next, reached := okNext()
	h := chain(tidAcme, activeGate(store), next)
	if code := serve(t, h, "/acme/x").Code; code != http.StatusNotFound {
		t.Fatalf("a route pinned to the suspended tenant = %d, want 404", code)
	}
	if *reached {
		t.Fatal("the suspended pinned tenant was served because another tenant is active")
	}
	if len(store.calls) != 1 || store.calls[0] != "acme" {
		t.Fatalf("lookups = %v, want exactly [acme]", store.calls)
	}
}

func TestRequireActiveTenant_NothingPinnedIsConfigError(t *testing.T) {
	store := &statusStore{byID: map[string]tenant.Descriptor{
		"acme": {ID: "acme", Status: tenant.StatusActive},
	}}
	next, reached := okNext()
	// Mounted without a tenant gate.
	h := RequireActiveTenant(activeGate(store))(next)
	rec := serve(t, h, "/acme/x")

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("no pinned tenant = %d, want 500", rec.Code)
	}
	if *reached {
		t.Fatal("a request with no pinned tenant was served")
	}
	if got := rec.Body.String(); got == missBody {
		t.Fatal("a wiring bug was reported as a missing tenant")
	}
}

// ---------------------------------------------------------------------
// The construction guard (rule 6: the guard ships with a test that fires)
// ---------------------------------------------------------------------

func TestRequireActiveTenant_PanicsOnMisconfiguration(t *testing.T) {
	store := &statusStore{}
	ok := activeGate(store)
	w := doubleWriter(http.StatusNotFound, missBody)

	cases := map[string]ActiveTenantGate{
		"nil store":   {Label: ok.Label, WriteNotActive: ok.WriteNotActive, WriteError: ok.WriteError},
		"nil miss":    {Store: store, Label: ok.Label, WriteError: ok.WriteError},
		"nil error":   {Store: store, Label: ok.Label, WriteNotActive: w},
		"empty label": {Store: store, WriteNotActive: w, WriteError: w},
	}
	for name, g := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("%s: want panic, got none", name)
				}
			}()
			RequireActiveTenant(g)
		})
	}
}
