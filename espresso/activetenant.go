package espresso

import (
	"errors"
	"net/http"

	espressofw "github.com/suryakencana007/espresso/v2"

	"github.com/suryakencana007/tamper/tenant"
)

// ActiveTenantGate configures RequireActiveTenant — the Phase 9 gate that
// refuses a tenant which is not serving requests (TD-06).
type ActiveTenantGate struct {
	// Store resolves the tenant's status. Required — nil panics.
	//
	// It is read, never written: setting a status is the application's job
	// (TD-05 would add a port for it). Wrapping this store with a short-TTL
	// cache is supported; the accepted window is that a suspension takes
	// effect within that TTL.
	Store tenant.Store
	// Label names the gate in the 500 message ("tenant status"), so operator
	// logs keep their grep-ability. Required — empty panics.
	Label string
	// WriteNotActive writes the app's miss response. Required.
	//
	// It is used for an unknown tenant AND for a non-active one, which is what
	// keeps the two indistinguishable on the wire: a distinguishable
	// "suspended" is a tenant-existence oracle (tenant.ErrSuspended's doc).
	WriteNotActive DenyWriter
	// WriteError writes the response for a store failure. Required.
	//
	// Unlike DecisionGate.WriteProbeError there is no fallback to the deny
	// writer: reporting an outage as "no such tenant" would be a false
	// statement about a tenant's existence and would hide an incident.
	WriteError DenyWriter
}

// RequireActiveTenant returns middleware that refuses every request for a
// tenant whose status is not tenant.StatusActive.
//
// It reads the tenant the route already pinned (TenantFromContext), so it must
// run AFTER PinTenant on a public route or AFTER RequireTenant on an
// authenticated one. It never resolves a tenant itself: a gate that could
// disagree with the route would be checking a different tenant than the one the
// request is served as.
//
// What it decides:
//
//	pinned tenant is tenant.Single  -> next      (a single-tenant deployment
//	                                              has no row to find, so there
//	                                              is no status to check)
//	nothing pinned                 -> 500 CONFIG_ERROR  (a wiring bug)
//	Store.ByID returns ErrNotFound  -> WriteNotActive    (a miss)
//	Store.ByID returns any error    -> WriteError        (fail closed)
//	Status != StatusActive          -> WriteNotActive    (same bytes as a miss)
//	Status == StatusActive          -> next
//
// Any status it does not recognise denies, including one a later version might
// add: deny-by-default extends to status.
//
// Panics on a nil Store, a nil writer, or an empty Label. A gate that cannot
// decide must fail when it is built, never on a request (standing rule 4), and
// the guard ships with a test that proves it fires (rule 6).
func RequireActiveTenant(g ActiveTenantGate) func(http.Handler) http.Handler {
	switch {
	case g.Store == nil:
		panic("tamper/espresso: RequireActiveTenant requires a tenant.Store — " +
			"a status gate with nothing to read would refuse every request")
	case g.WriteNotActive == nil:
		panic("tamper/espresso: RequireActiveTenant requires WriteNotActive — " +
			"it writes the response for both an unknown and a non-active tenant")
	case g.WriteError == nil:
		panic("tamper/espresso: RequireActiveTenant requires WriteError — " +
			"falling back to the miss writer would report an outage as a missing tenant")
	case g.Label == "":
		panic("tamper/espresso: RequireActiveTenant requires a Label — " +
			"the config-error message would not say which gate failed")
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, ok := TenantFromContext(r.Context())
			if !ok {
				// Nothing pinned: this gate was mounted without a tenant gate.
				// That is a wiring bug, and it must not read as a pass.
				_ = espressofw.ErrInternal("middleware: " + g.Label + " gate ran without a pinned tenant").
					WithCode("CONFIG_ERROR").
					WriteResponse(w)
				return
			}
			if id.IsSingle() {
				// The single-tenant deployment: the empty id, and tenant.Store
				// documents that an empty lookup key never resolves. Looking it
				// up would answer ErrNotFound and 404 every request, so there is
				// no status to check here.
				next.ServeHTTP(w, r)
				return
			}

			desc, err := g.Store.ByID(r.Context(), id.String())
			if err != nil {
				if errors.Is(err, tenant.ErrNotFound) {
					g.WriteNotActive(w)
					return
				}
				// An outage is not a miss and not an allow.
				g.WriteError(w)
				return
			}
			if desc.Status != tenant.StatusActive {
				// Suspended, pending, or a status this version has never seen.
				g.WriteNotActive(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
