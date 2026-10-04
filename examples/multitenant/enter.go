package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	tamperespresso "github.com/suryakencana007/tamper/espresso"
	"github.com/suryakencana007/tamper/identity"
	"github.com/suryakencana007/tamper/tenant"
)

// enterTenant is the whole "platform admin enters a customer's tenant"
// flow on the transport side. tamper ships no route for it: the shape
// of the URL and of the response is the application's.
//
// It sits behind RequireAuth and RequireTenant(home), so by the time it
// runs the caller holds a genuine token of the tenant this route
// belongs to. The rights check is not here — Core.EnterTenant asks the
// MembershipStore, and there is no way to get the token without it.
func enterTenant(core *identity.Core, target string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := tamperespresso.AccessClaimsFromContext(r.Context())
		if !ok {
			writeJSON(w, http.StatusUnauthorized, errorBody{"unauthenticated"})
			return
		}
		// The claims go in whole. The Core takes the user, auth_time and
		// acr from them, and refuses a session that is itself entered: an
		// entered token is a guest pass, not a credential to ask for more.
		tok, err := core.EnterTenant(r.Context(), claims, tenant.New(target))
		switch {
		case err == nil:
			// An access token and nothing else. No refresh cookie is set:
			// when this expires the client calls this route again.
			writeJSON(w, http.StatusOK, enterResponse{Token: tok.Access, Tenant: target})
		case errors.Is(err, identity.ErrNotFound):
			// Not a member, no such user, not a home session: one answer.
			writeJSON(w, http.StatusNotFound, errorBody{"not found"})
		case errors.Is(err, identity.ErrUserInactive):
			writeJSON(w, http.StatusUnauthorized, errorBody{"user is inactive"})
		default:
			// Includes a failed membership lookup. Never a yes.
			log.Printf("multitenant: enter %s: %v", target, err)
			writeJSON(w, http.StatusInternalServerError, errorBody{"internal error"})
		}
	})
}

// whoami reports what the token says. For an entered token `tenant` and
// `home_tenant` differ; that pair is what the audit log records too
// (Event.TenantID and Actor.TenantID).
func whoami(w http.ResponseWriter, r *http.Request) {
	claims, ok := tamperespresso.AccessClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorBody{"unauthenticated"})
		return
	}
	writeJSON(w, http.StatusOK, whoamiResponse{
		UserID:     claims.Subject,
		Tenant:     claims.TenantID,
		HomeTenant: claims.ActorTenantID(),
		Entered:    claims.HomeTenantID != "",
	})
}

type enterResponse struct {
	Token  string `json:"token"`
	Tenant string `json:"tenant"`
}

type whoamiResponse struct {
	UserID     string `json:"user_id"`
	Tenant     string `json:"tenant"`
	HomeTenant string `json:"home_tenant"`
	Entered    bool   `json:"entered"`
}

type errorBody struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
