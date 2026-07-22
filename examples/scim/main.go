// Command scim is a runnable, end-to-end example of exposing a SCIM 2.0
// provisioning surface with the Tamper framework: build the engines with
// tamper.New, aggregate the surface with tamper/espresso.Routes (a SCIM
// bundle), implement the scim.UserStore + scim.GroupStore ports in-memory
// (store.go), and gate every route behind a service-account bearer token.
//
//	go run ./packages/tamper/examples/scim
//
// SCIM is machine-to-machine: a workforce IdP (Okta, Azure AD / Entra) pushes
// user + group provisioning to /scim/v2/* using a long-lived service-account
// token — never a person's session. This app is the SCIM *server*; the IdP is
// the client. main_test.go acts as that client and drives the whole flow.
//
// The load-bearing pattern is the audit crossing: the transport emits no audit
// rows — the store (the app) does, with the actor pulled from the context the
// service-account gate stashed. See docs/SCIM-INTEGRATION-RUNBOOK.md.
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	espresso "github.com/suryakencana007/espresso/v2"

	tamper "github.com/suryakencana007/tamper"
	"github.com/suryakencana007/tamper/crypto"
	tamperespresso "github.com/suryakencana007/tamper/espresso"
	"github.com/suryakencana007/tamper/identity"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("scim: %v", err)
	}
}

func run() error {
	secret := os.Getenv("SCIM_JWT_SECRET")
	if secret == "" {
		secret = "insecure-demo-secret-set-SCIM_JWT_SECRET-in-production"
		log.Println("scim: SCIM_JWT_SECRET unset — using an insecure demo secret")
	}
	saToken := os.Getenv("SCIM_TOKEN")
	if saToken == "" {
		saToken = "demo-service-account-token"
		log.Printf("scim: SCIM_TOKEN unset — the demo service-account token is %q", saToken)
	}

	// Empty audit DBPath => a NoopLogger for the runnable demo. The test passes
	// a real SQLite path so it can assert the emitted rows.
	router, provider, _, _, err := buildHandler("", secret, saToken)
	if err != nil {
		return err
	}
	router.OnShutdown(func(context.Context) error { return provider.Close() })

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Println("scim: listening on :8080 — /scim/v2/* behind the service-account bearer token")
	return router.BrewContext(ctx,
		espresso.WithAddr(":8080"),
		espresso.WithReadTimeout(15*time.Second),
		espresso.WithWriteTimeout(15*time.Second),
		espresso.WithShutdownTimeout(30*time.Second),
	)
}

// buildHandler wires the SCIM surface and returns the router + the Provider +
// the stores (the test asserts against the stores + the Provider's audit log).
func buildHandler(auditDBPath, jwtSecret, saToken string) (*espresso.Router, *tamper.Provider, *memUserStore, *memGroupStore, error) {
	// 1. Engines. Audit is the point of this example, so it's configured:
	//    DBPath != "" opens the SQLite hash-chain logger; "" => NoopLogger.
	//    provider.Audit is always non-nil.
	provider, err := tamper.New(tamper.Config{
		JWT:   crypto.JWTConfig{Secret: jwtSecret, TTL: 15 * time.Minute, Issuer: "scim-example"},
		Audit: tamper.AuditConfig{DBPath: auditDBPath},
	})
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// 2. The stores get the Provider's audit logger DIRECTLY — Routes threads
	//    no logger into them (A3: the port impls emit their own audit).
	users := newUserStore(provider.Audit)
	groups := newGroupStore(provider.Audit, users)

	// 3. The service-account validator. MUST return ErrInvalidCredential on a
	//    bad token, or the gate returns 500 instead of 401.
	validator := tamperespresso.ValidatorFunc(func(_ context.Context, token string) (tamperespresso.Principal, error) {
		if token != saToken {
			return tamperespresso.Principal{}, tamperespresso.ErrInvalidCredential
		}
		return tamperespresso.Principal{ID: "sa-demo", Name: "demo-idp", CreatedAt: time.Now()}, nil
	})

	// 4. Aggregate the surface. Routes ALWAYS builds the core-auth surface, so a
	//    SCIM-only app still supplies an IdentityService (stubbed here) + a
	//    valid Auth config (ProjectUser is required).
	surfaces, err := tamperespresso.Routes(provider, tamperespresso.RouteConfig{
		Auth: tamperespresso.AuthRoutesConfig{
			MountPrefix: "/api/auth",
			Cookies:     tamperespresso.CookieConfig{Name: "scim_refresh"},
			ProjectUser: projectUser,
		},
		Identity: stubIdentity{},
		SCIM: &tamperespresso.SCIMBundle{
			Config: tamperespresso.SCIMConfig{
				Prefix:            "/scim/v2",
				MaxResults:        100,
				BulkMaxOperations: 50,
			},
			Users:     users,
			Groups:    groups,
			Validator: validator,
		},
	})
	if err != nil {
		_ = provider.Close()
		return nil, nil, nil, nil, err
	}

	// 5. Register the SCIM surface, EVERY route behind the service-account gate.
	//    (No open routes: GroupsCreate/Replace/Patch call MustGetPrincipal, which
	//    panics outside a RequireServiceAccount wrap.) SCIM methods are raw
	//    net/http handlers.
	sc := surfaces.SCIM
	guard := surfaces.RequireServiceAccount

	r := espresso.Portafilter()
	r.Get("/scim/v2/ServiceProviderConfig", guard(http.HandlerFunc(sc.ServiceProviderConfig)))
	r.Get("/scim/v2/ResourceTypes", guard(http.HandlerFunc(sc.ResourceTypes)))
	r.Get("/scim/v2/Schemas", guard(http.HandlerFunc(sc.Schemas)))

	r.Get("/scim/v2/Users", guard(http.HandlerFunc(sc.UsersList)))
	r.Post("/scim/v2/Users", guard(http.HandlerFunc(sc.UsersCreate)))
	r.Get("/scim/v2/Users/{id}", guard(http.HandlerFunc(sc.UsersGet)))
	r.Put("/scim/v2/Users/{id}", guard(http.HandlerFunc(sc.UsersReplace)))
	r.Patch("/scim/v2/Users/{id}", guard(http.HandlerFunc(sc.UsersPatch)))
	r.Delete("/scim/v2/Users/{id}", guard(http.HandlerFunc(sc.UsersDelete)))

	r.Get("/scim/v2/Groups", guard(http.HandlerFunc(sc.GroupsList)))
	r.Post("/scim/v2/Groups", guard(http.HandlerFunc(sc.GroupsCreate)))
	r.Get("/scim/v2/Groups/{id}", guard(http.HandlerFunc(sc.GroupsGet)))
	r.Put("/scim/v2/Groups/{id}", guard(http.HandlerFunc(sc.GroupsReplace)))
	r.Patch("/scim/v2/Groups/{id}", guard(http.HandlerFunc(sc.GroupsPatch)))
	r.Delete("/scim/v2/Groups/{id}", guard(http.HandlerFunc(sc.GroupsDelete)))

	// 6. Bulk is app-side (tamper ships no Bulk method) — see bulk.go.
	registerBulk(r, sc, guard, provider.Audit, 50)

	return r, provider, users, groups, nil
}

// projectUser renders the app's user payload for the (unused, stubbed) auth
// surface. Required by AuthRoutesConfig even though this app never logs anyone in.
func projectUser(_ context.Context, u *identity.User) json.RawMessage {
	if u == nil {
		return json.RawMessage("null")
	}
	b, _ := json.Marshal(struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}{ID: u.ID, Email: u.Email})
	return b
}
