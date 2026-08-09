// Command multitenant is the POOLED PROVING GROUND for Phase 7: one
// process, one store, two tenants, and a test that asserts a genuine
// cross-tenant denial.
//
//	go run ./examples/multitenant
//
// It exists because Barista — tamper's flagship and usual proving ground
// — is single-tenant by construction. A Barista facade over tenancy would
// pass tenantID="" everywhere and prove only that the compatibility
// escape hatch works, which is the least interesting half. This example
// is the consumer that makes the tenant path real (sketch section 3.2),
// and it lands in M1 rather than at the end for exactly that reason.
//
// What it shows:
//
//   - Two tenants, acme and globex, served from ONE process over ONE
//     identity.Store, tenant-scoped (store.go).
//   - bob@acme.com and bob@globex.com as two different people — the same
//     address in two tenants, which blocker B1 made impossible.
//   - globex's first user receiving the bootstrap signal even though acme
//     is already full of users — blocker B2, the one that fails silently.
//   - An access token minted for acme being refused on a globex route.
//
// It runs with no external services: an in-memory store and nothing else.
//
// SCOPE NOTE. The manifest's shape for this slice also mentions a
// verified domain and an OIDC provider per tenant on an embedded fake
// IdP. Neither is buildable at 7b-3: per-tenant OIDC registries are 7e-1
// and verified domains are 7f-1, both M3, and this slice gates only on
// 7b-2. Building them now would mean an app-side tenant->provider map
// against the still-process-wide registry that 7e-1 exists to replace —
// an implementation two slices early, which is the trap the phase rules
// name. The federated path is still exercised, through the Core's
// tenant-scoped ResolveByIdentityInTenant / ProvisionUserWithIdentityInTenant,
// which is the part 7b-2 actually made tenant-aware. The OIDC leg joins
// at M3.
package main

import (
	"context"
	"encoding/json"
	"log"
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

// The two tenants. Opaque, app-defined strings — tamper never parses one.
const (
	tenantAcme   = "acme"
	tenantGlobex = "globex"
)

var tenants = []string{tenantAcme, tenantGlobex}

func main() {
	if err := run(); err != nil {
		log.Fatalf("multitenant: %v", err)
	}
}

func run() error {
	secret := os.Getenv("MULTITENANT_JWT_SECRET")
	if secret == "" {
		secret = "insecure-demo-secret-set-MULTITENANT_JWT_SECRET-in-production"
		log.Println("multitenant: MULTITENANT_JWT_SECRET unset — using an insecure demo secret")
	}

	router, provider, err := buildHandler(newTenantStore(), secret)
	if err != nil {
		return err
	}
	router.OnShutdown(func(context.Context) error { return provider.Close() })

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Println("multitenant: listening on :8080")
	for _, t := range tenants {
		log.Printf("  tenant %-7s POST /t/%s/auth/register  /login  /refresh  /logout   GET /t/%s/auth/me", t, t, t)
	}
	return router.BrewContext(ctx,
		espresso.WithAddr(":8080"),
		espresso.WithReadTimeout(15*time.Second),
		espresso.WithWriteTimeout(15*time.Second),
		espresso.WithShutdownTimeout(30*time.Second),
	)
}

// buildHandler wires ONE Provider and mounts ONE auth surface PER TENANT.
//
// The Provider — and therefore the identity.Core, the JWT service and the
// store — is shared. Only the adapter differs: each tenant's routes are
// backed by a tenantIdentity closed over that tenant's id. That is what
// makes this pooled rather than N processes, and it is the smallest
// wiring that puts a real tenant boundary in the request path.
func buildHandler(store *tenantStore, jwtSecret string) (*espresso.Router, *tamper.Provider, error) {
	// Tenancy.Enabled makes the Core route every scoped read through the
	// *InTenant methods. It also asserts at BOOT that the store can serve
	// them — swap tenantStore for one that cannot and New fails here,
	// naming the type, rather than leaking on the first cross-tenant read.
	provider, err := tamper.New(tamper.Config{
		JWT: crypto.JWTConfig{Secret: jwtSecret, TTL: 15 * time.Minute, Issuer: "multitenant-example"},
		Identity: &tamper.IdentityConfig{
			Store:   store,
			Options: []identity.Option{identity.WithRefreshTTL(30 * 24 * time.Hour)},
		},
	})
	if err != nil {
		return nil, nil, err
	}

	r := espresso.Portafilter()
	for _, tenantID := range tenants {
		prefix := "/t/" + tenantID + "/auth"
		surfaces, serr := tamperespresso.Routes(provider, tamperespresso.RouteConfig{
			Auth: tamperespresso.AuthRoutesConfig{
				MountPrefix: prefix,
				// Per-tenant cookie name: one browser must be able to hold a
				// session in each tenant without them overwriting each other.
				Cookies:     tamperespresso.CookieConfig{Name: "mt_" + tenantID + "_refresh"},
				ProjectUser: projectUser,
			},
			Identity: tenantIdentity{core: provider.Identity, store: store, tenantID: tenantID},
		})
		if serr != nil {
			_ = provider.Close()
			return nil, nil, serr
		}

		auth := surfaces.Auth
		readCookie := auth.ReadRefreshCookie()
		r.Post(prefix+"/register", espresso.Doppio(auth.Register))
		r.Post(prefix+"/login", espresso.Doppio(auth.Login))
		r.Get(prefix+"/me", surfaces.RequireAuth(espresso.HandlerCtx(auth.Me)))
		r.Post(prefix+"/refresh", readCookie(espresso.HandlerCtx(auth.Refresh)))
		r.Post(prefix+"/logout", readCookie(espresso.HandlerCtx(auth.Logout)))
	}

	return r, provider, nil
}

// projectUser renders the app's user payload. TenantID is included
// because in a pooled deployment the client genuinely needs to know
// which tenant it is acting in — but it is the APP's choice to expose
// it, not the framework's; the DTO never enters tamper.
func projectUser(_ context.Context, u *identity.User) json.RawMessage {
	if u == nil {
		return json.RawMessage("null")
	}
	b, _ := json.Marshal(struct {
		ID       string `json:"id"`
		TenantID string `json:"tenant_id"`
		Email    string `json:"email"`
	}{ID: u.ID, TenantID: u.TenantID, Email: u.Email})
	return b
}
