// Command multitenant is the POOLED PROVING GROUND for Phase 7: one
// process, one store, two tenants, and a test that asserts a genuine
// cross-tenant denial.
//
//	go run ./examples/multitenant
//
// It exists because Barista — tamper's flagship and usual proving ground
// — is single-tenant by construction. A Barista facade over tenancy would
// pass tenant.Single everywhere and prove only the single-tenant half,
// which is the least interesting one. This example is the consumer that
// makes the tenant path real (sketch section 3.2).
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
//   - A PLATFORM ADMIN: a user stored in a third tenant, platform, who
//     holds a membership in acme and enters it (enter.go). The token they
//     get works on acme's routes and nowhere else.
//
// It runs with no external services: an in-memory store and nothing else.
//
// SCOPE NOTE. There is no OIDC or SAML leg here, and no verified
// domain. The federated path is still exercised at the Core, through the
// tenant-scoped ResolveByIdentity / ProvisionUserWithIdentity an OIDC
// callback would call. examples/federation shows the transport side.
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
	"github.com/suryakencana007/tamper/tenant"
)

// The two tenants. Opaque, app-defined strings — tamper never parses one.
//
// platform is a tenant like the others. What makes it the operator's is
// only that its users are the ones given memberships.
const (
	tenantAcme     = "acme"
	tenantGlobex   = "globex"
	tenantPlatform = "platform"
)

var tenants = []string{tenantAcme, tenantGlobex, tenantPlatform}

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
	log.Printf("  tenants %v share ONE surface: POST /t/{tenant}/auth/{register,login,refresh,logout,enter/{target}}  GET /t/{tenant}/auth/me  /t/{tenant}/whoami", tenants)
	return router.BrewContext(ctx,
		espresso.WithAddr(":8080"),
		espresso.WithReadTimeout(15*time.Second),
		espresso.WithWriteTimeout(15*time.Second),
		espresso.WithShutdownTimeout(30*time.Second),
	)
}

// buildHandler wires ONE Provider and mounts ONE auth surface PER TENANT.
//
// The Provider — and therefore the identity.Core, the JWT service, the
// store and the adapter — is shared. Only the tenant differs: each
// prefix resolves its own, and the port hands it to the adapter on every
// call. That is what makes this pooled rather than N processes, and it
// is the smallest wiring that puts a real tenant boundary in the request
// path.
func buildHandler(store *tenantStore, jwtSecret string) (*espresso.Router, *tamper.Provider, error) {
	// There is no tenancy switch to turn on. Every identity.Store is
	// tenant-scoped, so a store that cannot scope by tenant does not
	// compile, and the Core denies any call made without a tenant.
	provider, err := tamper.New(tamper.Config{
		JWT: crypto.JWTConfig{Secret: jwtSecret, TTL: 15 * time.Minute, Issuer: "multitenant-example"},
		Identity: &tamper.IdentityConfig{
			Store: store,
			Options: []identity.Option{
				identity.WithRefreshTTL(30 * 24 * time.Hour),
				// Phase 8: the store also answers "may this user enter this
				// tenant". Entered tokens are short: there is no refresh
				// session behind one, so this is how long a membership that
				// was taken away keeps working.
				identity.WithMemberships(store),
				identity.WithEnterTenantTTL(5 * time.Minute),
			},
		},
	})
	if err != nil {
		return nil, nil, err
	}

	// One adapter for every tenant. The port hands it the tenant on
	// each call, resolved per prefix below.
	svc := newPooledIdentity(provider, store)

	r := espresso.Portafilter()
	// ONE auth surface for every tenant, present and future. This is Phase 14's
	// point (TD-14): the old shape mounted a surface per tenant in a loop at boot,
	// so a tenant created at runtime by the console had no routes until a restart.
	//
	// The prefix is a TEMPLATE. TenantPathSegment is filled per request from the
	// tenant the resolver below pins — the same value the port receives and the
	// same one the refresh cookie's Path is derived from, so neither can drift.
	const authPrefix = "/t/" + tamperespresso.TenantPathSegment + "/auth"

	// routeTenant is the ONE resolver. It reads the path parameter; everything
	// downstream reads the pin. There is deliberately no second resolver to
	// disagree with it.
	// The bool is the resolver's honest answer about whether it FOUND a tenant.
	// tenant.New("") is the invalid zero id, not the single tenant, so an empty
	// segment reports false and PinTenant answers NOT_FOUND. Returning true
	// unconditionally would compile and behave the same here — and would teach the
	// wrong contract to the application copying this file.
	routeTenant := func(r *http.Request) (tenant.ID, bool) {
		id := tenant.New(r.PathValue("tenant"))
		return id, id.Valid()
	}
	pin := tamperespresso.PinTenant(routeTenant)

	surfaces, serr := tamperespresso.Routes(provider, tamperespresso.RouteConfig{
		Auth: tamperespresso.AuthRoutesConfig{
			MountPrefix: authPrefix,
			// The same pin the gates read, from the context form the config takes:
			// one resolver fills {tenant}, and the port receives that value.
			Tenant: tamperespresso.TenantFromContext,
			// ONE cookie name: the PATH separates the tenants' jars, so a single
			// browser still holds a live session per tenant. The old example used a
			// per-tenant name, which the path had already made unnecessary.
			Cookies:     tamperespresso.CookieConfig{Name: "mt_refresh"},
			ProjectUser: projectUser,
		},
		Identity: svc,
	})
	if serr != nil {
		_ = provider.Close()
		return nil, nil, serr
	}

	auth := surfaces.Auth
	readCookie := auth.ReadRefreshCookie()

	// The public legs. pin is mandatory on every one of them: without a pinned
	// tenant the template cannot be filled, and the auth routes refuse rather
	// than write a cookie at a path no route would send it to.
	r.Post(authPrefix+"/register", pin(espresso.Doppio(auth.Register)))
	r.Post(authPrefix+"/login", pin(espresso.Doppio(auth.Login)))
	r.Post(authPrefix+"/refresh", pin(readCookie(espresso.HandlerCtx(auth.Refresh))))
	r.Post(authPrefix+"/logout", pin(readCookie(espresso.HandlerCtx(auth.Logout))))

	// Every authenticated route gets BOTH gates. RequireAuth says the token is
	// genuine; RequireTenant says it was minted for THIS tenant, by comparing its
	// `tid` with the pinned tenant. The tenant comes from the ROUTE, never from
	// the token. A route with only RequireAuth accepts any tenant's token — add
	// RequireTenant to every route you mount beside this one.
	requireTenant := tamperespresso.RequireTenant(tamperespresso.TenantFromRoutedContext)
	r.Get(authPrefix+"/me", pin(surfaces.RequireAuth(requireTenant(espresso.HandlerCtx(auth.Me)))))

	// Phase 8: whoami is the one route a platform admin may use. It accepts this
	// tenant's own tokens AND token entered into it; every route above uses
	// RequireTenant, which refuses an entered token — they are "my account"
	// routes, and an entered admin has no account in this tenant.
	guestsToo := tamperespresso.RequireTenantAllowEntered(tamperespresso.TenantFromRoutedContext)
	r.Get("/t/"+tamperespresso.TenantPathSegment+"/whoami",
		pin(surfaces.RequireAuth(guestsToo(http.HandlerFunc(whoami)))))

	// One enter route for every target: the caller proves who they are with their
	// home session, then asks to go elsewhere. The target is a path parameter, and
	// the Core refuses a target it does not hold a membership for.
	// {target}, not the tenant placeholder again: a pattern cannot repeat a wildcard
	// name, and the two segments mean different things — the tenant the caller acts
	// FROM, and the one they ask to enter.
	r.Post(authPrefix+"/enter/{target}",
		pin(surfaces.RequireAuth(requireTenant(enterTenantFromPath(provider.Identity)))))

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
