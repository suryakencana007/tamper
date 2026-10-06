// Command quickstart is a runnable, end-to-end example of embedding the
// Tamper framework: build the engines with tamper.New, aggregate the HTTP
// surface with tamper/espresso.Routes, register it on an Espresso router, and
// serve register / login / me / refresh / logout.
//
//	go run ./packages/tamper/examples/quickstart
//
// It uses the in-memory identity store (identity.NewMemStore) so it runs with
// no external dependencies — a real deployment plugs in its own persistent
// identity.Store. The whole flow is exercised by main_test.go.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/suryakencana007/tamper/tenant"
)

func main() {
	// main -> run() so the deferred Close in run actually fires: log.Fatal
	// would exit before a defer in main ever ran.
	if err := run(); err != nil {
		log.Fatalf("quickstart: %v", err)
	}
}

func run() error {
	secret := os.Getenv("QUICKSTART_JWT_SECRET")
	if secret == "" {
		// A runnable example must start with no setup. NEVER ship a hard-coded
		// secret in production — set QUICKSTART_JWT_SECRET.
		secret = "insecure-demo-secret-set-QUICKSTART_JWT_SECRET-in-production"
		log.Println("quickstart: QUICKSTART_JWT_SECRET is unset — using an insecure demo secret")
	}

	router, provider, err := buildHandler(identity.NewMemStore(), secret)
	if err != nil {
		return err
	}
	// Release the Provider (e.g. a SQLite audit DB handle) on graceful stop.
	// A defer here would not fire on SIGINT/SIGTERM — the signal-derived ctx +
	// OnShutdown hook is Espresso's lifecycle idiom (and Brew's ReadHeaderTimeout
	// default is the G114 protection a raw ListenAndServe lacks).
	router.OnShutdown(func(context.Context) error { return provider.Close() })

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Println("quickstart: listening on :8080 (POST /api/auth/register, /login, /refresh, /logout; GET /api/auth/me)")
	return router.BrewContext(ctx,
		espresso.WithAddr(":8080"),
		espresso.WithReadTimeout(15*time.Second),
		espresso.WithWriteTimeout(15*time.Second),
		espresso.WithShutdownTimeout(30*time.Second),
	)
}

// buildHandler wires the whole auth surface and returns the router plus the
// Provider (the caller closes it on shutdown, via OnShutdown). This is the
// shape a real application's server-init follows.
func buildHandler(store identity.Store, jwtSecret string) (*espresso.Router, *tamper.Provider, error) {
	// 1. Build the engines. Identity is configured, so the Provider exposes an
	//    identity.Core over the supplied store, with the JWT service threaded in.
	provider, err := tamper.New(tamper.Config{
		JWT: crypto.JWTConfig{Secret: jwtSecret, TTL: 15 * time.Minute, Issuer: "quickstart"},
		Identity: &tamper.IdentityConfig{
			Store:   store,
			Options: []identity.Option{identity.WithRefreshTTL(30 * 24 * time.Hour)},
		},
	})
	if err != nil {
		return nil, nil, err
	}

	// 2. Adapt the Core to the transport's IdentityService port. identity.Core
	//    cannot satisfy it directly (it has no Me and no session-token TOTP
	//    ceremony — those are app policy), so the app supplies this thin wrapper.
	svc := coreIdentity{core: provider.Identity, store: store}

	// 3. Aggregate the HTTP surface. Routes binds the middleware from the
	//    Provider's engines; here only the always-built Auth surface is used.
	surfaces, err := tamperespresso.Routes(provider, tamperespresso.RouteConfig{
		Auth: tamperespresso.AuthRoutesConfig{
			MountPrefix: "/api/auth",
			Tenant:      tamperespresso.FixedTenant(tenant.Single),
			Cookies:     tamperespresso.CookieConfig{Name: "quickstart_refresh"},
			ProjectUser: projectUser,
		},
		Identity: svc,
	})
	if err != nil {
		_ = provider.Close()
		return nil, nil, err
	}

	// 4. Register the returned surface on an Espresso router. Routes hands back
	//    the surfaces (no Mount) so the app owns its paths + the public/authed
	//    split: register/login/refresh/logout are public; me is behind RequireAuth;
	//    refresh/logout read the refresh cookie via the ReadRefreshCookie middleware.
	auth := surfaces.Auth
	readCookie := auth.ReadRefreshCookie()

	r := espresso.Portafilter()
	r.Post("/api/auth/register", espresso.Doppio(auth.Register))
	r.Post("/api/auth/login", espresso.Doppio(auth.Login))
	r.Get("/api/auth/me", surfaces.RequireAuth(espresso.HandlerCtx(auth.Me)))
	r.Post("/api/auth/refresh", readCookie(espresso.HandlerCtx(auth.Refresh)))
	r.Post("/api/auth/logout", readCookie(espresso.HandlerCtx(auth.Logout)))

	return r, provider, nil
}

// projectUser renders the app's user payload for the AuthRes envelope. The
// user DTO never enters the framework — this hook owns it. It is called with
// nil on empty-body branches; return a stable zero projection there.
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

// coreIdentity adapts *identity.Core to the transport's IdentityService port.
//
// Every port method is handed the tenant the request was routed to. The
// Core methods that take a tenant (Register, Login, IssueTokensForUser)
// get it passed through. The ones keyed by a bare user id or a bare
// token (Me, Refresh, Logout, the TOTP verbs) are preceded by a check
// that the user — or the session's user — is stored in that tenant, and
// a mismatch is answered with the error a missing user gets. This
// example is single-tenant and the tenant is always tenant.Single, but
// the adapter is written the way a pooled one is, because that is the
// shape the port asks for.
//
// The session-token TOTP ceremony is app policy with no Core primitive,
// so this minimal example stubs it out — those methods are never reached
// unless TOTP is required.
type coreIdentity struct {
	core  *identity.Core
	store identity.Store
}

var _ tamperespresso.IdentityService = coreIdentity{}

// userIn loads a user and refuses one that is not stored in tenantID
// with the same error a missing user gets. A deny and a miss must be
// indistinguishable.
func (c coreIdentity) userIn(ctx context.Context, tenantID tenant.ID, userID string) (identity.User, error) {
	u, err := c.store.UserByID(ctx, userID)
	if err != nil {
		return identity.User{}, err
	}
	if tenant.FromStored(u.TenantID) != tenantID {
		// Spelled exactly as the store spells a missing user, so the two
		// cannot be told apart by their text either.
		return identity.User{}, fmt.Errorf("%w: user %s", identity.ErrNotFound, userID)
	}
	return u, nil
}

// sessionIn reports whether the refresh token names a live session of
// tenantID. It reads only; the Core does the rotation or the revoke.
func (c coreIdentity) sessionIn(ctx context.Context, tenantID tenant.ID, refreshToken string) bool {
	hash, err := crypto.HashRefreshToken(refreshToken)
	if err != nil {
		return false
	}
	s, err := c.store.RefreshSessionByHash(ctx, hash)
	return err == nil && tenant.FromStored(s.TenantID) == tenantID
}

func (c coreIdentity) Register(ctx context.Context, tenantID tenant.ID, email, password string) (tamperespresso.AuthResult, error) {
	u, t, err := c.core.Register(ctx, tenantID, email, password)
	if err != nil {
		return tamperespresso.AuthResult{}, err
	}
	return tamperespresso.AuthResult{User: &u, Tokens: t}, nil
}

func (c coreIdentity) Login(ctx context.Context, tenantID tenant.ID, email, password string) (tamperespresso.AuthResult, error) {
	u, t, err := c.core.Login(ctx, tenantID, email, password)
	if err != nil {
		// On ErrTOTPRequired the Core returns the user (so the routes can render
		// the verify form) but no tokens — carry the user through with the error.
		if errors.Is(err, identity.ErrTOTPRequired) {
			return tamperespresso.AuthResult{User: &u}, err
		}
		return tamperespresso.AuthResult{}, err
	}
	return tamperespresso.AuthResult{User: &u, Tokens: t}, nil
}

func (c coreIdentity) Me(ctx context.Context, tenantID tenant.ID, userID string) (*identity.User, error) {
	u, err := c.userIn(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (c coreIdentity) Refresh(ctx context.Context, tenantID tenant.ID, refreshToken string) (tamperespresso.AuthResult, error) {
	// A token of another tenant is refused as an unknown one, before
	// anything rotates or is revoked.
	if !c.sessionIn(ctx, tenantID, refreshToken) {
		return tamperespresso.AuthResult{}, identity.ErrInvalidSession
	}
	u, t, err := c.core.Refresh(ctx, refreshToken)
	if err != nil {
		return tamperespresso.AuthResult{}, err
	}
	return tamperespresso.AuthResult{User: &u, Tokens: t}, nil
}

func (c coreIdentity) Logout(ctx context.Context, tenantID tenant.ID, refreshToken string) error {
	// Logout is idempotent: a token of another tenant is treated like a
	// stale one and nothing happens.
	if !c.sessionIn(ctx, tenantID, refreshToken) {
		return nil
	}
	return c.core.Logout(ctx, refreshToken)
}

func (c coreIdentity) IssueTokensForUser(ctx context.Context, tenantID tenant.ID, userID string) (tamperespresso.AuthResult, error) {
	// This is the TOTP second leg: the user authenticated with a password
	// and a code just now, so the auth_time is now and the ACR is the one
	// the Core stamps on a password login, so the two local logins agree.
	// The Core checks the tenant again itself.
	u, err := c.userIn(ctx, tenantID, userID)
	if err != nil {
		return tamperespresso.AuthResult{}, err
	}
	t, err := c.core.IssueTokensForUser(ctx, userID, tenantID, time.Now().Unix(), c.core.DefaultACR())
	if err != nil {
		return tamperespresso.AuthResult{}, err
	}
	return tamperespresso.AuthResult{User: &u, Tokens: t}, nil
}

func (c coreIdentity) VerifyTOTP(ctx context.Context, tenantID tenant.ID, userID, code string) error {
	if _, err := c.userIn(ctx, tenantID, userID); err != nil {
		return err
	}
	return c.core.VerifyTOTP(ctx, userID, code)
}

func (c coreIdentity) VerifyRecoveryCode(ctx context.Context, tenantID tenant.ID, userID, code string) error {
	if _, err := c.userIn(ctx, tenantID, userID); err != nil {
		return err
	}
	return c.core.VerifyRecoveryCode(ctx, userID, code)
}

func (c coreIdentity) EnrollTOTP(ctx context.Context, tenantID tenant.ID, userID string) (tamperespresso.TOTPEnrollment, error) {
	if _, err := c.userIn(ctx, tenantID, userID); err != nil {
		return tamperespresso.TOTPEnrollment{}, err
	}
	e, err := c.core.EnrollTOTP(ctx, userID)
	if err != nil {
		return tamperespresso.TOTPEnrollment{}, err
	}
	return tamperespresso.TOTPEnrollment{OTPAuthURI: e.OTPAuthURI, RecoveryCodes: e.RecoveryCodes}, nil
}

func (c coreIdentity) DisableTOTP(ctx context.Context, tenantID tenant.ID, userID, code string) error {
	if _, err := c.userIn(ctx, tenantID, userID); err != nil {
		return err
	}
	return c.core.DisableTOTP(ctx, userID, code)
}

// The session-token two-phase TOTP ceremony is app policy (the token shape +
// TTL are the app's), with no identity.Core primitive. This example does
// not enable TOTP, so these are never reached; a real app implements them
// (e.g. minting a short-lived pending JWT with the Provider's JWT service).
var errNoSessionTOTP = errors.New("session-token TOTP is app policy — not implemented in this example")

func (c coreIdentity) IssueTOTPPending(context.Context, tenant.ID, string) (string, error) {
	return "", errNoSessionTOTP
}
func (c coreIdentity) VerifyTOTPPending(context.Context, tenant.ID, string) (string, error) {
	return "", errNoSessionTOTP
}
func (c coreIdentity) EnrollTOTPViaSession(context.Context, tenant.ID, string, string) (*tamperespresso.TOTPEnrollment, *tamperespresso.AuthResult, error) {
	return nil, nil, errNoSessionTOTP
}
