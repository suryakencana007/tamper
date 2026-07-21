// Command federation is a runnable, end-to-end example of OIDC single sign-on
// with the Tamper framework: build the engines with tamper.New (including an
// OIDC provider), aggregate the HTTP surface with tamper/espresso.Routes
// (including the Federation surface), and run the full authorization-code flow
// against an embedded fake IdP.
//
//	go run ./packages/tamper/examples/federation
//
// The embedded fake IdP (fakeidp.go) stands in for a real one so the example
// runs with no external dependencies — the tamper wiring is identical to a
// real Keycloak/Auth0/Okta; only the issuer URL + client credentials change.
// See the README's "Integrating with Keycloak" section. main_test.go drives
// the whole browser dance and is the proof the flow works.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	espresso "github.com/suryakencana007/espresso/v2"
	"github.com/suryakencana007/espresso/v2/extractor"

	tamper "github.com/suryakencana007/barista/packages/tamper"
	"github.com/suryakencana007/barista/packages/tamper/crypto"
	tamperespresso "github.com/suryakencana007/barista/packages/tamper/espresso"
	"github.com/suryakencana007/barista/packages/tamper/identity"
	"github.com/suryakencana007/barista/packages/tamper/oidc"
)

// demoKEKHex is an insecure, all-zeros-but-one 32-byte KEK (64 hex chars) used
// only to seal the demo provider's client secret. NEVER hardcode a KEK in
// production — supply real random KEKs via config.
const demoKEKHex = "0000000000000000000000000000000000000000000000000000000000000001"

func main() {
	if err := run(); err != nil {
		log.Fatalf("federation: %v", err)
	}
}

func run() error {
	secret := os.Getenv("FEDERATION_JWT_SECRET")
	if secret == "" {
		secret = "insecure-demo-secret-set-FEDERATION_JWT_SECRET-in-production"
		log.Println("federation: FEDERATION_JWT_SECRET unset — using an insecure demo secret")
	}

	idp, err := newFakeIDP()
	if err != nil {
		return err
	}
	defer idp.Close()
	log.Printf("federation: embedded fake OIDC IdP at %s (stands in for a real Keycloak)", idp.URL)

	const addr = ":8080"
	appBaseURL := func() string { return "http://localhost" + addr }

	router, provider, err := buildHandler(identity.NewMemStore(), secret, idp.URL, appBaseURL)
	if err != nil {
		return err
	}
	router.OnShutdown(func(context.Context) error { return provider.Close() })

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("federation: listening on %s — GET /api/auth/oidc/start/keycloak begins the SSO flow", addr)
	return router.BrewContext(ctx,
		espresso.WithAddr(addr),
		espresso.WithReadTimeout(15*time.Second),
		espresso.WithWriteTimeout(15*time.Second),
		espresso.WithShutdownTimeout(30*time.Second),
	)
}

// buildHandler wires local auth + the OIDC federation surface over one
// Provider, seeds a Keycloak-shaped provider pointed at idpIssuer, and returns
// the router. appBaseURL is a lazy accessor for the app's own base URL (the
// callback redirect target) — lazy because in tests it is only known after the
// httptest server starts; the Manager's registry is left un-cached (TTL 0) so
// it resolves fresh per request.
func buildHandler(store identity.Store, jwtSecret, idpIssuer string, appBaseURL func() string) (*espresso.Router, *tamper.Provider, error) {
	// 1. Engines. KEKs are REQUIRED here (unlike the quickstart): the OIDC
	//    Manager seals provider client secrets, and Create fails without a
	//    KeySet.
	provider, err := tamper.New(tamper.Config{
		JWT:        crypto.JWTConfig{Secret: jwtSecret, TTL: 15 * time.Minute, Issuer: "federation-example"},
		KEKs:       []crypto.KEKEntry{{ID: 1, Key: demoKEKHex}},
		WriteKeyID: 1,
		Identity: &tamper.IdentityConfig{
			Store:   store,
			Options: []identity.Option{identity.WithRefreshTTL(30 * 24 * time.Hour)},
		},
		OIDC: &tamper.OIDCConfig{
			Store: oidc.NewMemProviderStore(),
			// The callback URL the IdP redirects back to. Derived lazily from
			// the app base + provider id.
			RedirectURL: func(id string) string { return appBaseURL() + "/api/auth/oidc/callback/" + id },
			// TTL 0 => the registry rebuilds on every GetRegistry, so the lazy
			// appBaseURL() resolves at request time.
		},
	})
	if err != nil {
		return nil, nil, err
	}

	// 2. Seed one Keycloak-shaped provider. Create seals the secret + stores
	//    the record (no discovery yet — that happens lazily at first use), so
	//    it is safe to seed before the app's own URL is known. Enabled MUST be
	//    true or the live registry omits it.
	if err := provider.OIDC.Create(context.Background(), oidc.ProviderDefinition{
		ID:           "keycloak",
		IssuerURL:    idpIssuer,
		ClientID:     "example-client",
		ClientSecret: "example-secret",
		DisplayName:  "Keycloak",
		Enabled:      true,
		Scopes:       []string{"openid", "profile", "email"},
	}); err != nil {
		_ = provider.Close()
		return nil, nil, err
	}

	// 3. Aggregate the surface. Routes auto-wires the Federation registry hook
	//    from provider.OIDC; the app supplies the OnFederatedExchange tail.
	svc := coreIdentity{core: provider.Identity, store: store}
	surfaces, err := tamperespresso.Routes(provider, tamperespresso.RouteConfig{
		Auth: tamperespresso.AuthRoutesConfig{
			MountPrefix: "/api/auth",
			Cookies:     tamperespresso.CookieConfig{Name: "federation_refresh"},
			ProjectUser: projectUser,
		},
		Identity: svc,
		Federation: &tamperespresso.FederationBundle{
			Config: tamperespresso.FederationConfig{
				LandingPath: "/auth/oidc/landing",
				StateCookie: tamperespresso.StateCookieConfig{
					BaseName: "federation_oidc_state",
					Secure:   false, // HTTP demo/test; set true (adds __Host-) behind HTTPS
					Path:     "/",
					TTL:      10 * time.Minute,
					SameSite: http.SameSiteLaxMode, // MUST be explicit (OIDC callback is a top-level GET)
				},
				StateSecret: []byte(jwtSecret),
				StateIssuer: "federation-example-state",
				Cookies:     tamperespresso.CookieConfig{Name: "federation_refresh", MaxAgeSeconds: 30 * 24 * 3600},
				MountPrefix: "/api/auth",
			},
			// Registry auto-wired from provider.OIDC. SanitizeRedirect +
			// CallingUserID left nil (deny-all->"/" and GetUserID defaults).
			Hooks: tamperespresso.FederationHooks{
				OnFederatedExchange: federationLoginHook(provider.Identity, projectUser),
			},
		},
	})
	if err != nil {
		_ = provider.Close()
		return nil, nil, err
	}

	// 4. Register the surfaces. Local auth mirrors the quickstart; the OIDC
	//    surface adds start/callback (browser redirects) + exchange (the SPA
	//    posts the code/state carried back in the callback fragment).
	auth := surfaces.Auth
	readRefresh := auth.ReadRefreshCookie()
	fed := surfaces.Federation
	readState := fed.ReadStateCookie()

	r := espresso.Portafilter()
	r.Post("/api/auth/register", espresso.Doppio(auth.Register))
	r.Post("/api/auth/login", espresso.Doppio(auth.Login))
	r.Get("/api/auth/me", surfaces.RequireAuth(espresso.HandlerCtx(auth.Me)))
	r.Post("/api/auth/refresh", readRefresh(espresso.HandlerCtx(auth.Refresh)))
	r.Post("/api/auth/logout", readRefresh(espresso.HandlerCtx(auth.Logout)))

	// OIDC SSO: start -> IdP -> callback (302 to LandingPath with code/state in
	// the URL fragment) -> the SPA posts /exchange. ReadStateCookie MUST wrap
	// exchange, or it can't read the state cookie and every exchange 401s.
	r.Get("/api/auth/oidc/start/{id}", espresso.Lungo(startOIDC(fed)))
	r.Get("/api/auth/oidc/callback/{id}", espresso.Lungo(callbackOIDC(fed)))
	r.Post("/api/auth/oidc/exchange", readState(espresso.Doppio(fed.Exchange)))
	// The account-linking leg (/oidc/link-start) is intentionally omitted — it
	// needs RequireAuth + the caller's user id; this example covers login only.

	return r, provider, nil
}

// projectUser renders the app's user payload for the auth/exchange responses.
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

// federationLoginHook is the one required app seam: it runs the post-verify
// tail. By the time it fires, tamper has already verified the state cookie,
// exchanged the code, and validated the ID token (signature, audience, nonce).
// The hook resolves-or-provisions the federated user by (provider, subject)
// and mints a login session.
func federationLoginHook(core *identity.Core, project func(context.Context, *identity.User) json.RawMessage) func(context.Context, *oidc.Provider, tamperespresso.OIDCVerified) (tamperespresso.FederationOutcome, error) {
	return func(ctx context.Context, p *oidc.Provider, v tamperespresso.OIDCVerified) (tamperespresso.FederationOutcome, error) {
		providerID := p.Config.ID // the RESOLVED provider tamper hands in
		subject := v.Claims.Sub    // the verified id_token subject

		// Repeat sign-in: resolve the existing (provider, subject) identity.
		user, _, found, err := core.ResolveByIdentity(ctx, providerID, subject)
		if err != nil {
			return tamperespresso.FederationOutcome{}, mapFederationError(err)
		}
		if !found {
			// First sign-in: JIT-provision a federated-only user + its identity.
			email, nerr := identity.NormaliseEmail(v.Claims.Email)
			if nerr != nil {
				return tamperespresso.FederationOutcome{}, mapFederationError(nerr)
			}
			user, _, err = core.ProvisionUserWithIdentity(ctx, email, providerID, subject)
			if err != nil {
				return tamperespresso.FederationOutcome{}, mapFederationError(err)
			}
		}

		// Mint the login session, threading the IdP's auth_time + acr through
		// (NOT the local-password defaults IssueTokensForUser would stamp) — so a
		// later step-up freshness check stays honest about how this session
		// authenticated. refreshTTL > 0 => a refresh token + cookie.
		tokens, err := core.IssueTokensForUserWithACR(ctx, user.ID, v.Claims.AuthTime(time.Now), v.Claims.ACR(crypto.ACRIncommonSilver))
		if err != nil {
			return tamperespresso.FederationOutcome{}, mapFederationError(err)
		}
		return tamperespresso.FederationOutcome{
			Tokens:   tokens,
			User:     project(ctx, &user),
			Redirect: v.State.RedirectAfterLogin, // already sanitized at Start; trusted verbatim
			Linked:   false,                       // login leg (not link)
		}, nil
	}
}

// mapFederationError turns identity-core sentinels into clean *espresso.Error
// codes. The hook is a handler seam — a raw error would render as an opaque
// 500. These are the paths a real IdP integration hits on day one:
//   - a deactivated user re-authenticating,
//   - a federated email that already belongs to a local account (this example
//     refuses JIT-provision — a real app links explicitly from account settings,
//     Barista's "email-collision veto").
func mapFederationError(err error) error {
	switch {
	case errors.Is(err, identity.ErrUserInactive):
		return espresso.ErrUnauthorized("account is deactivated").WithCode("USER_INACTIVE")
	case errors.Is(err, identity.ErrEmailTaken), errors.Is(err, identity.ErrIdentityTaken):
		return espresso.ErrConflict("that email is already registered — link this provider from account settings").WithCode("OIDC_EMAIL_CONFLICT")
	case errors.Is(err, identity.ErrInvalidEmail):
		return espresso.ErrBadRequest("the identity provider returned a malformed email").WithCode("INVALID_EMAIL")
	default:
		return espresso.ErrInternal("federated sign-in failed").Wrap(err)
	}
}

// --- Lungo wrappers: Start/Callback take a provider id (path) + query params,
//     so they need thin adapters to fit the espresso Path+Query handler shape.

type oidcStartPath struct {
	ProviderID string `path:"id"`
}
type oidcStartQuery struct {
	Redirect  string `query:"redirect"`
	MaxAge    int64  `query:"max_age"`
	ACRValues string `query:"acr_values"`
}
type oidcCallbackPath struct {
	ProviderID string `path:"id"`
}
type oidcCallbackQuery struct {
	Code  string `query:"code"`
	State string `query:"state"`
	Error string `query:"error"`
}

func startOIDC(fed *tamperespresso.FederationRoutes) func(context.Context, *extractor.Path[oidcStartPath], *extractor.Query[oidcStartQuery]) (tamperespresso.Redirect, error) {
	return func(ctx context.Context, p *extractor.Path[oidcStartPath], q *extractor.Query[oidcStartQuery]) (tamperespresso.Redirect, error) {
		return fed.Start(ctx, p.Data.ProviderID, tamperespresso.StartParams{
			Redirect:  q.Data.Redirect,
			MaxAge:    q.Data.MaxAge,
			ACRValues: q.Data.ACRValues,
		})
	}
}

func callbackOIDC(fed *tamperespresso.FederationRoutes) func(context.Context, *extractor.Path[oidcCallbackPath], *extractor.Query[oidcCallbackQuery]) (tamperespresso.Redirect, error) {
	return func(ctx context.Context, p *extractor.Path[oidcCallbackPath], q *extractor.Query[oidcCallbackQuery]) (tamperespresso.Redirect, error) {
		return fed.Callback(ctx, p.Data.ProviderID, tamperespresso.CallbackParams{
			Code:  q.Data.Code,
			State: q.Data.State,
			Error: q.Data.Error,
		})
	}
}
