// Command discord is a runnable, end-to-end example of "Sign in with
// Discord" — a provider with NO OpenID Connect layer — using
// tamper/oauth2social.
//
//	go run ./examples/discord
//
// # What this example is really demonstrating
//
// Not that Discord works. That it works THROUGH THE SAME APPLICATION CODE
// as an OIDC provider.
//
// signIn below is the app's federated sign-in tail: resolve the identity by
// (provider, subject), just-in-time provision on first sight, mint a session.
// It takes an *oidc.Claims and never asks which protocol produced it, because
// oauth2social.Provider.FetchIdentity returns exactly the type the OIDC path
// returns. An application adopting social login writes no second code path,
// no protocol switch, and no parallel provisioning branch — which is the whole
// argument for the package existing in this shape.
//
// The embedded fake Discord (fakediscord.go) stands in for the real service so
// this runs with no application registration. A real integration changes the
// endpoint URLs and the client credentials; nothing else here moves.
//
// main_test.go drives the full browser dance and is the proof.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	espresso "github.com/suryakencana007/espresso/v2"
	"github.com/suryakencana007/espresso/v2/extractor"

	"github.com/suryakencana007/tamper/crypto"
	tamperespresso "github.com/suryakencana007/tamper/espresso"
	"github.com/suryakencana007/tamper/identity"
	"github.com/suryakencana007/tamper/oauth2social"
	"github.com/suryakencana007/tamper/oidc"
	"github.com/suryakencana007/tamper/tenant"
	"golang.org/x/oauth2"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("discord: %v", err)
	}
}

func run() error {
	secret := os.Getenv("DISCORD_JWT_SECRET")
	if secret == "" {
		secret = "insecure-demo-secret-set-DISCORD_JWT_SECRET-in-production"
		log.Println("discord: DISCORD_JWT_SECRET unset — using an insecure demo secret")
	}

	fake := newFakeDiscord()
	defer fake.Close()
	log.Printf("discord: embedded fake Discord at %s (stands in for discord.com)", fake.URL())

	const addr = ":8080"
	app := newApp(secret, fake, func() string { return "http://localhost" + addr })

	router := espresso.Portafilter()
	app.mount(router)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("discord: listening on %s — GET /auth/discord/start begins the flow", addr)
	return router.BrewContext(ctx,
		espresso.WithAddr(addr),
		espresso.WithReadTimeout(15*time.Second),
		espresso.WithWriteTimeout(15*time.Second),
		espresso.WithShutdownTimeout(30*time.Second),
	)
}

// app holds the wiring. Split from run() so main_test.go can mount the same
// routes on an httptest server.
type app struct {
	core       *identity.Core
	provider   *oauth2social.Provider
	jwtSecret  []byte
	issuer     string
	cookie     tamperespresso.StateCookieConfig
	appBaseURL func() string
	// httpClient is the fake's TLS client, threaded into the flow's context
	// so the self-signed certificate verifies. A real deployment passes
	// nothing here and gets the default client.
	httpClient *http.Client
}

func newApp(jwtSecret string, fake *fakeDiscord, appBaseURL func() string) *app {
	jwt := crypto.NewJWTService(crypto.JWTConfig{
		Secret: jwtSecret, TTL: 15 * time.Minute, Issuer: "discord-example",
	})
	core, err := identity.New(
		identity.NewMemStore(), jwt,
		identity.WithRefreshTTL(30*24*time.Hour),
	)
	if err != nil {
		log.Fatalf("discord: identity core: %v", err)
	}

	// The provider. Discord() supplies the endpoints, scopes and claim map;
	// here we only repoint it at the embedded fake.
	cfg := oauth2social.Discord("demo-client-id", "demo-client-secret",
		appBaseURL()+"/auth/discord/callback")
	cfg.AuthURL = fake.URL() + "/oauth2/authorize"
	cfg.TokenURL = fake.URL() + "/api/oauth2/token"
	cfg.UserinfoURL = fake.URL() + "/api/users/@me"

	p, perr := oauth2social.New(cfg)
	if perr != nil {
		// Construction validates endpoints + claim map, so a broken provider
		// cannot reach a live flow. In a real app this is a boot failure.
		log.Fatalf("discord: provider config: %v", perr)
	}

	return &app{
		core:      core,
		provider:  p,
		jwtSecret: []byte(jwtSecret),
		issuer:    "discord-example",
		cookie: tamperespresso.StateCookieConfig{
			BaseName: "discord_state",
			Path:     "/",
			TTL:      10 * time.Minute,
			// Secure would be true in production; the example serves plain
			// http on localhost.
		},
		appBaseURL: appBaseURL,
		httpClient: fake.srv.Client(),
	}
}

// clientContext threads the fake's TLS-trusting client into the flow.
//
// Deliberately NOT InsecureSkipVerify: oauth2social refuses plain-http
// endpoints on purpose, and an example that disabled certificate
// verification would be demonstrating a transport the package does not
// permit. A real deployment omits this entirely.
func (a *app) clientContext(ctx context.Context) context.Context {
	if a.httpClient == nil {
		return ctx
	}
	return context.WithValue(ctx, oauth2.HTTPClient, a.httpClient)
}

// stateSlot is the context slot the callback reads the state cookie
// through. tamper ships ReadNamedCookie for exactly this: the cookie read
// stays app-side middleware, so the flow function takes a plain string and
// never touches *http.Request.
const stateSlot = "discord_state_cookie"

func (a *app) mount(r *espresso.Router) {
	r.Get("/auth/discord/start", espresso.HandlerCtx(a.start))
	r.Use(tamperespresso.ReadNamedCookie(stateSlot, a.cookie.Name()))
	r.Get("/auth/discord/callback", espresso.Doppio(a.callback))
}

// start redirects the browser to Discord's consent screen.
func (a *app) start(ctx context.Context) (tamperespresso.Redirect, error) {
	authURL, cookie, err := tamperespresso.StartOAuth2Flow(
		a.provider, a.jwtSecret, a.issuer, time.Now(), a.cookie,
		tamperespresso.StartOptions{Redirect: "/"},
	)
	if err != nil {
		return tamperespresso.Redirect{}, espresso.ErrInternal("could not start sign-in").Wrap(err)
	}
	return tamperespresso.Redirect{URL: authURL, Cookies: []*http.Cookie{cookie}}, nil
}

// callbackQuery binds the two parameters the provider sends back.
type callbackQuery struct {
	Code  string `query:"code"`
	State string `query:"state"`
}

// callbackResult is what the example returns instead of setting a session
// cookie — enough to see that a real session was minted.
type callbackResult struct {
	UserID      string `json:"user_id"`
	Email       string `json:"email"`
	Provider    string `json:"provider"`
	Subject     string `json:"subject"`
	Token       string `json:"access_token"`
	FirstSignIn bool   `json:"first_sign_in"`
}

// callback completes the flow: tamper verifies the state cookie, exchanges the
// code with PKCE, spends the access token on userinfo, and hands back claims.
// Everything after that is the app's own sign-in tail — and it is protocol-blind.
func (a *app) callback(ctx context.Context, q *extractor.Query[callbackQuery]) (espresso.JSON[callbackResult], error) {
	cookieVal, ok := tamperespresso.NamedCookieValue(ctx, stateSlot)
	if !ok {
		return espresso.JSON[callbackResult]{}, espresso.ErrBadRequest("missing state cookie").WithCode("INVALID_STATE")
	}

	verified, err := tamperespresso.VerifyOAuth2Callback(
		a.clientContext(ctx), a.provider,
		q.Data.Code, q.Data.State, cookieVal,
		a.jwtSecret, a.issuer, time.Now,
	)
	if err != nil {
		return espresso.JSON[callbackResult]{}, mapFlowError(err)
	}

	// --- the app's own tail. Note what is NOT here: any mention of OAuth2,
	// userinfo, or Discord. It takes claims. ---
	out, err := a.signIn(ctx, verified.ProviderID, verified.Claims)
	if err != nil {
		return espresso.JSON[callbackResult]{}, err
	}
	return espresso.JSON[callbackResult]{StatusCode: http.StatusOK, Data: out}, nil
}

// signIn is the protocol-blind federated sign-in tail.
//
// It takes an *oidc.Claims and a provider id, and would serve an OIDC
// callback unchanged — which is the point. Resolve by (provider, subject),
// JIT-provision on first sight, mint a session.
//
// Keying on the SUBJECT rather than the email is what makes it safe: a
// Discord username is user-changeable and an email can be reassigned, but the
// snowflake is stable and opaque forever.
func (a *app) signIn(ctx context.Context, providerID string, claims *oidc.Claims) (callbackResult, error) {
	user, _, found, err := a.core.ResolveByIdentity(ctx, tenant.Single, providerID, claims.Sub)
	if err != nil {
		return callbackResult{}, mapIdentityError(err)
	}
	first := !found
	if !found {
		email, nerr := identity.NormaliseEmail(claims.Email)
		if nerr != nil {
			return callbackResult{}, espresso.ErrBadRequest("the provider returned no usable email address").
				WithCode("EMAIL_REQUIRED")
		}
		user, _, err = a.core.ProvisionUserWithIdentity(ctx, tenant.Single, email, providerID, claims.Sub)
		if err != nil {
			return callbackResult{}, mapIdentityError(err)
		}
	}

	tokens, err := a.core.IssueTokensForUserWithACR(ctx, user.ID, time.Now().Unix(), crypto.ACRLocalPassword)
	if err != nil {
		return callbackResult{}, mapIdentityError(err)
	}
	return callbackResult{
		UserID: user.ID, Email: user.Email,
		Provider: providerID, Subject: claims.Sub,
		Token: tokens.Access, FirstSignIn: first,
	}, nil
}

// mapFlowError turns the flow sentinels into wire codes. The split that
// matters is user-actionable versus upstream: a person who needs to verify
// their Discord email can fix that themselves, while a 502 is the operator's
// problem.
func mapFlowError(err error) error {
	switch {
	case errors.Is(err, tamperespresso.ErrOAuth2State):
		return espresso.ErrBadRequest("sign-in could not be verified; please try again").WithCode("INVALID_STATE")
	case errors.Is(err, oauth2social.ErrEmailUnverified):
		return espresso.ErrForbidden("verify your email address with the provider, then sign in again").
			WithCode("EMAIL_UNVERIFIED")
	case errors.Is(err, oauth2social.ErrEmailRequired):
		return espresso.ErrForbidden("the provider returned no email address").WithCode("EMAIL_REQUIRED")
	case errors.Is(err, oauth2social.ErrNoSubject):
		return espresso.ErrServiceUnavailable("the provider returned no usable identity").WithCode("IDP_ERROR")
	case errors.Is(err, tamperespresso.ErrOAuth2Exchange), errors.Is(err, oauth2social.ErrUserinfo):
		return espresso.ErrServiceUnavailable("the provider is unavailable; please try again").WithCode("IDP_UNAVAILABLE")
	default:
		return espresso.ErrInternal("sign-in failed").Wrap(err)
	}
}

func mapIdentityError(err error) error {
	switch {
	case errors.Is(err, identity.ErrUserInactive):
		return espresso.ErrForbidden("this account has been deactivated").WithCode("ACCOUNT_DISABLED")
	case errors.Is(err, identity.ErrEmailTaken):
		// The email-collision veto: a federated identity must never attach
		// itself to an existing account just because the addresses match.
		// A real app sends the user through an explicit link flow instead.
		return espresso.ErrConflict("an account with this email already exists; sign in and link the provider from account settings").
			WithCode("EMAIL_CONFLICT")
	default:
		return espresso.ErrInternal(fmt.Sprintf("sign-in failed: %v", err))
	}
}
