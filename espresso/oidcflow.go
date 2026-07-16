package espresso

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/suryakencana007/barista/packages/tamper/oidc"
)

// The OIDC verification spine: the RFC/PKCE/state-cookie mechanics of
// the SP-initiated flow, handler-agnostic. A non-SPA consumer uses
// StartOIDCFlow + VerifyOIDCCallback directly, without Mount. What
// stays the app's: the redirect allowlist (sanitize BEFORE StartOIDCFlow),
// the callback->landing SPA protocol, and the entire post-verify
// business tail (upsert/link/reconcile/mint/audit/project).

var (
	// ErrOIDCState wraps every state-cookie failure on the callback —
	// bad/expired signature, provider mismatch, state mismatch. Apps
	// map it to their INVALID_STATE wire code (a single collapse so
	// the failure is not a validation oracle).
	ErrOIDCState = errors.New("oidc: state invalid")
	// ErrOIDCExchange wraps an IdP token-exchange failure (upstream
	// 5xx / network). Apps map it to a 502.
	ErrOIDCExchange = errors.New("oidc: idp token exchange failed")
	// ErrOIDCNoIDToken is the IdP returning a token response with no
	// id_token. Apps map it to INVALID_IDTOKEN.
	ErrOIDCNoIDToken = errors.New("oidc: idp returned no id token")
)

// StartOptions carries the per-request flow inputs. Redirect is the
// ALREADY-SANITIZED post-login target — the app owns its redirect
// allowlist; tamper stores the value verbatim in the state cookie.
// Mode is oidc.ModeLogin or oidc.ModeLink; UserID is required for
// link mode; CallingUserID is the audit actor for step-up starts.
type StartOptions struct {
	Redirect      string
	MaxAge        int64
	ACRValues     []string
	Mode          string
	UserID        string
	CallingUserID string
}

// StartOIDCFlow builds an SP-initiated authorization redirect: mints
// PKCE + nonce randomness, signs the state cookie, and assembles the
// IdP authorize URL with step-up forwarding — max_age + acr_values
// (space-joined per OIDC Core §3.1.2.1) + prompt=login when either is
// requested, so the IdP can't short-circuit on an existing session
// and skip the re-auth the app asked for. Returns the authorize URL +
// the state Set-Cookie; the app returns these as a Redirect (login
// flow) or a JSON body carrying the cookie (link-start flow).
func StartOIDCFlow(p *oidc.Provider, secret []byte, issuer string, now time.Time, cookie StateCookieConfig, o StartOptions) (string, *http.Cookie, error) {
	if p == nil {
		return "", nil, fmt.Errorf("oidc: nil provider")
	}
	flow, err := oidc.NewFlow()
	if err != nil {
		return "", nil, fmt.Errorf("oidc: flow randomness: %w", err)
	}
	mode := o.Mode
	if mode == "" {
		mode = oidc.ModeLogin
	}
	maxAge := o.MaxAge
	if maxAge < 0 {
		maxAge = 0
	}
	cookieValue, err := oidc.SignOIDCStateWithSecret(
		secret,
		oidc.StateCookieClaims{
			State:                  flow.State,
			Nonce:                  flow.Nonce,
			CodeVerifier:           flow.CodeVerifier,
			ProviderID:             p.Config.ID,
			RedirectAfterLogin:     o.Redirect,
			Mode:                   mode,
			UserID:                 o.UserID,
			RequestedMaxAgeSeconds: maxAge,
			RequestedACRValues:     o.ACRValues,
			CallingUserID:          o.CallingUserID,
		},
		issuer, now, oidc.StateTTL,
	)
	if err != nil {
		return "", nil, fmt.Errorf("oidc: sign state: %w", err)
	}

	opts := []oauth2.AuthCodeOption{
		oauth2.AccessTypeOnline,
		oauth2.SetAuthURLParam("nonce", flow.Nonce),
		oauth2.S256ChallengeOption(flow.CodeVerifier),
	}
	isStepUp := maxAge > 0 || len(o.ACRValues) > 0
	if maxAge > 0 {
		opts = append(opts, oauth2.SetAuthURLParam("max_age", strconv.FormatInt(maxAge, 10)))
	}
	if len(o.ACRValues) > 0 {
		opts = append(opts, oauth2.SetAuthURLParam("acr_values", strings.Join(o.ACRValues, " ")))
	}
	if isStepUp {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", "login"))
	}
	authURL := p.OAuth2.AuthCodeURL(flow.State, opts...)
	return authURL, cookie.Set(cookieValue), nil
}

// OIDCVerified is the validated callback result: the verified
// ID-token Claims (with .Raw, .AuthTime, .ACR) plus the signed state
// claims (Mode / UserID / Requested* / CallingUserID / Redirect) the
// app's business tail dispatches on.
type OIDCVerified struct {
	ProviderID string
	Claims     *oidc.Claims
	State      oidc.StateCookieClaims
}

// VerifyOIDCCallback validates a callback end to end: verifies +
// cross-checks the signed state cookie (provider id + state param),
// exchanges the code, and verifies the ID token including the nonce.
// cookieVal is the raw state-cookie value the app read from the
// request (the cookie-read bridge stays app-side, mounted on the
// route). Errors — each mapped by the app to its wire code:
//
//   - ErrOIDCState        — any state-cookie failure (INVALID_STATE)
//   - ErrOIDCExchange     — IdP token exchange failed (502)
//   - ErrOIDCNoIDToken    — no id_token in the response (INVALID_IDTOKEN)
//   - oidc.ErrNonceMismatch / oidc.ErrIDTokenInvalid — pass through
func VerifyOIDCCallback(ctx context.Context, p *oidc.Provider, code, state, cookieVal string, secret []byte, issuer string, now func() time.Time) (OIDCVerified, error) {
	if p == nil {
		return OIDCVerified{}, fmt.Errorf("oidc: nil provider")
	}
	claims, err := oidc.VerifyOIDCStateWithSecret(secret, cookieVal, issuer, now)
	if err != nil {
		return OIDCVerified{}, fmt.Errorf("%w: %v", ErrOIDCState, err)
	}
	if claims.ProviderID != p.Config.ID {
		return OIDCVerified{}, fmt.Errorf("%w: provider mismatch", ErrOIDCState)
	}
	if claims.State != state {
		return OIDCVerified{}, fmt.Errorf("%w: state mismatch", ErrOIDCState)
	}
	token, err := p.OAuth2.Exchange(ctx, code, oauth2.VerifierOption(claims.CodeVerifier))
	if err != nil {
		return OIDCVerified{}, fmt.Errorf("%w: %v", ErrOIDCExchange, err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return OIDCVerified{}, ErrOIDCNoIDToken
	}
	verified, err := oidc.VerifyIDToken(ctx, p, rawIDToken, claims.Nonce)
	if err != nil {
		return OIDCVerified{}, err // oidc.ErrNonceMismatch / ErrIDTokenInvalid pass through
	}
	return OIDCVerified{ProviderID: p.Config.ID, Claims: verified, State: claims}, nil
}
