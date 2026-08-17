package espresso

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/suryakencana007/tamper/oauth2social"
	"github.com/suryakencana007/tamper/oidc"
	"golang.org/x/oauth2"
)

var (
	// ErrOAuth2State is any state-cookie failure on a social callback.
	// Apps map it exactly as they map ErrOIDCState (INVALID_STATE).
	ErrOAuth2State = errors.New("oauth2social: state cookie invalid")
	// ErrOAuth2Exchange is a failed code-for-token exchange.
	ErrOAuth2Exchange = errors.New("oauth2social: token exchange failed")
)

// StartOAuth2Flow builds the authorization redirect for a social
// provider: mints flow randomness, signs the state cookie, and
// assembles the authorize URL.
//
// It is the sibling of [StartOIDCFlow] and differs in exactly two ways,
// both forced by the protocol rather than chosen:
//
//   - No nonce is sent. A nonce is an id_token claim, and there is no
//     id_token here, so a nonce would be a parameter nobody ever checks
//     — worse than useless, because it would LOOK like replay
//     protection to a future reader. The state cookie therefore carries
//     the whole CSRF defence: per-flow random, provider-bound, signed,
//     and consumed once.
//   - No step-up parameters. `max_age` and `acr_values` are OIDC Core
//     concepts with no plain-OAuth2 equivalent; forwarding them would
//     be ignored by the provider while telling the app a re-auth had
//     been demanded. A social provider cannot satisfy a step-up, so
//     this flow does not pretend to offer one.
//
// PKCE (S256) is unconditional. There is no knob, because the only
// reason to omit it is a provider that cannot parse the parameters, and
// such a provider should be fixed rather than accommodated.
func StartOAuth2Flow(
	p *oauth2social.Provider,
	secret []byte,
	issuer string,
	now time.Time,
	cookie StateCookieConfig,
	o StartOptions,
) (string, *http.Cookie, error) {
	if p == nil {
		return "", nil, fmt.Errorf("oauth2social: nil provider")
	}
	// Reuses the OIDC flow randomness deliberately: same state entropy,
	// same PKCE verifier/challenge derivation. The nonce it also mints
	// is simply not sent (see above).
	flow, err := oidc.NewFlow()
	if err != nil {
		return "", nil, fmt.Errorf("oauth2social: flow randomness: %w", err)
	}
	mode := o.Mode
	if mode == "" {
		mode = oidc.ModeLogin
	}

	claims := oidc.StateCookieClaims{
		State:              flow.State,
		CodeVerifier:       flow.CodeVerifier,
		ProviderID:         p.Config.ID,
		RedirectAfterLogin: o.Redirect,
		Mode:               mode,
		UserID:             o.UserID,
		CallingUserID:      o.CallingUserID,
		// Nonce deliberately left empty: nothing downstream can check it.
	}
	signed, err := oidc.SignOIDCStateWithSecret(secret, claims, issuer, now, cookie.TTL)
	if err != nil {
		return "", nil, fmt.Errorf("oauth2social: sign state: %w", err)
	}

	authURL := p.OAuth2.AuthCodeURL(
		flow.State,
		oauth2.S256ChallengeOption(flow.CodeVerifier),
	)
	return authURL, cookie.Set(signed), nil
}

// OAuth2Verified is the validated social callback: identity claims in
// the SAME shape an OIDC callback yields, plus the signed state claims
// the app's business tail dispatches on.
//
// Claims is [*oidc.Claims] on purpose — see the oauth2social package
// doc. An app's federated sign-in path takes this value without knowing
// which protocol produced it.
type OAuth2Verified struct {
	ProviderID string
	Claims     *oidc.Claims
	State      oidc.StateCookieClaims
}

// VerifyOAuth2Callback validates a social callback end to end:
// verifies the signed state cookie, cross-checks the provider id and
// the state parameter, exchanges the code with the PKCE verifier, then
// spends the access token on userinfo and maps the result to claims.
//
// The state cross-check is not a formality here. With no id_token and
// no nonce, these two comparisons — cookie-vs-parameter state, and
// cookie-vs-provider id — ARE the binding between the browser that
// started the flow and the response coming back. An implementation that
// skipped them would still work in every manual test and would accept a
// callback injected by any site.
//
// Errors, each mapped by the app to its wire code:
//
//   - ErrOAuth2State                  — state failure (INVALID_STATE)
//   - ErrOAuth2Exchange               — exchange failed (502)
//   - oauth2social.ErrUserinfo        — userinfo failed (502)
//   - oauth2social.ErrNoSubject       — unusable identity
//   - oauth2social.ErrEmailRequired   — no address (user-actionable)
//   - oauth2social.ErrEmailUnverified — unverified (user-actionable)
func VerifyOAuth2Callback(
	ctx context.Context,
	p *oauth2social.Provider,
	code, state, cookieVal string,
	secret []byte,
	issuer string,
	now func() time.Time,
) (OAuth2Verified, error) {
	if p == nil {
		return OAuth2Verified{}, fmt.Errorf("oauth2social: nil provider")
	}
	claims, err := oidc.VerifyOIDCStateWithSecret(secret, cookieVal, issuer, now)
	if err != nil {
		return OAuth2Verified{}, fmt.Errorf("%w: %v", ErrOAuth2State, err)
	}
	if claims.ProviderID != p.Config.ID {
		return OAuth2Verified{}, fmt.Errorf("%w: provider mismatch", ErrOAuth2State)
	}
	if claims.State != state {
		return OAuth2Verified{}, fmt.Errorf("%w: state mismatch", ErrOAuth2State)
	}

	token, err := p.OAuth2.Exchange(ctx, code, oauth2.VerifierOption(claims.CodeVerifier))
	if err != nil {
		return OAuth2Verified{}, fmt.Errorf("%w: %v", ErrOAuth2Exchange, err)
	}

	identity, err := p.FetchIdentity(ctx, token)
	if err != nil {
		return OAuth2Verified{}, err // oauth2social sentinels pass through
	}
	return OAuth2Verified{ProviderID: p.Config.ID, Claims: identity, State: claims}, nil
}
