// State-cookie helpers for the SP-initiated flow (including step-up).
//
// SAML doesn't have an OIDC-equivalent state/nonce protocol primitive,
// so the app mints a signed cookie at its /login route that its ACS
// handler reads on the callback. The cookie carries:
//
//   - the step-up parameters forwarded at /login time (max_age +
//     acr_values) so the ACS can compare them against the assertion's
//     AuthnInstant + AuthnContextClassRef.
//   - the calling user id so step-up audit emissions attribute the
//     row to the session user, not the (possibly freshly
//     JIT-provisioned) IdP-returned subject.
//   - the redirect-after-login path (rather than via RelayState — the
//     80-byte SAML RelayState ceiling is too tight for a future-proof
//     payload).
//
// The cookie is a signed JWT with a short TTL and a purpose
// discriminator so it can safely share a signing secret with the
// app's other HS256 surfaces ("one secret to rotate") — safety rests
// on purpose + issuer discrimination, which is why purpose checking
// is mandatory in VerifyStateCookieWithSecret. Cookie NAMES are the
// app's concern (apps brand their cookies; a `__Host-` prefix on
// HTTPS deploys is recommended for Secure + Path=/ strictness).

package saml

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// StateTTL bounds how long a /login cookie stays valid. 10 minutes
	// is the SAML AuthnRequest "active window" most IdPs honor; older
	// pending logins are safer to expire than to honor.
	StateTTL = 10 * time.Minute

	// stateCookiePurpose discriminates the cookie's JWT from access
	// JWTs, OIDC state cookies, and any other tokens sharing the
	// HS256 secret.
	stateCookiePurpose = "saml_state"

	// ModeLogin is the default state-cookie mode — the ACS terminates
	// in the app's federated sign-in path (JIT-provision or repeat
	// sign-in). Empty mode strings decode as ModeLogin so cookies
	// signed by an older deploy still resolve cleanly during a
	// rolling-deploy window.
	ModeLogin = "login"

	// ModeLink is the mode set by an authenticated link-start route;
	// the ACS handler dispatches into the app's identity-link path
	// instead of the sign-in path. The cookie also carries UserID so
	// the link attaches to the session's existing user — NOT to
	// whatever user the IdP's email-attribute happens to match.
	ModeLink = "link"
)

// ErrStateExpired is returned by VerifyStateCookieWithSecret for any
// failure (bad signature, wrong purpose, expired). Collapses to a
// single error so the ACS handler can fail-closed without leaking
// which check tripped.
var ErrStateExpired = errors.New("saml: state cookie expired or invalid")

// StateCookieClaims is the payload of the signed SAML state cookie.
// All step-up fields are omit-empty so a /login without step-up params
// signs a minimal cookie + the ACS handler can detect "no step-up
// requested" by the zero values.
type StateCookieClaims struct {
	// ProviderID is the SAML provider id from the path. The ACS
	// handler re-checks it against the path id so a state cookie
	// minted under provider A can't be replayed against provider B's
	// ACS endpoint.
	ProviderID string `json:"pid"`
	// RedirectAfterLogin is the post-sign-in target, sanitised at
	// /login time. Lives in the cookie (NOT in RelayState) because
	// RelayState's 80-byte spec ceiling is too tight for the JWT-
	// shaped payload needed to carry the step-up params anyway.
	RedirectAfterLogin string `json:"red,omitempty"`
	// RequestedMaxAgeSeconds carries the step-up `max_age` parameter.
	// The ACS handler compares the assertion's AuthnInstant against
	// this bound. Zero means non-step-up.
	RequestedMaxAgeSeconds int64 `json:"rma,omitempty"`
	// RequestedACRValues is the satisfaction set. Empty means
	// non-step-up.
	RequestedACRValues []string `json:"rav,omitempty"`
	// CallingUserID is the authenticated user who triggered the
	// step-up. Stamped so audit emissions attribute to the session
	// user. Empty when anonymous (e.g. fresh login — tolerated but
	// typically not a step-up case).
	CallingUserID string `json:"cuid,omitempty"`
	// Mode is ModeLogin (default) for the public sign-in flow or
	// ModeLink for an authenticated link round-trip. Empty mode reads
	// as ModeLogin so cookies signed by older /login flows still
	// verify cleanly during a rolling-deploy window.
	Mode string `json:"mode,omitempty"`
	// UserID is set only on ModeLink cookies — captures the session's
	// authenticated subject at link-start time so the ACS callback
	// can attach the IdP-side identity to that user, NOT to whatever
	// user the IdP's email-attribute happens to match. Link flows
	// bypass email-collision guardrails because the link is
	// intentional + the actor is authenticated.
	UserID  string `json:"uid,omitempty"`
	Purpose string `json:"purpose"`
	jwt.RegisteredClaims
}

// SignStateCookieWithSecret signs a StateCookieClaims via HS256.
// Caller injects the secret, issuer + now so the app controls key
// rotation and tests stay deterministic.
func SignStateCookieWithSecret(secret []byte, claims StateCookieClaims, issuer string, now time.Time, ttl time.Duration) (string, error) {
	if len(secret) == 0 {
		return "", fmt.Errorf("saml: state cookie secret is empty")
	}
	claims.Purpose = stateCookiePurpose
	claims.Issuer = issuer
	claims.IssuedAt = jwt.NewNumericDate(now)
	claims.ExpiresAt = jwt.NewNumericDate(now.Add(ttl))
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("saml: sign state cookie: %w", err)
	}
	return signed, nil
}

// VerifyStateCookieWithSecret round-trips a signed cookie value back
// into claims. Any failure collapses to ErrStateExpired (caller maps
// to its canonical invalid-state error). nowFn lets tests drive
// expiry. Purpose checking is mandatory — it is what keeps a shared
// HS256 secret safe across token surfaces.
func VerifyStateCookieWithSecret(secret []byte, token, issuer string, nowFn func() time.Time) (StateCookieClaims, error) {
	if len(secret) == 0 {
		return StateCookieClaims{}, fmt.Errorf("saml: state cookie secret is empty")
	}
	claims := &StateCookieClaims{}
	parsed, err := jwt.ParseWithClaims(token, claims,
		func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method %q", t.Method.Alg())
			}
			return secret, nil
		},
		jwt.WithTimeFunc(nowFn),
		jwt.WithIssuer(issuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return StateCookieClaims{}, fmt.Errorf("%w: %v", ErrStateExpired, err)
	}
	if !parsed.Valid {
		return StateCookieClaims{}, fmt.Errorf("%w: token not valid", ErrStateExpired)
	}
	if claims.Purpose != stateCookiePurpose {
		return StateCookieClaims{}, fmt.Errorf("%w: wrong purpose %q", ErrStateExpired, claims.Purpose)
	}
	return *claims, nil
}
