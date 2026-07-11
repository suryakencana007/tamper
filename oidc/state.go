package oidc

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

const (
	// StateTTL is how long the signed state cookie stays valid. 10
	// minutes is generous for users who tab away mid-login but tight
	// enough that a leaked cookie has minimal replay window.
	StateTTL = 10 * time.Minute

	// stateCookiePurpose discriminates the JWT inside the cookie from
	// access JWTs and any other tokens sharing the HS256 secret. The
	// cookie verifier rejects tokens with the wrong purpose so an
	// attacker can't swap an access JWT into the state cookie slot.
	stateCookiePurpose = "oidc_state"

	// ModeLogin is the default state-cookie mode — the IdP round trip
	// terminates in the app's federated sign-in path (JIT-provision
	// or repeat sign-in). Empty mode strings read as ModeLogin to
	// keep cookies signed by older flows resolving cleanly.
	ModeLogin = "login"
	// ModeLink is the mode set by an authenticated link-start route;
	// the callback dispatches into the app's identity-link path
	// instead of the sign-in path. The cookie also carries UserID so
	// the link attaches to the session's existing user, not whatever
	// user the IdP's claim set happens to match by email.
	ModeLink = "link"
)

// ErrStateExpired wraps any failure during state-cookie validation
// (bad signature, expired, wrong purpose, malformed). Callers should
// collapse to a single invalid-state error so the wire surface stays
// uniform regardless of which check failed.
var ErrStateExpired = errors.New("oidc: state cookie expired or invalid")

// StateCookieClaims is the payload of the signed state cookie. The
// shape carries everything the exchange handler needs to:
//   - cross-check the IdP-returned `state` query param against the
//     value originally sent (CSRF protection).
//   - verify the ID token's `nonce` claim matches what was sent
//     (replay protection).
//   - re-use the PKCE code verifier on the token exchange.
//   - confirm the IdP redirected to the right provider's callback URL
//     (defense against a confused-deputy if two providers share a
//     redirect base).
//   - resume the original navigation post-login.
type StateCookieClaims struct {
	State              string `json:"st"`
	Nonce              string `json:"nc"`
	CodeVerifier       string `json:"cv"`
	ProviderID         string `json:"pid"`
	RedirectAfterLogin string `json:"red,omitempty"`
	// Mode is ModeLogin (default) for the public sign-in flow or
	// ModeLink for an authenticated link round-trip. Empty mode reads
	// as ModeLogin so cookies signed by older /start flows still
	// verify cleanly.
	Mode string `json:"mode,omitempty"`
	// UserID is set only on ModeLink cookies — captures the session's
	// authenticated subject at link-start time so the callback can
	// attach the IdP-side identity to that user, NOT to whatever user
	// the IdP's email-claim happens to match.
	UserID string `json:"uid,omitempty"`
	// RequestedMaxAgeSeconds carries the step-up `max_age` parameter
	// forwarded at /start time (OIDC Core 1.0 §3.1.2.1). The exchange
	// handler compares the IdP-delivered `auth_time` against this
	// bound. Zero means the start was not a step-up flow.
	RequestedMaxAgeSeconds int64 `json:"rma,omitempty"`
	// RequestedACRValues carries the step-up `acr_values` parameter
	// (space-separated when forwarded to the IdP) supplied at /start
	// time. The exchange handler treats this as the satisfaction set:
	// a delivered acr that matches ANY entry counts as success. Empty
	// means the start was not a step-up flow.
	RequestedACRValues []string `json:"rav,omitempty"`
	// CallingUserID is the authenticated user who triggered the
	// step-up. Stamped at /start time so audit emissions carry the
	// actor even on JIT-provisioned IdP-returned identities. Empty
	// when the start is anonymous (rare for step-up but tolerated).
	CallingUserID string `json:"cuid,omitempty"`
	Purpose       string `json:"purpose"`
	jwt.RegisteredClaims
}

// Flow is the per-request bundle returned by NewFlow. The handler
// uses State + CodeChallenge on the authorization-URL build, signs
// the {state, nonce, verifier, ...} payload into a cookie, and the
// browser bounces to the IdP.
type Flow struct {
	State         string
	Nonce         string
	CodeVerifier  string
	CodeChallenge string
}

// NewFlow generates the per-request randomness. State + nonce are
// 32 bytes of crypto/rand, base64url-encoded. Code verifier uses
// golang.org/x/oauth2's GenerateVerifier (32 bytes, RFC 7636 §4.1).
// Code challenge is the SHA-256 of the verifier, base64url-encoded
// — handled by oauth2.S256ChallengeOption at AuthCodeURL time, but
// materialised here so the value can be logged in tests without
// re-deriving.
func NewFlow() (*Flow, error) {
	state, err := randomB64(32)
	if err != nil {
		return nil, fmt.Errorf("oidc: state: %w", err)
	}
	nonce, err := randomB64(32)
	if err != nil {
		return nil, fmt.Errorf("oidc: nonce: %w", err)
	}
	verifier := oauth2.GenerateVerifier()
	return &Flow{
		State:         state,
		Nonce:         nonce,
		CodeVerifier:  verifier,
		CodeChallenge: oauth2.S256ChallengeFromVerifier(verifier),
	}, nil
}

// CookieSigner signs + verifies state cookies. Implemented over an
// existing HS256 JWT secret rather than a fresh key — the state
// cookie has a short TTL and a clear `purpose` discriminator, so
// reusing the secret keeps the operational story to "one secret to
// rotate" without inviting cross-cookie reuse attacks.
//
// Implementations: any type that can sign a JWT + verify it. Apps
// typically wire their JWT service; tests inject a fake.
type CookieSigner interface {
	SignOIDCState(claims StateCookieClaims, ttl time.Duration) (string, error)
	VerifyOIDCState(token string) (StateCookieClaims, error)
}

// SignOIDCStateWithSecret signs a StateCookieClaims via HS256. The
// secret is the raw byte slice the app's JWT service holds; callers
// pass it in instead of taking a service dependency to keep this
// package import-light. Caller injects the issuer + now so the app
// controls key rotation and tests stay deterministic.
func SignOIDCStateWithSecret(secret []byte, claims StateCookieClaims, issuer string, now time.Time, ttl time.Duration) (string, error) {
	if len(secret) == 0 {
		return "", fmt.Errorf("oidc: state cookie secret is empty")
	}
	claims.Purpose = stateCookiePurpose
	claims.Issuer = issuer
	claims.IssuedAt = jwt.NewNumericDate(now)
	claims.ExpiresAt = jwt.NewNumericDate(now.Add(ttl))
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("oidc: sign state cookie: %w", err)
	}
	return signed, nil
}

// VerifyOIDCStateWithSecret round-trips the signed cookie back into
// the claims. Any failure — bad signature, wrong purpose, expired —
// collapses to ErrStateExpired so handlers can't leak which check
// failed. Caller injects the clock so tests can drive expiry
// deterministically; production passes time.Now. Purpose checking is
// mandatory — it is what keeps a shared HS256 secret safe across
// token surfaces.
func VerifyOIDCStateWithSecret(secret []byte, token, issuer string, now func() time.Time) (StateCookieClaims, error) {
	if len(secret) == 0 {
		return StateCookieClaims{}, fmt.Errorf("oidc: state cookie secret is empty")
	}
	claims := &StateCookieClaims{}
	parsed, err := jwt.ParseWithClaims(token, claims,
		func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method %q", t.Method.Alg())
			}
			return secret, nil
		},
		jwt.WithTimeFunc(now),
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

// randomB64 returns n bytes of crypto/rand encoded as base64url
// (no padding). Used for state + nonce values where the wire encoding
// must be URL-safe and a fixed length is undesirable.
func randomB64(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
