package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// ErrIDTokenInvalid wraps every ID-token validation failure path
// (bad signature, expired, wrong issuer, audience mismatch, nonce
// mismatch). Handlers collapse to 401 INVALID_IDTOKEN so the wire
// surface stays uniform — an attacker probing for which check fired
// gets the same status code regardless.
var ErrIDTokenInvalid = errors.New("oidc: id token invalid")

// ErrNonceMismatch is a subset of ErrIDTokenInvalid surfaced
// separately so the integration test suite can assert the nonce
// check fires. Handlers fold it back into INVALID_IDTOKEN.
var ErrNonceMismatch = errors.New("oidc: id token nonce does not match flow nonce")

// Claims is the typed view of the ID token payload the app cares
// about. Raw retains the FULL claim set so a group-claim
// role mapper can read configurable claim names (groups, roles,
// custom Auth0 paths) without re-parsing the token.
//
// The IdP-mandated fields (Sub, Aud, Iss, Exp) live on the
// coreoidc.IDToken value; this type holds the application-level
// fields (Email, Name, EmailVerified, PreferredUsername) plus the
// raw bag.
type Claims struct {
	// Sub is the IdP subject identifier — opaque, stable per user
	// per IdP, never reused across IdPs. The app persists it as the identity subject.
	Sub string `json:"sub"`
	// Email is the user-facing identifier on the app side.
	// The app normalises (lowercase + trim) before
	// storing.
	Email string `json:"email"`
	// EmailVerified is the IdP-side flag. the app should not gate
	// sign-in on this — it's the operator's responsibility to
	// configure the IdP to refuse unverified email sign-ins
	// upstream. The flag is surfaced through Raw so audit views
	// can flag suspicious sign-ins.
	EmailVerified bool `json:"email_verified"`
	// Name is the user-display string (e.g. "Alice Liddell").
	// Surfaced in the SPA topbar; not used for authorization.
	Name string `json:"name"`
	// PreferredUsername is the IdP-side display handle (e.g.
	// "alice", "alice@example.com"). Some IdPs (Azure AD) emit
	// this instead of Name.
	PreferredUsername string `json:"preferred_username"`

	// Raw retains the full claim map so a group-claim mapper can
	// read configurable claim names (see ExtractGroups). The app
	// passes this to its federated sign-in path.
	Raw map[string]any `json:"-"`
}

// VerifyIDToken parses + validates an ID token via coreos/go-oidc's
// IDTokenVerifier (signature via the JWKS, exp, iss, aud), then
// cross-checks the nonce claim against the flow-supplied nonce.
// The verifier's underlying JWKS auto-refreshes on a `kid` miss, so
// Google + Auth0's JWKS rotation is transparent.
//
// Returns a Claims value with both the typed fields and the raw
// claim map. Failures collapse to ErrIDTokenInvalid /
// ErrNonceMismatch so handlers map cleanly.
func VerifyIDToken(ctx context.Context, p *Provider, rawIDToken, expectedNonce string) (*Claims, error) {
	if p == nil {
		return nil, fmt.Errorf("oidc: provider is nil")
	}
	tok, err := p.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIDTokenInvalid, err)
	}
	if expectedNonce != "" && tok.Nonce != expectedNonce {
		return nil, fmt.Errorf("%w: got=%q want=%q", ErrNonceMismatch, tok.Nonce, expectedNonce)
	}
	// First materialise the typed fields, then re-read the raw map
	// for group mapping. coreos/go-oidc's IDToken.Claims dispatches via
	// json.Unmarshal under the hood, so two reads cost one extra
	// allocation but keep the typed + raw paths clean.
	typed := &Claims{}
	if err := tok.Claims(typed); err != nil {
		return nil, fmt.Errorf("%w: decode typed claims: %v", ErrIDTokenInvalid, err)
	}
	raw := map[string]any{}
	if err := tok.Claims(&raw); err != nil {
		return nil, fmt.Errorf("%w: decode raw claims: %v", ErrIDTokenInvalid, err)
	}
	typed.Raw = raw
	if typed.Sub == "" {
		// coreos/go-oidc's verifier doesn't require Subject — but
		// every real IdP emits it. Treat a missing sub as
		// invalid; without it we can't track JIT-provisioned users
		// across sign-ins.
		return nil, fmt.Errorf("%w: id token has no sub claim", ErrIDTokenInvalid)
	}
	return typed, nil
}

// MergeUserinfoIntoClaims overlays userinfo-endpoint claims onto an
// ID token claim set. Used when the ID token lacks groups
// (Azure AD strips groups from ID tokens by default; the userinfo
// endpoint carries them). Merge precedence:
//
//   - email + name + groups: userinfo wins (IdP-authoritative source
//     for the slowly-changing attribute set).
//   - sub + aud + iss + exp + nonce + iat: ID token wins (the
//     security-sensitive fields userinfo cannot change).
//
// The app wires it in front of its federated sign-in path when the
// provider config indicates the IdP needs userinfo enrichment.
func MergeUserinfoIntoClaims(idClaims *Claims, userinfo map[string]any) {
	if idClaims == nil || len(userinfo) == 0 {
		return
	}
	if idClaims.Raw == nil {
		idClaims.Raw = map[string]any{}
	}
	idTokenWins := map[string]struct{}{
		"sub": {}, "aud": {}, "iss": {}, "exp": {},
		"nonce": {}, "iat": {}, "at_hash": {},
	}
	for k, v := range userinfo {
		if _, fixed := idTokenWins[k]; fixed {
			continue
		}
		idClaims.Raw[k] = v
	}
	if email, ok := userinfo["email"].(string); ok && email != "" {
		idClaims.Email = email
	}
	if name, ok := userinfo["name"].(string); ok && name != "" {
		idClaims.Name = name
	}
}

// FetchUserinfo fetches the userinfo endpoint with the provided
// access token. Used when ID-token claims need enrichment — the
// app calls FetchUserinfo + MergeUserinfoIntoClaims before its
// federated sign-in path.
//
// Errors collapse to ErrIDTokenInvalid since a userinfo failure
// means we couldn't complete the OIDC handshake. The IdP might be
// transiently down, but from the RP's perspective the user can
// retry the sign-in.
func FetchUserinfo(ctx context.Context, p *Provider, accessToken string) (map[string]any, error) {
	if p == nil || p.UserInfoURL == "" {
		return nil, fmt.Errorf("%w: provider has no userinfo endpoint", ErrIDTokenInvalid)
	}
	src := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: accessToken})
	userinfo, err := p.OIDC.UserInfo(ctx, src)
	if err != nil {
		return nil, fmt.Errorf("%w: fetch userinfo: %v", ErrIDTokenInvalid, err)
	}
	raw := map[string]any{}
	if err := userinfo.Claims(&raw); err != nil {
		return nil, fmt.Errorf("%w: decode userinfo claims: %v", ErrIDTokenInvalid, err)
	}
	return raw, nil
}

// JSONRawFromClaims is a small helper for tests + audit-log callers
// that want a serialised view of the raw claim map. Returns nil for
// an empty / nil claim set so callers can pass the result straight
// into audit.Event.After without a separate nil check.
func JSONRawFromClaims(claims *Claims) json.RawMessage {
	if claims == nil || len(claims.Raw) == 0 {
		return nil
	}
	b, err := json.Marshal(claims.Raw)
	if err != nil {
		return nil
	}
	return b
}

// _ keeps the coreoidc import alive in the off-chance the file's
// only consumer ends up using only oauth2.
var _ coreoidc.IDToken

// AuthTime reads the IdP's auth_time claim (Unix seconds) from the
// verified ID-token raw claim map, mirroring the SAML
// ParsedAssertion.AuthnTime view. Per OIDC Core 1.0 §2, auth_time is
// the Unix timestamp of end-user authentication; when absent (some
// IdPs don't emit it without a max_age request param), falls back to
// nowFn().Unix().
//
// SECURITY (federation foot-gun): auth_time MUST come from the IdP
// when present — otherwise an attacker controlling callback timing
// could feign fresh authentication and collapse the step-up boundary.
// The three number shapes are all handled because a JSON decoder's
// mode determines which lands: float64 (default), int64, or
// json.Number (UseNumber decoders); missing json.Number silently
// weakens the boundary.
func (c *Claims) AuthTime(nowFn func() time.Time) int64 {
	if c != nil {
		if v, ok := c.Raw["auth_time"]; ok {
			switch t := v.(type) {
			case float64:
				if t > 0 {
					return int64(t)
				}
			case int64:
				if t > 0 {
					return t
				}
			case json.Number:
				if n, err := t.Int64(); err == nil && n > 0 {
					return n
				}
			}
		}
	}
	return nowFn().Unix()
}

// ACR reads the IdP's acr claim (Authentication Context Class
// Reference URN) from the verified ID-token raw claim map, mirroring
// ParsedAssertion.ACR. Returns fallback when the claim is absent or
// empty — the app supplies its assurance-level default (most modern
// IdPs emit something stronger when step-up is requested).
func (c *Claims) ACR(fallback string) string {
	if c != nil {
		if v, ok := c.Raw["acr"].(string); ok && v != "" {
			return v
		}
	}
	return fallback
}
