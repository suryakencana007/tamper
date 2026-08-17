// Package oauth2social federates identity from providers that speak
// plain OAuth 2.0 and have no OpenID Connect layer — Discord being the
// case that forced it into existence.
//
// # Why this package exists at all
//
// The [oidc] package cannot serve these providers, and not for want of
// configuration. OIDC's whole security model rests on an id_token: a
// signed assertion the client verifies against the issuer's JWKS,
// binding subject, audience, expiry, and a nonce in one artefact.
// Discord issues no id_token. Its undocumented discovery document
// advertises no id_token response type, and tamper's OIDC path
// hard-fails without one (ErrOIDCNoIDToken) — correctly, because
// accepting a flow with no signed assertion would silently drop the
// verification OIDC callers are relying on.
//
// So identity here comes from a second, authenticated round trip: after
// the code exchange, the access token is spent against the provider's
// userinfo endpoint, and the JSON that comes back IS the assertion.
// That is a weaker artefact than a signed id_token, and the difference
// is worth naming rather than papering over:
//
//   - There is no signature to verify. Trust rests entirely on TLS to
//     the userinfo endpoint plus the fact that the access token was
//     obtained through a PKCE-protected exchange with a client secret.
//   - There is no nonce, so nothing binds the authorization response to
//     this particular browser beyond the state cookie. The state
//     parameter therefore carries the ENTIRE CSRF defence here, which
//     is why it stays per-flow, provider-bound, and single-use.
//   - There is no audience claim, so a token minted for a different
//     application cannot be detected by inspection. It is detected by
//     the exchange itself failing — the client secret is what scopes it.
//
// # Protocol-blind output
//
// [Provider.FetchIdentity] returns [*oidc.Claims] — the very type the
// OIDC path produces, not a parallel one. That is deliberate and is the
// design's load-bearing decision: an application's just-in-time
// provisioning, email-collision veto, and account-linking paths key on
// (provider, subject) and read Email/EmailVerified, and NONE of them
// should have to learn which protocol delivered the claims. A second
// claims type would force every consumer to branch, and every branch is
// somewhere the two protocols can drift apart in handling.
package oauth2social

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
)

var (
	// ErrConfig is a malformed provider configuration — caught at
	// construction so a broken provider can never reach a live flow.
	ErrConfig = errors.New("oauth2social: invalid provider config")
	// ErrUserinfo is a failed or unparseable userinfo round trip.
	// Callers map it the way they map an OIDC token-exchange failure:
	// upstream trouble, not a user error.
	ErrUserinfo = errors.New("oauth2social: userinfo request failed")
	// ErrNoSubject is a userinfo response with no usable subject. It is
	// fatal rather than recoverable: the subject is the account key, and
	// without it there is nothing stable to link an identity to.
	ErrNoSubject = errors.New("oauth2social: userinfo carried no subject")
	// ErrEmailRequired is a userinfo response with no email address on a
	// provider configured to require one.
	ErrEmailRequired = errors.New("oauth2social: userinfo carried no email address")
	// ErrEmailUnverified is a present-but-unverified email on a provider
	// configured to reject those. See [ClaimMap.RejectUnverifiedEmail]
	// for why that default is what it is.
	ErrEmailUnverified = errors.New("oauth2social: userinfo email is not verified")
)

// ClaimMap names the userinfo JSON fields that carry each piece of
// identity, because plain OAuth2 has no standard for them: Discord
// returns `id`, GitHub returns `id` as a NUMBER, GitLab returns
// `sub`. Rather than encode a provider zoo in code, the mapping is
// configuration and the presets supply it.
type ClaimMap struct {
	// Subject is the field holding the provider-side stable id — the
	// value that becomes the identity subject. Required.
	//
	// It is read leniently (string or number) because providers
	// disagree: Discord's snowflake arrives as a JSON string, GitHub's
	// id as a number. Both are stable and opaque, which is all the
	// account key needs to be.
	Subject string
	// Email is the field holding the email address. Optional only in
	// the sense that a provider might not return one; see
	// RequireEmail for what happens then.
	Email string
	// EmailVerified is the field holding the provider's own
	// verification flag (Discord: `verified`). Empty means the provider
	// exposes no such flag, which is treated as UNVERIFIED rather than
	// verified — see RejectUnverifiedEmail.
	EmailVerified string
	// Name and Username are display-only. They populate the
	// corresponding oidc.Claims fields and are never used for
	// authorization or matching.
	Name     string
	Username string

	// RequireEmail rejects a sign-in whose userinfo carries no email.
	//
	// Presets set this true, and applications should think hard before
	// turning it off. An account with no email cannot receive an
	// invitation, cannot be matched by the email-collision veto that
	// stops one person's provider identity attaching to another's
	// account, and cannot be reached by any notification. The absence
	// is not a smaller account; it is an account outside several
	// safety mechanisms that assume an address exists.
	RequireEmail bool
	// RejectUnverifiedEmail refuses a present-but-unverified address.
	//
	// This is the fence that matters most in this package, because the
	// email is what the consuming application's collision veto keys on.
	// A provider that lets anyone claim an address without proving it
	// turns "sign in with X" into "assert you are whoever you like" —
	// and if the application then treats a matching address as evidence
	// of anything, an unverified claim becomes an account-takeover
	// primitive. Presets set this true.
	//
	// An empty EmailVerified mapping means the provider offers no flag,
	// and this then rejects EVERY sign-in. That is intentional: a
	// provider with no verification signal cannot satisfy a
	// verification requirement, and failing loudly at the first sign-in
	// beats silently accepting unverified addresses forever.
	RejectUnverifiedEmail bool
}

// Config is a social provider definition. It is deliberately explicit
// about endpoints rather than discovering them: these providers publish
// no discovery document worth trusting (Discord's is undocumented and
// advertises capabilities it does not have), so the endpoints are
// operator- or preset-supplied and reviewable.
type Config struct {
	// ID is the opaque provider identifier. It appears in callback
	// paths and is bound into the state cookie, so it must be stable
	// and URL-safe.
	ID string
	// DisplayName is the button label. Presentation only.
	DisplayName string

	ClientID     string
	ClientSecret string
	RedirectURL  string

	// AuthURL / TokenURL / UserinfoURL are the three endpoints the flow
	// needs. All three are required; there is no discovery fallback.
	AuthURL     string
	TokenURL    string
	UserinfoURL string

	// Scopes are requested verbatim. Presets supply the minimum that
	// yields an identity — asking for more than identity is a privacy
	// cost paid by every user who signs in.
	Scopes []string

	// ClaimMap maps userinfo JSON onto claims. Required.
	ClaimMap ClaimMap
}

// Provider is a validated, ready-to-use social provider.
type Provider struct {
	Config Config
	OAuth2 *oauth2.Config
}

// New validates a Config and builds the provider.
//
// Validation is strict at construction on purpose: every field checked
// here is one that would otherwise fail deep inside a live sign-in, at
// the point where the user is mid-redirect and the operator sees only a
// generic failure.
func New(cfg Config) (*Provider, error) {
	if strings.TrimSpace(cfg.ID) == "" {
		return nil, fmt.Errorf("%w: id is required", ErrConfig)
	}
	if strings.TrimSpace(cfg.ClientID) == "" {
		return nil, fmt.Errorf("%w: provider %q: client id is required", ErrConfig, cfg.ID)
	}
	if strings.TrimSpace(cfg.ClientSecret) == "" {
		return nil, fmt.Errorf("%w: provider %q: client secret is required", ErrConfig, cfg.ID)
	}
	for _, e := range []struct{ name, raw string }{
		{"auth url", cfg.AuthURL},
		{"token url", cfg.TokenURL},
		{"userinfo url", cfg.UserinfoURL},
	} {
		if err := requireHTTPSURL(e.raw); err != nil {
			return nil, fmt.Errorf("%w: provider %q: %s: %v", ErrConfig, cfg.ID, e.name, err)
		}
	}
	if strings.TrimSpace(cfg.ClaimMap.Subject) == "" {
		return nil, fmt.Errorf("%w: provider %q: claim map needs a subject field", ErrConfig, cfg.ID)
	}
	// A provider that requires verified email but exposes no flag to
	// read it would reject every sign-in at runtime. Say so now.
	if cfg.ClaimMap.RejectUnverifiedEmail && strings.TrimSpace(cfg.ClaimMap.EmailVerified) == "" {
		return nil, fmt.Errorf(
			"%w: provider %q: RejectUnverifiedEmail is set but ClaimMap.EmailVerified names no field, so every sign-in would be refused",
			ErrConfig, cfg.ID)
	}

	return &Provider{
		Config: cfg,
		OAuth2: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       cfg.Scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  cfg.AuthURL,
				TokenURL: cfg.TokenURL,
				// These providers all support client_secret_post; being
				// explicit avoids the library probing and retrying.
				AuthStyle: oauth2.AuthStyleInParams,
			},
		},
	}, nil
}

// requireHTTPSURL rejects anything that is not an absolute https URL.
//
// Plain http is refused with no localhost exemption, unlike an OIDC
// issuer where a dev-mode escape hatch exists. The access token from
// this exchange is spent against the userinfo endpoint as a bearer
// credential, so http would put a live credential on the wire in
// cleartext; and unlike an id_token, nothing downstream would notice a
// tampered response.
func requireHTTPSURL(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return errors.New("is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("is not a valid url: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("must be https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("has no host")
	}
	return nil
}
