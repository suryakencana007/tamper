// Package oidc implements an OpenID Connect Relying Party (RP)
// substrate for Tamper consumers. It wraps github.com/coreos/go-oidc/v3
// (discovery + ID token verification + JWKS rotation) and
// golang.org/x/oauth2 (auth-code flow + PKCE) so the app's HTTP layer
// sees a clean Provider / ProviderRegistry / Claims surface.
//
// Route shapes stay the APP's concern: ProviderConfig carries the full
// per-provider RedirectURL as data — the package never composes an
// endpoint path. State-cookie NAMES are likewise the app's; this
// package owns the signed-claims format and its purpose
// discrimination.
//
// Why a third-party library: hand-rolling OIDC ID-token verification
// (JWKS rotation, alg-confusion guards, audience/issuer pinning, nonce
// check sequencing) is exactly the surface where security bugs hide.
// coreos/go-oidc is the battle-tested standard used by Kubernetes,
// ArgoCD, and Vault; its IDTokenVerifier handles the kid-rotation
// retry case (Google + Auth0 rotate JWKS every few hours) and the
// signing-algorithm allowlist that defends against alg=none / RS256
// confusion attacks.
package oidc

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"sync"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// ErrUnknownProvider surfaces from ProviderRegistry.Get when the
// requested id is not in the configured set. Callers should map to a
// 404 so an attacker probing for valid provider ids gets the same
// shape as a typo — id enumeration provides no useful signal.
var ErrUnknownProvider = errors.New("oidc: unknown provider")

// ErrDiscoveryFailed wraps any error from coreos/go-oidc's
// NewProvider call (network failure, malformed discovery document,
// issuer mismatch, etc.). Callers should map to a 503 so an IdP
// outage looks like a transient upstream failure rather than a 500.
var ErrDiscoveryFailed = errors.New("oidc: discovery failed")

// ProviderConfig is the in-memory shape of one IdP entry. The app
// sources entries from its own config or store and builds one per
// provider before calling BuildRegistryFromConfigs.
type ProviderConfig struct {
	// ID is the opaque identifier the operator assigned (e.g.
	// "keycloak", "google", "azure"). The app uses it as the path
	// segment of its callback route and in provider lists. Must be a
	// valid URL path segment; BuildProvider rejects empty +
	// path-unsafe ids.
	ID string
	// IssuerURL is the OIDC issuer (e.g.
	// https://auth.example.com/realms/myapp for Keycloak). Used by
	// coreos/go-oidc for the well-known discovery fetch.
	IssuerURL string
	// ClientID + ClientSecret are issued by the IdP-side admin during
	// client registration.
	ClientID     string
	ClientSecret string
	// RedirectURL is the full per-provider callback URL the IdP
	// redirects back to after authentication. Route shapes are the
	// app's concern — the package takes the endpoint as data rather
	// than composing a path. Required by BuildProvider.
	RedirectURL string
	// DisplayName is what the app renders on its login button
	// (e.g. "Sign in with Keycloak"). Operator-controlled.
	DisplayName string
	// Scopes is the OAuth scope list requested at authorization.
	// Defaults to [openid, profile, email] when empty. "openid" is
	// mandatory per OIDC; the BuildProvider constructor prepends it
	// if missing.
	Scopes []string
	// GroupsClaim is the configurable name of the OIDC claim holding
	// the user's group list. Empty falls back to "groups" at the
	// ExtractGroups call boundary; operators override for IdPs like
	// Azure AD ("roles") or Auth0 (URL-shaped custom claims).
	GroupsClaim string
}

// Provider bundles the operator-supplied config with the discovery-
// derived oauth2.Config and ID-token verifier. Built once per
// registry construction; immutable across the registry's lifetime.
//
// The Verifier's JWKS is refreshed lazily by coreos/go-oidc when
// it sees a `kid` that isn't in its cache — Google + Auth0 rotate
// JWKS every few hours, and the library handles that transparently.
type Provider struct {
	Config      ProviderConfig
	OIDC        *coreoidc.Provider
	OAuth2      *oauth2.Config
	Verifier    *coreoidc.IDTokenVerifier
	UserInfoURL string
	JWKSURL     string
}

// ProviderRegistry is the request-time lookup surface. Built once per
// registry construction, looked up by id on every federated-auth
// call. An empty registry (no providers configured) is represented by
// a nil pointer so callers can gate the whole OIDC surface on
// non-nil.
type ProviderRegistry struct {
	mu        sync.RWMutex
	providers map[string]*Provider
	// order preserves input order so List() returns the login button
	// list deterministically.
	order []string
}

// BuildProvider runs OIDC discovery against ProviderConfig.IssuerURL
// and assembles the full Provider. cfg.RedirectURL must carry the
// full per-provider callback URL — validated parseable so a typo
// (e.g. missing scheme) fails loudly at construction instead of at
// the first sign-in attempt. Failures wrap ErrDiscoveryFailed so
// callers can short-circuit cleanly.
//
// Scope handling: OIDC requires "openid" in the scope list; the
// constructor prepends it if the operator left it out (a common
// foot-gun). Empty scope list defaults to [openid, profile, email].
func BuildProvider(ctx context.Context, cfg ProviderConfig) (*Provider, error) {
	if cfg.ID == "" {
		return nil, fmt.Errorf("oidc: provider id is required")
	}
	if cfg.IssuerURL == "" {
		return nil, fmt.Errorf("oidc: provider %q: issuerURL is required", cfg.ID)
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("oidc: provider %q: clientID is required", cfg.ID)
	}
	if !validProviderID(cfg.ID) {
		return nil, fmt.Errorf("oidc: provider id %q is not a URL-safe path segment", cfg.ID)
	}
	if cfg.RedirectURL == "" {
		return nil, fmt.Errorf("oidc: provider %q: redirect URL: redirect URL is empty", cfg.ID)
	}
	if _, err := url.Parse(cfg.RedirectURL); err != nil {
		return nil, fmt.Errorf("oidc: provider %q: redirect URL: parse %q: %w", cfg.ID, cfg.RedirectURL, err)
	}

	scopes := normaliseScopes(cfg.Scopes)

	oidcProvider, err := coreoidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("%w: provider %q: %v", ErrDiscoveryFailed, cfg.ID, err)
	}

	// Extract optional endpoints not exposed via Provider.Endpoint()
	// for the userinfo/JWKS surfaces apps use in tests + audit.
	var endpoints struct {
		JWKSURL     string `json:"jwks_uri"`
		UserInfoURL string `json:"userinfo_endpoint"`
	}
	if err := oidcProvider.Claims(&endpoints); err != nil {
		return nil, fmt.Errorf("%w: provider %q: parse discovery endpoints: %v", ErrDiscoveryFailed, cfg.ID, err)
	}

	verifier := oidcProvider.Verifier(&coreoidc.Config{
		ClientID: cfg.ClientID,
	})

	cfgCopy := cfg
	cfgCopy.Scopes = scopes

	return &Provider{
		Config: cfgCopy,
		OIDC:   oidcProvider,
		OAuth2: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     oidcProvider.Endpoint(),
			RedirectURL:  cfg.RedirectURL,
			Scopes:       scopes,
		},
		Verifier:    verifier,
		UserInfoURL: endpoints.UserInfoURL,
		JWKSURL:     endpoints.JWKSURL,
	}, nil
}

// BuildRegistryFromConfigs constructs a ProviderRegistry from the
// supplied provider list. Each entry runs discovery in turn.
//
// partialOK softens the discovery-failure mode:
//   - partialOK=false (boot-time config path): any single provider
//     whose discovery fails fails the whole construction. Fail-loud
//     so an operator sees the bad provider id at boot.
//   - partialOK=true (store-backed reload path): a failing entry
//     logs a warning via the standard library logger + is omitted
//     from the registry; the rebuild succeeds with the remaining
//     providers. Login attempts for the missing provider should
//     surface as a 503 until the next reload finds the IdP healthy.
//
// The discovery network calls run sequentially in input order. For
// typical setups (1-3 providers) the total cost is tens of
// milliseconds.
//
// Returns nil-and-nil for an empty input slice in either mode so
// callers can treat a nil registry as "OIDC not configured".
func BuildRegistryFromConfigs(ctx context.Context, providers []ProviderConfig, partialOK bool) (*ProviderRegistry, error) {
	if len(providers) == 0 {
		return nil, nil
	}
	reg := &ProviderRegistry{
		providers: make(map[string]*Provider, len(providers)),
		order:     make([]string, 0, len(providers)),
	}
	for _, cfg := range providers {
		if _, dup := reg.providers[cfg.ID]; dup {
			return nil, fmt.Errorf("oidc: duplicate provider id %q in provider list", cfg.ID)
		}
		p, err := BuildProvider(ctx, cfg)
		if err != nil {
			if partialOK {
				log.Printf("oidc: provider %q discovery failed; omitting from registry until next reload: %v", cfg.ID, err)
				continue
			}
			return nil, err
		}
		reg.providers[cfg.ID] = p
		reg.order = append(reg.order, cfg.ID)
	}
	return reg, nil
}

// Get returns the provider with the given id, or ErrUnknownProvider
// when the id is not in the registry. Thread-safe.
func (r *ProviderRegistry) Get(id string) (*Provider, error) {
	if r == nil {
		return nil, ErrUnknownProvider
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[id]
	if !ok {
		return nil, fmt.Errorf("%w: id %q", ErrUnknownProvider, id)
	}
	return p, nil
}

// ProviderSummary is the public summary a provider-list endpoint may
// return. Only id + display name leak; client secret and issuer URL
// stay inside the binary.
type ProviderSummary struct {
	ID          string
	DisplayName string
}

// List returns the public summaries in registry order.
func (r *ProviderRegistry) List() []ProviderSummary {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]ProviderSummary, 0, len(r.order))
	for _, id := range r.order {
		p := r.providers[id]
		display := p.Config.DisplayName
		if display == "" {
			display = id
		}
		out = append(out, ProviderSummary{ID: id, DisplayName: display})
	}
	return out
}

// validProviderID is a conservative check: ASCII letters / digits /
// hyphens / underscores only. Anything else would either need URL-
// escaping in the callback path (cookie + signature complexity) or
// invites IdP-side quirks. Rejecting loud at construction keeps a
// typo from reaching production.
func validProviderID(id string) bool {
	if id == "" {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_':
		default:
			return false
		}
	}
	return true
}

// normaliseScopes inserts the mandatory "openid" scope if absent
// and applies the [openid, profile, email] default for empty lists.
// The OAuth library treats scope strictly — without "openid" the
// IdP returns a regular OAuth2 access token, not an OIDC ID token,
// and the verifier rejects the missing ID token branch with a clear
// error rather than silently degrading.
func normaliseScopes(in []string) []string {
	if len(in) == 0 {
		return []string{coreoidc.ScopeOpenID, "profile", "email"}
	}
	has := false
	for _, s := range in {
		if s == coreoidc.ScopeOpenID {
			has = true
			break
		}
	}
	if has {
		out := make([]string, len(in))
		copy(out, in)
		return out
	}
	out := make([]string, 0, len(in)+1)
	out = append(out, coreoidc.ScopeOpenID)
	out = append(out, in...)
	return out
}
