package saml

import (
	"fmt"
	"net/url"

	crewjamsaml "github.com/crewjam/saml"
)

// AuthnRequestOptions controls optional SAML AuthnRequest features
// the SP can set per-request. Zero values are omitted from the wire
// payload.
//
// v1.14 Sprint 1 Task 01 — used by the step-up flow to:
//
//   - Set RequestedAuthnContext to the satisfaction set the SPA
//     supplied (`acr_values=` at /login). Per SAML Core §3.4.1.4 the
//     IdP SHOULD authenticate the user under a class matching the
//     SP's request; crewjam's AuthnContextClassRef field is a single
//     string, so we pin to the first/strongest entry from the
//     SPA-supplied list.
//   - Force re-authentication via ForceAuthn=true when the SPA
//     asked for `max_age` (SAML doesn't have a direct max_age
//     equivalent; ForceAuthn is the closest semantic — the IdP MUST
//     re-prompt the user even if a satisfying session exists).
type AuthnRequestOptions struct {
	// ForceAuthn, when true, sets the AuthnRequest's ForceAuthn=true
	// attribute. The IdP MUST re-prompt the user. Zero (false) leaves
	// the attribute at the SP default (typically nil — the IdP picks).
	ForceAuthn bool
	// RequestedACRClass, when non-empty, sets the AuthnRequest's
	// RequestedAuthnContext with AuthnContextClassRef=<value>. crewjam
	// only supports a single class (not a list); pass the strongest /
	// most-specific URN from the SPA's acr_values list.
	RequestedACRClass string
	// Comparison sets the RequestedAuthnContext.Comparison attribute.
	// Defaults to "minimum" when empty + RequestedACRClass is set. Per
	// SAML Core §3.4.1.4: exact / minimum / maximum / better.
	//
	// v1.15 Sprint 1 Task 01 changed the default from "exact" to
	// "minimum" after the live-Keycloak walk surfaced the wart at the
	// task's Foot-gun B: KC's stock SAML auth flow returns ACR strings
	// from its own `urn:oasis:names:tc:SAML:2.0:ac:classes:*` family
	// (Password / PasswordProtectedTransport / etc.), which never
	// equal Barista's OIDC-side `urn:mace:incommon:iap:silver` literal.
	// With Comparison="exact", KC rejects the AuthnRequest with a
	// "no matching AuthnContextClassRef" 4xx; with "minimum", KC
	// gracefully honours the request + the realm's Browser-StepUp flow
	// (provisioned by scripts/provision-keycloak.ps1 -ProvisionStepUp)
	// enforces the TOTP gate based on the LoA mapping rather than a
	// literal-URN match. Per Sprint 1 Task 01 PR body for the matching
	// strategy decision tree.
	Comparison string
}

// BuildAuthnRequestURL constructs the IdP redirect URL for an
// SP-initiated SSO flow. Wraps crewjam/saml's
// MakeRedirectAuthenticationRequest so the handler layer doesn't
// import crewjam directly.
//
// relayState is the AuthnRequest's RelayState parameter -- the IdP
// echoes it back to the ACS endpoint so Barista can resume the
// user's intended post-login navigation (e.g. /projects/foo). The
// caller is responsible for allowlisting + signing the value before
// passing it here; this helper does no relay-state validation.
//
// On success, the returned URL carries the deflated + base64-encoded
// SAMLRequest in the query string per the HTTP-Redirect binding spec,
// signed with the provider's SP signing key when SignatureMethod is
// configured on the underlying ServiceProvider. The library picks
// HTTP-Redirect when the AuthnRequest fits in the URL; large requests
// would need HTTP-POST (an SP feature reserved for v1.13+ -- v1.12
// targets the common HTTP-Redirect path).
//
// v1.12 Sprint 2 Task 04. v1.14 Sprint 1 Task 01 adds the opts
// parameter for the step-up flow.
func BuildAuthnRequestURL(p *Provider, relayState string, opts AuthnRequestOptions) (*url.URL, string, error) {
	if p == nil || p.SP == nil {
		return nil, "", fmt.Errorf("saml: provider service provider is nil")
	}
	// One path for every request shape. There used to be a "fast path"
	// calling MakeRedirectAuthenticationRequest for the non-step-up
	// case, but that helper is literally
	//
	//	req, _ := sp.MakeAuthenticationRequest(
	//	    sp.GetSSOBindingLocation(HTTPRedirectBinding),
	//	    HTTPRedirectBinding, HTTPPostBinding)
	//	return req.Redirect(relayState, sp)
	//
	// — the same three arguments the step-up path already passed. So
	// collapsing them is byte-identical, and it lets the AuthnRequest's
	// ID escape, which the fast path buried inside the helper.
	//
	// The ID is the whole point: it is SAML's only correlator between
	// the request we issued and the assertion that comes back (there is
	// no nonce, no PKCE). Returning it lets the caller stash it in the
	// signed state cookie and hand it back at the ACS as the
	// InResponseTo allow-list — SAML's analogue of OIDC's `state`
	// cross-check. Without it the ACS cannot tell an assertion answering
	// OUR request from one replayed by an attacker.
	req, err := p.SP.MakeAuthenticationRequest(
		p.SP.GetSSOBindingLocation(crewjamsaml.HTTPRedirectBinding),
		crewjamsaml.HTTPRedirectBinding,
		crewjamsaml.HTTPPostBinding,
	)
	if err != nil {
		return nil, "", fmt.Errorf("saml: build authn request: %w", err)
	}
	if opts.ForceAuthn {
		forceAuthn := true
		req.ForceAuthn = &forceAuthn
	}
	if opts.RequestedACRClass != "" {
		comparison := opts.Comparison
		if comparison == "" {
			// v1.15 Sprint 1 Task 01: default to "minimum" (see
			// AuthnRequestOptions.Comparison godoc for the KC interop
			// reason). Callers explicitly wanting strict matching can
			// still pass "exact".
			comparison = "minimum"
		}
		req.RequestedAuthnContext = &crewjamsaml.RequestedAuthnContext{
			Comparison:           comparison,
			AuthnContextClassRef: opts.RequestedACRClass,
		}
	}
	u, err := req.Redirect(relayState, p.SP)
	if err != nil {
		return nil, "", fmt.Errorf("saml: build authn request redirect: %w", err)
	}
	return u, req.ID, nil
}
