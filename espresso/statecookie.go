package espresso

import (
	"net/http"
	"time"
)

// StateCookieConfig is the app's branding + policy for a federation
// state cookie (OIDC / SAML). The cookie NAME is the app's brand;
// tamper owns the `__Host-` prefix mechanics and HttpOnly, so the D4
// silent-failure foot-guns — the CSRF fence and the HTTP->HTTPS upgrade
// cookie split — can't be misconfigured.
type StateCookieConfig struct {
	// BaseName is the app's cookie brand WITHOUT the `__Host-` prefix
	// (e.g. "barista_oidc_state"). Required.
	BaseName string
	// Secure adds the `__Host-` prefix AND the Secure flag together —
	// the prefix's browser rules (Secure + Path=/ + no Domain) are
	// exactly what this single toggle guarantees, so a mixed state
	// (prefixed name without Secure) is unrepresentable.
	Secure bool
	// Path scopes the cookie. Federation state cookies use "/" (the
	// callback + exchange span the app root).
	Path string
	// TTL bounds the set cookie's Max-Age.
	TTL time.Duration
	// SameSite is the cross-site policy. Zero means Lax.
	//
	// This is NOT a "tighten it if you like" knob — it is protocol
	// surface, and the correct value is dictated by how the IdP hands
	// control back:
	//
	//   - OIDC callback = a top-level GET redirect. Lax sends the
	//     cookie. Lax is correct, and stricter than the alternative.
	//   - SAML ACS = a top-level cross-site POST (the HTTP-POST
	//     binding: the IdP auto-submits a form from ITS origin). Lax
	//     does NOT send cookies on cross-site POST, so the cookie never
	//     arrives and the flow silently degrades. That requires
	//     SameSite=None.
	//
	// This field exists because tamper previously hard-coded Lax and
	// called it a non-configurable invariant. It was correct for OIDC
	// and silently wrong for SAML — see TD-FUNC-28, where SAML link mode
	// and step-up were dead on every cross-domain IdP because of it.
	//
	// SameSite=None REQUIRES Secure (browsers reject it otherwise);
	// NewFederationRoutes rejects that combination at wiring rather than
	// letting the browser drop the cookie at runtime. Note None does not
	// conflict with `__Host-`: that prefix demands Secure + Path=/, both
	// of which None already implies.
	//
	// Choosing None is not a CSRF concession by itself. The state cookie
	// is signed, HttpOnly, single-use and short-lived, and it is not a
	// session credential — it carries flow state. What defends the flow
	// is the correlation between the request the app issued and the
	// assertion/code that comes back (OIDC's `state`, SAML's
	// InResponseTo), NOT the browser's cross-site rule. An app relaxing
	// this to None without that correlation in place is relying on an
	// accident.
	SameSite http.SameSite
}

// sameSite resolves the effective policy: zero reads as Lax, matching
// the value tamper hard-coded before this field existed.
func (c StateCookieConfig) sameSite() http.SameSite {
	if c.SameSite == 0 {
		return http.SameSiteLaxMode
	}
	return c.SameSite
}

// Name returns the effective cookie name: `__Host-`-prefixed under
// Secure, the bare brand otherwise. The app wires its cookie-read
// middleware with this same value.
func (c StateCookieConfig) Name() string {
	if c.Secure {
		return "__Host-" + c.BaseName
	}
	return c.BaseName
}

// Set builds the Set-Cookie carrying value (TTL-bounded).
func (c StateCookieConfig) Set(value string) *http.Cookie {
	return &http.Cookie{
		Name:     c.Name(),
		Value:    value,
		Path:     c.Path,
		HttpOnly: true,
		Secure:   c.Secure,
		SameSite: c.sameSite(),
		MaxAge:   int(c.TTL.Seconds()),
	}
}

// Clear builds the single-use clear cookie with attribute parity to
// Set (MaxAge=-1 + empty value) — some browsers refuse to overwrite
// otherwise.
func (c StateCookieConfig) Clear() *http.Cookie {
	return &http.Cookie{
		Name:     c.Name(),
		Value:    "",
		Path:     c.Path,
		HttpOnly: true,
		Secure:   c.Secure,
		SameSite: c.sameSite(),
		MaxAge:   -1,
	}
}
