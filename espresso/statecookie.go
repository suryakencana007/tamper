package espresso

import (
	"net/http"
	"time"
)

// StateCookieConfig is the app's branding + policy for a federation
// state cookie (OIDC / SAML). The cookie NAME is the app's brand;
// tamper owns the `__Host-` prefix mechanics and the invariant
// attributes (HttpOnly, SameSite=Lax), so the two D4 silent-failure
// foot-guns — the CSRF fence and the HTTP->HTTPS upgrade cookie split —
// can't be misconfigured.
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
		SameSite: http.SameSiteLaxMode,
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
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	}
}
