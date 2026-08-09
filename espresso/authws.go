package espresso

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/suryakencana007/tamper/crypto"
)

// RequireAuthWS returns middleware that authenticates a WebSocket
// upgrade request via either a standard `Authorization: Bearer <tok>`
// header (same as RequireAuth) OR a Sec-WebSocket-Protocol entry of
// the form `<subprotocolPrefix><base64url(tok)>` — the pattern
// browsers need because the WebSocket API doesn't allow custom
// request headers (mirrors Kubernetes'
// `base64url.bearer.authorization.k8s.io.` scheme).
//
// subprotocolPrefix is REQUIRED config with no default: the prefix is
// the app's wire contract with its frontend AND the anti-replay
// branding that stops a token minted for one service being replayed
// against another in the same browser session. Constructing with an
// empty prefix panics at wiring time rather than failing open.
//
// On success the context carries the same identity triple as
// RequireAuth (user id + typed claims + audit actor), so downstream
// middleware and handlers never special-case the WS path — including
// fresh-auth gates, which need the typed claims.
//
// The bearer subprotocol entry is stripped from the request header
// before next.ServeHTTP, leaving only "real" content subprotocols
// for the upgrade negotiator to choose from.
func RequireAuthWS(jwt *crypto.JWTService, subprotocolPrefix string) func(http.Handler) http.Handler {
	if subprotocolPrefix == "" {
		panic("tamper/espresso: RequireAuthWS requires a non-empty subprotocol prefix")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok, err := tokenFromRequest(r, subprotocolPrefix)
			if err != nil {
				writeUnauthenticated(w, err.Error())
				return
			}
			// The tenant is taken from the request context, never from the
			// token: a tenant read out of the credential being checked would
			// be checking the token against itself. An unpinned request is
			// DENIED rather than defaulted to Single — defaulting is what
			// turns one forgotten RequireTenant into an unscoped read, and
			// it is the whole reason tenant.ID has an invalid zero value.
			// A single-tenant deployment installs RequireTenant returning
			// tenant.Single and says so.
			//
			// The denial is the same 401 as a bad token, deliberately: a
			// caller must not be able to tell "wrong tenant" from "bad
			// credential" (§6.3).
			tid, pinned := TenantFromContext(r.Context())
			if !pinned {
				writeUnauthenticated(w, "invalid token")
				return
			}
			claims, err := jwt.VerifyAccess(tok, tid)
			if err != nil {
				writeUnauthenticated(w, "invalid token")
				return
			}
			next.ServeHTTP(w, r.WithContext(decorateAuthed(r.Context(), claims)))
		})
	}
}

// tokenFromRequest extracts a JWT from either the standard
// Authorization header or the WebSocket subprotocol fallback. When
// the subprotocol form is used, the offending entry is removed from
// r.Header so downstream code (notably the WebSocket Accept) doesn't
// try to negotiate the bearer pseudo-subprotocol.
func tokenFromRequest(r *http.Request, prefix string) (string, error) {
	if hdr := r.Header.Get("Authorization"); hdr != "" {
		return bearerToken(hdr)
	}
	tok, found := stripBearerSubprotocol(r.Header, prefix)
	if found {
		return tok, nil
	}
	return "", errMissingAuthHeader
}

// stripBearerSubprotocol scans every Sec-WebSocket-Protocol entry,
// removes the first bearer-prefixed one (returning the decoded
// token), and rewrites the header in-place. Returns ok=false when no
// bearer entry is present.
//
// The header may appear as multiple values (one per http.Header
// entry) or as a single comma-separated value — RFC 6455 allows both,
// and browsers commonly use the comma form. We handle both.
func stripBearerSubprotocol(h http.Header, prefix string) (string, bool) {
	const headerName = "Sec-WebSocket-Protocol"
	values := h.Values(headerName)
	if len(values) == 0 {
		return "", false
	}

	var (
		token string
		found bool
	)
	rewritten := make([]string, 0, len(values))
	for _, raw := range values {
		parts := strings.Split(raw, ",")
		kept := make([]string, 0, len(parts))
		for _, p := range parts {
			entry := strings.TrimSpace(p)
			if entry == "" {
				continue
			}
			if !found && strings.HasPrefix(entry, prefix) {
				if t, err := decodeBearerSubprotocol(entry, prefix); err == nil {
					token = t
					found = true
					continue
				}
				// Malformed bearer entry — drop it so it doesn't get
				// negotiated, but don't authenticate.
				continue
			}
			kept = append(kept, entry)
		}
		if len(kept) > 0 {
			rewritten = append(rewritten, strings.Join(kept, ", "))
		}
	}

	h.Del(headerName)
	for _, v := range rewritten {
		h.Add(headerName, v)
	}
	return token, found
}

// decodeBearerSubprotocol parses an entry of the form
// `<prefix><base64url(token)>` and returns the decoded token. Empty /
// undecodable entries return an error so the caller skips them and
// the middleware reports UNAUTHENTICATED downstream.
func decodeBearerSubprotocol(entry, prefix string) (string, error) {
	suffix := strings.TrimPrefix(entry, prefix)
	if suffix == "" {
		return "", errEmptyBearerToken
	}
	// Browsers can be picky about padding; tolerate both raw and
	// padded base64url to keep the JS side simple.
	dec, err := base64.RawURLEncoding.DecodeString(suffix)
	if err != nil {
		dec, err = base64.URLEncoding.DecodeString(suffix)
		if err != nil {
			return "", errors.New("invalid bearer subprotocol payload")
		}
	}
	tok := strings.TrimSpace(string(dec))
	if tok == "" {
		return "", errEmptyBearerToken
	}
	return tok, nil
}
