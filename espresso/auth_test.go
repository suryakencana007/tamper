package espresso

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/suryakencana007/tamper/audit"
	"github.com/suryakencana007/tamper/crypto"
)

func testJWT(t *testing.T) (*crypto.JWTService, string) {
	t.Helper()
	jwt := crypto.NewJWTService(crypto.JWTConfig{
		Secret: "tamper-espresso-test-secret",
		TTL:    time.Hour,
		Issuer: "tamper-test",
	})
	tok, err := jwt.Issue("u-1")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return jwt, tok
}

func TestRequireAuth_StashesIdentityTriple(t *testing.T) {
	jwt, tok := testJWT(t)
	var id string
	var claimsOK bool
	var actor audit.Actor
	h := RequireAuth(jwt)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id = MustGetUserID(r.Context())
		_, claimsOK = AccessClaimsFromContext(r.Context())
		actor = audit.ActorFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || id != "u-1" || !claimsOK {
		t.Fatalf("status=%d id=%q claims=%v, want 200/u-1/true", rec.Code, id, claimsOK)
	}
	if actor.Type != audit.ActorTypeUser || actor.UserID != "u-1" {
		t.Fatalf("actor = %+v, want user actor u-1", actor)
	}
}

func TestRequireAuth_Unauthenticated(t *testing.T) {
	jwt, _ := testJWT(t)
	h := RequireAuth(jwt)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler must not run")
	}))
	for name, decorate := range map[string]func(*http.Request){
		"missing header": func(*http.Request) {},
		"wrong scheme":   func(r *http.Request) { r.Header.Set("Authorization", "Basic abc") },
		"empty token":    func(r *http.Request) { r.Header.Set("Authorization", "Bearer   ") },
		"invalid token":  func(r *http.Request) { r.Header.Set("Authorization", "Bearer not-a-jwt") },
	} {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		decorate(req)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", name, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "UNAUTHENTICATED") {
			t.Errorf("%s: body missing UNAUTHENTICATED code: %s", name, rec.Body.String())
		}
	}
}

func TestRequireAuthWS_SubprotocolAndPrefixRequired(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("empty subprotocol prefix must panic at wiring time")
		}
	}()

	jwt, tok := testJWT(t)
	const prefix = "base64url.bearer.authorization.test.io."
	var id string
	var claimsOK bool
	h := RequireAuthWS(jwt, prefix)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id = MustGetUserID(r.Context())
		_, claimsOK = AccessClaimsFromContext(r.Context())
		// The bearer entry must be stripped; content protocol survives.
		if got := r.Header.Get("Sec-WebSocket-Protocol"); got != "app.terminal.v1" {
			t.Errorf("subprotocols after strip = %q, want app.terminal.v1", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.Header.Set("Sec-WebSocket-Protocol",
		prefix+base64.RawURLEncoding.EncodeToString([]byte(tok))+", app.terminal.v1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || id != "u-1" {
		t.Fatalf("status=%d id=%q, want 200/u-1", rec.Code, id)
	}
	if !claimsOK {
		t.Fatal("WS path must stash typed claims (the 4a VerifyAccess unification)")
	}

	// Trigger the deferred panic assertion last.
	RequireAuthWS(jwt, "")
}

func TestNamedCookieSlotsCoexist(t *testing.T) {
	var refresh, state string
	h := ReadNamedCookie("refresh", "app_refresh")(
		ReadNamedCookie("oidc_state", "app_state")(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				refresh, _ = NamedCookieValue(r.Context(), "refresh")
				state, _ = NamedCookieValue(r.Context(), "oidc_state")
				w.WriteHeader(http.StatusOK)
			})))
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.AddCookie(&http.Cookie{Name: "app_refresh", Value: "r-1"})
	req.AddCookie(&http.Cookie{Name: "app_state", Value: "s-1"})
	h.ServeHTTP(httptest.NewRecorder(), req)
	if refresh != "r-1" || state != "s-1" {
		t.Fatalf("slots collided: refresh=%q state=%q", refresh, state)
	}
	if _, ok := NamedCookieValue(context.Background(), "refresh"); ok {
		t.Fatal("bare context must report no cookie")
	}
}

func TestIPFromRequest(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.RemoteAddr = "10.0.0.9:1234"
	if got := IPFromRequest(r); got != "10.0.0.9" {
		t.Errorf("RemoteAddr path = %q", got)
	}
	r.Header.Set("X-Forwarded-For", "203.0.113.7, 10.0.0.1")
	if got := IPFromRequest(r); got != "203.0.113.7" {
		t.Errorf("XFF path = %q", got)
	}
}
