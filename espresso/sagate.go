package espresso

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/suryakencana007/barista/packages/tamper/audit"
)

// ErrInvalidCredential is the sentinel a ServiceAccountValidator
// returns for a well-formed-but-wrong bearer token. The gate maps it
// to a 401 SCIM envelope; any other error maps to a 500 — the
// distinction keeps credential probing indistinguishable from typos
// while genuine backend failures stay visible.
var ErrInvalidCredential = errors.New("tamper/espresso: invalid credential")

// Principal is the authenticated non-user identity RequireServiceAccount
// stashes — the identity card the validator vouches for. Name /
// Description / CreatedAt ride along for resource rendering (SCIM /Me
// serves the caller's own record with an ETag derived from
// CreatedAt); apps project whatever their surfaces need.
type Principal struct {
	ID          string
	Name        string
	Description string
	CreatedAt   time.Time
}

// ServiceAccountValidator authenticates machine bearer tokens. The
// token FORMAT (prefixes, hash loops) is validator-internal — the
// gate never inspects it. Return ErrInvalidCredential for a bad
// token.
type ServiceAccountValidator interface {
	Validate(ctx context.Context, token string) (Principal, error)
}

// ValidatorFunc adapts a closure to ServiceAccountValidator.
type ValidatorFunc func(ctx context.Context, token string) (Principal, error)

// Validate implements ServiceAccountValidator.
func (f ValidatorFunc) Validate(ctx context.Context, token string) (Principal, error) {
	return f(ctx, token)
}

// principalKey is the context key for the authenticated Principal.
type principalKey struct{}

// MustGetPrincipal returns the principal stashed by
// RequireServiceAccount. Panics when missing — the handler is mounted
// outside a RequireServiceAccount group, which is a programmer error.
func MustGetPrincipal(ctx context.Context) Principal {
	p, ok := GetPrincipal(ctx)
	if !ok {
		panic("tamper/espresso: principal not in context — handler mounted outside RequireServiceAccount")
	}
	return p
}

// GetPrincipal returns (principal, true) when RequireServiceAccount
// stashed one, otherwise (zero, false).
func GetPrincipal(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok && p.ID != ""
}

// RequireServiceAccount returns middleware that enforces an
// `Authorization: Bearer <token>` header carrying a machine
// credential. On success it stashes the Principal (MustGetPrincipal)
// and an audit service actor so downstream emissions attribute the
// mutation to the service account, not "some user."
//
// Failures emit a SCIM 2.0 error envelope (RFC 7644 §3.12) with
// status 401 — SCIM clients fail-closed on app-branded envelopes, and
// non-SCIM consumers still receive valid code+detail JSON.
//
// Stack ordering: mutually exclusive with RequireAuth per route group.
func RequireServiceAccount(v ServiceAccountValidator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok, err := bearerToken(r.Header.Get("Authorization"))
			if err != nil {
				WriteSCIMError(w, http.StatusUnauthorized, err.Error())
				return
			}
			principal, err := v.Validate(r.Context(), tok)
			if err != nil {
				if errors.Is(err, ErrInvalidCredential) {
					WriteSCIMError(w, http.StatusUnauthorized, "invalid bearer token")
					return
				}
				WriteSCIMError(w, http.StatusInternalServerError, "service-account validation failed")
				return
			}
			ctx := context.WithValue(r.Context(), principalKey{}, principal)
			ctx = audit.WithActor(ctx, audit.ActorService(principal.ID, principal.Name))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// SCIMError is the JSON shape RFC 7644 §3.12 mandates for SCIM 2.0
// errors.
type SCIMError struct {
	Schemas  []string `json:"schemas"`
	Status   string   `json:"status"`
	SCIMType string   `json:"scimType,omitempty"`
	Detail   string   `json:"detail"`
}

// scimErrSchema is the canonical schema URN from RFC 7643 §3.12.
const scimErrSchema = "urn:ietf:params:scim:api:messages:2.0:Error"

// WriteSCIMError serialises a §3.12 error envelope with the given status
// and no scimType (the SA-gate's 401 shape). Delegates to
// WriteSCIMErrorTyped (scimerror.go) so every SCIM error — auth-gate or
// resource-handler — renders through one writer.
func WriteSCIMError(w http.ResponseWriter, status int, detail string) {
	WriteSCIMErrorTyped(w, status, detail, "")
}
