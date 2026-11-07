package espresso

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/suryakencana007/tamper/audit"
	"github.com/suryakencana007/tamper/tenant"
)

// ErrInvalidCredential is the sentinel a ServiceAccountValidator
// returns for a well-formed-but-wrong bearer token. The gate maps it
// to a 401 SCIM envelope; any other error maps to a 500 — the
// distinction keeps credential probing indistinguishable from typos
// while genuine backend failures stay visible.
var ErrInvalidCredential = errors.New("tamper/espresso: invalid credential")

// PrincipalScope names what a machine credential is valid for. It is the field that lets one
// process hold two kinds of service account without either being able to do the other's job.
type PrincipalScope string

const (
	// PrincipalScopeTenant is the ZERO VALUE, so every credential that predates this field —
	// and every app that never sets it — keeps exactly its old authority: it acts inside
	// Principal.TenantID, and nowhere else.
	//
	// Its value is the empty string, which makes an explicit `Scope: "tenant"` an UNKNOWN scope
	// and a 401 indistinguishable from a bad token. That is the intended reading (leave it
	// unset), not an oversight, and the test suite pins it so nobody "fixes" it into an alias:
	// a second accepted spelling is how a deny-by-default check grows a hole.
	PrincipalScopeTenant PrincipalScope = ""

	// PrincipalScopePlatform is a credential valid ONLY on platform routes. It must carry no
	// home tenant: a platform credential that also names a tenant is ambiguous, and ambiguity
	// on a credential is how a scope check becomes decoration, so it is refused.
	PrincipalScopePlatform PrincipalScope = "platform"
)

// Principal is the authenticated non-user identity RequireServiceAccount
// stashes — the identity card the validator vouches for. Name /
// Description / CreatedAt ride along for resource rendering (SCIM /Me
// serves the caller's own record with an ETag derived from
// CreatedAt); apps project whatever their surfaces need.
type Principal struct {
	ID string

	// TenantID is the tenant this service account acts in; "" is a
	// single-tenant deployment.
	//
	// IT COMES FROM THE TOKEN, NEVER FROM THE URL PATH OR A HEADER.
	// The ServiceAccountValidator returns it as part of vouching for the
	// credential, so it is a fact the deployment authenticated — not a
	// value the caller supplied.
	//
	// A path-derived tenant is a horizontal-privilege-escalation bug with
	// extra steps: the caller is authenticated, so the request looks
	// legitimate in every log, and it reads every other customer's
	// directory by editing one URL segment. The same goes for a header.
	// If a handler in this package ever needs the tenant, it reads it
	// here; a route that wants a tenant in its path may use it for
	// routing, but must never let it reach a store.
	TenantID string

	// Scope is what this credential is valid for. The zero value means a tenant credential,
	// so leaving it unset is the old behaviour.
	//
	// THE TWO GATES ARE MUTUALLY EXCLUSIVE, and an unknown scope satisfies neither: a
	// platform credential is refused by RequireServiceAccount and a tenant credential by
	// RequirePlatformServiceAccount, both with the same 401 and the same body as a bad token.
	// A caller therefore cannot learn which of the two it got wrong — "wrong scope" and "wrong
	// credential" are indistinguishable, which is the discipline every other denial here
	// follows.
	Scope PrincipalScope

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
// RequireServiceAccount or RequirePlatformServiceAccount. Panics when missing — the handler is
// mounted outside both gates, which is a programmer error.
func MustGetPrincipal(ctx context.Context) Principal {
	p, ok := GetPrincipal(ctx)
	if !ok {
		panic("tamper/espresso: principal not in context — handler mounted outside " +
			"RequireServiceAccount/RequirePlatformServiceAccount")
	}
	return p
}

// GetPrincipal returns (principal, true) when RequireServiceAccount
// stashed one, otherwise (zero, false).
func GetPrincipal(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok && p.ID != ""
}

// validateServiceAccount is the authentication half both gates share, so the credential
// rules — the bearer header, the ErrInvalidCredential/500 split, and the indistinguishability
// of every 401 — exist exactly once. It writes the response and returns false on failure.
func validateServiceAccount(w http.ResponseWriter, r *http.Request, v ServiceAccountValidator) (Principal, bool) {
	tok, err := bearerToken(r.Header.Get("Authorization"))
	if err != nil {
		WriteSCIMError(w, http.StatusUnauthorized, err.Error())
		return Principal{}, false
	}
	principal, err := v.Validate(r.Context(), tok)
	if err != nil {
		if errors.Is(err, ErrInvalidCredential) {
			WriteSCIMError(w, http.StatusUnauthorized, "invalid bearer token")
			return Principal{}, false
		}
		WriteSCIMError(w, http.StatusInternalServerError, "service-account validation failed")
		return Principal{}, false
	}
	// A credential with no identity is not a credential. Refusing it here, in the one place both
	// gates authenticate, is what keeps the invariant the gates advertise: a request that
	// reaches a handler HAS a principal. Without it a validator returning (Principal{}, nil)
	// passes the gate, leaves GetPrincipal reporting false, and attributes the mutation to a
	// service account with no UserID and no Name — an authenticated request that is anonymous
	// everywhere downstream, and unattributable in the audit log.
	//
	// Programmer error on the validator's side, and a 401 (not a 500) because the caller's
	// credential is the thing that did not identify anybody; it is also the same envelope as a
	// bad token, so nothing new is learnable from it.
	if principal.ID == "" {
		WriteSCIMError(w, http.StatusUnauthorized, "invalid bearer token")
		return Principal{}, false
	}
	return principal, true
}

// stashPrincipal puts the authenticated principal and its audit actor on the context. The
// actor's tenant is the credential's HOME tenant, which a platform credential does not have —
// see RequirePlatformServiceAccount for why it gets the zero ID rather than tenant.Single.
func stashPrincipal(ctx context.Context, p Principal, actorTenant tenant.ID) context.Context {
	ctx = context.WithValue(ctx, principalKey{}, p)
	return audit.WithActor(ctx, audit.ActorService(p.ID, p.Name, actorTenant))
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
// Only a TENANT credential is accepted here: a platform credential, and any scope this package
// does not know, is refused with the same 401 as a bad token. Stack ordering: mutually
// exclusive with RequireAuth per route group.
func RequireServiceAccount(v ServiceAccountValidator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, ok := validateServiceAccount(w, r, v)
			if !ok {
				return
			}
			if principal.Scope != PrincipalScopeTenant {
				// Deliberately the same envelope as a bad token: a credential probing for the
				// platform surface must not learn that its scope, rather than its secret, was
				// the problem.
				WriteSCIMError(w, http.StatusUnauthorized, "invalid bearer token")
				return
			}
			ctx := stashPrincipal(r.Context(), principal, tenant.FromStored(principal.TenantID))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequirePlatformServiceAccount is RequireServiceAccount's other half: it accepts ONLY a
// credential whose Scope is PrincipalScopePlatform and whose TenantID is empty, and it is the
// gate a platform surface (tenant provisioning, cross-tenant automation) mounts.
//
// Why a second gate rather than a flag on the first: the two authorities do not overlap, and
// expressing that as "refuse the other kind here" in each direction is what makes the
// exclusion checkable. A tenant credential cannot reach a platform route, and a platform
// credential cannot read a tenant's directory — the failure is a 401 at the gate, never a
// store call that trusts a value the caller chose.
//
// The actor it stashes carries the ZERO tenant id, not tenant.Single. Single is a claim about
// the deployment ("this one is not pooled"); a platform credential's tenancy is genuinely
// unset. tenant.Actor's stored string is "" either way, so the audit payload is unchanged —
// what is refused is the false claim, not the bits.
func RequirePlatformServiceAccount(v ServiceAccountValidator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, ok := validateServiceAccount(w, r, v)
			if !ok {
				return
			}
			if principal.Scope != PrincipalScopePlatform || principal.TenantID != "" {
				WriteSCIMError(w, http.StatusUnauthorized, "invalid bearer token")
				return
			}
			ctx := stashPrincipal(r.Context(), principal, tenant.ID{})
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

// WriteSCIMError serialises a §3.12 error envelope with the given status
// and no scimType (the SA-gate's 401 shape). Delegates to
// WriteSCIMErrorTyped (scimerror.go) so every SCIM error — auth-gate or
// resource-handler — renders through one writer.
func WriteSCIMError(w http.ResponseWriter, status int, detail string) {
	WriteSCIMErrorTyped(w, status, detail, "")
}
