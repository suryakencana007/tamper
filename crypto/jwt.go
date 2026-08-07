package crypto

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ErrInvalidToken collapses every JWT failure mode (bad signature,
// expired, malformed, wrong issuer, missing sub, etc.) so handlers
// return one stable status code and don't leak which check failed.
var ErrInvalidToken = errors.New("auth: invalid token")

// JWTConfig is tamper's native JWT options struct. It intentionally
// carries no dependency on any host application's config package — the
// caller populates it from wherever their configuration lives.
type JWTConfig struct {
	Secret string
	TTL    time.Duration
	Issuer string
}

// JWTService issues and verifies HS256 JWTs. One instance per process;
// the auth service holds it inside its struct.
type JWTService struct {
	secret []byte
	ttl    time.Duration
	issuer string
	// now is the clock source; tests override via Testing().SetNow.
	now func() time.Time
}

// NewJWTService constructs a JWTService from a JWTConfig. Panics on
// empty secret — callers are expected to validate their config at
// startup; reaching NewJWTService with an empty secret is a programmer
// error.
func NewJWTService(cfg JWTConfig) *JWTService {
	if cfg.Secret == "" {
		panic("auth: jwt secret is empty — config validation should have caught this")
	}
	return &JWTService{
		secret: []byte(cfg.Secret),
		ttl:    cfg.TTL,
		issuer: cfg.Issuer,
		now:    time.Now,
	}
}

// AccessClaims is the v1.14 shape of the access-token JWT. Extends
// jwt.RegisteredClaims with auth_time + acr per OIDC Core 1.0 §2 +
// §3.1.2.1. Refresh-token rotation carries auth_time + acr forward
// unchanged — only IdP-side authentication (OIDC callback, SAML
// callback, local-password Login, TOTP-verify) advances them.
//
// Pre-v1.14 JWTs in the wild parse tolerantly: missing auth_time
// reads as 0, missing acr reads as "". Middleware (RequireFreshAuth)
// treats both as "trips the step-up gate" — the migration is
// naturally graceful via refresh-rotation.
type AccessClaims struct {
	AuthTime int64  `json:"auth_time"`
	ACR      string `json:"acr"`
	// Purpose discriminates an access JWT from the other token shapes
	// this service mints under the SAME secret — currently the
	// totp-pending session token (IssueTOTPPending). VerifyAccess
	// rejects a token carrying a foreign purpose, which is what stops a
	// pre-2FA session token from authenticating as a full session.
	//
	// Legacy-tolerant on the same terms as auth_time + acr above:
	// pre-v1.15 access JWTs carry no purpose claim and read as "",
	// which VerifyAccess accepts. Only a NON-EMPTY, non-access purpose
	// rejects. That tolerance is safe because the claim can only be
	// removed by re-signing, which needs the secret — so it buys a
	// graceful rollout (no mass logout on deploy) without reopening the
	// bypass.
	Purpose string `json:"purpose,omitempty"`
	// TenantID names the tenant this token was minted for, in a pooled
	// multi-tenant deployment. Opaque and app-defined; tamper compares it
	// for equality and never parses it.
	//
	// Legacy-tolerant on exactly the same terms as purpose above, and the
	// tolerance has the same shape: every access JWT minted before this
	// claim existed carries no `tid` and reads as "", and VerifyAccess
	// accepts it. That buys a graceful rollout — no mass logout on the
	// deploy that introduces tenancy — for the single-tenant deployments
	// that are the only ones in a position to have such tokens.
	//
	// It is NOT a licence to accept an empty tid forever. The tolerance
	// ends where tenancy begins: once a deployment enables tenancy, an
	// empty tid must REJECT, because there "" is not a tenant but the
	// absence of one, and treating absence as a match is the wildcard
	// deny-by-default forbids. That rejection lands with
	// VerifyAccessInTenant in 7c-2; VerifyAccess is unchanged here.
	//
	// omitempty is load-bearing, not cosmetic: it is what makes a
	// no-tenant token byte-identical to a pre-tenancy one, so this claim
	// costs single-tenant deployments nothing on the wire.
	TenantID string `json:"tid,omitempty"`
	jwt.RegisteredClaims
}

// Token purpose values. These ride in the `purpose` claim and are the
// discriminator between the token shapes this service signs with one
// secret. Unexported: callers select a shape by calling the matching
// Issue*/Verify* pair, never by naming the wire value.
const (
	// purposeAccess marks a full access JWT (IssueAccess).
	purposeAccess = "access"
	// purposeTOTPPending marks the short-lived pre-2FA session token
	// (IssueTOTPPending) minted between password-success and
	// TOTP-verify.
	purposeTOTPPending = "totp_pending"
)

// ACR URN constants — well-known Authentication Context Class Reference
// values stamped on access JWTs. Centralised here so call sites don't
// sprinkle string literals.
const (
	// ACRLocalPassword is stamped on access JWTs minted from local-
	// password Login. Intentionally NOT in any default
	// RequireFreshAuth acrValues set — local-password DOES NOT satisfy
	// step-up by design (the security promise). Operators using
	// local-password for sensitive endpoints must federate first +
	// re-auth via OIDC/SAML.
	ACRLocalPassword = "urn:tamper:auth:local-password" //nolint:gosec // G101: well-known URN identifier, not a credential

	// ACRIncommonSilver is the OIDC step-up default (tamper namespace,
	// corresponding to urn:mace:incommon:iap:silver). Most OIDC IdPs
	// (Keycloak, Auth0, Okta, Azure AD) emit this when a step-up flow
	// with second-factor (TOTP, FIDO2, etc.) completes.
	ACRIncommonSilver = "urn:mace:incommon:iap:silver"

	// ACRSAMLPassword is the SAML default (tamper namespace,
	// corresponding to urn:oasis:names:tc:SAML:2.0:ac:classes:Password).
	// Stamped by the SAML callback when the assertion doesn't carry a
	// richer AuthnContextClassRef.
	ACRSAMLPassword = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password" //nolint:gosec // G101: well-known URN identifier, not a credential
)

// Issue returns a signed HS256 token with sub=userID, iat=now,
// exp=now+ttl, iss=cfg.Issuer, auth_time=now, acr=ACRLocalPassword.
// Backward-compat shim for v0.1-era callers — new v1.14 callers MUST
// use IssueAccess directly so they thread the IdP-supplied auth_time +
// acr through.
//
// Empty userID is rejected with ErrInvalidToken.
func (j *JWTService) Issue(userID string) (string, error) {
	return j.IssueAccess(userID, j.now().Unix(), ACRLocalPassword)
}

// IssueAccess mints a v1.14-shape access JWT with auth_time + acr
// claims. Refresh rotation MUST pass through the previous JWT's
// auth_time (NOT j.now()) — see Sprint 1 Task 01 contract.
//
// Empty userID, zero/negative authTime, or empty acr all reject with
// ErrInvalidToken so the caller can't accidentally mint a JWT that
// would always trip the step-up gate.
func (j *JWTService) IssueAccess(userID string, authTime int64, acr string) (string, error) {
	return j.IssueAccessForTenant(userID, "", authTime, acr)
}

// IssueAccessForTenant mints an access JWT carrying a `tid` claim naming
// the tenant, for pooled multi-tenant deployments.
//
// An empty tenantID is legal and means the single-tenant deployment:
// `tid` is omitted entirely and the token is byte-identical to one
// IssueAccess produced before this claim existed. That is why IssueAccess
// is a one-line delegation rather than a parallel implementation — two
// mint paths would be two chances for them to drift.
//
// tenantID is deliberately NOT validated. tamper does not parse, namespace
// or canonicalize a tenant id (sketch §4.1); deciding that a tenant is
// real is the application's job, and the boot guard already refused a
// store that cannot scope by one.
//
// Same rejections as IssueAccess otherwise: empty userID, non-positive
// authTime, empty acr.
func (j *JWTService) IssueAccessForTenant(userID, tenantID string, authTime int64, acr string) (string, error) {
	if userID == "" {
		return "", fmt.Errorf("%w: sub is empty", ErrInvalidToken)
	}
	if authTime <= 0 {
		return "", fmt.Errorf("%w: auth_time must be positive", ErrInvalidToken)
	}
	if acr == "" {
		return "", fmt.Errorf("%w: acr must be non-empty", ErrInvalidToken)
	}
	now := j.now()
	claims := AccessClaims{
		AuthTime: authTime,
		ACR:      acr,
		Purpose:  purposeAccess,
		TenantID: tenantID,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    j.issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(j.ttl)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(j.secret)
	if err != nil {
		return "", fmt.Errorf("auth: sign jwt: %w", err)
	}
	return signed, nil
}

// Verify parses and validates tokenStr, returning the subject (user ID)
// on success. Any failure is wrapped in ErrInvalidToken so callers can
// compare with errors.Is.
//
// Retained for the non-step-up code path; RequireAuth middleware uses
// VerifyAccess instead so the typed claims can be stashed for
// RequireFreshAuth downstream.
func (j *JWTService) Verify(tokenStr string) (string, error) {
	claims, err := j.VerifyAccess(tokenStr)
	if err != nil {
		return "", err
	}
	return claims.Subject, nil
}

// VerifyAccess parses tokenStr as a v1.14-shape AccessClaims JWT.
// Returns the typed claims on success so middleware can inspect
// auth_time + acr without a re-parse. ErrInvalidToken wraps every
// failure mode.
//
// Legacy-tolerant: pre-v1.14 JWTs carry no auth_time + no acr; those
// fields parse as zero values. The middleware downstream treats
// AuthTime=0 as "older than any maxAge" and ACR="" as "matches no
// acrValues" — both trip the step-up gate, which is the intended
// migration path (operators get a forced re-auth on sensitive
// endpoints once, then their refreshed JWTs carry the new claims).
//
// The `tid` claim is READ but not enforced here, and that is deliberate
// for this slice: a missing tid parses as "" and a present one is handed
// to the caller untouched. VerifyAccess has no way to know which tenant
// the request was routed to, so it cannot decide whether a tid matches —
// that comparison needs the routed tenant and lands in
// VerifyAccessInTenant (7c-2). Until then, reading tid from these claims
// and comparing it yourself is the app's job.
//
// Rejects any token whose `purpose` claim names a different token
// shape. This is the other half of the discrimination VerifyTOTPPending
// already performed: both Verify* entry points now refuse the other's
// token, so a totp-pending session token handed out after a
// password-only login cannot be replayed as a bearer credential to
// skip the second factor. An absent purpose is accepted as a legacy
// access JWT — see AccessClaims.Purpose for why that is safe.
func (j *JWTService) VerifyAccess(tokenStr string) (*AccessClaims, error) {
	claims := &AccessClaims{}
	tok, err := jwt.ParseWithClaims(tokenStr, claims, j.keyFunc,
		jwt.WithTimeFunc(j.now),
		jwt.WithIssuer(j.issuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if !tok.Valid {
		return nil, fmt.Errorf("%w: token not valid", ErrInvalidToken)
	}
	if claims.Purpose != "" && claims.Purpose != purposeAccess {
		return nil, fmt.Errorf("%w: wrong purpose %q", ErrInvalidToken, claims.Purpose)
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("%w: sub is missing", ErrInvalidToken)
	}
	return claims, nil
}

func (j *JWTService) keyFunc(t *jwt.Token) (any, error) {
	if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("%w: unexpected signing method %q", ErrInvalidToken, t.Method.Alg())
	}
	return j.secret, nil
}

// totpPendingClaims is the v0.8 task 02 short-lived session token
// minted between password-success and TOTP-verify on logins where 2FA
// is required. The `purpose` claim discriminates it from the standard
// access JWT, and the discrimination is enforced in BOTH directions:
// VerifyTOTPPending rejects an access JWT submitted to the totp-verify
// endpoint, and VerifyAccess rejects this token submitted as a bearer
// credential. So a leaked access token can't skip the 2FA step, and
// the pending token handed out after a password-only login can't
// authenticate anything on its own.
type totpPendingClaims struct {
	Purpose string `json:"purpose"`
	jwt.RegisteredClaims
}

// IssueTOTPPending mints a short-lived (5 min) JWT carrying the user
// id + Purpose="totp_pending". Returned to the SPA after a successful
// password check on a 2FA-enrolled account; the SPA submits it back
// on /api/auth/totp/verify alongside the 6-digit code.
func (j *JWTService) IssueTOTPPending(userID string) (string, error) {
	if userID == "" {
		return "", fmt.Errorf("%w: sub is empty", ErrInvalidToken)
	}
	now := j.now()
	claims := totpPendingClaims{
		Purpose: purposeTOTPPending,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    j.issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(j.secret)
	if err != nil {
		return "", fmt.Errorf("auth: sign totp-pending jwt: %w", err)
	}
	return signed, nil
}

// VerifyTOTPPending parses + validates a totp-pending session token
// and returns the subject (user id). Rejects any token whose Purpose
// claim isn't "totp_pending" — guards against access JWTs being
// submitted to the totp-verify endpoint.
func (j *JWTService) VerifyTOTPPending(tokenStr string) (string, error) {
	claims := &totpPendingClaims{}
	tok, err := jwt.ParseWithClaims(tokenStr, claims, j.keyFunc,
		jwt.WithTimeFunc(j.now),
		jwt.WithIssuer(j.issuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if !tok.Valid {
		return "", fmt.Errorf("%w: token not valid", ErrInvalidToken)
	}
	if claims.Purpose != purposeTOTPPending {
		return "", fmt.Errorf("%w: wrong purpose %q", ErrInvalidToken, claims.Purpose)
	}
	if claims.Subject == "" {
		return "", fmt.Errorf("%w: sub is missing", ErrInvalidToken)
	}
	return claims.Subject, nil
}
