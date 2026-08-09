package crypto

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/suryakencana007/tamper/tenant"
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
	// signer, when non-nil, replaces the built-in HS256 path. nil is the
	// default and the ONLY configuration that can produce a
	// byte-identical pre-seam token — see sign.
	signer Signer
	// verifiers resolves a token's `kid` to the Signer that can check
	// it: key rotation, and eventually a per-tenant key. Empty means
	// "verify with signer".
	verifiers map[string]Signer
	// now is the clock source; tests override via Testing().SetNow.
	now func() time.Time
}

// JWTOption configures a JWTService at construction.
type JWTOption func(*JWTService)

// WithSigner replaces the built-in HS256 signing with s — the seam that
// makes asymmetric keys possible without changing a call site.
//
// Supplying a Signer bypasses the JWTConfig.Secret requirement: signing
// is delegated, so the service needs no key material of its own and an
// empty Secret is no longer a programmer error. The panic stays for the
// default path, where an empty secret still means every token is
// forgeable.
//
// A service with a Signer no longer produces byte-identical tokens to
// the default path unless the Signer is an equivalent HS256 with no
// kid — which is the point: you asked for different signing.
func WithSigner(s Signer) JWTOption { return func(j *JWTService) { j.signer = s } }

// WithVerifiers supplies the verification keys, keyed by `kid`, for
// rotation or per-tenant keys. A token's kid is looked up here; an
// unknown kid FAILS CLOSED rather than falling back to the signing key,
// because a fallback would let a token name a key that does not exist
// and still be checked against one that does.
//
// The map is copied, so a later mutation by the caller cannot change
// verification behaviour underneath a running service.
func WithVerifiers(byKID map[string]Signer) JWTOption {
	return func(j *JWTService) {
		if byKID == nil {
			j.verifiers = nil
			return
		}
		cp := make(map[string]Signer, len(byKID))
		maps.Copy(cp, byKID)
		j.verifiers = cp
	}
}

// NewJWTService constructs a JWTService from a JWTConfig. Panics on
// empty secret — callers are expected to validate their config at
// startup; reaching NewJWTService with an empty secret is a programmer
// error.
//
// With no options the service is exactly what it was before the Signer
// seam existed, down to the bytes it emits: the default path does not
// route through Signer at all.
func NewJWTService(cfg JWTConfig, opts ...JWTOption) *JWTService {
	j := &JWTService{
		secret: []byte(cfg.Secret),
		ttl:    cfg.TTL,
		issuer: cfg.Issuer,
		now:    time.Now,
	}
	for _, opt := range opts {
		opt(j)
	}
	// The secret is only required when THIS service does the signing.
	if j.signer == nil && cfg.Secret == "" {
		panic("auth: jwt secret is empty — config validation should have caught this")
	}
	return j
}

// sign produces the signed token for claims.
//
// The default branch is deliberately the original code, unchanged and
// untouched by the seam: byte-identity with a pre-7d-1 token is
// guaranteed by construction rather than merely asserted by a test. The
// pinned-token test then proves the guarantee held.
func (j *JWTService) sign(claims jwt.Claims) (string, error) {
	if j.signer == nil {
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		return tok.SignedString(j.secret)
	}
	tok := jwt.NewWithClaims(signerMethod{s: j.signer}, claims)
	if kid := j.signer.KeyID(); kid != "" {
		tok.Header["kid"] = kid
	}
	// The key travels inside the Signer, so nothing is passed here.
	return tok.SignedString(nil)
}

// parserOptions are the validation rules both verification paths apply.
// Shared so the delegated path cannot drift from the default one.
func (j *JWTService) parserOptions() []jwt.ParserOption {
	return []jwt.ParserOption{
		jwt.WithTimeFunc(j.now),
		jwt.WithIssuer(j.issuer),
		jwt.WithExpirationRequired(),
	}
}

// resolveVerifier picks the Signer that may check a token carrying kid.
//
// Fails closed on an unknown kid. Falling back to the signing key would
// mean a token could name any key it liked and still be verified against
// the one key the service holds, which makes the kid header decorative
// at exactly the moment it becomes load-bearing.
func (j *JWTService) resolveVerifier(kid string) (Signer, error) {
	if len(j.verifiers) > 0 {
		s, ok := j.verifiers[kid]
		if !ok {
			return nil, fmt.Errorf("%w: token not valid", ErrInvalidToken)
		}
		return s, nil
	}
	if j.signer == nil {
		return nil, fmt.Errorf("%w: token not valid", ErrInvalidToken)
	}
	return j.signer, nil
}

// parseClaims verifies tokenStr's signature and validates its claims
// into claims.
//
// The default branch is the original ParseWithClaims call, unchanged.
// The delegated branch verifies the signature through the resolved
// Signer and then hands the claims to jwt.NewValidator — golang-jwt's
// OWN validator, with the same options — rather than re-implementing
// expiry and issuer checks. Duplicating a security-critical validation
// is how the two paths would quietly diverge.
func (j *JWTService) parseClaims(tokenStr string, claims jwt.Claims) error {
	if j.signer == nil && len(j.verifiers) == 0 {
		tok, err := jwt.ParseWithClaims(tokenStr, claims, j.keyFunc, j.parserOptions()...)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidToken, err)
		}
		if !tok.Valid {
			return fmt.Errorf("%w: token not valid", ErrInvalidToken)
		}
		return nil
	}

	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return fmt.Errorf("%w: token not valid", ErrInvalidToken)
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("%w: token not valid", ErrInvalidToken)
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerRaw, &hdr); err != nil {
		return fmt.Errorf("%w: token not valid", ErrInvalidToken)
	}
	verifier, err := j.resolveVerifier(hdr.Kid)
	if err != nil {
		return err
	}
	// The token does not get to choose its algorithm. Accepting the
	// header's alg would be the classic confusion attack.
	if hdr.Alg != verifier.Alg() {
		return fmt.Errorf("%w: token not valid", ErrInvalidToken)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("%w: token not valid", ErrInvalidToken)
	}
	if err := verifier.Verify(parts[0]+"."+parts[1], sig); err != nil {
		return fmt.Errorf("%w: token not valid", ErrInvalidToken)
	}
	claimsRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("%w: token not valid", ErrInvalidToken)
	}
	if err := json.Unmarshal(claimsRaw, claims); err != nil {
		return fmt.Errorf("%w: token not valid", ErrInvalidToken)
	}
	if err := jwt.NewValidator(j.parserOptions()...).Validate(claims); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	return nil
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
	// VerifyAccess in 7c-2; VerifyAccess is unchanged here.
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
	return j.IssueAccess(userID, tenant.Single, j.now().Unix(), ACRLocalPassword)
}

// IssueAccess mints an access JWT carrying a `tid` claim naming
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
func (j *JWTService) IssueAccess(userID string, tenantID tenant.ID, authTime int64, acr string) (string, error) {
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
		TenantID: tenantID.String(),
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    j.issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(j.ttl)),
		},
	}
	signed, err := j.sign(claims)
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
	claims, err := j.VerifyAccess(tokenStr, tenant.Single)
	if err != nil {
		return "", err
	}
	return claims.Subject, nil
}

// VerifyAccess is VerifyAccess plus the tenant pin: the token's
// `tid` claim must equal tenantID EXACTLY, and every other outcome is a
// rejection.
//
// One equality does all the work, and it is worth reading the table
// rather than the rule:
//
//	route ""     token ""        allow  — single-tenant, byte-identical to before
//	route ""     token "acme"    REJECT — a tenant token on an untenanted route
//	route "acme" token ""        REJECT — tenancy is on; see below
//	route "acme" token "acme"    allow
//	route "acme" token "globex"  REJECT — the cross-tenant case
//
// The third row is where 7c-1's legacy tolerance ENDS, and it ends here
// deliberately. AccessClaims.TenantID is tolerant of a missing `tid`
// because a single-tenant deployment's existing tokens have none — but
// once a route names a tenant, an absent tid is not a match, it is the
// absence of an answer, and reading absence as a match is precisely the
// wildcard deny-by-default forbids (sketch §6.2). A caller that wants
// the tolerant read still has VerifyAccess.
//
// A mismatch collapses onto ErrInvalidToken with a message
// indistinguishable from an ordinary invalid token. That is not
// tidiness: a distinguishable "wrong tenant" error tells the caller
// that its token is well-formed and merely pointed at the wrong place,
// which is a tenant-existence oracle. One status, one message, no
// signal — the discipline this package already applies to every other
// JWT failure mode (§6.3).
func (j *JWTService) VerifyAccess(tokenStr string, tenantID tenant.ID) (*AccessClaims, error) {
	claims, err := j.verifyAccessUnpinned(tokenStr)
	if err != nil {
		return nil, err
	}
	if claims.TenantID != tenantID.String() {
		// Deliberately the SAME message the generic invalid branch uses.
		return nil, fmt.Errorf("%w: token not valid", ErrInvalidToken)
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
	signed, err := j.sign(claims)
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
	if err := j.parseClaims(tokenStr, claims); err != nil {
		return "", err
	}
	if claims.Purpose != purposeTOTPPending {
		return "", fmt.Errorf("%w: wrong purpose %q", ErrInvalidToken, claims.Purpose)
	}
	if claims.Subject == "" {
		return "", fmt.Errorf("%w: sub is missing", ErrInvalidToken)
	}
	return claims.Subject, nil
}

// verifyAccessUnpinned is VerifyAccess without the tenant comparison —
// the parse, purpose and subject checks only.
//
// It is unexported deliberately. Before v0.4.0 this was the public
// VerifyAccess and the tenant-pinning form sat beside it, which meant a
// caller could reach the unpinned path by accident simply by calling the
// shorter name. Folding the two made the pinned form the only way in, and
// this helper exists so the pinned form has something to delegate to
// rather than recursing.
func (j *JWTService) verifyAccessUnpinned(tokenStr string) (*AccessClaims, error) {
	claims := &AccessClaims{}
	if err := j.parseClaims(tokenStr, claims); err != nil {
		return nil, err
	}
	if claims.Purpose != "" && claims.Purpose != purposeAccess {
		return nil, fmt.Errorf("%w: wrong purpose %q", ErrInvalidToken, claims.Purpose)
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("%w: sub is missing", ErrInvalidToken)
	}
	return claims, nil
}
