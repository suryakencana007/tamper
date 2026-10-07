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

// invalidTokenError is what every VERIFICATION failure returns.
//
// Its text is one fixed string, whatever went wrong. A message that
// varied would tell whoever can read it which check failed, and the
// case that matters is the tenant check: "expired" or "bad signature"
// says the token is no good, while a different message for a wrong
// tenant says the token is genuine and merely aimed elsewhere. The
// status code was already uniform; the text now is too, so an adapter
// or a log line that prints the error discloses nothing either.
//
// The reason is not thrown away. It is the second error in Unwrap, so
// server-side code that wants it can ask — errors.Is(err,
// jwt.ErrTokenExpired), or errors.Unwrap on the chain for a debug log.
// It is never part of Error(), so it reaches a caller only if something
// deliberately puts it there.
type invalidTokenError struct{ cause error }

func (e *invalidTokenError) Error() string { return ErrInvalidToken.Error() + ": token not valid" }

func (e *invalidTokenError) Unwrap() []error {
	if e.cause == nil {
		return []error{ErrInvalidToken}
	}
	return []error{ErrInvalidToken, e.cause}
}

// invalidToken wraps the reason a token failed verification.
func invalidToken(cause error) error { return &invalidTokenError{cause: cause} }

// The reasons this package adds on top of the JWT library's own. They
// exist so the cause is not lost; they are unexported because nothing
// outside should branch on them.
var (
	errUnknownKeyID       = errors.New("no verification key for the token's kid")
	errMalformedToken     = errors.New("token is malformed")
	errWrongAlgorithm     = errors.New("token alg does not match the verification key")
	errBadSignature       = errors.New("signature does not verify")
	errWrongPurpose       = errors.New("token purpose is not the one this entry point accepts")
	errMissingSubject     = errors.New("token has no subject")
	errMissingAuthContext = errors.New("token has no auth_time or no acr")
	errWrongTenant        = errors.New("token tid does not match the tenant it was verified for")
	errBadHomeTenant      = errors.New("htid without a different tid")
)

// ErrTenantRequired — [JWTService.IssueAccess] or
// [JWTService.VerifyAccess] was handed an UNSET tenant id (the zero
// [tenant.ID], not [tenant.Single]). The
// totp-pending pair ([JWTService.IssueTOTPPending],
// [JWTService.VerifyTOTPPending]) returns it on the same terms.
//
// This is the crypto-side twin of identity's error of the same name,
// and it exists for the same reason: tenant.ID distinguishes "I forgot
// to thread a tenant" from "I am deliberately single-tenant", and only
// the first denies. The check has to be explicit: an unset id
// stringifies to "" and so compares EQUAL to a tid-less token's claim.
// Without it a caller that never resolved a tenant would verify, and
// mint, single-tenant tokens and look correct doing it.
//
// Deliberately NOT collapsed into ErrInvalidToken, despite that being
// this package's rule for every other failure. The rule exists to deny
// attackers a signal, and it earns its keep because those conditions
// are decided from ATTACKER-SUPPLIED input. This one is decided from
// the CALLER's own argument, before the token is even consulted: it is
// identical for every token, discloses nothing about any tenant, and is
// a wiring bug in the deployment. Folding it into "invalid token" would
// send an operator hunting a token problem that does not exist.
//
// Transport obligation: map it onto the SAME generic 401 envelope as
// ErrInvalidToken. It is legible in logs, never on the wire.
var ErrTenantRequired = errors.New("auth: tenant id is required")

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
	// default, and the only configuration that produces the golden
	// vectors in the tests — see sign.
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
// A service with a Signer produces different bytes from the default path
// unless the Signer is an equivalent HS256 with no kid — which is the
// point: you asked for different signing.
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
// The default branch is the plain HS256 mint with no kid header. Its
// output is pinned by the golden-vector tests, so a change to the wire
// format cannot go unnoticed.
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
			return nil, invalidToken(errUnknownKeyID)
		}
		return s, nil
	}
	if j.signer == nil {
		return nil, invalidToken(errUnknownKeyID)
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
			return invalidToken(err)
		}
		if !tok.Valid {
			return invalidToken(errMalformedToken)
		}
		return nil
	}

	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return invalidToken(errMalformedToken)
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return invalidToken(errMalformedToken)
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerRaw, &hdr); err != nil {
		return invalidToken(errMalformedToken)
	}
	verifier, err := j.resolveVerifier(hdr.Kid)
	if err != nil {
		return err
	}
	// The token does not get to choose its algorithm. Accepting the
	// header's alg would be the classic confusion attack.
	if hdr.Alg != verifier.Alg() {
		return invalidToken(errWrongAlgorithm)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return invalidToken(errMalformedToken)
	}
	if err := verifier.Verify(parts[0]+"."+parts[1], sig); err != nil {
		return invalidToken(errBadSignature)
	}
	claimsRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return invalidToken(errMalformedToken)
	}
	if err := json.Unmarshal(claimsRaw, claims); err != nil {
		return invalidToken(errMalformedToken)
	}
	if err := jwt.NewValidator(j.parserOptions()...).Validate(claims); err != nil {
		return invalidToken(err)
	}
	return nil
}

// AccessClaims is the access-token JWT. It extends
// jwt.RegisteredClaims with auth_time + acr per OIDC Core 1.0 §2 +
// §3.1.2.1. Refresh-token rotation carries auth_time + acr forward
// unchanged — only IdP-side authentication (OIDC callback, SAML
// callback, local-password Login, TOTP-verify) advances them.
//
// Every claim IssueAccess writes is required on the way back in. A
// token without a purpose, an auth_time or an acr was not minted by
// this service as an access token, and ParseAccess refuses it. There is
// no tolerance for an older shape.
type AccessClaims struct {
	AuthTime int64  `json:"auth_time"`
	ACR      string `json:"acr"`
	// Purpose discriminates an access JWT from the other token shapes
	// this service mints under the SAME secret — currently the
	// totp-pending session token (IssueTOTPPending). ParseAccess accepts
	// exactly "access", which is what stops a pre-2FA session token, or
	// any other shape signed with this key, from authenticating as a
	// full session.
	Purpose string `json:"purpose"`
	// TenantID names the tenant this token was minted for. Opaque and
	// app-defined; tamper compares it for equality and never parses it.
	//
	// The single tenant is the empty string, in storage and on the wire
	// alike, so a token for tenant.Single carries no `tid` at all
	// (omitempty). That is the single tenant's own spelling, not a
	// missing claim: VerifyAccess compares the claim with the tenant it
	// is asked about for exact equality, so a tid-less token fits
	// tenant.Single and nothing else.
	TenantID string `json:"tid,omitempty"`
	// HomeTenantID is present only on an ENTERED token: one minted by
	// IssueAccessEntered for a subject who is stored in one tenant and is
	// acting in another (a platform admin inside a customer's tenant).
	// TenantID is then the tenant the token is FOR; this is the tenant
	// the subject is FROM.
	//
	// It grants nothing. Every verifier still compares TenantID, and
	// only TenantID, with the tenant it was asked about. This claim is
	// for attribution: an audit row can say who acted and where they
	// came from. Read it through ActorTenantID.
	//
	// omitempty: an ordinary token has no htid on the wire.
	HomeTenantID string `json:"htid,omitempty"`
	jwt.RegisteredClaims
}

// ActorTenantID returns the tenant the token's subject is from: the
// home tenant of an entered token, and TenantID for every other token,
// where the two are the same thing.
func (c *AccessClaims) ActorTenantID() string {
	if c.HomeTenantID != "" {
		return c.HomeTenantID
	}
	return c.TenantID
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

// IssueAccess mints an access JWT for userID in tenantID.
//
// tenant.Single is a tenant like any other here; its token carries no
// `tid` claim (see AccessClaims.TenantID).
//
// An UNSET tenant denies with [ErrTenantRequired]. This is the only
// mint of an ordinary access token, and the zero tenant.ID has the same
// string form as tenant.Single: without the check, a caller whose
// tenant was never resolved would get a valid single-tenant token.
//
// tenantID is otherwise NOT validated. tamper does not parse, namespace
// or canonicalize a tenant id; deciding that a tenant is real is the
// application's job.
//
// Rejected with ErrInvalidToken: an empty userID, a non-positive
// authTime, an empty acr.
func (j *JWTService) IssueAccess(userID string, tenantID tenant.ID, authTime int64, acr string) (string, error) {
	if !tenantID.Valid() {
		return "", ErrTenantRequired
	}
	return j.issueAccess(userID, tenantID.String(), "", authTime, acr, j.ttl)
}

// ErrEnteredTenants — IssueAccessEntered was asked for a pair of
// tenants that cannot make an entered token: one of them is the single
// tenant, or the two are the same. A caller bug, decided from the
// caller's own arguments, so it has its own text like ErrTenantRequired.
var ErrEnteredTenants = errors.New("auth: an entered token needs two different tenants, neither of them the single tenant")

// IssueAccessEntered mints an access token for a subject who is stored
// in homeTenantID and is acting in tenantID. The token carries
// tid=tenantID, so it is accepted exactly where an ordinary token for
// that tenant is, and htid=homeTenantID, so whoever reads it knows where
// the subject is from.
//
// THIS METHOD CHECKS NO RIGHT. Whether the subject may enter the tenant
// is decided before it is called — by identity.Core.EnterTenant, which
// is the entry point to use. Calling this directly mints a cross-tenant
// token on the caller's say-so alone.
//
// ttl is the lifetime. Zero or negative means the service TTL, and a
// ttl longer than the service TTL is cut to it: an entered token is
// never longer-lived than an ordinary one. It has no refresh session
// behind it, so its lifetime is how long a removed right keeps working.
//
// Both tenants must be set (ErrTenantRequired), neither may be the
// single tenant, and they must differ (ErrEnteredTenants). An entered
// token with an empty htid would be indistinguishable from an ordinary
// one, and a token "entering" its own home tenant is an ordinary token.
func (j *JWTService) IssueAccessEntered(userID string, tenantID, homeTenantID tenant.ID, authTime int64, acr string, ttl time.Duration) (string, error) {
	if !tenantID.Valid() || !homeTenantID.Valid() {
		return "", ErrTenantRequired
	}
	if tenantID.IsSingle() || homeTenantID.IsSingle() || tenantID == homeTenantID {
		return "", ErrEnteredTenants
	}
	if ttl <= 0 || ttl > j.ttl {
		ttl = j.ttl
	}
	return j.issueAccess(userID, tenantID.String(), homeTenantID.String(), authTime, acr, ttl)
}

// issueAccess is the one mint behind IssueAccess and IssueAccessEntered,
// so the two cannot drift apart in anything but the claims they differ
// on by design.
func (j *JWTService) issueAccess(userID, tid, htid string, authTime int64, acr string, ttl time.Duration) (string, error) {
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
		AuthTime:     authTime,
		ACR:          acr,
		Purpose:      purposeAccess,
		TenantID:     tid,
		HomeTenantID: htid,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    j.issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	signed, err := j.sign(claims)
	if err != nil {
		return "", fmt.Errorf("auth: sign jwt: %w", err)
	}
	return signed, nil
}

// VerifyAccess verifies an access token FOR a tenant: the token's `tid`
// claim must equal tenantID EXACTLY, and every other outcome is a
// rejection.
//
// One equality does all the work, and it is worth reading the table
// rather than the rule:
//
//	asked ""     token ""        allow  — the single tenant
//	asked ""     token "acme"    REJECT — a tenant token in the single tenant
//	asked "acme" token ""        REJECT — an absent tid is not a match
//	asked "acme" token "acme"    allow
//	asked "acme" token "globex"  REJECT — the cross-tenant case
//
// The third row: an absent tid is the single tenant's spelling, so it
// fits tenant.Single and nothing else. Reading it as a match for a named
// tenant would be the wildcard deny-by-default forbids.
//
// A mismatch collapses onto ErrInvalidToken with a message
// indistinguishable from an ordinary invalid token. That is not
// tidiness: a distinguishable "wrong tenant" error tells the caller
// that its token is well-formed and merely pointed at the wrong place,
// which is a tenant-existence oracle. One status, one message, no
// signal — the discipline this package already applies to every other
// JWT failure mode (§6.3).
func (j *JWTService) VerifyAccess(tokenStr string, tenantID tenant.ID) (*AccessClaims, error) {
	// Deny an UNSET tenant BEFORE parsing. Checked first
	// deliberately -- a wiring bug should surface identically whether
	// the token happened to be well-formed, expired, or garbage, or the
	// error an operator sees would depend on which request tripped it.
	if !tenantID.Valid() {
		return nil, ErrTenantRequired
	}
	claims, err := j.ParseAccess(tokenStr)
	if err != nil {
		return nil, err
	}
	if claims.TenantID != tenantID.String() {
		return nil, invalidToken(errWrongTenant)
	}
	return claims, nil
}

func (j *JWTService) keyFunc(t *jwt.Token) (any, error) {
	if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, errWrongAlgorithm
	}
	return j.secret, nil
}

// totpPendingClaims is the short-lived session token
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
	// TenantID names the tenant whose password step minted this token,
	// and it is what stops the token being finished somewhere else.
	//
	// Without it the pending token says only WHO cleared the password
	// check, not WHERE. In a pooled deployment that is half an answer: a
	// user of tenant B could carry the token to tenant A's totp-verify
	// endpoint, and nothing in the token would object — the second leg
	// of a login would complete in a tenant the first leg never ran in.
	// VerifyTOTPPending compares this claim against the routed tenant
	// for exact equality, the same single rule VerifyAccess applies to
	// an access token's `tid`.
	//
	// omitempty for the reason it is on AccessClaims.TenantID: the
	// single tenant is spelled as no claim.
	TenantID string `json:"tid,omitempty"`
	jwt.RegisteredClaims
}

// IssueTOTPPending mints a short-lived (5 min) JWT carrying the user
// id, Purpose="totp_pending", and the tenant the password step ran in.
// It is returned to the client after a successful password check on a
// 2FA-enrolled account; the client submits it back on the totp-verify
// endpoint with the 6-digit code, and [JWTService.VerifyTOTPPending]
// refuses it in any other tenant.
//
// The binding has to live in the token because nothing else on the
// second leg can supply it. The totp-verify request is unauthenticated
// — this token IS its credential — and the code check that follows is
// keyed by user id alone, so a pending token with no tenant would be
// accepted by every tenant's verify endpoint alike.
//
// An UNSET tenant denies with [ErrTenantRequired]. A single-tenant
// deployment passes tenant.Single. tenantID is otherwise not validated,
// as in IssueAccess.
func (j *JWTService) IssueTOTPPending(userID string, tenantID tenant.ID) (string, error) {
	if !tenantID.Valid() {
		return "", ErrTenantRequired
	}
	if userID == "" {
		return "", fmt.Errorf("%w: sub is empty", ErrInvalidToken)
	}
	now := j.now()
	claims := totpPendingClaims{
		Purpose:  purposeTOTPPending,
		TenantID: tenantID.String(),
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

// VerifyTOTPPending parses and validates a totp-pending session token
// and returns the subject (user id). The token's Purpose must be
// "totp_pending", which keeps an access JWT out of the totp-verify
// endpoint, and its `tid` must equal tenantID EXACTLY. It is the
// pending-token twin of VerifyAccess and follows the same table:
//
//	asked ""     token ""        allow  — the single tenant
//	asked ""     token "acme"    REJECT — a tenant token in the single tenant
//	asked "acme" token ""        REJECT — an absent tid is not a match
//	asked "acme" token "acme"    allow
//	asked "acme" token "globex"  REJECT — the cross-tenant case
//
// The last row is the reason for the tenant. The pending token is the
// only credential the totp-verify endpoint sees, and the code check
// behind it is keyed by user id alone — so without the pin, a globex
// user's pending token finishes its login at acme's endpoint, and
// whatever mints the session next is the only thing left to notice.
//
// An UNSET tenant denies with [ErrTenantRequired] BEFORE parsing, and a
// mismatch collapses onto ErrInvalidToken with the same generic message
// VerifyAccess gives its own mismatch — both for the reasons recorded
// there. A distinguishable "wrong tenant" would tell the holder its
// token is genuine and merely misaimed, which is a tenant-existence
// oracle.
func (j *JWTService) VerifyTOTPPending(tokenStr string, tenantID tenant.ID) (string, error) {
	// Checked first so a wiring bug reports identically whatever token
	// happened to arrive — see VerifyAccess.
	if !tenantID.Valid() {
		return "", ErrTenantRequired
	}
	claims := &totpPendingClaims{}
	if err := j.parseClaims(tokenStr, claims); err != nil {
		return "", err
	}
	if claims.Purpose != purposeTOTPPending {
		return "", invalidToken(errWrongPurpose)
	}
	if claims.Subject == "" {
		return "", invalidToken(errMissingSubject)
	}
	if claims.TenantID != tenantID.String() {
		return "", invalidToken(errWrongTenant)
	}
	return claims.Subject, nil
}

// ParseAccess validates an access token and returns its claims WITHOUT
// checking the tenant. It checks the signature, expiry and issuer, that
// the purpose is "access", and that the token has a subject, a positive
// auth_time and an acr. A caller may rely on all of those being set on
// the claims it gets back.
//
// The name is the warning. Use [JWTService.VerifyAccess] unless you are
// composing the tenant check yourself — espresso's RequireAuth does,
// because RequireTenant runs after it and performs the comparison against
// the ROUTED tenant, which RequireAuth cannot know.
//
// This is deliberately not called VerifyAccess-something: VerifyAccess
// checks the tenant, and skipping the check requires saying Parse.
func (j *JWTService) ParseAccess(tokenStr string) (*AccessClaims, error) {
	claims := &AccessClaims{}
	if err := j.parseClaims(tokenStr, claims); err != nil {
		return nil, err
	}
	// Exactly "access". An absent purpose is refused like a foreign one:
	// every access token this service mints carries the claim.
	if claims.Purpose != purposeAccess {
		return nil, invalidToken(errWrongPurpose)
	}
	if claims.Subject == "" {
		return nil, invalidToken(errMissingSubject)
	}
	// IssueAccess refuses to mint without these two, so a token that
	// lacks them is not one of ours. Step-up reads both, and must not
	// have to decide what a missing one means.
	if claims.AuthTime <= 0 || claims.ACR == "" {
		return nil, invalidToken(errMissingAuthContext)
	}
	// An htid is only ever minted beside a different, non-empty tid
	// (IssueAccessEntered). A token that says otherwise was not minted
	// here, and its htid would be recorded as the audit actor's tenant.
	if claims.HomeTenantID != "" && (claims.TenantID == "" || claims.HomeTenantID == claims.TenantID) {
		return nil, invalidToken(errBadHomeTenant)
	}
	return claims, nil
}

// Entered reports whether the token is an entered one: minted by
// IssueAccessEntered for a subject who is acting outside their home
// tenant.
func (c *AccessClaims) Entered() bool { return c.HomeTenantID != "" }

// AccessTTL returns the lifetime of the access tokens this service
// mints.
func (j *JWTService) AccessTTL() time.Duration { return j.ttl }
