package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/suryakencana007/tamper/crypto"
	"github.com/suryakencana007/tamper/tenant"
)

// Password length bounds. Min mirrors common baseline guidance; Max is
// bcrypt's 72-byte input limit (Barista precedent: 8/72).
const (
	MinPasswordLen = 8
	MaxPasswordLen = 72
)

// Core is the identity service: registration, password login,
// refresh-session rotation, and revocation. Construct with New; safe
// for concurrent use as long as the Store is.
type Core struct {
	store Store
	// tenancy + scoped are settled ONCE at construction. The type
	// assertion runs in New, never per request: a store that cannot
	// serve tenants must fail at boot, not as a silent per-request deny
	// (sketch §4.2, §6.4). scoped is non-nil exactly when tenancy is true.
	jwt          *crypto.JWTService // nil = token-less instance; mint flows error
	keys         *crypto.KeySet     // nil = TOTP envelope flows error (ErrNoKeySet)
	refreshTTL   time.Duration      // 0 disables refresh sessions entirely
	totpRequired bool
	defaultACR   string
	hooks        Hooks
	throttling   Throttling      // zero value = no rate limiting (pre-7k-1 behavior)
	invitations  InvitationStore // nil = invitation verbs error (opt-in, 7j-1)
	now          func() time.Time
	newID        func() string
}

// Option configures a Core.
type Option func(*Core)

// WithRefreshTTL sets the refresh-session lifetime. 0 (the default)
// disables session continuity: no refresh tokens are minted and
// Refresh always rejects.
func WithRefreshTTL(d time.Duration) Option { return func(c *Core) { c.refreshTTL = d } }

// WithTOTPRequired turns on system-wide two-factor enforcement: Login
// returns ErrTOTPRequired even for users who have not enrolled yet
// (the caller routes them into enrollment).
func WithTOTPRequired(required bool) Option { return func(c *Core) { c.totpRequired = required } }

// WithDefaultACR sets the ACR stamped on freshly-authenticated sessions
// (Register, Login) and used as the legacy-row fallback during
// rotation. Applications with persisted ACR values MUST pass their own
// (Barista: urn:barista:auth:local-password — stored in
// refresh_tokens.acr, so the framework default would break step-up
// freshness against existing rows). Defaults to crypto.ACRLocalPassword.
func WithDefaultACR(acr string) Option { return func(c *Core) { c.defaultACR = acr } }

// WithTenancy was here. It gated the fallback path while the additive
// phase was open. v0.4.0 removed the fallback, so there is nothing to
// enable: every Core is tenant-scoped and a single-tenant deployment says
// so by passing tenant.Single.

// WithHooks attaches the app-side extension points.
func WithHooks(h Hooks) Option { return func(c *Core) { c.hooks = h } }

// WithClock injects a time source (tests).
func WithClock(now func() time.Time) Option { return func(c *Core) { c.now = now } }

// WithIDGenerator injects the id generator for users + sessions
// (tests). Defaults to UUIDv4.
func WithIDGenerator(newID func() string) Option { return func(c *Core) { c.newID = newID } }

// New constructs a Core. jwt may be nil for token-less instances
// (crypto-ops, bootstrap CLIs) — every flow that must mint tokens then
// fails with ErrNoTokenService.
func New(store Store, jwt *crypto.JWTService, opts ...Option) (*Core, error) {
	if store == nil {
		return nil, fmt.Errorf("identity: New requires a Store")
	}
	c := &Core{
		store:      store,
		jwt:        jwt,
		defaultACR: crypto.ACRLocalPassword,
		now:        time.Now,
		newID:      uuid.NewString,
	}
	for _, opt := range opts {
		opt(c)
	}
	if c.defaultACR == "" {
		return nil, fmt.Errorf("identity: default ACR must not be empty")
	}
	// The optional-interface upgrade and its boot assertion were here.
	// v0.4.0 folded TenantScopedStore into Store, so there is no longer a
	// second interface to assert against: a Store that does not implement
	// the tenant-scoped methods does not compile, which is strictly better
	// than a boot-time error. Phase 0c's lesson is preserved by making the
	// failure earlier, not by keeping the check.
	return c, nil
}

// --- the tenancy routing choice points -------------------------------
//
// Every scoped read funnels through one of these three, so the
// scoped-vs-unscoped decision exists in exactly three places and each
// is individually mutation-testable. Callers never branch on tenancy.

// tenantGate rejects the one shape that must never reach a store: an
// UNSET tenant, which is what a caller who forgot to thread it produces.
// It fails closed.
//
// Before v0.4.0 this had a second arm, for a non-empty tenant against a
// tenancy-disabled Core. There is no disabled mode now, so that shape
// cannot occur. What remains is the shape a bare string could never
// express: tenant.ID's zero value is distinguishable from tenant.Single,
// so "I forgot" and "I am single-tenant" are finally different inputs and
// only the first one denies (§6.2, sketch §8 item 7).
func (c *Core) tenantGate(tenantID tenant.ID) error {
	if !tenantID.Valid() {
		return ErrTenantRequired
	}
	return nil
}

func (c *Core) userByEmail(ctx context.Context, tenantID tenant.ID, email string) (User, error) {
	if err := c.tenantGate(tenantID); err != nil {
		return User{}, err
	}
	return c.store.UserByEmail(ctx, tenantID, email)
}

// countUsers drives the firstUser bootstrap signal, which is why it is
// per-tenant when tenancy is on. This is blocker B2 and it is the one
// that fails SILENTLY: a global count compiles, passes, ships, and
// surfaces months later as "the new customer's admin has no
// permissions".
func (c *Core) countUsers(ctx context.Context, tenantID tenant.ID) (int64, error) {
	if err := c.tenantGate(tenantID); err != nil {
		return 0, err
	}
	return c.store.CountUsers(ctx, tenantID)
}

func (c *Core) identityByProviderSubject(ctx context.Context, tenantID tenant.ID, provider, subject string) (Identity, error) {
	if err := c.tenantGate(tenantID); err != nil {
		return Identity{}, err
	}
	return c.store.IdentityByProviderSubject(ctx, tenantID, provider, subject)
}

// RefreshTTL exposes the configured session lifetime so transport
// layers can align cookie Max-Age with the row expiry.
func (c *Core) RefreshTTL() time.Duration { return c.refreshTTL }

// Register creates a user within a tenant. The tenant is an
// EXPLICIT argument, never derived from the context: an implicit tenant
// is a cross-tenant leak waiting for one missing middleware call, and it
// fails open (tenant.WithTenant documents the same rule for ports).
//
// firstUser is counted WITHIN the tenant, so tenant #2's first admin
// receives firstUser=true even though tenant #1 is full of users. That
// is blocker B2.
func (c *Core) Register(ctx context.Context, tenantID tenant.ID, email, password string) (User, Tokens, error) {
	normalised, err := NormaliseEmail(email)
	if err != nil {
		return User{}, Tokens{}, err
	}
	if err := validatePassword(password); err != nil {
		return User{}, Tokens{}, err
	}
	hash, err := crypto.HashPassword(password)
	if err != nil {
		return User{}, Tokens{}, fmt.Errorf("identity: hash password: %w", err)
	}

	count, err := c.countUsers(ctx, tenantID)
	if err != nil {
		return User{}, Tokens{}, fmt.Errorf("identity: count users: %w", err)
	}
	first := count == 0

	u := NewUser{
		ID:           c.newID(),
		TenantID:     tenantID.String(),
		Email:        normalised,
		PasswordHash: hash,
		CreatedAt:    c.now(),
	}
	if err := c.store.CreateUser(ctx, u, first); err != nil {
		if errors.Is(err, ErrEmailTaken) {
			return User{}, Tokens{}, ErrEmailTaken
		}
		return User{}, Tokens{}, fmt.Errorf("identity: create user: %w", err)
	}
	user := User{
		ID:           u.ID,
		TenantID:     u.TenantID, // carried, never read
		Email:        u.Email,
		PasswordHash: u.PasswordHash,
		Active:       true,
		CreatedAt:    u.CreatedAt,
	}

	if c.hooks.OnRegistered != nil {
		c.hooks.OnRegistered(ctx, user, first)
	}

	tokens, err := c.issueTokens(ctx, user.ID, tenant.FromStored(user.TenantID), c.now().Unix(), c.defaultACR)
	if err != nil {
		return User{}, Tokens{}, err
	}
	return user, tokens, nil
}

// Login authenticates within a tenant.
//
// Timing parity is preserved and it is the reason the tenant is applied
// by the LOOKUP rather than by a comparison afterwards. A wrong tenant
// makes UserByEmailInTenant miss, which lands on the SAME branch as an
// unknown email — stub bcrypt burn, then ErrInvalidCredentials. There is
// deliberately no "fetch globally, then compare TenantID" step: that
// would both leak (the row is read) and return early before the hash
// comparison, making a wrong tenant measurably cheaper than a wrong
// password.
//
// The empty-tenant rejection is decided from the argument alone, before
// any store read, and is identical for every email — see
// ErrTenantRequired for why it is not an enumeration oracle.
func (c *Core) Login(ctx context.Context, tenantID tenant.ID, email, password string) (User, Tokens, error) {
	normalised, err := NormaliseEmail(email)
	if err != nil {
		_ = crypto.VerifyStub(password)
		return User{}, Tokens{}, ErrInvalidCredentials
	}
	// Throttle on the NORMALISED address, and before the store read.
	//
	// Normalised, because a limiter keyed on the raw input is evaded by
	// changing the case of one letter — the attacker gets a fresh bucket
	// per spelling of the same account, which is no limiter at all.
	//
	// Before the read, because that ordering is the whole of the
	// non-disclosure property: the key is composed from what the caller
	// typed, so a throttled answer is identical for an address that
	// exists, one that never existed, one that is federated-only and one
	// that is deactivated. Move this below the lookup and "throttled"
	// starts meaning "this account is real".
	if retryAfter, ok := c.allowLogin(ctx, tenantID, normalised); !ok {
		return User{}, Tokens{}, &ThrottledError{RetryAfter: retryAfter}
	}
	user, err := c.userByEmail(ctx, tenantID, normalised)
	if err != nil {
		if errors.Is(err, ErrTenantRequired) {
			return User{}, Tokens{}, err
		}
		if errors.Is(err, ErrNotFound) {
			_ = crypto.VerifyStub(password)
			return User{}, Tokens{}, ErrInvalidCredentials
		}
		return User{}, Tokens{}, fmt.Errorf("identity: lookup user: %w", err)
	}
	if user.PasswordHash == "" || !user.Active {
		_ = crypto.VerifyStub(password)
		return User{}, Tokens{}, ErrInvalidCredentials
	}
	if err := crypto.VerifyPassword(user.PasswordHash, password); err != nil {
		return User{}, Tokens{}, ErrInvalidCredentials
	}

	if user.TOTPEnrolled || c.totpRequired {
		return user, Tokens{}, ErrTOTPRequired
	}

	tokens, err := c.issueTokens(ctx, user.ID, tenant.FromStored(user.TenantID), c.now().Unix(), c.defaultACR)
	if err != nil {
		return User{}, Tokens{}, err
	}
	return user, tokens, nil
}

// IssueTokensForUser mints a session with fresh auth_time and the
// default ACR — the post-TOTP-verify and shim path.
//
// The minted session carries an EMPTY tenant. These two shims take a
// bare user id, so there is no tenant to carry, and resolving one here
// would mean a second store read this method has never done. A pooled
// deployment mints through a tenant-aware entry point instead (7b-2);
// until then this is byte-identical to pre-7b-1 behavior, because
// nothing supplies a tenant yet.
func (c *Core) IssueTokensForUser(ctx context.Context, userID string) (Tokens, error) {
	return c.issueTokens(ctx, userID, tenant.Single, 0, "")
}

// IssueTokensForUserWithACR mints a session carrying explicit step-up
// claims (federated logins thread their own auth_time + ACR through).
// Non-positive authTime falls back to now; empty acr to the default.
// Empty tenant, for the reason on IssueTokensForUser.
func (c *Core) IssueTokensForUserWithACR(ctx context.Context, userID string, authTime int64, acr string) (Tokens, error) {
	return c.issueTokens(ctx, userID, tenant.Single, authTime, acr)
}

// IssueTokensForUserInTenant mints a session BOUND TO A TENANT — the
// entry point the two shims above promised and did not have (v0.5.0,
// closing the 7b-2 gap).
//
// The tenant lands in two places, and both matter:
//
//   - the access JWT's `tid` claim, so a verifier can bind the request
//     to a tenant without a store read;
//   - the refresh session row, so the rotation successor inherits it
//     unchanged (see Refresh) instead of silently reverting to Single.
//
// An UNSET tenant DENIES with [ErrTenantRequired] rather than falling
// back to [tenant.Single]. That asymmetry is the whole point of this
// method existing next to the shims: those two take a bare user id and
// have no tenant to carry, so Single is the honest answer there. A
// caller who reached for THIS method is asserting it has a tenant, so
// an unset one is a wiring bug — the tenant-resolving step did not run —
// and quietly minting a Single-tenant session for it would hand back a
// token that authorises the wrong scope. Deny-by-default extends to
// tenancy: absent never means "every tenant".
//
// Single-tenant deployments keep calling the shims and are unaffected;
// this method is byte-identical to IssueTokensForUserWithACR when passed
// [tenant.Single] explicitly.
func (c *Core) IssueTokensForUserInTenant(ctx context.Context, userID string, tenantID tenant.ID, authTime int64, acr string) (Tokens, error) {
	if err := c.tenantGate(tenantID); err != nil {
		return Tokens{}, err
	}
	return c.issueTokens(ctx, userID, tenantID, authTime, acr)
}

// Refresh validates and rotates a refresh session: the old row is
// revoked and a successor minted. Failures collapse to
// ErrInvalidSession (anti-enumeration), with ONE exception —
// ErrUserInactive, returned after revoking the presented session so a
// deactivated user's cookie cannot be retried.
//
// Step-up carry-forward: the successor row and access JWT inherit the
// old row's auth_time + ACR UNCHANGED. Legacy rows (zero auth_time)
// fall back to now + the default ACR exactly once.
func (c *Core) Refresh(ctx context.Context, refreshToken string) (User, Tokens, error) {
	if c.refreshTTL <= 0 {
		return User{}, Tokens{}, ErrInvalidSession
	}
	hash, err := crypto.HashRefreshToken(refreshToken)
	if err != nil {
		return User{}, Tokens{}, ErrInvalidSession
	}
	session, err := c.store.RefreshSessionByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return User{}, Tokens{}, ErrInvalidSession
		}
		return User{}, Tokens{}, fmt.Errorf("identity: lookup session: %w", err)
	}
	now := c.now()
	if session.Revoked() || !session.ExpiresAt.After(now) {
		return User{}, Tokens{}, ErrInvalidSession
	}

	user, err := c.store.UserByID(ctx, session.UserID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return User{}, Tokens{}, ErrInvalidSession
		}
		return User{}, Tokens{}, fmt.Errorf("identity: lookup user for session: %w", err)
	}
	if !user.Active {
		// Revoke the presented session best-effort; the inactive verdict
		// stands regardless.
		_ = c.store.RevokeRefreshSession(ctx, session.ID, now)
		return User{}, Tokens{}, ErrUserInactive
	}

	if err := c.store.RevokeRefreshSession(ctx, session.ID, now); err != nil {
		return User{}, Tokens{}, fmt.Errorf("identity: revoke session: %w", err)
	}

	carryAuthTime := int64(0)
	if !session.AuthTime.IsZero() {
		carryAuthTime = session.AuthTime.Unix()
	}
	// session.TenantID rides across the rotation UNCHANGED, exactly like
	// AuthTime and ACR above. Dropping it here would widen the successor
	// from one tenant to none — and "none" reads as the single-tenant
	// shape, which is the wildcard.
	tokens, err := c.issueTokens(ctx, session.UserID, tenant.FromStored(session.TenantID), carryAuthTime, session.ACR)
	if err != nil {
		return User{}, Tokens{}, err
	}
	return user, tokens, nil
}

// Logout revokes the session matching the presented refresh token.
// Idempotent by design: unknown, malformed, already-revoked tokens and
// disabled refresh all succeed silently so a stale cookie can always be
// cleared without a noisy error.
func (c *Core) Logout(ctx context.Context, refreshToken string) error {
	if c.refreshTTL <= 0 || refreshToken == "" {
		return nil
	}
	hash, err := crypto.HashRefreshToken(refreshToken)
	if err != nil {
		return nil
	}
	session, err := c.store.RefreshSessionByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return fmt.Errorf("identity: lookup session: %w", err)
	}
	if session.Revoked() {
		return nil
	}
	if err := c.store.RevokeRefreshSession(ctx, session.ID, c.now()); err != nil {
		return fmt.Errorf("identity: revoke session: %w", err)
	}
	return nil
}

// RevokeAllSessions is "sign out everywhere": every live refresh
// session for the user is revoked. Access JWTs already in the wild
// expire on their own (they are stateless by design — revocability is
// exactly what refresh sessions trade statelessness for).
// It is deliberately UNCHANGED by tenancy. The 7b-2 routing rule listed
// RevokeAllSessions among the methods that "use the *InTenant methods",
// but the only tenant-scoped revoke on the port is
// RevokeAllRefreshSessionsForTenant — and that is not the tenant-scoped
// form of this operation. The port's own naming says so: *InTenant
// narrows an existing lookup to a tenant, while ForTenant is the sibling
// of ForUser and names the SUBJECT of a bulk revoke. Routing this method
// onto it would silently turn one user's "log out everywhere" into
// signing out an entire customer. Blast radius is not a scope
// adjustment, so the tenant-wide operation gets its own name below.
func (c *Core) RevokeAllSessions(ctx context.Context, userID string) error {
	if userID == "" {
		return fmt.Errorf("identity: user id is required")
	}
	if err := c.store.RevokeAllRefreshSessionsForUser(ctx, userID, c.now()); err != nil {
		return fmt.Errorf("identity: revoke all sessions: %w", err)
	}
	return nil
}

// RevokeAllSessionsForTenant revokes every live session belonging to one
// tenant — the "we are locking this customer out" operation (a suspended
// account, a breach response, an offboarded organisation).
//
// It is NOT the tenant-scoped form of RevokeAllSessions, and the name
// says so: ForTenant names the subject, matching the port's
// RevokeAllRefreshSessionsForUser / ...ForTenant pair. Reaching for this
// when you meant a single user signs out every user that tenant has.
//
// An unset tenant denies: revoking "everything" is never what a caller
// who forgot to thread the tenant meant.
func (c *Core) RevokeAllSessionsForTenant(ctx context.Context, tenantID tenant.ID) error {
	if err := c.tenantGate(tenantID); err != nil {
		return err
	}
	if err := c.store.RevokeAllRefreshSessionsForTenant(ctx, tenantID, c.now()); err != nil {
		return fmt.Errorf("identity: revoke all sessions for tenant: %w", err)
	}
	return nil
}

// issueTokens mints an access JWT and (when refresh is enabled) a
// persisted refresh session. Non-positive authTime falls back to now,
// empty acr to the default — the legacy-shim shape.
//
// tenantID is stamped on the successor row verbatim and is never read
// or defaulted: an empty tenant means a single-tenant deployment, and
// substituting anything for it here would invent a tenant the caller
// did not name.
func (c *Core) issueTokens(ctx context.Context, userID string, tenantID tenant.ID, authTime int64, acr string) (Tokens, error) {
	if c.jwt == nil {
		return Tokens{}, ErrNoTokenService
	}
	if authTime <= 0 {
		authTime = c.now().Unix()
	}
	if acr == "" {
		acr = c.defaultACR
	}
	access, err := c.jwt.IssueAccess(userID, tenantID, authTime, acr)
	if err != nil {
		return Tokens{}, fmt.Errorf("identity: issue access token: %w", err)
	}
	if c.refreshTTL <= 0 {
		return Tokens{Access: access}, nil
	}
	refresh, err := crypto.NewRefreshToken()
	if err != nil {
		return Tokens{}, fmt.Errorf("identity: mint refresh token: %w", err)
	}
	hash, err := crypto.HashRefreshToken(refresh)
	if err != nil {
		return Tokens{}, fmt.Errorf("identity: hash refresh token: %w", err)
	}
	now := c.now()
	exp := now.Add(c.refreshTTL)
	if err := c.store.CreateRefreshSession(ctx, RefreshSession{
		ID:        c.newID(),
		UserID:    userID,
		TenantID:  tenantID.String(),
		TokenHash: hash,
		IssuedAt:  now,
		ExpiresAt: exp,
		AuthTime:  time.Unix(authTime, 0).UTC(),
		ACR:       acr,
	}); err != nil {
		return Tokens{}, fmt.Errorf("identity: persist refresh session: %w", err)
	}
	return Tokens{Access: access, Refresh: refresh, RefreshExpiresAt: exp}, nil
}

// NormaliseEmail lowercases + trims and applies the minimal structural
// check (single @, non-empty local part, dotted domain). Exported so
// application layers normalise identically before their own lookups.
func NormaliseEmail(raw string) (string, error) {
	e := strings.ToLower(strings.TrimSpace(raw))
	if e == "" {
		return "", fmt.Errorf("%w: email is required", ErrInvalidEmail)
	}
	at := strings.Index(e, "@")
	if at <= 0 || at == len(e)-1 || strings.Contains(e[at+1:], "@") || !strings.Contains(e[at+1:], ".") {
		return "", ErrInvalidEmail
	}
	return e, nil
}

func validatePassword(p string) error {
	if len(p) < MinPasswordLen || len(p) > MaxPasswordLen {
		return fmt.Errorf("%w: must be between %d and %d characters", ErrPasswordPolicy, MinPasswordLen, MaxPasswordLen)
	}
	return nil
}
