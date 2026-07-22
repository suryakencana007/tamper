package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/suryakencana007/tamper/crypto"
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
	store        Store
	jwt          *crypto.JWTService // nil = token-less instance; mint flows error
	keys         *crypto.KeySet     // nil = TOTP envelope flows error (ErrNoKeySet)
	refreshTTL   time.Duration      // 0 disables refresh sessions entirely
	totpRequired bool
	defaultACR   string
	hooks        Hooks
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
	return c, nil
}

// RefreshTTL exposes the configured session lifetime so transport
// layers can align cookie Max-Age with the row expiry.
func (c *Core) RefreshTTL() time.Duration { return c.refreshTTL }

// Register creates a user from an email + password and mints the first
// session. The email is normalised (lowercased, trimmed, shape-checked);
// duplicates return ErrEmailTaken. The firstUser bootstrap signal and
// the OnRegistered hook are documented on Store and Hooks.
func (c *Core) Register(ctx context.Context, email, password string) (User, Tokens, error) {
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

	count, err := c.store.CountUsers(ctx)
	if err != nil {
		return User{}, Tokens{}, fmt.Errorf("identity: count users: %w", err)
	}
	first := count == 0

	u := NewUser{
		ID:           c.newID(),
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
		Email:        u.Email,
		PasswordHash: u.PasswordHash,
		Active:       true,
		CreatedAt:    u.CreatedAt,
	}

	if c.hooks.OnRegistered != nil {
		c.hooks.OnRegistered(ctx, user, first)
	}

	tokens, err := c.issueTokens(ctx, user.ID, c.now().Unix(), c.defaultACR)
	if err != nil {
		return User{}, Tokens{}, err
	}
	return user, tokens, nil
}

// Login authenticates an email + password. Every failure mode —
// unknown email, malformed email, federated-only account (empty hash),
// deactivated account, wrong password — collapses to
// ErrInvalidCredentials, and the non-verify paths burn a stub bcrypt
// comparison so rejections are timing-indistinguishable from a wrong
// password (Barista TD-SEC-01).
//
// When the user is TOTP-enrolled (or system-wide enforcement is on),
// Login returns (user, zero Tokens, ErrTOTPRequired): password stands,
// but the caller must complete the TOTP step before minting tokens.
func (c *Core) Login(ctx context.Context, email, password string) (User, Tokens, error) {
	normalised, err := NormaliseEmail(email)
	if err != nil {
		_ = crypto.VerifyStub(password)
		return User{}, Tokens{}, ErrInvalidCredentials
	}
	user, err := c.store.UserByEmail(ctx, normalised)
	if err != nil {
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

	tokens, err := c.issueTokens(ctx, user.ID, c.now().Unix(), c.defaultACR)
	if err != nil {
		return User{}, Tokens{}, err
	}
	return user, tokens, nil
}

// IssueTokensForUser mints a session with fresh auth_time and the
// default ACR — the post-TOTP-verify and shim path.
func (c *Core) IssueTokensForUser(ctx context.Context, userID string) (Tokens, error) {
	return c.issueTokens(ctx, userID, 0, "")
}

// IssueTokensForUserWithACR mints a session carrying explicit step-up
// claims (federated logins thread their own auth_time + ACR through).
// Non-positive authTime falls back to now; empty acr to the default.
func (c *Core) IssueTokensForUserWithACR(ctx context.Context, userID string, authTime int64, acr string) (Tokens, error) {
	return c.issueTokens(ctx, userID, authTime, acr)
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
	tokens, err := c.issueTokens(ctx, session.UserID, carryAuthTime, session.ACR)
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
func (c *Core) RevokeAllSessions(ctx context.Context, userID string) error {
	if userID == "" {
		return fmt.Errorf("identity: user id is required")
	}
	if err := c.store.RevokeAllRefreshSessionsForUser(ctx, userID, c.now()); err != nil {
		return fmt.Errorf("identity: revoke all sessions: %w", err)
	}
	return nil
}

// issueTokens mints an access JWT and (when refresh is enabled) a
// persisted refresh session. Non-positive authTime falls back to now,
// empty acr to the default — the legacy-shim shape.
func (c *Core) issueTokens(ctx context.Context, userID string, authTime int64, acr string) (Tokens, error) {
	if c.jwt == nil {
		return Tokens{}, ErrNoTokenService
	}
	if authTime <= 0 {
		authTime = c.now().Unix()
	}
	if acr == "" {
		acr = c.defaultACR
	}
	access, err := c.jwt.IssueAccess(userID, authTime, acr)
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
