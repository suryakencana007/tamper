package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	tamper "github.com/suryakencana007/tamper"
	"github.com/suryakencana007/tamper/crypto"
	tamperespresso "github.com/suryakencana007/tamper/espresso"
	"github.com/suryakencana007/tamper/identity"
	"github.com/suryakencana007/tamper/tenant"
)

// pooledIdentity adapts *identity.Core to the transport's
// IdentityService port for EVERY tenant at once. One instance serves all
// the prefixes; the port hands each call the tenant the request was
// routed to (AuthRoutesConfig.Tenant), so there is no code path here
// that can forget a tenant, because there is no call that lacks one.
//
// The adapter is the second fence, not the first. On an authenticated
// route the first is espresso.RequireTenant, mounted in main.go, which
// refuses a token whose `tid` is not the routed tenant before any
// method here runs.
//
// The Core methods that take a tenant (Register, Login,
// IssueTokensForUser) get it passed through, and the Core checks it
// against the stored row itself. The ones keyed by a bare user id or a
// bare token (Me, Refresh, Logout, the TOTP verbs) are preceded by a
// check here that the user, or the session's user, is stored in that
// tenant. A mismatch is answered with the error a missing user gets:
// a deny and a miss must be indistinguishable.
type pooledIdentity struct {
	core  *identity.Core
	store *tenantStore
	// jwt mints and verifies the totp-pending token. It is the SAME
	// service the Core signs access tokens with (the Provider's), so the
	// ceremony token and the session it leads to share one key.
	jwt *crypto.JWTService
}

var _ tamperespresso.IdentityService = pooledIdentity{}

// newPooledIdentity binds the adapter to the shared Provider. A
// constructor rather than a struct literal at the mount site so that
// the wiring the routes get is the wiring the tests exercise: the JWT
// service is only reached on the TOTP leg, and a literal that forgot it
// would pass every other test and fail on the first 2FA login.
func newPooledIdentity(p *tamper.Provider, store *tenantStore) pooledIdentity {
	return pooledIdentity{core: p.Identity, store: store, jwt: p.JWT}
}

// userIn loads a user and refuses one that is not stored in tenantID
// with the same error a missing user gets.
func (p pooledIdentity) userIn(ctx context.Context, tenantID tenant.ID, userID string) (identity.User, error) {
	u, err := p.store.UserByID(ctx, userID)
	if err != nil {
		return identity.User{}, err
	}
	if tenant.FromStored(u.TenantID) != tenantID {
		// Spelled exactly as the store spells a missing user, so the two
		// cannot be told apart by their text either.
		return identity.User{}, fmt.Errorf("%w: user %s", identity.ErrNotFound, userID)
	}
	return u, nil
}

// sessionIn refuses a refresh token that does not name a session of
// tenantID, with ErrInvalidSession. It uses only public API — hash the
// presented token, read the row, compare — and reads only; the Core
// does the rotation or the revoke.
func (p pooledIdentity) sessionIn(ctx context.Context, tenantID tenant.ID, refreshToken string) error {
	hash, err := crypto.HashRefreshToken(refreshToken)
	if err != nil {
		return identity.ErrInvalidSession
	}
	s, err := p.store.RefreshSessionByHash(ctx, hash)
	if err != nil {
		// A missing row is an invalid session. Any other error is the
		// store's, and it is NOT an invalid session: a transient failure
		// must not sign the user out.
		if errors.Is(err, identity.ErrNotFound) {
			return identity.ErrInvalidSession
		}
		return err
	}
	if tenant.FromStored(s.TenantID) != tenantID {
		return identity.ErrInvalidSession
	}
	return nil
}

func (p pooledIdentity) Register(ctx context.Context, tenantID tenant.ID, email, password string) (tamperespresso.AuthResult, error) {
	u, tok, err := p.core.Register(ctx, tenantID, email, password)
	if err != nil {
		return tamperespresso.AuthResult{}, err
	}
	return tamperespresso.AuthResult{User: &u, Tokens: tok}, nil
}

func (p pooledIdentity) Login(ctx context.Context, tenantID tenant.ID, email, password string) (tamperespresso.AuthResult, error) {
	u, tok, err := p.core.Login(ctx, tenantID, email, password)
	if err != nil {
		if errors.Is(err, identity.ErrTOTPRequired) {
			return tamperespresso.AuthResult{User: &u}, err
		}
		return tamperespresso.AuthResult{}, err
	}
	return tamperespresso.AuthResult{User: &u, Tokens: tok}, nil
}

// Me checks the user's STORED tenant, although RequireTenant has already
// checked the token's `tid` on the route. The two checks read different
// facts: the gate compares the token with the route; this compares the
// user row with the routed tenant, and it is what still holds if a
// route is ever mounted without the gate.
func (p pooledIdentity) Me(ctx context.Context, tenantID tenant.ID, userID string) (*identity.User, error) {
	u, err := p.userIn(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// Refresh checks the session's tenant BEFORE rotating. Core.Refresh
// takes no tenant (rotation is keyed by the token hash), so without this
// an acme refresh token would rotate happily on a globex route. A
// wrong-tenant token and an unknown one look the same.
func (p pooledIdentity) Refresh(ctx context.Context, tenantID tenant.ID, refreshToken string) (tamperespresso.AuthResult, error) {
	if err := p.sessionIn(ctx, tenantID, refreshToken); err != nil {
		return tamperespresso.AuthResult{}, err
	}
	u, tok, err := p.core.Refresh(ctx, refreshToken)
	if err != nil {
		return tamperespresso.AuthResult{}, err
	}
	return tamperespresso.AuthResult{User: &u, Tokens: tok}, nil
}

// Logout is idempotent: a token of another tenant is treated like a
// stale one, and nothing happens.
func (p pooledIdentity) Logout(ctx context.Context, tenantID tenant.ID, refreshToken string) error {
	if err := p.sessionIn(ctx, tenantID, refreshToken); err != nil {
		if errors.Is(err, identity.ErrInvalidSession) {
			return nil
		}
		return err
	}
	return p.core.Logout(ctx, refreshToken)
}

// IssueTokensForUser is the mint at the end of the TOTP second leg. The
// tenant is checked against the user's STORED row twice over — here,
// and again inside Core.IssueTokensForUser. The comparison here stays
// even though the Core makes the same one: the row is loaded here
// regardless, the port returns the user, and an adapter that leans on a
// check it cannot see is one refactor away from having none.
func (p pooledIdentity) IssueTokensForUser(ctx context.Context, tenantID tenant.ID, userID string) (tamperespresso.AuthResult, error) {
	u, err := p.userIn(ctx, tenantID, userID)
	if err != nil {
		return tamperespresso.AuthResult{}, err
	}
	// The user cleared a password and a code just now: auth_time is now,
	// and the ACR is the one the Core stamps on a password login.
	tok, err := p.core.IssueTokensForUser(ctx, userID, tenantID, time.Now().Unix(), p.core.DefaultACR())
	if err != nil {
		return tamperespresso.AuthResult{}, err
	}
	return tamperespresso.AuthResult{User: &u, Tokens: tok}, nil
}

func (p pooledIdentity) VerifyTOTP(ctx context.Context, tenantID tenant.ID, userID, code string) error {
	if _, err := p.userIn(ctx, tenantID, userID); err != nil {
		return err
	}
	return p.core.VerifyTOTP(ctx, userID, code)
}

func (p pooledIdentity) VerifyRecoveryCode(ctx context.Context, tenantID tenant.ID, userID, code string) error {
	if _, err := p.userIn(ctx, tenantID, userID); err != nil {
		return err
	}
	return p.core.VerifyRecoveryCode(ctx, userID, code)
}

func (p pooledIdentity) EnrollTOTP(ctx context.Context, tenantID tenant.ID, userID string) (tamperespresso.TOTPEnrollment, error) {
	if _, err := p.userIn(ctx, tenantID, userID); err != nil {
		return tamperespresso.TOTPEnrollment{}, err
	}
	e, err := p.core.EnrollTOTP(ctx, userID)
	if err != nil {
		return tamperespresso.TOTPEnrollment{}, err
	}
	return tamperespresso.TOTPEnrollment{OTPAuthURI: e.OTPAuthURI, RecoveryCodes: e.RecoveryCodes}, nil
}

func (p pooledIdentity) DisableTOTP(ctx context.Context, tenantID tenant.ID, userID, code string) error {
	if _, err := p.userIn(ctx, tenantID, userID); err != nil {
		return err
	}
	return p.core.DisableTOTP(ctx, userID, code)
}

// IssueTOTPPending binds the pending token to the tenant the password
// step ran in. The routes call it straight after a Login in that
// tenant, and the `tid` claim records the fact in the one credential
// the second leg will present.
func (p pooledIdentity) IssueTOTPPending(_ context.Context, tenantID tenant.ID, userID string) (string, error) {
	return p.jwt.IssueTOTPPending(userID, tenantID)
}

// VerifyTOTPPending is where a pending token minted under another
// tenant's prefix is refused — before any code is checked and before
// anything is minted. The token must have been minted for exactly the
// routed tenant.
func (p pooledIdentity) VerifyTOTPPending(_ context.Context, tenantID tenant.ID, sessionToken string) (string, error) {
	return p.jwt.VerifyTOTPPending(sessionToken, tenantID)
}

var errNoSessionTOTP = errors.New("multitenant: session-token TOTP enrollment is app policy — not implemented in this example")

func (p pooledIdentity) EnrollTOTPViaSession(context.Context, tenant.ID, string, string) (*tamperespresso.TOTPEnrollment, *tamperespresso.AuthResult, error) {
	return nil, nil, errNoSessionTOTP
}
