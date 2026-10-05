package main

import (
	"context"
	"errors"

	tamper "github.com/suryakencana007/tamper"
	"github.com/suryakencana007/tamper/crypto"
	tamperespresso "github.com/suryakencana007/tamper/espresso"
	"github.com/suryakencana007/tamper/identity"
	"github.com/suryakencana007/tamper/tenant"
)

// tenantIdentity adapts *identity.Core to the transport's
// IdentityService port FOR ONE TENANT. One instance per tenant is
// mounted under that tenant's route prefix, so the tenant is bound at
// wiring time and every request under that prefix is scoped by
// construction.
//
// IdentityService's methods take (email, password) with no tenant, so
// the tenant rides on the ADAPTER rather than on the call. Closing over
// it is also the safer shape: there is no code path here that can
// forget to pass a tenant, because there is no path that passes one.
//
// The adapter is the second fence, not the first. On an authenticated
// route the first is espresso.RequireTenant, mounted in main.go, which
// refuses a token whose `tid` is not this tenant before any method here
// runs.
//
// It is deliberately NOT read from the request context. tamper's
// tenant.WithTenant documents why: an implicit tenant is a cross-tenant
// leak waiting for one missing middleware call, and it fails OPEN.
type tenantIdentity struct {
	core  *identity.Core
	store *tenantStore
	// jwt mints and verifies the totp-pending token. It is the SAME
	// service the Core signs access tokens with (the Provider's), so the
	// ceremony token and the session it leads to share one key.
	jwt      *crypto.JWTService
	tenantID string
}

var _ tamperespresso.IdentityService = tenantIdentity{}

// newTenantIdentity binds one tenant's adapter to the shared Provider.
// A constructor rather than a struct literal at the mount site so that
// the wiring the routes get is the wiring the tests exercise: the JWT
// service is only reached on the TOTP leg, and a literal that forgot it
// would pass every other test and fail on the first 2FA login.
func newTenantIdentity(p *tamper.Provider, store *tenantStore, tenantID string) tenantIdentity {
	return tenantIdentity{core: p.Identity, store: store, jwt: p.JWT, tenantID: tenantID}
}

func (t tenantIdentity) Register(ctx context.Context, email, password string) (tamperespresso.AuthResult, error) {
	u, tok, err := t.core.Register(ctx, tenant.New(t.tenantID), email, password)
	if err != nil {
		return tamperespresso.AuthResult{}, err
	}
	return tamperespresso.AuthResult{User: &u, Tokens: tok}, nil
}

func (t tenantIdentity) Login(ctx context.Context, email, password string) (tamperespresso.AuthResult, error) {
	u, tok, err := t.core.Login(ctx, tenant.New(t.tenantID), email, password)
	if err != nil {
		if errors.Is(err, identity.ErrTOTPRequired) {
			return tamperespresso.AuthResult{User: &u}, err
		}
		return tamperespresso.AuthResult{}, err
	}
	return tamperespresso.AuthResult{User: &u, Tokens: tok}, nil
}

// Me checks the user's STORED tenant, although RequireTenant has already
// checked the token's `tid` on the route.
//
// The two checks read different facts. The gate compares the token with
// the route. This compares the user row with the adapter's tenant, and
// it is what still holds if a route is ever mounted without the gate,
// or if a token and its user's row have come to disagree.
//
// The mismatch returns ErrNotFound, never a permission error. A deny and
// a miss must be indistinguishable, or the response tells the caller
// that a user it may not see exists.
func (t tenantIdentity) Me(ctx context.Context, userID string) (*identity.User, error) {
	u, err := t.store.UserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if u.TenantID != t.tenantID {
		return nil, identity.ErrNotFound
	}
	return &u, nil
}

// Refresh checks the session's tenant BEFORE rotating. Core.Refresh
// takes no tenant (rotation is keyed by the token hash), so without this
// an acme refresh token would rotate happily on a globex route. The
// check uses only public API — hash the presented token, read the row,
// compare — and it happens before any state changes, so a cross-tenant
// attempt neither rotates nor revokes.
func (t tenantIdentity) Refresh(ctx context.Context, refreshToken string) (tamperespresso.AuthResult, error) {
	if hash, err := crypto.HashRefreshToken(refreshToken); err == nil {
		if s, err := t.store.RefreshSessionByHash(ctx, hash); err == nil && s.TenantID != t.tenantID {
			// Collapsed onto the ordinary invalid-session rejection: a
			// wrong-tenant token and an unknown one look the same.
			return tamperespresso.AuthResult{}, identity.ErrInvalidSession
		}
	}
	u, tok, err := t.core.Refresh(ctx, refreshToken)
	if err != nil {
		return tamperespresso.AuthResult{}, err
	}
	return tamperespresso.AuthResult{User: &u, Tokens: tok}, nil
}

func (t tenantIdentity) Logout(ctx context.Context, refreshToken string) error {
	return t.core.Logout(ctx, refreshToken)
}

// IssueTokensForUser is the mint at the end of the TOTP second leg, and
// the port hands it nothing but a user id. The tenant therefore comes
// from the adapter, and it is checked against the user's STORED row
// twice over — here, and again inside IssueTokensForUserInTenant.
//
// It mints through the InTenant entry point, not Core.IssueTokensForUser.
// That shim mints for tenant.Single: the token would carry no `tid`, and
// a user who had just cleared 2FA would hold a session that every
// tenant-pinned verifier refuses.
//
// The comparison below stays even though the Core now makes the same
// one. The row is loaded here regardless — the port returns the user —
// and an adapter that leans on a check it cannot see is one refactor
// away from having none.
func (t tenantIdentity) IssueTokensForUser(ctx context.Context, userID string) (tamperespresso.AuthResult, error) {
	u, err := t.store.UserByID(ctx, userID)
	if err != nil {
		return tamperespresso.AuthResult{}, err
	}
	if u.TenantID != t.tenantID {
		return tamperespresso.AuthResult{}, identity.ErrNotFound
	}
	// authTime 0 and acr "" are the shim's own arguments: fresh auth_time,
	// the Core's default ACR.
	tok, err := t.core.IssueTokensForUserInTenant(ctx, userID, tenant.New(t.tenantID), 0, "")
	if err != nil {
		return tamperespresso.AuthResult{}, err
	}
	return tamperespresso.AuthResult{User: &u, Tokens: tok}, nil
}

func (t tenantIdentity) VerifyTOTP(ctx context.Context, userID, code string) error {
	return t.core.VerifyTOTP(ctx, userID, code)
}

func (t tenantIdentity) VerifyRecoveryCode(ctx context.Context, userID, code string) error {
	return t.core.VerifyRecoveryCode(ctx, userID, code)
}

func (t tenantIdentity) EnrollTOTP(ctx context.Context, userID string) (tamperespresso.TOTPEnrollment, error) {
	e, err := t.core.EnrollTOTP(ctx, userID)
	if err != nil {
		return tamperespresso.TOTPEnrollment{}, err
	}
	return tamperespresso.TOTPEnrollment{OTPAuthURI: e.OTPAuthURI, RecoveryCodes: e.RecoveryCodes}, nil
}

func (t tenantIdentity) DisableTOTP(ctx context.Context, userID, code string) error {
	return t.core.DisableTOTP(ctx, userID, code)
}

// IssueTOTPPending binds the pending token to THIS tenant. The routes
// call it straight after a Login that already ran in this tenant, so the
// user id it is handed belongs here; the `tid` claim records that fact
// in the one credential the second leg will present.
func (t tenantIdentity) IssueTOTPPending(userID string) (string, error) {
	return t.jwt.IssueTOTPPending(userID, tenant.New(t.tenantID))
}

// VerifyTOTPPending is where a pending token minted under another
// tenant's prefix is refused — before any code is checked and before
// anything is minted. The port hands this method no tenant, so the
// adapter names its own: the token must have been minted for exactly
// this tenant.
func (t tenantIdentity) VerifyTOTPPending(sessionToken string) (string, error) {
	return t.jwt.VerifyTOTPPending(sessionToken, tenant.New(t.tenantID))
}

var errNoSessionTOTP = errors.New("multitenant: session-token TOTP enrollment is app policy — not implemented in this example")

func (t tenantIdentity) EnrollTOTPViaSession(context.Context, string, string) (*tamperespresso.TOTPEnrollment, *tamperespresso.AuthResult, error) {
	return nil, nil, errNoSessionTOTP
}
