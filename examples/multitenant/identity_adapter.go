package main

import (
	"context"
	"errors"

	"github.com/suryakencana007/tamper/crypto"
	tamperespresso "github.com/suryakencana007/tamper/espresso"
	"github.com/suryakencana007/tamper/identity"
)

// tenantIdentity adapts *identity.Core to the transport's
// IdentityService port FOR ONE TENANT. One instance per tenant is
// mounted under that tenant's route prefix, so the tenant is bound at
// wiring time and every request under that prefix is scoped by
// construction.
//
// This is how an app carries a tenant today. IdentityService's methods
// take (email, password) with no tenant — the transport has no tenant
// concept until espresso.RequireTenant lands in 7c-2 — so the tenant
// rides on the ADAPTER rather than on the call. Closing over it is also
// the safer shape: there is no code path here that can forget to pass a
// tenant, because there is no path that passes one.
//
// It is deliberately NOT read from the request context. tamper's
// tenant.WithTenant documents why: an implicit tenant is a cross-tenant
// leak waiting for one missing middleware call, and it fails OPEN.
type tenantIdentity struct {
	core     *identity.Core
	store    *tenantStore
	tenantID string
}

var _ tamperespresso.IdentityService = tenantIdentity{}

func (t tenantIdentity) Register(ctx context.Context, email, password string) (tamperespresso.AuthResult, error) {
	u, tok, err := t.core.RegisterInTenant(ctx, t.tenantID, email, password)
	if err != nil {
		return tamperespresso.AuthResult{}, err
	}
	return tamperespresso.AuthResult{User: &u, Tokens: tok}, nil
}

func (t tenantIdentity) Login(ctx context.Context, email, password string) (tamperespresso.AuthResult, error) {
	u, tok, err := t.core.LoginInTenant(ctx, t.tenantID, email, password)
	if err != nil {
		if errors.Is(err, identity.ErrTOTPRequired) {
			return tamperespresso.AuthResult{User: &u}, err
		}
		return tamperespresso.AuthResult{}, err
	}
	return tamperespresso.AuthResult{User: &u, Tokens: tok}, nil
}

// Me is where a cross-tenant access token is rejected, and it is worth
// being precise about why it lives here.
//
// The access token carries no tenant yet — the `tid` claim is 7c-1 and
// VerifyAccessInTenant is 7c-2 — so RequireAuth validates the signature
// and hands over a user id that is genuine but says nothing about which
// tenant the request was routed to. The app closes that gap with the
// fact tamper DOES carry: identity.User.TenantID, populated since 7b-1.
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

func (t tenantIdentity) IssueTokensForUser(ctx context.Context, userID string) (tamperespresso.AuthResult, error) {
	u, err := t.store.UserByID(ctx, userID)
	if err != nil {
		return tamperespresso.AuthResult{}, err
	}
	if u.TenantID != t.tenantID {
		return tamperespresso.AuthResult{}, identity.ErrNotFound
	}
	tok, err := t.core.IssueTokensForUser(ctx, userID)
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

var errNoSessionTOTP = errors.New("multitenant: session-token TOTP is app policy — not implemented in this example")

func (t tenantIdentity) IssueTOTPPending(string) (string, error)  { return "", errNoSessionTOTP }
func (t tenantIdentity) VerifyTOTPPending(string) (string, error) { return "", errNoSessionTOTP }
func (t tenantIdentity) EnrollTOTPViaSession(context.Context, string, string) (*tamperespresso.TOTPEnrollment, *tamperespresso.AuthResult, error) {
	return nil, nil, errNoSessionTOTP
}
