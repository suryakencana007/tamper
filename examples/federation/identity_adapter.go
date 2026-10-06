package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/suryakencana007/tamper/crypto"
	tamperespresso "github.com/suryakencana007/tamper/espresso"
	"github.com/suryakencana007/tamper/identity"
	"github.com/suryakencana007/tamper/tenant"
)

// coreIdentity adapts *identity.Core to the transport's IdentityService port.
// It is the same adapter as examples/quickstart (examples don't share code).
//
// Every port method is handed the tenant the request was routed to. The
// Core methods that take a tenant (Register, Login, IssueTokensForUser)
// get it passed through. The ones keyed by a bare user id or a bare
// token (Me, Refresh, Logout, the TOTP verbs) are preceded by a check
// that the user — or the session's user — is stored in that tenant, and
// a mismatch is answered with the error a missing user gets. This
// example is single-tenant and the tenant is always tenant.Single, but
// the adapter is written the way a pooled one is, because that is the
// shape the port asks for.
//
// The session-token TOTP ceremony is app policy with no Core primitive,
// so this minimal example stubs it out — those methods are never reached
// unless TOTP is required.
type coreIdentity struct {
	core  *identity.Core
	store identity.Store
}

var _ tamperespresso.IdentityService = coreIdentity{}

// userIn loads a user and refuses one that is not stored in tenantID
// with the same error a missing user gets. A deny and a miss must be
// indistinguishable.
func (c coreIdentity) userIn(ctx context.Context, tenantID tenant.ID, userID string) (identity.User, error) {
	u, err := c.store.UserByID(ctx, userID)
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

// sessionIn reports whether the refresh token names a live session of
// tenantID. It reads only; the Core does the rotation or the revoke.
func (c coreIdentity) sessionIn(ctx context.Context, tenantID tenant.ID, refreshToken string) bool {
	hash, err := crypto.HashRefreshToken(refreshToken)
	if err != nil {
		return false
	}
	s, err := c.store.RefreshSessionByHash(ctx, hash)
	return err == nil && tenant.FromStored(s.TenantID) == tenantID
}

func (c coreIdentity) Register(ctx context.Context, tenantID tenant.ID, email, password string) (tamperespresso.AuthResult, error) {
	u, t, err := c.core.Register(ctx, tenantID, email, password)
	if err != nil {
		return tamperespresso.AuthResult{}, err
	}
	return tamperespresso.AuthResult{User: &u, Tokens: t}, nil
}

func (c coreIdentity) Login(ctx context.Context, tenantID tenant.ID, email, password string) (tamperespresso.AuthResult, error) {
	u, t, err := c.core.Login(ctx, tenantID, email, password)
	if err != nil {
		// On ErrTOTPRequired the Core returns the user (so the routes can render
		// the verify form) but no tokens — carry the user through with the error.
		if errors.Is(err, identity.ErrTOTPRequired) {
			return tamperespresso.AuthResult{User: &u}, err
		}
		return tamperespresso.AuthResult{}, err
	}
	return tamperespresso.AuthResult{User: &u, Tokens: t}, nil
}

func (c coreIdentity) Me(ctx context.Context, tenantID tenant.ID, userID string) (*identity.User, error) {
	u, err := c.userIn(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (c coreIdentity) Refresh(ctx context.Context, tenantID tenant.ID, refreshToken string) (tamperespresso.AuthResult, error) {
	// A token of another tenant is refused as an unknown one, before
	// anything rotates or is revoked.
	if !c.sessionIn(ctx, tenantID, refreshToken) {
		return tamperespresso.AuthResult{}, identity.ErrInvalidSession
	}
	u, t, err := c.core.Refresh(ctx, refreshToken)
	if err != nil {
		return tamperespresso.AuthResult{}, err
	}
	return tamperespresso.AuthResult{User: &u, Tokens: t}, nil
}

func (c coreIdentity) Logout(ctx context.Context, tenantID tenant.ID, refreshToken string) error {
	// Logout is idempotent: a token of another tenant is treated like a
	// stale one and nothing happens.
	if !c.sessionIn(ctx, tenantID, refreshToken) {
		return nil
	}
	return c.core.Logout(ctx, refreshToken)
}

func (c coreIdentity) IssueTokensForUser(ctx context.Context, tenantID tenant.ID, userID string) (tamperespresso.AuthResult, error) {
	// This is the TOTP second leg: the user authenticated with a password
	// and a code just now, so the auth_time is now and the ACR is the one
	// the Core stamps on a password login, so the two local logins agree.
	// The Core checks the tenant again itself.
	u, err := c.userIn(ctx, tenantID, userID)
	if err != nil {
		return tamperespresso.AuthResult{}, err
	}
	t, err := c.core.IssueTokensForUser(ctx, userID, tenantID, time.Now().Unix(), c.core.DefaultACR())
	if err != nil {
		return tamperespresso.AuthResult{}, err
	}
	return tamperespresso.AuthResult{User: &u, Tokens: t}, nil
}

func (c coreIdentity) VerifyTOTP(ctx context.Context, tenantID tenant.ID, userID, code string) error {
	if _, err := c.userIn(ctx, tenantID, userID); err != nil {
		return err
	}
	return c.core.VerifyTOTP(ctx, userID, code)
}

func (c coreIdentity) VerifyRecoveryCode(ctx context.Context, tenantID tenant.ID, userID, code string) error {
	if _, err := c.userIn(ctx, tenantID, userID); err != nil {
		return err
	}
	return c.core.VerifyRecoveryCode(ctx, userID, code)
}

func (c coreIdentity) EnrollTOTP(ctx context.Context, tenantID tenant.ID, userID string) (tamperespresso.TOTPEnrollment, error) {
	if _, err := c.userIn(ctx, tenantID, userID); err != nil {
		return tamperespresso.TOTPEnrollment{}, err
	}
	e, err := c.core.EnrollTOTP(ctx, userID)
	if err != nil {
		return tamperespresso.TOTPEnrollment{}, err
	}
	return tamperespresso.TOTPEnrollment{OTPAuthURI: e.OTPAuthURI, RecoveryCodes: e.RecoveryCodes}, nil
}

func (c coreIdentity) DisableTOTP(ctx context.Context, tenantID tenant.ID, userID, code string) error {
	if _, err := c.userIn(ctx, tenantID, userID); err != nil {
		return err
	}
	return c.core.DisableTOTP(ctx, userID, code)
}

// The session-token two-phase TOTP ceremony is app policy (the token shape +
// TTL are the app's), with no identity.Core primitive. This example does
// not enable TOTP, so these are never reached; a real app implements them
// (e.g. minting a short-lived pending JWT with the Provider's JWT service).
var errNoSessionTOTP = errors.New("session-token TOTP is app policy — not implemented in this example")

func (c coreIdentity) IssueTOTPPending(context.Context, tenant.ID, string) (string, error) {
	return "", errNoSessionTOTP
}
func (c coreIdentity) VerifyTOTPPending(context.Context, tenant.ID, string) (string, error) {
	return "", errNoSessionTOTP
}
func (c coreIdentity) EnrollTOTPViaSession(context.Context, tenant.ID, string, string) (*tamperespresso.TOTPEnrollment, *tamperespresso.AuthResult, error) {
	return nil, nil, errNoSessionTOTP
}
