package main

import (
	"context"
	"errors"
	"github.com/suryakencana007/tamper/crypto"
	"time"

	tamperespresso "github.com/suryakencana007/tamper/espresso"
	"github.com/suryakencana007/tamper/identity"
	"github.com/suryakencana007/tamper/tenant"
)

// coreIdentity adapts *identity.Core to the transport's IdentityService port.
// It is copied verbatim from examples/quickstart (examples don't share code):
// the five core-auth methods delegate to the Core (mapping its
// (User, Tokens, error) returns onto AuthResult); Me reads the store directly
// (the Core exposes no user-by-id lookup); the session-token TOTP ceremony is
// app policy with no Core primitive, so this example stubs it out — those
// methods are never reached unless TOTP is required.
type coreIdentity struct {
	core  *identity.Core
	store identity.Store
}

var _ tamperespresso.IdentityService = coreIdentity{}

func (c coreIdentity) Register(ctx context.Context, email, password string) (tamperespresso.AuthResult, error) {
	u, t, err := c.core.Register(ctx, tenant.Single, email, password)
	if err != nil {
		return tamperespresso.AuthResult{}, err
	}
	return tamperespresso.AuthResult{User: &u, Tokens: t}, nil
}

func (c coreIdentity) Login(ctx context.Context, email, password string) (tamperespresso.AuthResult, error) {
	u, t, err := c.core.Login(ctx, tenant.Single, email, password)
	if err != nil {
		if errors.Is(err, identity.ErrTOTPRequired) {
			return tamperespresso.AuthResult{User: &u}, err
		}
		return tamperespresso.AuthResult{}, err
	}
	return tamperespresso.AuthResult{User: &u, Tokens: t}, nil
}

func (c coreIdentity) Me(ctx context.Context, userID string) (*identity.User, error) {
	u, err := c.store.UserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (c coreIdentity) Refresh(ctx context.Context, refreshToken string) (tamperespresso.AuthResult, error) {
	u, t, err := c.core.Refresh(ctx, refreshToken)
	if err != nil {
		return tamperespresso.AuthResult{}, err
	}
	return tamperespresso.AuthResult{User: &u, Tokens: t}, nil
}

func (c coreIdentity) Logout(ctx context.Context, refreshToken string) error {
	return c.core.Logout(ctx, refreshToken)
}

func (c coreIdentity) IssueTokensForUser(ctx context.Context, userID string) (tamperespresso.AuthResult, error) {
	// The port returns the user, so the row is loaded here; the Core
	// loads it again for its own check. This is the TOTP second leg: the
	// user authenticated with a password and a code just now, so the
	// auth_time is now and the ACR is the local-password one.
	u, err := c.store.UserByID(ctx, userID)
	if err != nil {
		return tamperespresso.AuthResult{}, err
	}
	t, err := c.core.IssueTokensForUser(ctx, userID, tenant.Single, time.Now().Unix(), crypto.ACRLocalPassword)
	if err != nil {
		return tamperespresso.AuthResult{}, err
	}
	return tamperespresso.AuthResult{User: &u, Tokens: t}, nil
}

func (c coreIdentity) VerifyTOTP(ctx context.Context, userID, code string) error {
	return c.core.VerifyTOTP(ctx, userID, code)
}

func (c coreIdentity) VerifyRecoveryCode(ctx context.Context, userID, code string) error {
	return c.core.VerifyRecoveryCode(ctx, userID, code)
}

func (c coreIdentity) EnrollTOTP(ctx context.Context, userID string) (tamperespresso.TOTPEnrollment, error) {
	e, err := c.core.EnrollTOTP(ctx, userID)
	if err != nil {
		return tamperespresso.TOTPEnrollment{}, err
	}
	return tamperespresso.TOTPEnrollment{OTPAuthURI: e.OTPAuthURI, RecoveryCodes: e.RecoveryCodes}, nil
}

func (c coreIdentity) DisableTOTP(ctx context.Context, userID, code string) error {
	return c.core.DisableTOTP(ctx, userID, code)
}

var errNoSessionTOTP = errors.New("federation example: session-token TOTP is app policy — not implemented here")

func (c coreIdentity) IssueTOTPPending(string) (string, error)  { return "", errNoSessionTOTP }
func (c coreIdentity) VerifyTOTPPending(string) (string, error) { return "", errNoSessionTOTP }
func (c coreIdentity) EnrollTOTPViaSession(context.Context, string, string) (*tamperespresso.TOTPEnrollment, *tamperespresso.AuthResult, error) {
	return nil, nil, errNoSessionTOTP
}
