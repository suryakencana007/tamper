package main

import (
	"context"
	"errors"

	tamperespresso "github.com/suryakencana007/tamper/espresso"
	"github.com/suryakencana007/tamper/identity"
)

// stubIdentity satisfies the transport's IdentityService port with a
// not-implemented sentinel on every method.
//
// Why it's here: tamper/espresso.Routes ALWAYS builds the core-auth surface,
// so even a SCIM-only app must supply an IdentityService + a valid
// AuthRoutesConfig to construct it. This example is about SCIM
// (machine-to-machine provisioning), not interactive login — so buildHandler
// builds the auth surface (to satisfy Routes) but never MOUNTS it: only the
// SCIM routes are registered, so /api/auth/* returns 404. These sentinels only
// surface if a caller wires surfaces.Auth up. A real app that also does
// interactive login plugs its own service in here (see examples/quickstart's
// coreIdentity adapter).
type stubIdentity struct{}

var _ tamperespresso.IdentityService = stubIdentity{}

var errNoInteractiveAuth = errors.New("scim example: interactive auth is not enabled (this app only does SCIM provisioning)")

func (stubIdentity) Register(context.Context, string, string) (tamperespresso.AuthResult, error) {
	return tamperespresso.AuthResult{}, errNoInteractiveAuth
}
func (stubIdentity) Login(context.Context, string, string) (tamperespresso.AuthResult, error) {
	return tamperespresso.AuthResult{}, errNoInteractiveAuth
}
func (stubIdentity) Me(context.Context, string) (*identity.User, error) {
	return nil, errNoInteractiveAuth
}
func (stubIdentity) Refresh(context.Context, string) (tamperespresso.AuthResult, error) {
	return tamperespresso.AuthResult{}, errNoInteractiveAuth
}
func (stubIdentity) Logout(context.Context, string) error { return errNoInteractiveAuth }
func (stubIdentity) IssueTOTPPending(string) (string, error) {
	return "", errNoInteractiveAuth
}
func (stubIdentity) VerifyTOTPPending(string) (string, error) {
	return "", errNoInteractiveAuth
}
func (stubIdentity) VerifyTOTP(context.Context, string, string) error { return errNoInteractiveAuth }
func (stubIdentity) VerifyRecoveryCode(context.Context, string, string) error {
	return errNoInteractiveAuth
}
func (stubIdentity) IssueTokensForUser(context.Context, string) (tamperespresso.AuthResult, error) {
	return tamperespresso.AuthResult{}, errNoInteractiveAuth
}
func (stubIdentity) EnrollTOTP(context.Context, string) (tamperespresso.TOTPEnrollment, error) {
	return tamperespresso.TOTPEnrollment{}, errNoInteractiveAuth
}
func (stubIdentity) DisableTOTP(context.Context, string, string) error { return errNoInteractiveAuth }
func (stubIdentity) EnrollTOTPViaSession(context.Context, string, string) (*tamperespresso.TOTPEnrollment, *tamperespresso.AuthResult, error) {
	return nil, nil, errNoInteractiveAuth
}
