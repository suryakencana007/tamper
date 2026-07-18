package espresso

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	espressofw "github.com/suryakencana007/espresso/v2"

	"github.com/suryakencana007/barista/packages/tamper/identity"
)

// AuthResult bundles the authenticated user with the minted tokens.
type AuthResult struct {
	User   *identity.User
	Tokens identity.Tokens
}

// TOTPEnrollment is the enrollment material handed to the caller once
// (QR URI + plaintext recovery codes).
type TOTPEnrollment struct {
	OTPAuthURI    string
	RecoveryCodes []string
}

// IdentityService is the port the mounted auth routes drive. Apps
// satisfy it with their auth service (the method set mirrors the
// proving app's almost 1:1); greenfield consumers can wrap
// identity.Core. Implementations return identity.Err* sentinels — the
// wire mapping keys on them.
//
// Login returns (result-with-User, identity.ErrTOTPRequired) when the
// password cleared but a second factor is pending: the routes mint a
// session token for the two-phase flow and the user payload renders
// the verify form. TOTP-pending session tokens are owned BEHIND this
// port (mint + verify both) — one owner for the ceremony token.
type IdentityService interface {
	Register(ctx context.Context, email, password string) (AuthResult, error)
	Login(ctx context.Context, email, password string) (AuthResult, error)
	Me(ctx context.Context, userID string) (*identity.User, error)
	Refresh(ctx context.Context, refreshToken string) (AuthResult, error)
	Logout(ctx context.Context, refreshToken string) error

	IssueTOTPPending(userID string) (string, error)
	VerifyTOTPPending(sessionToken string) (userID string, err error)
	VerifyTOTP(ctx context.Context, userID, code string) error
	VerifyRecoveryCode(ctx context.Context, userID, code string) error
	IssueTokensForUser(ctx context.Context, userID string) (AuthResult, error)
	EnrollTOTP(ctx context.Context, userID string) (TOTPEnrollment, error)
	DisableTOTP(ctx context.Context, userID, code string) error
	// EnrollTOTPViaSession is the two-phase session-token enrollment:
	// phase 1 (empty currentCode) returns the enrollment material;
	// phase 2 returns the minted AuthResult.
	EnrollTOTPViaSession(ctx context.Context, sessionToken, currentCode string) (*TOTPEnrollment, *AuthResult, error)
}

// CookieConfig carries the app's refresh-cookie branding. The cookie
// Path is NOT here — it derives from the mount prefix by
// construction (the CSRF fence cannot be misconfigured); HttpOnly and
// SameSite=Lax are non-configurable invariants.
type CookieConfig struct {
	// Name is the refresh cookie's name (the app's brand). Required.
	Name string
	// Secure marks the cookie HTTPS-only (production).
	Secure bool
	// MaxAgeSeconds is the cookie lifetime; zero omits Max-Age
	// (session cookie) matching a zero refresh TTL.
	MaxAgeSeconds int
}

// AuthRoutesConfig wires the app-policy seams for the mounted routes.
type AuthRoutesConfig struct {
	// MountPrefix is the route prefix ("/api/auth"). The refresh
	// cookie's Path IS this value. Required, must start with "/".
	MountPrefix string
	// Cookies is the refresh-cookie branding. Name required.
	Cookies CookieConfig
	// ProjectUser renders the app's user payload for the AuthRes
	// envelope. Called with nil on empty-body branches (the
	// USER_INACTIVE 401 shape) — return the app's zero-value
	// projection there for byte parity. Required.
	ProjectUser func(ctx context.Context, user *identity.User) json.RawMessage
	// ValidationMessage projects a client-safe message from a
	// validation error. Optional; the default never leaks error text.
	ValidationMessage func(error) string
	// OnAuthenticated fires when a login flow COMPLETES (password
	// login, TOTP verify, session-enroll phase 2) with the user id —
	// the audit capture-slot backfill. Optional; defaults to
	// SetUserID.
	OnAuthenticated func(ctx context.Context, userID string)
	// OnTOTPEnrolledViaSession fires after a successful enroll-session
	// phase 2, BEFORE the response ships — the app emits its own audit
	// vocabulary here. Optional.
	OnTOTPEnrolledViaSession func(ctx context.Context, userID string)
}

// AuthRoutes is the core-auth surface: register / login / me / refresh
// / logout / the TOTP ceremony routes. Construct with NewAuthRoutes,
// then let the APP register the methods on its own router.
//
// There is deliberately no Mount. This surface spans both the public
// block (register/login/refresh/logout) and the authed block
// (me/totp/*), and Espresso's Router has no sub-router while Use is
// positional — Get/Post snapshot the middleware stack at registration
// — so a single Mount would have to register both blocks at one
// middleware position. Handing registration back to the app also keeps
// the auth boundary legible at the call site and leaves route paths,
// which are app wire surface, app owned. FederationRoutes follows the
// same shape; see PHASE4D-BOUNDARY-DECISION.md §A10.
type AuthRoutes struct {
	svc IdentityService
	cfg AuthRoutesConfig
}

// NewAuthRoutes validates the config (fail at wiring time, never at
// request time).
func NewAuthRoutes(svc IdentityService, cfg AuthRoutesConfig) (*AuthRoutes, error) {
	if svc == nil {
		return nil, errors.New("tamper/espresso: auth routes require an IdentityService")
	}
	if !strings.HasPrefix(cfg.MountPrefix, "/") || strings.HasSuffix(cfg.MountPrefix, "/") {
		return nil, errors.New(`tamper/espresso: MountPrefix must start with "/" and not end with one`)
	}
	if cfg.Cookies.Name == "" {
		return nil, errors.New("tamper/espresso: refresh cookie name is required (the app's brand)")
	}
	if cfg.ProjectUser == nil {
		return nil, errors.New("tamper/espresso: ProjectUser hook is required")
	}
	if cfg.ValidationMessage == nil {
		cfg.ValidationMessage = defaultValidationMessage
	}
	if cfg.OnAuthenticated == nil {
		cfg.OnAuthenticated = SetUserID
	}
	return &AuthRoutes{svc: svc, cfg: cfg}, nil
}

// refreshCookieSlotName is the context slot the mounted refresh /
// logout routes read the cookie through (via ReadNamedCookie).
const refreshCookieSlotName = "tamper_refresh"

// refreshCookies returns the Set-Cookie list for a successful auth
// response; empty when refresh issuance is disabled so no stray
// cookie ships. Path == MountPrefix by construction.
func (a *AuthRoutes) refreshCookies(tokens identity.Tokens) []*http.Cookie {
	if tokens.Refresh == "" {
		return nil
	}
	return []*http.Cookie{{
		Name:     a.cfg.Cookies.Name,
		Value:    tokens.Refresh,
		Path:     a.cfg.MountPrefix,
		HttpOnly: true,
		Secure:   a.cfg.Cookies.Secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   a.cfg.Cookies.MaxAgeSeconds,
	}}
}

// clearRefreshCookie instructs the browser to drop the refresh
// cookie: MaxAge=-1 + empty value with attribute parity (some
// browsers refuse the overwrite otherwise).
func (a *AuthRoutes) clearRefreshCookie() *http.Cookie {
	return &http.Cookie{
		Name:     a.cfg.Cookies.Name,
		Value:    "",
		Path:     a.cfg.MountPrefix,
		HttpOnly: true,
		Secure:   a.cfg.Cookies.Secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	}
}

// ReadRefreshCookie is the middleware the app mounts on the refresh +
// logout routes (or the whole auth group) so the handlers can read
// the cookie through the context slot.
func (a *AuthRoutes) ReadRefreshCookie() func(http.Handler) http.Handler {
	return ReadNamedCookie(refreshCookieSlotName, a.cfg.Cookies.Name)
}

// authRes assembles the standard success envelope.
func (a *AuthRoutes) authRes(ctx context.Context, status int, res AuthResult) espressofw.JSON[AuthRes] {
	return espressofw.JSON[AuthRes]{
		StatusCode: status,
		Data:       AuthRes{Token: res.Tokens.Access, User: a.cfg.ProjectUser(ctx, res.User)},
		Cookies:    a.refreshCookies(res.Tokens),
	}
}

// Register handles POST {prefix}/register: 201 + refresh cookie, 409
// EMAIL_TAKEN on duplicates, 400 VALIDATION_ERROR on bad input.
func (a *AuthRoutes) Register(ctx context.Context, req *espressofw.JSON[RegisterReq]) (espressofw.JSON[AuthRes], error) {
	res, err := a.svc.Register(ctx, req.Data.Email, req.Data.Password)
	if err != nil {
		return espressofw.JSON[AuthRes]{}, mapAuthWireError(err, a.cfg.ValidationMessage)
	}
	return a.authRes(ctx, http.StatusCreated, res), nil
}

// Login handles POST {prefix}/login. On identity.ErrTOTPRequired the
// response is 200 with totp_required + a session token and NO refresh
// cookie — the cookie is minted only after the second factor lands.
func (a *AuthRoutes) Login(ctx context.Context, req *espressofw.JSON[LoginReq]) (espressofw.JSON[AuthRes], error) {
	res, err := a.svc.Login(ctx, req.Data.Email, req.Data.Password)
	if err != nil {
		if errors.Is(err, identity.ErrTOTPRequired) && res.User != nil {
			sessionTok, mintErr := a.svc.IssueTOTPPending(res.User.ID)
			if mintErr != nil {
				return espressofw.JSON[AuthRes]{}, espressofw.ErrInternal("internal error").Wrap(mintErr)
			}
			return espressofw.JSON[AuthRes]{
				StatusCode: http.StatusOK,
				Data: AuthRes{
					User:         a.cfg.ProjectUser(ctx, res.User),
					TOTPRequired: true,
					SessionToken: sessionTok,
				},
			}, nil
		}
		return espressofw.JSON[AuthRes]{}, mapAuthWireError(err, a.cfg.ValidationMessage)
	}
	a.cfg.OnAuthenticated(ctx, res.User.ID)
	return a.authRes(ctx, http.StatusOK, res), nil
}

// Me handles GET {prefix}/me behind RequireAuth. A valid token whose
// user row is gone reads as unauthenticated.
func (a *AuthRoutes) Me(ctx context.Context) (espressofw.JSON[json.RawMessage], error) {
	userID := MustGetUserID(ctx)
	user, err := a.svc.Me(ctx, userID)
	if err != nil {
		if errors.Is(err, identity.ErrNotFound) {
			return espressofw.JSON[json.RawMessage]{},
				espressofw.ErrUnauthorized("invalid token").WithCode("UNAUTHENTICATED")
		}
		return espressofw.JSON[json.RawMessage]{}, espressofw.ErrInternal("internal error").Wrap(err)
	}
	return espressofw.JSON[json.RawMessage]{
		StatusCode: http.StatusOK,
		Data:       a.cfg.ProjectUser(ctx, user),
	}, nil
}

// VerifyTOTP handles POST {prefix}/totp/verify — the second login
// leg. Codes of exactly 6 digits verify as TOTP; anything else as a
// recovery code; both failure paths surface INVALID_TOTP so the UX
// stays uniform.
func (a *AuthRoutes) VerifyTOTP(ctx context.Context, req *espressofw.JSON[TOTPVerifyReq]) (espressofw.JSON[AuthRes], error) {
	userID, err := a.svc.VerifyTOTPPending(req.Data.SessionToken)
	if err != nil {
		return espressofw.JSON[AuthRes]{},
			espressofw.ErrUnauthorized("session expired").WithCode("UNAUTHENTICATED")
	}
	if len(req.Data.Code) == 6 {
		if err := a.svc.VerifyTOTP(ctx, userID, req.Data.Code); err != nil {
			return espressofw.JSON[AuthRes]{}, mapTOTPWireError(err, a.cfg.ValidationMessage)
		}
	} else {
		if err := a.svc.VerifyRecoveryCode(ctx, userID, req.Data.Code); err != nil {
			return espressofw.JSON[AuthRes]{}, mapTOTPWireError(err, a.cfg.ValidationMessage)
		}
	}
	res, err := a.svc.IssueTokensForUser(ctx, userID)
	if err != nil {
		return espressofw.JSON[AuthRes]{}, mapAuthWireError(err, a.cfg.ValidationMessage)
	}
	a.cfg.OnAuthenticated(ctx, res.User.ID)
	return a.authRes(ctx, http.StatusOK, res), nil
}

// EnrollTOTP handles POST {prefix}/totp/enroll behind RequireAuth.
func (a *AuthRoutes) EnrollTOTP(ctx context.Context) (espressofw.JSON[TOTPEnrollRes], error) {
	userID := MustGetUserID(ctx)
	enr, err := a.svc.EnrollTOTP(ctx, userID)
	if err != nil {
		return espressofw.JSON[TOTPEnrollRes]{}, mapAuthWireError(err, a.cfg.ValidationMessage)
	}
	return espressofw.JSON[TOTPEnrollRes]{
		StatusCode: http.StatusOK,
		// Explicit field map, NOT TOTPEnrollRes(enr): enr is the port's
		// return type and TOTPEnrollRes is the wire DTO (json tags).
		// staticcheck S1016 flags the literal because the field sets
		// coincide today, but a type conversion would COUPLE the two —
		// a new field on the port type would auto-propagate onto the
		// wire. The whole point of a separate DTO is that it can't.
		Data: TOTPEnrollRes{OTPAuthURI: enr.OTPAuthURI, RecoveryCodes: enr.RecoveryCodes}, //nolint:staticcheck // S1016: boundary map, must stay explicit
	}, nil
}

// DisableTOTP handles POST {prefix}/totp/disable behind RequireAuth —
// requires a current code (a hijacked session cannot silently drop
// 2FA).
func (a *AuthRoutes) DisableTOTP(ctx context.Context, req *espressofw.JSON[TOTPDisableReq]) (espressofw.Status, error) {
	userID := MustGetUserID(ctx)
	if err := a.svc.DisableTOTP(ctx, userID, req.Data.Code); err != nil {
		return 0, mapTOTPWireError(err, a.cfg.ValidationMessage)
	}
	return espressofw.Status(http.StatusNoContent), nil
}

// EnrollSession handles POST {prefix}/totp/enroll-session — the
// two-phase session-token enrollment. Phase 2 mirrors the login
// response shape (token + user + refresh cookie) and fires the app's
// OnTOTPEnrolledViaSession hook before the response ships.
func (a *AuthRoutes) EnrollSession(ctx context.Context, req *espressofw.JSON[TOTPEnrollSessionReq]) (espressofw.JSON[TOTPEnrollSessionRes], error) {
	phase1, phase2, err := a.svc.EnrollTOTPViaSession(ctx, req.Data.SessionToken, req.Data.CurrentCode)
	if err != nil {
		switch {
		case errors.Is(err, identity.ErrTOTPAlreadyEnrolled):
			return espressofw.JSON[TOTPEnrollSessionRes]{},
				espressofw.ErrConflict("user already has TOTP enrolled").WithCode("TOTP_ALREADY_ENROLLED")
		case errors.Is(err, identity.ErrInvalidSession):
			return espressofw.JSON[TOTPEnrollSessionRes]{},
				espressofw.ErrUnauthorized("session expired").WithCode("UNAUTHENTICATED")
		default:
			return espressofw.JSON[TOTPEnrollSessionRes]{}, mapTOTPWireError(err, a.cfg.ValidationMessage)
		}
	}
	if phase2 != nil {
		a.cfg.OnAuthenticated(ctx, phase2.User.ID)
		if a.cfg.OnTOTPEnrolledViaSession != nil {
			a.cfg.OnTOTPEnrolledViaSession(ctx, phase2.User.ID)
		}
		return espressofw.JSON[TOTPEnrollSessionRes]{
			StatusCode: http.StatusOK,
			Data: TOTPEnrollSessionRes{
				Token: phase2.Tokens.Access,
				User:  a.cfg.ProjectUser(ctx, phase2.User),
			},
			Cookies: a.refreshCookies(phase2.Tokens),
		}, nil
	}
	return espressofw.JSON[TOTPEnrollSessionRes]{
		StatusCode: http.StatusOK,
		Data: TOTPEnrollSessionRes{
			OTPAuthURI:    phase1.OTPAuthURI,
			RecoveryCodes: phase1.RecoveryCodes,
			// The user key is ALWAYS present on this envelope (the
			// proving app's struct-value omitempty was a no-op, so
			// phase 1 shipped the zero projection — byte parity says
			// we do too).
			User: a.cfg.ProjectUser(ctx, nil),
		},
	}, nil
}

// Refresh handles POST {prefix}/refresh. The USER_INACTIVE branch is
// the adapter-standard cookies-on-error shape: the typed-error path
// cannot carry Set-Cookie, so a deactivated user gets a JSON-shaped
// 401 with a clear-cookie so the browser stops replaying the stale
// cookie (the app's fetcher branches on the 401 status alone).
func (a *AuthRoutes) Refresh(ctx context.Context) (espressofw.JSON[AuthRes], error) {
	tok, ok := NamedCookieValue(ctx, refreshCookieSlotName)
	if !ok {
		return espressofw.JSON[AuthRes]{},
			espressofw.ErrUnauthorized("refresh token missing").WithCode("UNAUTHENTICATED")
	}
	res, err := a.svc.Refresh(ctx, tok)
	if err != nil {
		if errors.Is(err, identity.ErrUserInactive) {
			return espressofw.JSON[AuthRes]{
				StatusCode: http.StatusUnauthorized,
				Cookies:    []*http.Cookie{a.clearRefreshCookie()},
				Data:       AuthRes{User: a.cfg.ProjectUser(ctx, nil)},
			}, nil
		}
		if errors.Is(err, identity.ErrInvalidSession) || errors.Is(err, identity.ErrNotFound) ||
			errors.Is(err, identity.ErrInvalidCredentials) {
			return espressofw.JSON[AuthRes]{},
				espressofw.ErrUnauthorized("refresh failed").WithCode("UNAUTHENTICATED")
		}
		return espressofw.JSON[AuthRes]{}, espressofw.ErrInternal("internal error").Wrap(err)
	}
	return a.authRes(ctx, http.StatusOK, res), nil
}

// Logout handles POST {prefix}/logout: best-effort revocation +
// unconditional clear-cookie, idempotent 204.
func (a *AuthRoutes) Logout(ctx context.Context) (espressofw.JSON[struct{}], error) {
	if tok, ok := NamedCookieValue(ctx, refreshCookieSlotName); ok {
		_ = a.svc.Logout(ctx, tok)
	}
	return espressofw.JSON[struct{}]{
		StatusCode: http.StatusNoContent,
		Cookies:    []*http.Cookie{a.clearRefreshCookie()},
	}, nil
}
