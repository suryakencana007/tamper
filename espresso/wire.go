package espresso

import (
	"encoding/json"
	"errors"
	"net/http"

	espressofw "github.com/suryakencana007/espresso/v2"

	"github.com/suryakencana007/tamper/identity"
	"github.com/suryakencana007/tamper/oidc"
)

// WireV1 — the versioned default wire contract for the mounted auth
// routes. Field names, omitempty behavior, and error-code strings are
// copied byte-for-byte from the proving app so a delegation is a wire
// no-op; any future change ships as an opt-in WireV2, never as an
// edit here.

// AuthRes is the unified auth response (register / login / totp
// verify / refresh). User carries the app-projected payload verbatim
// — the user DTO never enters the framework (the ProjectUser hook
// owns it).
type AuthRes struct {
	Token        string          `json:"token,omitempty"`
	User         json.RawMessage `json:"user"`
	TOTPRequired bool            `json:"totp_required,omitempty"`
	SessionToken string          `json:"session_token,omitempty"`
}

// RegisterReq is the body of POST {prefix}/register.
type RegisterReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginReq is the body of POST {prefix}/login.
type LoginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// TOTPVerifyReq is the body of POST {prefix}/totp/verify.
type TOTPVerifyReq struct {
	SessionToken string `json:"session_token"`
	Code         string `json:"code"`
}

// TOTPEnrollRes is the body of POST {prefix}/totp/enroll.
type TOTPEnrollRes struct {
	OTPAuthURI    string   `json:"otpauth_uri"`
	RecoveryCodes []string `json:"recovery_codes"`
}

// TOTPDisableReq is the body of POST {prefix}/totp/disable.
type TOTPDisableReq struct {
	Code string `json:"code"`
}

// TOTPEnrollSessionReq is the body of POST {prefix}/totp/enroll-session
// — two-phase under one session token (phase 1: empty CurrentCode).
type TOTPEnrollSessionReq struct {
	SessionToken string `json:"session_token"`
	CurrentCode  string `json:"current_code,omitempty"`
}

// TOTPEnrollSessionRes is the unified response for both enroll-session
// phases: phase 1 populates OTPAuthURI + RecoveryCodes, phase 2
// populates Token + User (mirroring AuthRes).
type TOTPEnrollSessionRes struct {
	OTPAuthURI    string          `json:"otpauth_uri,omitempty"`
	RecoveryCodes []string        `json:"recovery_codes,omitempty"`
	Token         string          `json:"token,omitempty"`
	User          json.RawMessage `json:"user,omitempty"`
}

// ExchangeReq is the body of POST {prefix}/oidc/exchange — the code +
// state the SPA read back off the landing fragment.
type ExchangeReq struct {
	ProviderID string `json:"provider_id"`
	Code       string `json:"code"`
	State      string `json:"state"`
}

// ExchangeRes is the body of a successful /oidc/exchange.
//
// Token has NO omitempty, deliberately, and unlike AuthRes.Token which
// does: the link leg ships the LITERAL `"token":""`. Adding omitempty
// here "for consistency" drops the key and the SPA reads undefined.
// Field ORDER is wire surface too — encoding/json emits declaration
// order, so this is token,user,redirect on the wire.
type ExchangeRes struct {
	Token    string          `json:"token"`
	User     json.RawMessage `json:"user"`
	Redirect string          `json:"redirect,omitempty"`
}

// LinkStartRes is the body of POST {prefix}/oidc/link-start/{id}.
//
// The tag is camelCase `authUrl`, diverging from every other WireV1 tag
// (session_token / otpauth_uri / provider_id). That is the proving
// app's existing wire; copy the bytes, not the convention. Writing
// auth_url from muscle memory breaks the SPA's link flow.
type LinkStartRes struct {
	AuthURL string `json:"authUrl"`
}

// mapFederationVerifyError translates the OIDC verification sentinels
// to WireV1 codes.
//
// Two shapes here are load-bearing and must not be "cleaned up":
//
//   - The default is INVALID_IDTOKEN, not INTERNAL. There is no
//     validation oracle for an IdP-supplied token; an unrecognised
//     failure is still the token's fault, not ours.
//   - Everything here is 401 EXCEPT the exchange failure, which is 502:
//     the IdP is a separate upstream, and its outage is not the
//     caller's error. The mode-dispatch errors (elsewhere) are 400s.
//     That 401/400 asymmetry on one code string is intentional —
//     INVALID_STATE means "your cookie is wrong" on the verify path and
//     "your cookie says something impossible" on dispatch.
func mapFederationVerifyError(err error) error {
	switch {
	case errors.Is(err, ErrOIDCState):
		return espressofw.ErrUnauthorized("oidc state invalid").WithCode("INVALID_STATE")
	case errors.Is(err, ErrOIDCExchange):
		return espressofw.NewError(http.StatusBadGateway, "idp token exchange failed").WithCode("IDP_ERROR")
	case errors.Is(err, ErrOIDCNoIDToken):
		return espressofw.ErrUnauthorized("idp returned no id token").WithCode("INVALID_IDTOKEN")
	case errors.Is(err, oidc.ErrNonceMismatch):
		return espressofw.ErrUnauthorized("nonce mismatch").WithCode("INVALID_NONCE")
	default:
		return espressofw.ErrUnauthorized("id token invalid").WithCode("INVALID_IDTOKEN")
	}
}

// mapAuthWireError translates identity sentinels to the WireV1 error
// codes. Messages are crafted here (never forwarded from services) so
// wire copy stays stable as internals evolve. ErrUserInactive wraps
// broader unauthorized semantics in some implementations — it is
// checked FIRST so it never collapses into INVALID_CREDENTIALS.
func mapAuthWireError(err error, validationMsg func(error) string) error {
	switch {
	case errors.Is(err, identity.ErrEmailTaken):
		return espressofw.ErrConflict("email is already registered").WithCode("EMAIL_TAKEN")
	case errors.Is(err, identity.ErrUserInactive):
		return espressofw.ErrUnauthorized("account is deactivated").WithCode("USER_INACTIVE")
	case errors.Is(err, identity.ErrInvalidCredentials), errors.Is(err, identity.ErrInvalidSession):
		return espressofw.ErrUnauthorized("invalid credentials").WithCode("INVALID_CREDENTIALS")
	case errors.Is(err, identity.ErrInvalidEmail), errors.Is(err, identity.ErrPasswordPolicy), errors.Is(err, identity.ErrInvalidInput):
		return espressofw.ErrBadRequest(validationMsg(err)).WithCode("VALIDATION_ERROR")
	case errors.Is(err, identity.ErrThrottled):
		return throttledWireError(err)
	default:
		return espressofw.ErrInternal("internal error").Wrap(err)
	}
}

// throttledWireError maps identity.ErrThrottled onto the route gate's
// stable 429.
//
// The CODE is ThrottledCode — the constant the route-level Throttled
// middleware already emits — so one condition has one spelling across the
// surface rather than a second RATE_LIMITED a client has to learn.
//
// The retry hint is the same Retry-After header that middleware sets, carried
// through espresso's Error.WithHeader (v2.5.0). retryAfterSeconds is the one
// rounding both paths use, so a client sees one wait, not two. There is
// deliberately no body detail: the detail was the pre-v2.5.0 stand-in for a
// header this package could not set, it was never released, and two forms for
// one thing is what standing rule 1 forbids. See PHASE7-MULTITENANCY-SKETCH.md,
// M5 amendment (#163).
//
// The message is FIXED and the header carries only the bucket's retry time.
// Never the email, user id or key: ThrottledError's doc comment explains that a
// limiter which echoes the attempted address is a credential-stuffing receipt.
func throttledWireError(err error) *espressofw.Error {
	e := espressofw.ErrTooManyRequests("too many attempts").WithCode(ThrottledCode)
	var te *identity.ThrottledError
	if errors.As(err, &te) && te.RetryAfter > 0 {
		e = e.WithHeader("Retry-After", retryAfterSeconds(te.RetryAfter))
	}
	return e
}

// mapTOTPWireError translates the TOTP sentinels; everything else
// falls through to the auth mapping.
func mapTOTPWireError(err error, validationMsg func(error) string) error {
	switch {
	case errors.Is(err, identity.ErrInvalidTOTP):
		return espressofw.ErrUnauthorized("invalid totp code").WithCode("INVALID_TOTP")
	case errors.Is(err, identity.ErrTOTPNotEnrolled):
		return espressofw.ErrBadRequest(validationMsg(err)).WithCode("VALIDATION_ERROR")
	default:
		return mapAuthWireError(err, validationMsg)
	}
}

// defaultValidationMessage is the fallback when the app supplies no
// message projection: never leak internal error text.
func defaultValidationMessage(error) string { return "validation error" }
