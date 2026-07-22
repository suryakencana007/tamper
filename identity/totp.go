package identity

import (
	"context"
	"errors"
	"fmt"

	"github.com/suryakencana007/tamper/crypto"
)

// WithKeySet attaches the KEK keyset that seals/opens the TOTP secret
// envelope. Every TOTP flow that touches the secret requires it;
// flows on a keyset-less Core fail with ErrNoKeySet.
func WithKeySet(keys *crypto.KeySet) Option { return func(c *Core) { c.keys = keys } }

// TOTPEnrollment is the one-time-visible enrollment payload: the
// otpauth pairing URI (and raw secret for manual entry) plus the
// plaintext recovery codes. Shown once; only hashes persist.
type TOTPEnrollment struct {
	Secret        string
	OTPAuthURI    string
	RecoveryCodes []string
}

// StartTOTPEnrollment stages phase 1 of the two-phase enrollment: mint
// a fresh secret + recovery codes, seal the secret under the keyset,
// persist as PENDING (enrolled stays false), and return the pairing
// payload. Restartable: re-invoking overwrites the prior pending
// envelope (the user re-pairs). Already-enrolled users get
// ErrTOTPAlreadyEnrolled.
func (c *Core) StartTOTPEnrollment(ctx context.Context, userID string) (TOTPEnrollment, error) {
	if c.keys == nil {
		return TOTPEnrollment{}, ErrNoKeySet
	}
	user, err := c.store.UserByID(ctx, userID)
	if err != nil {
		return TOTPEnrollment{}, err
	}
	if user.TOTPEnrolled {
		return TOTPEnrollment{}, fmt.Errorf("%w: user %s", ErrTOTPAlreadyEnrolled, userID)
	}
	secret, err := crypto.GenerateTOTPSecret()
	if err != nil {
		return TOTPEnrollment{}, fmt.Errorf("identity: generate totp secret: %w", err)
	}
	envelope, err := c.keys.Seal([]byte(secret))
	if err != nil {
		return TOTPEnrollment{}, fmt.Errorf("identity: seal totp secret: %w", err)
	}
	codes, err := crypto.GenerateTOTPRecoveryCodes()
	if err != nil {
		return TOTPEnrollment{}, fmt.Errorf("identity: generate recovery codes: %w", err)
	}
	hashes, err := crypto.HashRecoveryCodes(codes)
	if err != nil {
		return TOTPEnrollment{}, fmt.Errorf("identity: hash recovery codes: %w", err)
	}
	if err := c.store.SetTOTPPending(ctx, userID, envelope, hashes); err != nil {
		return TOTPEnrollment{}, fmt.Errorf("identity: stage totp enrollment: %w", err)
	}
	return TOTPEnrollment{
		Secret:        secret,
		OTPAuthURI:    crypto.OTPAuthURI(secret, user.Email),
		RecoveryCodes: codes,
	}, nil
}

// CompleteTOTPEnrollment is phase 2: verify the submitted code against
// the staged secret, promote the enrollment, and mint a fresh session
// (auth_time = the enrollment instant — the user just proved the
// second factor; ACR stays the default local tier). An invalid code
// returns ErrInvalidTOTP and leaves the staged state intact so the
// caller can retry without re-pairing; phase 2 before phase 1 is also
// ErrInvalidTOTP (nothing staged — the caller re-routes to phase 1).
func (c *Core) CompleteTOTPEnrollment(ctx context.Context, userID, code string) (User, Tokens, error) {
	if c.keys == nil {
		return User{}, Tokens{}, ErrNoKeySet
	}
	user, err := c.store.UserByID(ctx, userID)
	if err != nil {
		return User{}, Tokens{}, err
	}
	if user.TOTPEnrolled {
		return User{}, Tokens{}, fmt.Errorf("%w: user %s", ErrTOTPAlreadyEnrolled, userID)
	}
	state, err := c.store.TOTPState(ctx, userID)
	if err != nil {
		return User{}, Tokens{}, err
	}
	if len(state.Envelope) == 0 {
		return User{}, Tokens{}, fmt.Errorf("%w: no pending enrollment", ErrInvalidTOTP)
	}
	if err := c.verifyAgainstEnvelope(state.Envelope, code); err != nil {
		return User{}, Tokens{}, err
	}
	enrolledAt := c.now()
	if err := c.store.EnableTOTP(ctx, userID, state.Envelope, state.RecoveryCodeHashes, enrolledAt); err != nil {
		return User{}, Tokens{}, fmt.Errorf("identity: promote totp enrollment: %w", err)
	}
	tokens, err := c.issueTokens(ctx, userID, enrolledAt.Unix(), c.defaultACR)
	if err != nil {
		return User{}, Tokens{}, err
	}
	user.TOTPEnrolled = true
	return user, tokens, nil
}

// EnrollTOTP is the one-shot enrollment (no verification round-trip):
// mint + seal + enable in a SINGLE store write. Used by flows where the
// caller verifies pairing out-of-band.
//
// Unlike the two-phase ceremony (StartTOTPEnrollment/CompleteTOTPEnrollment,
// which reject an already-enrolled user with ErrTOTPAlreadyEnrolled),
// the one-shot is an idempotent OVERWRITE: re-enrolling rotates the
// secret + recovery codes in place. This is deliberate — it is the
// direct "reset my authenticator" verb — and the atomicity matters: a
// single EnableTOTP write means a failure never leaves the user with a
// half-cleared second factor (a stage-then-enable or clear-then-enroll
// sequence could strip an existing enrollment on a mid-sequence error).
func (c *Core) EnrollTOTP(ctx context.Context, userID string) (TOTPEnrollment, error) {
	if c.keys == nil {
		return TOTPEnrollment{}, ErrNoKeySet
	}
	user, err := c.store.UserByID(ctx, userID)
	if err != nil {
		return TOTPEnrollment{}, err
	}
	secret, err := crypto.GenerateTOTPSecret()
	if err != nil {
		return TOTPEnrollment{}, fmt.Errorf("identity: generate totp secret: %w", err)
	}
	envelope, err := c.keys.Seal([]byte(secret))
	if err != nil {
		return TOTPEnrollment{}, fmt.Errorf("identity: seal totp secret: %w", err)
	}
	codes, err := crypto.GenerateTOTPRecoveryCodes()
	if err != nil {
		return TOTPEnrollment{}, fmt.Errorf("identity: generate recovery codes: %w", err)
	}
	hashes, err := crypto.HashRecoveryCodes(codes)
	if err != nil {
		return TOTPEnrollment{}, fmt.Errorf("identity: hash recovery codes: %w", err)
	}
	if err := c.store.EnableTOTP(ctx, userID, envelope, hashes, c.now()); err != nil {
		return TOTPEnrollment{}, fmt.Errorf("identity: enable totp: %w", err)
	}
	return TOTPEnrollment{
		Secret:        secret,
		OTPAuthURI:    crypto.OTPAuthURI(secret, user.Email),
		RecoveryCodes: codes,
	}, nil
}

// VerifyTOTP checks a code against the enrolled secret. ErrTOTPNotEnrolled
// when the user has no enrolled second factor; ErrInvalidTOTP on
// rejection.
func (c *Core) VerifyTOTP(ctx context.Context, userID, code string) error {
	if c.keys == nil {
		return ErrNoKeySet
	}
	state, err := c.store.TOTPState(ctx, userID)
	if err != nil {
		return err
	}
	if !state.Enrolled || len(state.Envelope) == 0 {
		return fmt.Errorf("%w: user %s", ErrTOTPNotEnrolled, userID)
	}
	return c.verifyAgainstEnvelope(state.Envelope, code)
}

// VerifyRecoveryCode checks a recovery code against the stored hash
// list and consumes it on match (single-use).
func (c *Core) VerifyRecoveryCode(ctx context.Context, userID, code string) error {
	state, err := c.store.TOTPState(ctx, userID)
	if err != nil {
		return err
	}
	if !state.Enrolled {
		return fmt.Errorf("%w: user %s", ErrTOTPNotEnrolled, userID)
	}
	matched, ok := crypto.MatchRecoveryCode(code, state.RecoveryCodeHashes)
	if !ok {
		return fmt.Errorf("%w: recovery code did not match", ErrInvalidTOTP)
	}
	remaining := make([]string, 0, len(state.RecoveryCodeHashes)-1)
	for _, h := range state.RecoveryCodeHashes {
		if h != matched {
			remaining = append(remaining, h)
		}
	}
	if err := c.store.SetRecoveryCodeHashes(ctx, userID, remaining); err != nil {
		return fmt.Errorf("identity: consume recovery code: %w", err)
	}
	return nil
}

// DisableTOTP clears the second factor after re-proving possession
// (defense against a hijacked session disabling 2FA).
func (c *Core) DisableTOTP(ctx context.Context, userID, currentCode string) error {
	if err := c.VerifyTOTP(ctx, userID, currentCode); err != nil {
		return err
	}
	if err := c.store.ClearTOTP(ctx, userID); err != nil {
		return fmt.Errorf("identity: clear totp: %w", err)
	}
	return nil
}

// ClearTOTP is the unconditional (admin/recovery) reset — no code
// required. The caller owns the authorization decision.
func (c *Core) ClearTOTP(ctx context.Context, userID string) error {
	if err := c.store.ClearTOTP(ctx, userID); err != nil {
		return fmt.Errorf("identity: clear totp: %w", err)
	}
	return nil
}

func (c *Core) verifyAgainstEnvelope(envelope []byte, code string) error {
	plaintext, err := c.keys.Open(envelope)
	if err != nil {
		return fmt.Errorf("identity: open totp secret: %w", err)
	}
	if err := crypto.VerifyTOTPCode(string(plaintext), code); err != nil {
		if errors.Is(err, crypto.ErrInvalidTOTPCode) {
			return fmt.Errorf("%w: %v", ErrInvalidTOTP, err)
		}
		return fmt.Errorf("%w: %v", ErrInvalidTOTP, err)
	}
	return nil
}
