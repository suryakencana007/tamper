package crypto

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// TOTPSecretBytes is the secret length recommended by RFC 4226 / RFC 6238
// for SHA-1 HMAC. 20 bytes encodes to 32 base32 chars without padding —
// fits in any authenticator app's QR-code / paste flow.
const TOTPSecretBytes = 20

// TOTPRecoveryCodeCount is the number of single-use bcrypt-hashed
// codes generated at enrollment. Industry convention (Google /
// GitHub / GitLab all use 10) — one per "I lost my phone" event,
// reasonable for a year of normal operator life.
const TOTPRecoveryCodeCount = 10

// TOTPRecoveryCodeBytes is the entropy per recovery code. 6 random
// bytes encode to 10 base32 chars without padding (~50 bits entropy);
// the SPA renders them as `XXXXX-XXXXX` for readability.
const TOTPRecoveryCodeBytes = 6

// TOTPIssuer is the chart-supplied issuer label that authenticator
// apps show alongside the user's email. Hard-coded for v0.8; future
// milestones may parametrise it via chart values for white-labelled
// installs.
const TOTPIssuer = "Barista"

// ErrInvalidTOTPCode signals a rejected code (wrong window, bad
// length, malformed). AuthService translates to domain.ErrInvalidTOTP.
var ErrInvalidTOTPCode = errors.New("auth: invalid totp code")

// GenerateTOTPSecret returns a fresh base32-encoded 20-byte secret.
// Used by AuthService.EnrollTOTP; the caller passes this into the
// authenticator-app pairing URI (otpauth://...) and persists the
// secret encrypted under the keyset envelope.
func GenerateTOTPSecret() (string, error) {
	raw := make([]byte, TOTPSecretBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("auth: totp secret rand: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}

// OTPAuthURI builds the otpauth:// URI that authenticator apps consume
// when pairing. Per the Google Authenticator key-uri-format spec:
//
//	otpauth://totp/<issuer>:<account>?secret=<base32>&issuer=<issuer>&algorithm=SHA1&digits=6&period=30
//
// `account` is the user's email; `issuer` is the chart-configured
// brand label. Defaults match the authenticator-app baseline so any
// RFC 6238 client (Google Auth / Authy / 1Password / Bitwarden) reads
// it without bespoke configuration.
func OTPAuthURI(secretBase32, accountEmail string) string {
	return fmt.Sprintf(
		"otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		TOTPIssuer, accountEmail, secretBase32, TOTPIssuer,
	)
}

// VerifyTOTPCode checks `code` against the secret using RFC 6238 with
// the standard ±1 window tolerance (90 seconds total clock-skew
// budget). Returns nil on match; ErrInvalidTOTPCode otherwise.
//
// The pquerna/otp library's totp.Validate covers the current 30s
// window; explicit ValidateOpts with Skew=1 covers the previous +
// next windows so an authenticator app whose clock is within ±30s
// of the server still works.
func VerifyTOTPCode(secretBase32, code string) error {
	if len(code) != 6 {
		return fmt.Errorf("%w: code length %d (want 6)", ErrInvalidTOTPCode, len(code))
	}
	ok, err := totp.ValidateCustom(code, secretBase32, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      1, // accept current ± 1 window (~90s total budget)
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return fmt.Errorf("%w: validate: %v", ErrInvalidTOTPCode, err)
	}
	if !ok {
		return ErrInvalidTOTPCode
	}
	return nil
}

// GenerateTOTPRecoveryCodes returns a fresh batch of single-use
// recovery codes. Each is 10 base32 chars (~50 bits entropy) rendered
// as `XXXXX-XXXXX` for readability. The plaintext list is shown to
// the user exactly once at enroll time; callers persist only the
// bcrypt-hashed forms via HashRecoveryCodes.
func GenerateTOTPRecoveryCodes() ([]string, error) {
	out := make([]string, 0, TOTPRecoveryCodeCount)
	for range TOTPRecoveryCodeCount {
		raw := make([]byte, TOTPRecoveryCodeBytes)
		if _, err := rand.Read(raw); err != nil {
			return nil, fmt.Errorf("auth: recovery code rand: %w", err)
		}
		enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
		// Insert hyphen for readability: "XXXXX-XXXXX".
		out = append(out, enc[:5]+"-"+enc[5:])
	}
	return out, nil
}

// HashRecoveryCodes bcrypt-hashes each code in the input list.
// Persistence shape: newline-separated hashes in
// users.totp_recovery_codes. Single-use semantics implemented by
// VerifyRecoveryCode in the service layer (matches a code, removes
// the matching hash from the list).
func HashRecoveryCodes(codes []string) ([]string, error) {
	out := make([]string, 0, len(codes))
	for _, c := range codes {
		h, err := bcrypt.GenerateFromPassword([]byte(c), Cost)
		if err != nil {
			return nil, fmt.Errorf("auth: hash recovery code: %w", err)
		}
		out = append(out, string(h))
	}
	return out, nil
}

// MatchRecoveryCode bcrypt-compares `code` against each hash in
// `hashes`. Returns the matched hash (so the caller can remove it
// from the persisted list) and ok=true on success, ("", false)
// otherwise. Non-allocating-on-miss path: returns immediately on a
// successful match without comparing remaining hashes.
//
// `code` is normalised via normaliseRecoveryCode before comparison so
// the recovery flow forgives lowercase, missing hyphen, surrounding
// whitespace, and stray punctuation — stored hashes encode the
// canonical `XXXXX-XXXXX` form generated at enroll time, so any
// variant a user might paste collapses to the same string before
// bcrypt sees it (TD-UX-10).
func MatchRecoveryCode(code string, hashes []string) (matched string, ok bool) {
	candidate := normaliseRecoveryCode(code)
	for _, h := range hashes {
		if err := bcrypt.CompareHashAndPassword([]byte(h), []byte(candidate)); err == nil {
			return h, true
		}
	}
	return "", false
}

// normaliseRecoveryCode forgives the common input mistakes operators
// make when typing a recovery code: lowercase letters, missing
// hyphen, surrounding whitespace, stray punctuation. Strips every
// non-alphanumeric rune, uppercases letters, and re-inserts the
// hyphen at position 5 when the stripped length is exactly 10
// (the canonical XXXXX-XXXXX form generated at enroll time).
// Codes whose stripped length isn't 10 fall through unchanged;
// bcrypt will reject them naturally since stored hashes encode the
// canonical form.
func normaliseRecoveryCode(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r - 'a' + 'A')
		case (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
		}
	}
	raw := b.String()
	if len(raw) == 10 {
		return raw[:5] + "-" + raw[5:]
	}
	return raw
}
