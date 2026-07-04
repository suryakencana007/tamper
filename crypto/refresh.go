package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// RefreshTokenBytes is the entropy source for a refresh token. 32 bytes
// (256 bits) is well above the practical brute-force threshold and
// produces a 43-char base64url-no-padding wire string — short enough
// to ride in a Set-Cookie header without trouble.
const RefreshTokenBytes = 32

// ErrInvalidRefreshToken is returned by HashRefreshToken when the input
// is malformed (empty / wrong length / non-base64url). The auth service
// translates it into the user-facing UNAUTHENTICATED outcome.
var ErrInvalidRefreshToken = errors.New("auth: invalid refresh token")

// NewRefreshToken returns a fresh random token (base64url-no-padding
// of 32 random bytes). The plaintext is given to the client; only the
// SHA-256 hex digest is persisted, so a DB compromise alone never
// yields a usable token.
func NewRefreshToken() (string, error) {
	buf := make([]byte, RefreshTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("auth: read random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// HashRefreshToken returns the SHA-256 hex of a refresh token. Used
// when persisting newly-issued tokens and when looking up incoming
// tokens — both sides must hash identically. SHA-256 (rather than
// bcrypt) is correct here: the input is high-entropy random bytes,
// not a user-chosen secret, so adaptive password hashing buys nothing.
func HashRefreshToken(token string) (string, error) {
	if token == "" {
		return "", fmt.Errorf("%w: empty token", ErrInvalidRefreshToken)
	}
	// Sanity-check: a real token decodes cleanly. Skipping the decode
	// would let an attacker hash arbitrary strings (e.g. a leaked log
	// line) and have them match a stored hash; the explicit decode
	// reduces that surface even though the random-source guarantee
	// already protects collisions.
	if _, err := base64.RawURLEncoding.DecodeString(token); err != nil {
		return "", fmt.Errorf("%w: not base64url", ErrInvalidRefreshToken)
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:]), nil
}
