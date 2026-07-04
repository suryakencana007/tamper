// SecretBox is the at-rest encryption wrapper used by WebhookService
// to keep per-app HMAC secrets encrypted in SQLite. AES-GCM-256 with a
// random 12-byte nonce per Seal call; ciphertext layout is
// `nonce || aes-gcm-output(plaintext, aad=nil)`. The nonce is read
// off the front during Open, so callers store + retrieve the
// ciphertext as a single opaque blob.
//
// The KEK comes from chart-supplied env var
// `BARISTA_AUTH_WEBHOOKSECRETKEK` (32-byte hex). The chart fails to
// render when webhooks.enabled=true and the value is empty (mirrors
// the existing JWT-secret fail-render pattern).
//
// Threat model: an operator with kubectl exec into the Barista pod or
// a backup snapshot of the SQLite file can no longer extract project
// webhook secrets. The KEK is held in the pod's process memory only;
// a process-memory dump is still in scope (out of v0.5's threat
// model). KEK rotation is a v0.6 task — v0.5 single-KEK direct AES.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// kekHexLen is hex.EncodedLen(32) — 32-byte AES-256 key, hex-encoded
// for env-var ergonomics. Generated via `openssl rand -hex 32`.
const kekHexLen = 64

// ErrSecretBoxOpen is returned when ciphertext can't be decrypted.
// Possible causes: KEK rotated without re-encrypt, ciphertext
// truncated, ciphertext tampered. Handlers map this to a clean
// 5xx without leaking which case fired (don't help an attacker
// distinguish between key-mismatch and tamper).
var ErrSecretBoxOpen = errors.New("auth: secretbox open failed")

// SecretBox encrypts/decrypts opaque byte blobs at rest. Construct
// once at startup via NewSecretBox; the struct is safe for concurrent
// Seal + Open calls (the underlying cipher.AEAD is goroutine-safe).
type SecretBox struct {
	aead cipher.AEAD
}

// NewSecretBox builds a SecretBox from a hex-encoded 32-byte KEK.
// Empty input returns (nil, nil) — callers gate "is webhook
// encryption configured" on `box != nil` so a missing KEK is a
// fail-loud at the WebhookService boundary, not here.
func NewSecretBox(kekHex string) (*SecretBox, error) {
	if kekHex == "" {
		return nil, nil
	}
	if len(kekHex) != kekHexLen {
		return nil, fmt.Errorf("auth: secretbox KEK must be %d hex chars (32 bytes); got %d", kekHexLen, len(kekHex))
	}
	key, err := hex.DecodeString(kekHex)
	if err != nil {
		return nil, fmt.Errorf("auth: secretbox KEK hex-decode: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("auth: secretbox aes-cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("auth: secretbox gcm: %w", err)
	}
	return &SecretBox{aead: aead}, nil
}

// Seal encrypts plaintext under the box's KEK. Output is
// `nonce || aes-gcm-output`; nonces are random per-call so identical
// plaintexts never produce identical ciphertexts (avoids the
// distinguisher attack on deterministic encryption).
func (s *SecretBox) Seal(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("auth: secretbox nonce: %w", err)
	}
	// AEAD.Seal appends ciphertext+tag to the dst (nonce here), so the
	// output is nonce || ct || tag. NonceSize() is 12 for AES-GCM.
	return s.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Open decrypts a SealedSecret and returns the plaintext. Wrong-key,
// tampered-ciphertext, and truncated-input all return ErrSecretBoxOpen
// without distinguishing between them. Callers don't need that
// distinction — the response is the same: refuse the operation, log
// at the call site.
func (s *SecretBox) Open(sealed []byte) ([]byte, error) {
	if len(sealed) < s.aead.NonceSize() {
		return nil, ErrSecretBoxOpen
	}
	nonce, ct := sealed[:s.aead.NonceSize()], sealed[s.aead.NonceSize():]
	plaintext, err := s.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, ErrSecretBoxOpen
	}
	return plaintext, nil
}

// SealBase64 wraps Seal + base64-encode for SQLite TEXT columns.
// The TEXT column declaration in the schema means we want printable
// ASCII; base64 keeps the storage layout identical to the legacy
// plaintext shape (just longer) and avoids needing a column-type
// migration to BLOB.
func (s *SecretBox) SealBase64(plaintext string) (string, error) {
	sealed, err := s.Seal([]byte(plaintext))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// OpenBase64 is the SealBase64 inverse. ErrSecretBoxOpen surfaces for
// non-base64 input, wrong-key, tampered ciphertext, and truncated
// input — caller treats them all the same.
func (s *SecretBox) OpenBase64(b64 string) (string, error) {
	sealed, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", ErrSecretBoxOpen
	}
	plaintext, err := s.Open(sealed)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
