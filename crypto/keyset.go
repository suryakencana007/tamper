// KeySet extends the v0.5 single-KEK SecretBox with key-id versioning
// so an operator can rotate the KEK without re-issuing every webhook
// secret. v0.8 task 01 (closes the KEK-rotation non-goal carried since
// v0.5).
//
// Envelope layout:
//
//	keyId (1 byte) || nonce (12 bytes) || aes-gcm-output(plaintext, aad=nil)
//
// The first byte names the key under which the rest of the envelope
// is encrypted. KeySet.Open looks up the key by id, then runs standard
// AES-GCM-256 decrypt. Old keys stay valid for read-side decrypt
// during a rotation window; new keys become the writeKeyID once the
// operator points the chart at them. `barista rotate-kek <new-kek>`
// re-encrypts every webhook secret under the new id; afterward the
// operator can drop the old id from chart values.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
)

// ErrUnknownKeyID surfaces when KeySet.Open reads a keyId byte that
// isn't in the configured set. Operators see this when chart values
// dropped a key id that's still referenced by a row in the DB —
// recovery is to re-add the key id to chart values, helm-upgrade, and
// run `barista rotate-kek <current-key>` to migrate the dangling rows
// to the active id.
var ErrUnknownKeyID = errors.New("auth: keyset open: keyId not in keyset")

// ErrEmptyKeySet is returned by NewKeySet when no keys are supplied.
// The chart is expected to fail-render before reaching this point;
// the binary fail-loud path is belt-and-suspenders.
var ErrEmptyKeySet = errors.New("auth: keyset must have at least one key")

// ErrKeyIDZero is returned by NewKeySet when an entry uses keyId=0.
// We reserve 0 as a sentinel so existing v0.5-shape envelopes (which
// have a 12-byte nonce starting at byte 0) can be told apart from
// v0.8-shape envelopes (which have keyId at byte 0). Real keyIds
// start at 1; the bootstrap migration tags v0.5 envelopes with id=1.
var ErrKeyIDZero = errors.New("auth: keyset keyId 0 is reserved")

// KEKEntry is one (id, key) pair in the operator-supplied keyset.
// `Key` is the 32-byte AES-256 key, hex-encoded. The chart populates
// these from `auth.webhookSecretKeks: [...]` values.
type KEKEntry struct {
	ID  uint8
	Key string // hex-encoded 32-byte AES-256 key
}

// KeySet holds a map of keyId → AES-GCM AEAD plus the writeKeyID that
// new Seal calls use. Safe for concurrent Seal + Open calls; the
// underlying cipher.AEAD instances are goroutine-safe.
type KeySet struct {
	keys       map[uint8]cipher.AEAD
	writeKeyID uint8
}

// NewKeySet builds a KeySet from a list of (id, hex-key) pairs. The
// writeKeyID defaults to the highest id in the list — operators
// rotate by appending a new id; reads still work for older ids until
// the operator drops them. Pass writeKeyID explicitly to override
// (e.g. during `barista rotate-kek` to point writes at the freshly-
// added key before the chart-managed default flips).
//
// Returns nil + nil when entries is empty so callers can gate "is
// webhook encryption configured" on `keyset != nil` (mirroring the
// v0.5 SecretBox sentinel).
func NewKeySet(entries []KEKEntry, writeKeyID uint8) (*KeySet, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	keys := make(map[uint8]cipher.AEAD, len(entries))
	maxID := uint8(0)
	for _, e := range entries {
		if e.ID == 0 {
			return nil, ErrKeyIDZero
		}
		if _, dup := keys[e.ID]; dup {
			return nil, fmt.Errorf("auth: keyset duplicate keyId %d", e.ID)
		}
		if len(e.Key) != kekHexLen {
			return nil, fmt.Errorf("auth: keyset id=%d: key must be %d hex chars (32 bytes); got %d", e.ID, kekHexLen, len(e.Key))
		}
		raw, err := hex.DecodeString(e.Key)
		if err != nil {
			return nil, fmt.Errorf("auth: keyset id=%d: hex-decode: %w", e.ID, err)
		}
		block, err := aes.NewCipher(raw)
		if err != nil {
			return nil, fmt.Errorf("auth: keyset id=%d: aes-cipher: %w", e.ID, err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("auth: keyset id=%d: gcm: %w", e.ID, err)
		}
		keys[e.ID] = aead
		if e.ID > maxID {
			maxID = e.ID
		}
	}
	if writeKeyID == 0 {
		writeKeyID = maxID
	}
	if _, ok := keys[writeKeyID]; !ok {
		return nil, fmt.Errorf("auth: keyset writeKeyID %d not in keyset", writeKeyID)
	}
	return &KeySet{keys: keys, writeKeyID: writeKeyID}, nil
}

// WriteKeyID returns the id that Seal calls use. Surfaced for the
// `barista rotate-kek` CLI's progress logging.
func (s *KeySet) WriteKeyID() uint8 { return s.writeKeyID }

// HasKeyID reports whether the keyset has a key registered under id.
// Used by the rotate-kek CLI to verify the operator-supplied new key
// was actually loaded before re-encrypting.
func (s *KeySet) HasKeyID(id uint8) bool {
	_, ok := s.keys[id]
	return ok
}

// IDs returns the configured key ids in ascending order. Surfaced for
// boot-time logging so operators see which ids loaded.
func (s *KeySet) IDs() []uint8 {
	ids := make([]uint8, 0, len(s.keys))
	for id := range s.keys {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

// Seal encrypts plaintext under the writeKeyID's AEAD. Output is
// `keyId || nonce || aes-gcm-output`; nonces are random per-call.
func (s *KeySet) Seal(plaintext []byte) ([]byte, error) {
	aead, ok := s.keys[s.writeKeyID]
	if !ok {
		// Should be impossible — NewKeySet validates writeKeyID is in
		// the map. Defensive guard for the case where a future setter
		// mutates the field.
		return nil, fmt.Errorf("auth: keyset seal: writeKeyID %d not in keyset", s.writeKeyID)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("auth: keyset nonce: %w", err)
	}
	// Layout: [keyID byte] || nonce || aead.Seal(nonce, plaintext)
	envelope := make([]byte, 1, 1+aead.NonceSize()+len(plaintext)+aead.Overhead())
	envelope[0] = s.writeKeyID
	envelope = append(envelope, nonce...)
	envelope = aead.Seal(envelope, nonce, plaintext, nil)
	return envelope, nil
}

// Open decrypts a v0.8-shape envelope. Errors:
//   - ErrUnknownKeyID: keyId byte not in the keyset (probably the
//     operator dropped a key the DB still references).
//   - ErrSecretBoxOpen: ciphertext truncated, tampered, or encrypted
//     under a different key than the keyId byte claims.
//
// Open is the canonical read path for v0.8 envelope shape: every
// production webhook secret carries a `keyId` prefix.
func (s *KeySet) Open(envelope []byte) ([]byte, error) {
	if len(envelope) < 1 {
		return nil, ErrSecretBoxOpen
	}
	keyID := envelope[0]
	aead, ok := s.keys[keyID]
	if !ok {
		return nil, ErrUnknownKeyID
	}
	if len(envelope) < 1+aead.NonceSize() {
		return nil, ErrSecretBoxOpen
	}
	nonce := envelope[1 : 1+aead.NonceSize()]
	ct := envelope[1+aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, ErrSecretBoxOpen
	}
	return plaintext, nil
}

// SealBase64 wraps Seal + base64-encode for SQLite TEXT columns. Same
// rationale as SecretBox.SealBase64 — keep the storage layout ASCII
// without a column-type migration.
func (s *KeySet) SealBase64(plaintext string) (string, error) {
	sealed, err := s.Seal([]byte(plaintext))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// OpenBase64 is the SealBase64 inverse. ErrUnknownKeyID surfaces when
// the keyId byte isn't in the keyset; ErrSecretBoxOpen for everything
// else (non-base64 input, wrong key, tampered, truncated).
func (s *KeySet) OpenBase64(b64 string) (string, error) {
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
