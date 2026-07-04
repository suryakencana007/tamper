package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// freshKey returns a 64-char hex string for one AES-256 key.
func freshKey(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(raw)
}

func TestNewKeySet_EmptyReturnsNil(t *testing.T) {
	t.Parallel()
	ks, err := NewKeySet(nil, 0)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ks != nil {
		t.Errorf("expected nil keyset for empty entries, got %v", ks)
	}
}

func TestNewKeySet_DefaultsWriteKeyToHighestID(t *testing.T) {
	t.Parallel()
	k1 := freshKey(t)
	k2 := freshKey(t)
	ks, err := NewKeySet([]KEKEntry{{ID: 1, Key: k1}, {ID: 2, Key: k2}}, 0)
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	if got := ks.WriteKeyID(); got != 2 {
		t.Errorf("WriteKeyID = %d, want 2 (highest)", got)
	}
}

func TestNewKeySet_RejectsKeyIDZero(t *testing.T) {
	t.Parallel()
	_, err := NewKeySet([]KEKEntry{{ID: 0, Key: freshKey(t)}}, 0)
	if !errors.Is(err, ErrKeyIDZero) {
		t.Errorf("err = %v, want ErrKeyIDZero", err)
	}
}

func TestNewKeySet_RejectsDuplicateID(t *testing.T) {
	t.Parallel()
	_, err := NewKeySet([]KEKEntry{
		{ID: 1, Key: freshKey(t)},
		{ID: 1, Key: freshKey(t)},
	}, 0)
	if err == nil || !strings.Contains(err.Error(), "duplicate keyId") {
		t.Errorf("err = %v, want duplicate keyId", err)
	}
}

func TestNewKeySet_RejectsBadHex(t *testing.T) {
	t.Parallel()
	_, err := NewKeySet([]KEKEntry{{ID: 1, Key: "not-hex"}}, 0)
	if err == nil {
		t.Fatalf("expected error for short key")
	}
}

func TestNewKeySet_WriteKeyIDOverride(t *testing.T) {
	t.Parallel()
	k1 := freshKey(t)
	k2 := freshKey(t)
	ks, err := NewKeySet([]KEKEntry{{ID: 1, Key: k1}, {ID: 2, Key: k2}}, 1)
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	if got := ks.WriteKeyID(); got != 1 {
		t.Errorf("WriteKeyID = %d, want 1 (explicit override)", got)
	}
}

func TestNewKeySet_RejectsWriteKeyIDNotInSet(t *testing.T) {
	t.Parallel()
	_, err := NewKeySet([]KEKEntry{{ID: 1, Key: freshKey(t)}}, 7)
	if err == nil || !strings.Contains(err.Error(), "writeKeyID 7 not in keyset") {
		t.Errorf("err = %v, want writeKeyID-not-in-keyset", err)
	}
}

func TestKeySet_SealOpenRoundTrip(t *testing.T) {
	t.Parallel()
	ks, err := NewKeySet([]KEKEntry{{ID: 7, Key: freshKey(t)}}, 0)
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	plaintext := "whsec_abcdEFGH"
	envelope, err := ks.Seal([]byte(plaintext))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// Envelope's first byte must be the writeKeyID (7).
	if envelope[0] != 7 {
		t.Errorf("envelope[0] = %d, want 7 (writeKeyID prefix)", envelope[0])
	}
	got, err := ks.Open(envelope)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(got) != plaintext {
		t.Errorf("Open = %q, want %q", got, plaintext)
	}
}

func TestKeySet_OpenWithMultipleKeys(t *testing.T) {
	t.Parallel()
	// Build two separate keysets — one with id=1 only, one with both
	// id=1 and id=2. Seal under id=1's keyset, then verify the
	// combined keyset can open the envelope (read-side decrypt during
	// rotation grace window).
	k1 := freshKey(t)
	k2 := freshKey(t)
	oldKS, err := NewKeySet([]KEKEntry{{ID: 1, Key: k1}}, 0)
	if err != nil {
		t.Fatalf("oldKS: %v", err)
	}
	combinedKS, err := NewKeySet([]KEKEntry{{ID: 1, Key: k1}, {ID: 2, Key: k2}}, 2)
	if err != nil {
		t.Fatalf("combinedKS: %v", err)
	}
	envelope, err := oldKS.Seal([]byte("hello-rotation"))
	if err != nil {
		t.Fatalf("Seal under id=1: %v", err)
	}
	got, err := combinedKS.Open(envelope)
	if err != nil {
		t.Fatalf("Open under combined keyset: %v", err)
	}
	if string(got) != "hello-rotation" {
		t.Errorf("Open = %q, want hello-rotation", got)
	}
}

func TestKeySet_OpenUnknownKeyID(t *testing.T) {
	t.Parallel()
	// Seal under a keyset that has id=99 only, then try to open with a
	// keyset that doesn't have id=99 — should return ErrUnknownKeyID.
	oldKS, err := NewKeySet([]KEKEntry{{ID: 99, Key: freshKey(t)}}, 0)
	if err != nil {
		t.Fatalf("oldKS: %v", err)
	}
	newKS, err := NewKeySet([]KEKEntry{{ID: 1, Key: freshKey(t)}}, 0)
	if err != nil {
		t.Fatalf("newKS: %v", err)
	}
	envelope, err := oldKS.Seal([]byte("orphan"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	_, err = newKS.Open(envelope)
	if !errors.Is(err, ErrUnknownKeyID) {
		t.Errorf("err = %v, want ErrUnknownKeyID", err)
	}
}

func TestKeySet_OpenTamperedEnvelope(t *testing.T) {
	t.Parallel()
	ks, err := NewKeySet([]KEKEntry{{ID: 1, Key: freshKey(t)}}, 0)
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	envelope, err := ks.Seal([]byte("payload"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// Flip a byte in the ciphertext region (after keyId+nonce = 13 bytes).
	envelope[15] ^= 0xff
	_, err = ks.Open(envelope)
	if !errors.Is(err, ErrSecretBoxOpen) {
		t.Errorf("err = %v, want ErrSecretBoxOpen", err)
	}
}

func TestKeySet_OpenTruncatedEnvelope(t *testing.T) {
	t.Parallel()
	ks, err := NewKeySet([]KEKEntry{{ID: 1, Key: freshKey(t)}}, 0)
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	// Empty input.
	if _, err := ks.Open(nil); !errors.Is(err, ErrSecretBoxOpen) {
		t.Errorf("err = %v, want ErrSecretBoxOpen on empty", err)
	}
	// Just keyId byte, no nonce.
	if _, err := ks.Open([]byte{1}); !errors.Is(err, ErrSecretBoxOpen) {
		t.Errorf("err = %v, want ErrSecretBoxOpen on keyId-only", err)
	}
}

func TestKeySet_Base64RoundTrip(t *testing.T) {
	t.Parallel()
	ks, err := NewKeySet([]KEKEntry{{ID: 1, Key: freshKey(t)}}, 0)
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	b64, err := ks.SealBase64("plaintext-secret")
	if err != nil {
		t.Fatalf("SealBase64: %v", err)
	}
	got, err := ks.OpenBase64(b64)
	if err != nil {
		t.Fatalf("OpenBase64: %v", err)
	}
	if got != "plaintext-secret" {
		t.Errorf("OpenBase64 = %q, want plaintext-secret", got)
	}
}

func TestKeySet_OpenBase64InvalidBase64(t *testing.T) {
	t.Parallel()
	ks, err := NewKeySet([]KEKEntry{{ID: 1, Key: freshKey(t)}}, 0)
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	if _, err := ks.OpenBase64("@@@not-base64@@@"); !errors.Is(err, ErrSecretBoxOpen) {
		t.Errorf("err = %v, want ErrSecretBoxOpen on bad base64", err)
	}
}

func TestKeySet_IDsReturnsSortedAscending(t *testing.T) {
	t.Parallel()
	ks, err := NewKeySet([]KEKEntry{
		{ID: 5, Key: freshKey(t)},
		{ID: 1, Key: freshKey(t)},
		{ID: 3, Key: freshKey(t)},
	}, 5)
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	got := ks.IDs()
	want := []uint8{1, 3, 5}
	if len(got) != len(want) {
		t.Fatalf("len(ids) = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ids[%d] = %d, want %d", i, got[i], want[i])
		}
	}
}
