package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
)

// fixedKEK is a 32-byte all-zero key, sufficient for round-trip
// testing — production builds use a real `openssl rand -hex 32`.
const fixedKEK = "0000000000000000000000000000000000000000000000000000000000000000"

func newBox(t *testing.T, kek string) *SecretBox {
	t.Helper()
	box, err := NewSecretBox(kek)
	if err != nil {
		t.Fatalf("NewSecretBox: %v", err)
	}
	return box
}

func TestNewSecretBox_EmptyKEKReturnsNil(t *testing.T) {
	box, err := NewSecretBox("")
	if err != nil {
		t.Fatalf("NewSecretBox(\"\"): %v", err)
	}
	if box != nil {
		t.Fatalf("expected nil box for empty KEK, got %v", box)
	}
}

func TestNewSecretBox_RejectsWrongLengthKEK(t *testing.T) {
	cases := []struct {
		name string
		kek  string
	}{
		{"too short", "deadbeef"},
		{"too long", fixedKEK + "00"},
		{"empty after trim — handled by EmptyKEK case", ""},
	}
	for _, c := range cases[:2] {
		t.Run(c.name, func(t *testing.T) {
			box, err := NewSecretBox(c.kek)
			if err == nil {
				t.Fatalf("expected error for %q, got box=%v", c.name, box)
			}
		})
	}
}

func TestNewSecretBox_RejectsNonHex(t *testing.T) {
	// 64 chars, but with non-hex letters (g/h/i out of [0-9a-f]).
	box, err := NewSecretBox("gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg")
	if err == nil {
		t.Fatalf("expected hex-decode error, got box=%v", box)
	}
}

func TestSealOpen_RoundTrip(t *testing.T) {
	box := newBox(t, fixedKEK)
	plaintexts := [][]byte{
		[]byte("hello"),
		[]byte(""), // empty plaintext is still valid input
		[]byte("a-secret-with-special-chars-!@#$%^&*()"),
		make([]byte, 1024), // 1 KiB of zero bytes
	}
	for i, pt := range plaintexts {
		ct, err := box.Seal(pt)
		if err != nil {
			t.Fatalf("case %d Seal: %v", i, err)
		}
		got, err := box.Open(ct)
		if err != nil {
			t.Fatalf("case %d Open: %v", i, err)
		}
		if string(got) != string(pt) {
			t.Errorf("case %d: round-trip mismatch want=%q got=%q", i, pt, got)
		}
	}
}

func TestSeal_NonceIsRandom(t *testing.T) {
	box := newBox(t, fixedKEK)
	plaintext := []byte("identical-input")
	ct1, _ := box.Seal(plaintext)
	ct2, _ := box.Seal(plaintext)
	if string(ct1) == string(ct2) {
		t.Fatalf("expected different ciphertexts for identical plaintexts (random nonce); got identical")
	}
}

func TestOpen_WrongKeyFails(t *testing.T) {
	boxA := newBox(t, fixedKEK)
	otherKey := make([]byte, 32)
	if _, err := rand.Read(otherKey); err != nil {
		t.Fatal(err)
	}
	boxB := newBox(t, hex.EncodeToString(otherKey))

	ct, err := boxA.Seal([]byte("under key A"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := boxB.Open(ct); !errors.Is(err, ErrSecretBoxOpen) {
		t.Fatalf("expected ErrSecretBoxOpen for wrong key, got %v", err)
	}
}

func TestOpen_TamperedCiphertextFails(t *testing.T) {
	box := newBox(t, fixedKEK)
	ct, _ := box.Seal([]byte("intact"))
	// Flip a byte deep in the ciphertext (past the nonce).
	ct[len(ct)-1] ^= 0x01
	if _, err := box.Open(ct); !errors.Is(err, ErrSecretBoxOpen) {
		t.Fatalf("expected ErrSecretBoxOpen for tampered ct, got %v", err)
	}
}

func TestOpen_TruncatedInputFails(t *testing.T) {
	box := newBox(t, fixedKEK)
	// Anything shorter than the nonce can't even start GCM.
	if _, err := box.Open([]byte{0x00, 0x01}); !errors.Is(err, ErrSecretBoxOpen) {
		t.Fatalf("expected ErrSecretBoxOpen for truncated input, got %v", err)
	}
}

func TestSealOpenBase64_RoundTrip(t *testing.T) {
	box := newBox(t, fixedKEK)
	want := "an-actual-webhook-secret-32-bytes-long-or-so"
	b64, err := box.SealBase64(want)
	if err != nil {
		t.Fatalf("SealBase64: %v", err)
	}
	got, err := box.OpenBase64(b64)
	if err != nil {
		t.Fatalf("OpenBase64: %v", err)
	}
	if got != want {
		t.Errorf("base64 round-trip mismatch want=%q got=%q", want, got)
	}
}

func TestOpenBase64_NonBase64Fails(t *testing.T) {
	box := newBox(t, fixedKEK)
	if _, err := box.OpenBase64("not!base64@@"); !errors.Is(err, ErrSecretBoxOpen) {
		t.Fatalf("expected ErrSecretBoxOpen for non-base64 input, got %v", err)
	}
}
