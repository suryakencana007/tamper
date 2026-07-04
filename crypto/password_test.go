package crypto

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestMain(m *testing.M) {
	// bcrypt at cost 12 costs ~100-200ms per op; drop to MinCost so the
	// test suite stays snappy, especially under -race.
	prev := Cost
	Cost = bcrypt.MinCost
	defer func() { Cost = prev }()
	m.Run()
}

func TestHashPassword_ReturnsBcryptHash(t *testing.T) {
	h, err := HashPassword("hunter2")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(h, "$2a$") && !strings.HasPrefix(h, "$2y$") && !strings.HasPrefix(h, "$2b$") {
		t.Errorf("hash %q does not look like bcrypt", h)
	}
	if h == "hunter2" {
		t.Errorf("hash equals plain")
	}
}

func TestHashPassword_RejectsEmpty(t *testing.T) {
	h, err := HashPassword("")
	if err == nil {
		t.Fatalf("expected error, got hash %q", h)
	}
	if !errors.Is(err, ErrInvalidPassword) {
		t.Errorf("error %v: not wrapping ErrInvalidPassword", err)
	}
}

func TestVerifyPassword_RoundTrip(t *testing.T) {
	h, err := HashPassword("hunter2")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := VerifyPassword(h, "hunter2"); err != nil {
		t.Errorf("VerifyPassword: unexpected error %v", err)
	}
}

func TestVerifyPassword_WrongPassword(t *testing.T) {
	h, err := HashPassword("hunter2")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	err = VerifyPassword(h, "wrong")
	if err == nil {
		t.Fatalf("expected error for wrong password")
	}
	if !errors.Is(err, ErrInvalidPassword) {
		t.Errorf("error %v: not wrapping ErrInvalidPassword", err)
	}
}

func TestVerifyPassword_MalformedHash(t *testing.T) {
	err := VerifyPassword("not-a-bcrypt-hash", "hunter2")
	if err == nil {
		t.Fatalf("expected error for malformed hash")
	}
	if !errors.Is(err, ErrInvalidPassword) {
		t.Errorf("error %v: not wrapping ErrInvalidPassword", err)
	}
}

func TestHashPassword_TwoCallsDifferentHashes(t *testing.T) {
	h1, _ := HashPassword("hunter2")
	h2, _ := HashPassword("hunter2")
	if h1 == h2 {
		t.Errorf("identical hashes for identical inputs — bcrypt salt not applied?")
	}
	if err := VerifyPassword(h1, "hunter2"); err != nil {
		t.Errorf("h1 verify: %v", err)
	}
	if err := VerifyPassword(h2, "hunter2"); err != nil {
		t.Errorf("h2 verify: %v", err)
	}
}

func TestVerifyStub_AlwaysReturnsInvalidPassword(t *testing.T) {
	// The stub is used on "user not found" branches to pay the bcrypt
	// cost; the caller doesn't care what plain is.
	cases := []string{"", "short", "correct-horse-battery-staple", strings.Repeat("a", 72)}
	for _, plain := range cases {
		if err := VerifyStub(plain); err == nil {
			t.Errorf("VerifyStub(%q): expected error, got nil", plain)
		} else if !errors.Is(err, ErrInvalidPassword) {
			t.Errorf("VerifyStub(%q): error %v not wrapping ErrInvalidPassword", plain, err)
		}
	}
}

func TestVerifyStub_ProducesBcryptHashOnFirstCall(t *testing.T) {
	// Indirect check that stubHashBytes actually produces a bcrypt hash
	// rather than sitting at nil. We reach through the test-package-local
	// accessor so we don't expose internals to callers.
	if err := VerifyStub("anything"); err == nil {
		t.Fatalf("VerifyStub: expected error")
	}
	if len(stubHash) == 0 || stubHashErr != nil {
		t.Fatalf("stubHash not initialised after VerifyStub: len=%d err=%v", len(stubHash), stubHashErr)
	}
	if !strings.HasPrefix(string(stubHash), "$2") {
		t.Errorf("stubHash does not look like bcrypt: %q", string(stubHash))
	}
}
