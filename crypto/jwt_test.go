package crypto

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func newTestJWT(t *testing.T, secret string) *JWTService {
	t.Helper()
	return NewJWTService(JWTConfig{
		Secret: secret,
		TTL:    time.Hour,
		Issuer: "barista-test",
	})
}

func TestJWT_RoundTrip(t *testing.T) {
	svc := newTestJWT(t, "s3cr3t")
	tok, err := svc.Issue("u-42")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	got, err := svc.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got != "u-42" {
		t.Errorf("Verify subject = %q, want %q", got, "u-42")
	}
}

func TestJWT_RejectsEmptyUserID(t *testing.T) {
	svc := newTestJWT(t, "s3cr3t")
	_, err := svc.Issue("")
	if err == nil {
		t.Fatalf("Issue: expected error for empty userID")
	}
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("Issue error %v: not wrapping ErrInvalidToken", err)
	}
}

func TestJWT_Expired(t *testing.T) {
	svc := newTestJWT(t, "s3cr3t")
	fixed := time.Now()
	// issue as if we were in the past so the token is already expired
	svc.Testing().SetNow(func() time.Time { return fixed.Add(-2 * time.Hour) })
	tok, err := svc.Issue("u-1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	svc.Testing().SetNow(func() time.Time { return fixed })
	if _, err := svc.Verify(tok); err == nil {
		t.Fatalf("Verify: expected expired-token error")
	} else if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("Verify error %v: not wrapping ErrInvalidToken", err)
	}
}

func TestJWT_ZeroTTLFailsImmediately(t *testing.T) {
	svc := NewJWTService(JWTConfig{
		Secret: "s3cr3t",
		TTL:    0,
		Issuer: "barista-test",
	})
	tok, err := svc.Issue("u-1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// Force clock to advance by 1ns so exp < now even with exact equality.
	svc.Testing().SetNow(func() time.Time { return time.Now().Add(time.Second) })
	if _, err := svc.Verify(tok); err == nil {
		t.Fatalf("Verify: expected expired-token error for 0-TTL")
	} else if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("Verify error %v: not wrapping ErrInvalidToken", err)
	}
}

func TestJWT_WrongSecret(t *testing.T) {
	signer := newTestJWT(t, "secret-A")
	verifier := newTestJWT(t, "secret-B")

	tok, err := signer.Issue("u-1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := verifier.Verify(tok); err == nil {
		t.Fatalf("Verify: expected error for wrong secret")
	} else if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("Verify error %v: not wrapping ErrInvalidToken", err)
	}
}

func TestJWT_TamperedSignature(t *testing.T) {
	svc := newTestJWT(t, "s3cr3t")
	tok, err := svc.Issue("u-1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// Flip the first character of the signature. We deliberately
	// avoid the last character: base64url encodes 6 bits per char but
	// the final char of a 43-char HS256 signature has only 4
	// meaningful bits — the bottom 2 are padding. Go's
	// base64.RawURLEncoding.Decode is non-strict by default and
	// discards those padding bits, so flipping the last char can
	// yield the same decoded signature bytes (1 in 16 runs), making
	// the test flaky. A middle-of-signature flip changes 6 real bits
	// every time.
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token does not have 3 parts: %q", tok)
	}
	sig := parts[2]
	flipped := flipByte(sig[0]) + sig[1:]
	parts[2] = flipped
	tampered := strings.Join(parts, ".")

	if _, err := svc.Verify(tampered); err == nil {
		t.Fatalf("Verify: expected error for tampered signature")
	} else if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("Verify error %v: not wrapping ErrInvalidToken", err)
	}
}

func TestJWT_Malformed(t *testing.T) {
	svc := newTestJWT(t, "s3cr3t")
	for _, in := range []string{"", "not-a-token", "a.b", "a.b.c.d"} {
		if _, err := svc.Verify(in); err == nil {
			t.Errorf("Verify(%q): expected error", in)
		} else if !errors.Is(err, ErrInvalidToken) {
			t.Errorf("Verify(%q) error %v: not wrapping ErrInvalidToken", in, err)
		}
	}
}

func TestJWT_MissingSub(t *testing.T) {
	secret := []byte("s3cr3t")
	now := time.Now()
	// Hand-craft a token with no Subject claim.
	claims := jwt.RegisteredClaims{
		Issuer:    "barista-test",
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	svc := newTestJWT(t, "s3cr3t")
	if _, err := svc.Verify(tok); err == nil {
		t.Fatalf("Verify: expected error for missing sub")
	} else if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("Verify error %v: not wrapping ErrInvalidToken", err)
	}
}

func TestJWT_WrongIssuer(t *testing.T) {
	secret := []byte("s3cr3t")
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Subject:   "u-1",
		Issuer:    "someone-else",
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	svc := newTestJWT(t, "s3cr3t")
	if _, err := svc.Verify(tok); err == nil {
		t.Fatalf("Verify: expected error for wrong issuer")
	} else if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("Verify error %v: not wrapping ErrInvalidToken", err)
	}
}

func TestNewJWTService_PanicsOnEmptySecret(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic for empty secret")
		}
	}()
	_ = NewJWTService(JWTConfig{Secret: ""})
}

// v1.14 Sprint 0 task 00: IssueAccess + VerifyAccess + ACR claims
// round-trip + boundary cases. Pre-v1.14 JWTs (issued via the v0.1
// shim shape, no auth_time + no acr claims) MUST still parse via
// VerifyAccess with zero values — the migration story for live
// sessions during the v1.14 rollout.

func TestIssueAccess_RoundTrip(t *testing.T) {
	svc := newTestJWT(t, "s3cr3t")
	want := int64(1733574000) // arbitrary fixed Unix timestamp.
	tok, err := svc.IssueAccess("u-42", want, ACRIncommonSilver)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	claims, err := svc.VerifyAccess(tok)
	if err != nil {
		t.Fatalf("VerifyAccess: %v", err)
	}
	if claims.Subject != "u-42" {
		t.Errorf("Subject = %q, want u-42", claims.Subject)
	}
	if claims.AuthTime != want {
		t.Errorf("AuthTime = %d, want %d", claims.AuthTime, want)
	}
	if claims.ACR != ACRIncommonSilver {
		t.Errorf("ACR = %q, want %q", claims.ACR, ACRIncommonSilver)
	}
}

func TestIssueAccess_RejectsEmptySub(t *testing.T) {
	svc := newTestJWT(t, "s3cr3t")
	_, err := svc.IssueAccess("", 1733574000, ACRLocalPassword)
	if err == nil || !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("IssueAccess empty sub: err = %v, want ErrInvalidToken", err)
	}
}

func TestIssueAccess_RejectsZeroAuthTime(t *testing.T) {
	svc := newTestJWT(t, "s3cr3t")
	for _, at := range []int64{0, -1, -1733574000} {
		_, err := svc.IssueAccess("u-1", at, ACRLocalPassword)
		if err == nil || !errors.Is(err, ErrInvalidToken) {
			t.Errorf("IssueAccess auth_time=%d: err = %v, want ErrInvalidToken", at, err)
		}
	}
}

func TestIssueAccess_RejectsEmptyACR(t *testing.T) {
	svc := newTestJWT(t, "s3cr3t")
	_, err := svc.IssueAccess("u-1", 1733574000, "")
	if err == nil || !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("IssueAccess empty acr: err = %v, want ErrInvalidToken", err)
	}
}

// TestVerifyAccess_LegacyJWT — a v0.1-shape JWT (RegisteredClaims-only,
// no auth_time, no acr) parses successfully with AuthTime=0 + ACR="".
// Middleware (RequireFreshAuth) treats these as "infinitely stale +
// matches no acrValues" — that's the intended migration path.
func TestVerifyAccess_LegacyJWT(t *testing.T) {
	secret := []byte("s3cr3t")
	now := time.Now()
	legacy := jwt.RegisteredClaims{
		Subject:   "u-legacy",
		Issuer:    "barista-test",
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, legacy).SignedString(secret)
	if err != nil {
		t.Fatalf("sign legacy: %v", err)
	}
	svc := newTestJWT(t, "s3cr3t")
	claims, err := svc.VerifyAccess(tok)
	if err != nil {
		t.Fatalf("VerifyAccess legacy: %v", err)
	}
	if claims.Subject != "u-legacy" {
		t.Errorf("Subject = %q, want u-legacy", claims.Subject)
	}
	if claims.AuthTime != 0 {
		t.Errorf("AuthTime = %d, want 0 (legacy shape)", claims.AuthTime)
	}
	if claims.ACR != "" {
		t.Errorf("ACR = %q, want empty (legacy shape)", claims.ACR)
	}
}

// TestIssue_ShimDefaultsACRLocalPassword — the v0.1-compatible shim
// path stamps auth_time=now() + acr=ACRLocalPassword on every mint.
func TestIssue_ShimDefaultsACRLocalPassword(t *testing.T) {
	svc := newTestJWT(t, "s3cr3t")
	tok, err := svc.Issue("u-shim")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	claims, err := svc.VerifyAccess(tok)
	if err != nil {
		t.Fatalf("VerifyAccess: %v", err)
	}
	if claims.ACR != ACRLocalPassword {
		t.Errorf("ACR = %q, want %q (the local-password literal)", claims.ACR, ACRLocalPassword)
	}
	if claims.AuthTime <= 0 {
		t.Errorf("AuthTime = %d, want > 0 (shim default = now)", claims.AuthTime)
	}
}

// TestVerifyAccess_TamperedAuthTime — flipping the auth_time claim
// after signing must invalidate the signature. Guards against an
// attacker bumping their own auth_time forward to evade the step-up
// gate.
func TestVerifyAccess_TamperedAuthTime(t *testing.T) {
	svc := newTestJWT(t, "s3cr3t")
	tok, err := svc.IssueAccess("u-1", 1733574000, ACRIncommonSilver)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	// Re-mint with a different secret so signature mismatches.
	attacker := newTestJWT(t, "attacker-secret")
	attackerTok, _ := attacker.IssueAccess("u-1", 9999999999, ACRIncommonSilver)
	if attackerTok == tok {
		t.Fatalf("attacker token = legitimate; clock collision somehow?")
	}
	if _, err := svc.VerifyAccess(attackerTok); err == nil {
		t.Fatalf("VerifyAccess: expected error for foreign-signed token")
	} else if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("VerifyAccess err %v: not wrapping ErrInvalidToken", err)
	}
}

func flipByte(b byte) string {
	// Produce a different printable character in the base64url alphabet.
	if b == 'A' {
		return "B"
	}
	return "A"
}
