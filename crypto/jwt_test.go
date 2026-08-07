package crypto

import (
	"encoding/base64"
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

// Token-purpose discrimination. The totp-pending session token and the
// access JWT are signed with the SAME secret and differ only by the
// `purpose` claim, so each Verify* entry point must refuse the other's
// token.
//
// The regression these pin: VerifyTOTPPending had always checked
// purpose, but VerifyAccess never did — so the pending token handed to
// the client after a password-only login (espresso/authroutes.go
// returns it in the 200 body as SessionToken) verified cleanly as a
// full access token and authenticated every RequireAuth route for its
// 5-minute lifetime. A complete 2FA bypass for an attacker holding
// only the password. The doc on totpPendingClaims had claimed the
// bidirectional guard existed since v0.8; only one direction did.

func TestVerifyAccess_RejectsTOTPPendingToken(t *testing.T) {
	svc := newTestJWT(t, "s3cr3t")
	pending, err := svc.IssueTOTPPending("u-42")
	if err != nil {
		t.Fatalf("IssueTOTPPending: %v", err)
	}

	if _, err := svc.VerifyAccess(pending); err == nil {
		t.Fatal("VerifyAccess accepted a totp-pending token — 2FA bypass")
	} else if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("VerifyAccess err %v: not wrapping ErrInvalidToken", err)
	}

	// Verify() shares the VerifyAccess path, so it must reject too —
	// it is the other exported entry point onto the same token.
	if _, err := svc.Verify(pending); err == nil {
		t.Fatal("Verify accepted a totp-pending token — 2FA bypass")
	}
}

func TestVerifyTOTPPending_RejectsAccessToken(t *testing.T) {
	svc := newTestJWT(t, "s3cr3t")
	access, err := svc.IssueAccess("u-42", 1733574000, ACRIncommonSilver)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}

	if _, err := svc.VerifyTOTPPending(access); err == nil {
		t.Fatal("VerifyTOTPPending accepted an access token")
	} else if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("VerifyTOTPPending err %v: not wrapping ErrInvalidToken", err)
	}
}

func TestIssueAccess_StampsPurpose(t *testing.T) {
	svc := newTestJWT(t, "s3cr3t")
	tok, err := svc.IssueAccess("u-42", 1733574000, ACRIncommonSilver)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	claims, err := svc.VerifyAccess(tok)
	if err != nil {
		t.Fatalf("VerifyAccess: %v", err)
	}
	if claims.Purpose != purposeAccess {
		t.Errorf("Purpose = %q, want %q", claims.Purpose, purposeAccess)
	}
}

func TestVerifyAccess_RejectsUnknownPurpose(t *testing.T) {
	// A future token shape minted under the same secret must not be
	// accepted as an access token just because its purpose is unknown.
	secret := []byte("s3cr3t")
	now := time.Now()
	claims := struct {
		Purpose string `json:"purpose"`
		jwt.RegisteredClaims
	}{
		Purpose: "password_reset",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "u-1",
			Issuer:    "barista-test",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	svc := newTestJWT(t, "s3cr3t")
	if _, err := svc.VerifyAccess(tok); err == nil {
		t.Fatal("VerifyAccess accepted a token with an unknown purpose")
	} else if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("VerifyAccess err %v: not wrapping ErrInvalidToken", err)
	}
}

func TestVerifyAccess_AcceptsLegacyTokenWithoutPurpose(t *testing.T) {
	// Rollout guard. Access JWTs already in the wild when this fix
	// deploys carry no purpose claim. If they were rejected, every live
	// session would 401 at once. An absent purpose must still verify;
	// only a non-empty foreign purpose rejects. The claim cannot be
	// stripped from a pending token without the signing secret, so the
	// tolerance does not reopen the bypass.
	secret := []byte("s3cr3t")
	now := time.Now()
	claims := AccessClaims{
		AuthTime: now.Unix(),
		ACR:      ACRIncommonSilver,
		// Purpose deliberately unset — the pre-fix wire shape.
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "u-legacy",
			Issuer:    "barista-test",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// Assert the WIRE shape, not the encoded string: decode the payload
	// segment so this actually proves omitempty dropped the claim.
	segs := strings.Split(tok, ".")
	if len(segs) != 3 {
		t.Fatalf("test setup: malformed JWT with %d segments", len(segs))
	}
	raw, derr := base64.RawURLEncoding.DecodeString(segs[1])
	if derr != nil {
		t.Fatalf("test setup: decode payload: %v", derr)
	}
	if strings.Contains(string(raw), "purpose") {
		t.Fatalf("test setup: legacy token should carry no purpose claim, got %s", raw)
	}

	svc := newTestJWT(t, "s3cr3t")
	got, err := svc.VerifyAccess(tok)
	if err != nil {
		t.Fatalf("VerifyAccess rejected a legacy no-purpose token: %v", err)
	}
	if got.Subject != "u-legacy" {
		t.Errorf("Subject = %q, want %q", got.Subject, "u-legacy")
	}
	if got.Purpose != "" {
		t.Errorf("Purpose = %q, want empty", got.Purpose)
	}
}

// --- Phase 7 slice 7c-1: the `tid` claim ---------------------------

// pinnedPre7cToken is a REAL access token minted by this service BEFORE
// the tid claim existed, captured from the code at 7b-3 and pasted here
// verbatim. It is the fixed point every byte-identity claim in this file
// is measured against: a value produced by the old code cannot drift
// when the new code changes, which a freshly-computed expectation could.
const (
	pinnedSecret  = "pin-secret"
	pinnedIssuer  = "pin-issuer"
	pinnedSubject = "user-1"
	pinnedNow     = 1700000000
	pinnedAuthAt  = 1699999000

	pinnedPre7cPayload = "eyJhdXRoX3RpbWUiOjE2OTk5OTkwMDAsImFjciI6InVybjp0YW1wZXI6YXV0aDpsb2NhbC1wYXNzd29yZCIsInB1cnBvc2UiOiJhY2Nlc3MiLCJpc3MiOiJwaW4taXNzdWVyIiwic3ViIjoidXNlci0xIiwiZXhwIjoxNzAwMDAzNjAwLCJpYXQiOjE3MDAwMDAwMDB9"

	pinnedPre7cToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + pinnedPre7cPayload +
		".AJXqC7-FmGqvpioil-LBHnweaYrqTafXSI3XRdVkmLk"
)

func pinnedService(t *testing.T) *JWTService {
	t.Helper()
	s := NewJWTService(JWTConfig{Secret: pinnedSecret, TTL: time.Hour, Issuer: pinnedIssuer})
	s.Testing().SetNow(func() time.Time { return time.Unix(pinnedNow, 0).UTC() })
	return s
}

// TestIssueAccess_NoTenantIsByteIdenticalToPre7c is the invariant that
// makes this claim free for single-tenant deployments. The assertion is
// on the ENCODED payload, not the parsed struct, because a struct
// comparison cannot see the thing that would break: a `"tid":""` key
// appearing on the wire. Every existing token would change shape, and
// anything pinning a token — a golden fixture, a cached signature, an
// audit row — would break on deploy.
func TestIssueAccess_NoTenantIsByteIdenticalToPre7c(t *testing.T) {
	s := pinnedService(t)

	tok, err := s.IssueAccess(pinnedSubject, pinnedAuthAt, ACRLocalPassword)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3", len(parts))
	}
	if parts[1] != pinnedPre7cPayload {
		t.Errorf("encoded payload drifted from the pre-7c token.\n got: %s\nwant: %s\n"+
			"A no-tenant token must be byte-identical to one minted before the tid claim "+
			"existed — check that omitempty is still on TenantID.", parts[1], pinnedPre7cPayload)
	}
	// The signature covers header+payload, so a whole-token match proves
	// the header did not move either.
	if tok != pinnedPre7cToken {
		t.Errorf("full token drifted:\n got: %s\nwant: %s", tok, pinnedPre7cToken)
	}
}

// TestIssueAccessForTenant_EmptyTenantMatchesIssueAccess pins the
// delegation: the two entry points must produce the same bytes for the
// single-tenant case, or there are two mint paths that can drift.
func TestIssueAccessForTenant_EmptyTenantMatchesIssueAccess(t *testing.T) {
	s := pinnedService(t)

	plain, err := s.IssueAccess(pinnedSubject, pinnedAuthAt, ACRLocalPassword)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	viaTenant, err := s.IssueAccessForTenant(pinnedSubject, "", pinnedAuthAt, ACRLocalPassword)
	if err != nil {
		t.Fatalf("IssueAccessForTenant: %v", err)
	}
	if plain != viaTenant {
		t.Errorf("empty-tenant mint differs from IssueAccess:\n  %s\n  %s", plain, viaTenant)
	}
}

// TestIssueAccessForTenant_RoundTrip: a tenant goes in, the same tenant
// comes out, and the claim is actually on the wire.
func TestIssueAccessForTenant_RoundTrip(t *testing.T) {
	s := pinnedService(t)

	tok, err := s.IssueAccessForTenant(pinnedSubject, "acme", pinnedAuthAt, ACRIncommonSilver)
	if err != nil {
		t.Fatalf("IssueAccessForTenant: %v", err)
	}
	claims, err := s.VerifyAccess(tok)
	if err != nil {
		t.Fatalf("VerifyAccess: %v", err)
	}
	if claims.TenantID != "acme" {
		t.Errorf("TenantID = %q, want %q", claims.TenantID, "acme")
	}
	if claims.Subject != pinnedSubject || claims.ACR != ACRIncommonSilver {
		t.Errorf("other claims disturbed: %+v", claims)
	}

	// The claim is `tid` on the wire, not the Go field name. Decode the
	// payload rather than trusting the struct tag by inspection.
	payload := decodeSegment(t, tok)
	if !strings.Contains(payload, `"tid":"acme"`) {
		t.Errorf("payload does not carry tid: %s", payload)
	}
}

// TestVerifyAccess_LegacyTokenReadsEmptyTenant is the legacy-tolerance
// half. The token below was minted before the claim existed; it must
// still verify, and its tenant must read as "" rather than failing.
func TestVerifyAccess_LegacyTokenReadsEmptyTenant(t *testing.T) {
	s := pinnedService(t)

	claims, err := s.VerifyAccess(pinnedPre7cToken)
	if err != nil {
		t.Fatalf("a pre-7c token no longer verifies: %v — this would log out every existing "+
			"session on the deploy that adds tenancy", err)
	}
	if claims.TenantID != "" {
		t.Errorf("legacy token TenantID = %q, want empty", claims.TenantID)
	}
	if claims.Subject != pinnedSubject {
		t.Errorf("Subject = %q, want %q", claims.Subject, pinnedSubject)
	}
}

// TestIssueAccessForTenant_RejectionsUnchanged: adding a parameter must
// not weaken the existing guards.
func TestIssueAccessForTenant_RejectionsUnchanged(t *testing.T) {
	s := pinnedService(t)
	for _, tc := range []struct {
		name     string
		subject  string
		authTime int64
		acr      string
	}{
		{"empty subject", "", pinnedAuthAt, ACRLocalPassword},
		{"zero auth_time", pinnedSubject, 0, ACRLocalPassword},
		{"negative auth_time", pinnedSubject, -1, ACRLocalPassword},
		{"empty acr", pinnedSubject, pinnedAuthAt, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := s.IssueAccessForTenant(tc.subject, "acme", tc.authTime, tc.acr); !errors.Is(err, ErrInvalidToken) {
				t.Errorf("err = %v, want ErrInvalidToken", err)
			}
		})
	}
}

// decodeSegment returns the token's decoded payload as a string.
func decodeSegment(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	return string(raw)
}
