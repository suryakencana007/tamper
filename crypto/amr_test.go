package crypto

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/suryakencana007/tamper/tenant"
)

// amrJWT is this file's own service so the helper name cannot collide with the other
// test files' fixtures.
func amrJWT(t *testing.T) *JWTService {
	t.Helper()
	return NewJWTService(JWTConfig{Secret: "tamper-amr-test-secret", TTL: time.Hour, Issuer: "tamper-test"})
}

// Phase 16 (D3'): `amr` names the METHODS a session proved, so a gate can ask
// "was a second factor used?" without inventing an ACR that lies about the class.

func TestAccessClaims_AMRRoundTrips(t *testing.T) {
	j := amrJWT(t)
	tok, err := j.IssueAccess("u-1", tenant.New("acme"), 1_700_000_000, ACRLocalPassword, AMRPassword, AMROTP)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	claims, err := j.VerifyAccess(tok, tenant.New("acme"))
	if err != nil {
		t.Fatalf("VerifyAccess: %v", err)
	}
	if !claims.HasMethod(AMRPassword) || !claims.HasMethod(AMROTP) {
		t.Fatalf("amr = %v, want [pwd otp]", claims.AMR)
	}
	if claims.HasMethod(AMRSAML) {
		t.Fatalf("amr = %v claims saml", claims.AMR)
	}
	// ACR is untouched by this: it is still the policy class.
	if claims.ACR != ACRLocalPassword {
		t.Fatalf("acr = %q, want %q — amr must not change the class", claims.ACR, ACRLocalPassword)
	}
}

// Source compatibility: every existing two-argument call still compiles and mints a token
// with no amr at all, which HasMethod reports as "no" rather than panicking.
func TestIssueAccess_WithoutAMRStaysAsItWas(t *testing.T) {
	j := amrJWT(t)
	tok, err := j.IssueAccess("u-1", tenant.New("acme"), 1_700_000_000, ACRLocalPassword)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	claims, err := j.VerifyAccess(tok, tenant.New("acme"))
	if err != nil {
		t.Fatalf("VerifyAccess: %v", err)
	}
	if len(claims.AMR) != 0 {
		t.Fatalf("amr = %v, want none", claims.AMR)
	}
	if claims.HasMethod(AMRPassword) {
		t.Fatal("HasMethod reported a method the token never named")
	}
	// The wire has no amr key at all, so an old verifier sees the same payload.
	if strings.Contains(tok, "amr") {
		t.Fatal("a token with no amr must not carry the claim on the wire")
	}
}

func TestIssueAccess_RefusesAnEmptyMethod(t *testing.T) {
	j := amrJWT(t)
	if _, err := j.IssueAccess("u-1", tenant.New("acme"), 1_700_000_000, ACRLocalPassword, AMRPassword, ""); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken for an empty method", err)
	}
}

func TestHasMethod_NilAndEmpty(t *testing.T) {
	var nilClaims *AccessClaims
	if nilClaims.HasMethod(AMRPassword) {
		t.Fatal("nil claims must not report a method")
	}
	if (&AccessClaims{}).HasMethod(AMROTP) {
		t.Fatal("claims with no amr must not report a method")
	}
	if (&AccessClaims{AMR: []string{AMROTP}}).HasMethod("") {
		t.Fatal("an empty method name must never match")
	}
}

// The entered and impersonated mints carry it too, so a guest session says which methods
// produced it rather than silently losing the information at the second hop.
func TestAMR_CarriedByEnteredAndImpersonatedMints(t *testing.T) {
	j := amrJWT(t)
	entered, err := j.IssueAccessEntered("u-1", tenant.New("acme"), tenant.New("platform"),
		1_700_000_000, ACRIncommonSilver, 5_000_000_000, AMRPassword, AMROTP)
	if err != nil {
		t.Fatalf("IssueAccessEntered: %v", err)
	}
	c, err := j.VerifyAccess(entered, tenant.New("acme"))
	if err != nil {
		t.Fatalf("VerifyAccess(entered): %v", err)
	}
	if !c.HasMethod(AMROTP) {
		t.Fatalf("entered amr = %v, want otp present", c.AMR)
	}

	imp, err := j.IssueAccessImpersonated("bob", "ops", tenant.New("acme"), tenant.New("platform"),
		1_700_000_000, ACRIncommonSilver, 5_000_000_000, AMRPassword)
	if err != nil {
		t.Fatalf("IssueAccessImpersonated: %v", err)
	}
	c2, err := j.VerifyAccess(imp, tenant.New("acme"))
	if err != nil {
		t.Fatalf("VerifyAccess(impersonated): %v", err)
	}
	if !c2.HasMethod(AMRPassword) || c2.HasMethod(AMROTP) {
		t.Fatalf("impersonated amr = %v, want [pwd]", c2.AMR)
	}
}
