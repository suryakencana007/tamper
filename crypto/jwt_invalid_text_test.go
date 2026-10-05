package crypto

import (
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/suryakencana007/tamper/tenant"
)

// invalidTokenText is the one string every verification failure prints.
const invalidTokenText = "auth: invalid token: token not valid"

// TestInvalidToken_EveryFailureHasTheSameText: the error TEXT must not
// say which check failed. The case that matters is the wrong-tenant one.
// "Expired" or "bad signature" says the token is no good; a text of its
// own for a wrong tenant says the token is genuine and aimed elsewhere,
// which tells the holder that tenant accepted it. With one text for
// every failure, an adapter or a log line that prints the error
// discloses nothing.
func TestInvalidToken_EveryFailureHasTheSameText(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	svc := newTestJWT(t, "secret-one")
	svc.Testing().SetNow(func() time.Time { return now })
	other := newTestJWT(t, "secret-two")
	other.Testing().SetNow(func() time.Time { return now })
	acme, globex := tenant.New("acme"), tenant.New("globex")

	access := func(j *JWTService, tid tenant.ID) string {
		t.Helper()
		tok, err := j.IssueAccess("user-1", tid, now.Unix(), ACRLocalPassword)
		if err != nil {
			t.Fatalf("IssueAccess: %v", err)
		}
		return tok
	}
	pending := func(tid tenant.ID) string {
		t.Helper()
		tok, err := svc.IssueTOTPPending("user-1", tid)
		if err != nil {
			t.Fatalf("IssueTOTPPendingInTenant: %v", err)
		}
		return tok
	}
	// A token that was valid, read one hour after it expired.
	late := newTestJWT(t, "secret-one")
	late.Testing().SetNow(func() time.Time { return now.Add(2 * time.Hour) })

	verifyAccess := func(j *JWTService, tok string, tid tenant.ID) error {
		_, err := j.VerifyAccess(tok, tid)
		return err
	}
	verifyPending := func(tok string, tid tenant.ID) error {
		_, err := svc.VerifyTOTPPending(tok, tid)
		return err
	}

	for name, err := range map[string]error{
		"garbage":                          verifyAccess(svc, "not-a-token", acme),
		"empty":                            verifyAccess(svc, "", acme),
		"signed with another key":          verifyAccess(svc, access(other, acme), acme),
		"expired":                          verifyAccess(late, access(svc, acme), acme),
		"wrong tenant":                     verifyAccess(svc, access(svc, globex), acme),
		"no tid on a tenant route":         verifyAccess(svc, access(svc, tenant.Single), acme),
		"tid on a single-tenant route":     verifyAccess(svc, access(svc, acme), tenant.Single),
		"pending token used as access":     verifyAccess(svc, pending(acme), acme),
		"access token used as pending":     verifyPending(access(svc, acme), acme),
		"pending token for another tenant": verifyPending(pending(globex), acme),
		"pending garbage":                  verifyPending("not-a-token", acme),
	} {
		if err == nil {
			t.Errorf("%s: verified, want a rejection", name)
			continue
		}
		if !errors.Is(err, ErrInvalidToken) {
			t.Errorf("%s: err = %v, want ErrInvalidToken", name, err)
		}
		if err.Error() != invalidTokenText {
			t.Errorf("%s: text = %q, want %q — the message says which check failed", name, err.Error(), invalidTokenText)
		}
	}

	// ParseAccess has the same rule, with no tenant to check.
	if _, err := svc.ParseAccess(pending(acme)); err == nil || err.Error() != invalidTokenText {
		t.Errorf("ParseAccess(pending token): err = %v, want the fixed text", err)
	}
}

// The reason is kept, for server-side code that asks for it. It is in
// the error chain and never in the text.
func TestInvalidToken_CauseIsReachableButNotPrinted(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	svc := newTestJWT(t, "secret-one")
	svc.Testing().SetNow(func() time.Time { return now })
	tok, err := svc.IssueAccess("user-1", tenant.New("acme"), now.Unix(), ACRLocalPassword)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}

	svc.Testing().SetNow(func() time.Time { return now.Add(2 * time.Hour) })
	_, expired := svc.VerifyAccess(tok, tenant.New("acme"))
	if !errors.Is(expired, jwt.ErrTokenExpired) {
		t.Errorf("the expiry cause is not in the chain: %v", expired)
	}

	svc.Testing().SetNow(func() time.Time { return now })
	_, wrongTenant := svc.VerifyAccess(tok, tenant.New("globex"))
	if !errors.Is(wrongTenant, errWrongTenant) {
		t.Errorf("the tenant cause is not in the chain: %v", wrongTenant)
	}
	if errors.Is(wrongTenant, jwt.ErrTokenExpired) || errors.Is(expired, errWrongTenant) {
		t.Error("the two causes are not told apart in the chain")
	}
	if expired.Error() != wrongTenant.Error() {
		t.Errorf("the texts differ: %q vs %q", expired, wrongTenant)
	}
}

// The delegated-signer path (WithSigner / WithVerifiers) follows the
// same rule: an unknown kid and a bad signature print the same text.
func TestInvalidToken_DelegatedPathHasTheSameText(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	mk := func(secret string) *JWTService {
		j := NewJWTService(JWTConfig{TTL: time.Hour, Issuer: "barista-test"}, WithSigner(NewHS256Signer([]byte(secret))))
		j.Testing().SetNow(func() time.Time { return now })
		return j
	}
	a, b := mk("key-a"), mk("key-b")
	tok, err := a.IssueAccess("user-1", tenant.Single, now.Unix(), ACRLocalPassword)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	if _, err := a.VerifyAccess(tok, tenant.Single); err != nil {
		t.Fatalf("fixture: the signer's own token should verify: %v", err)
	}
	for name, err := range map[string]error{
		"another key": func() error { _, e := b.VerifyAccess(tok, tenant.Single); return e }(),
		"garbage":     func() error { _, e := a.VerifyAccess("a.b", tenant.Single); return e }(),
		"bad base64":  func() error { _, e := a.VerifyAccess("!.!.!", tenant.Single); return e }(),
	} {
		if err == nil || !errors.Is(err, ErrInvalidToken) || err.Error() != invalidTokenText {
			t.Errorf("%s: err = %v, want ErrInvalidToken with the fixed text", name, err)
		}
	}
}
