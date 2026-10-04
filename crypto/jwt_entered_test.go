package crypto

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/suryakencana007/tamper/tenant"
)

// payloadKeys returns the claim names in a token's payload.
func payloadKeys(t *testing.T, tok string) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", tok)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return out
}

// An entered token is FOR one tenant and FROM another. It verifies
// where an ordinary token for the target tenant verifies, and nowhere
// else — in particular not in its own home tenant.
func TestIssueAccessEntered_IsForTheTargetAndFromTheHome(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	svc := newTestJWT(t, "secret")
	svc.Testing().SetNow(func() time.Time { return now })
	acme, globex, platform := tenant.New("acme"), tenant.New("globex"), tenant.New("platform")

	tok, err := svc.IssueAccessEntered("admin-1", acme, platform, now.Unix(), ACRLocalPassword, 0)
	if err != nil {
		t.Fatalf("IssueAccessEntered: %v", err)
	}

	claims, err := svc.VerifyAccess(tok, acme)
	if err != nil {
		t.Fatalf("an entered token for acme does not verify for acme: %v", err)
	}
	if claims.TenantID != "acme" || claims.HomeTenantID != "platform" {
		t.Errorf("tid=%q htid=%q, want acme / platform", claims.TenantID, claims.HomeTenantID)
	}
	if got := claims.ActorTenantID(); got != "platform" {
		t.Errorf("ActorTenantID = %q, want the home tenant %q", got, "platform")
	}
	if claims.Subject != "admin-1" {
		t.Errorf("sub = %q, want admin-1", claims.Subject)
	}

	// htid grants nothing: the token is not valid for its home tenant,
	// nor for a third tenant, nor on an untenanted route.
	for name, tid := range map[string]tenant.ID{"its home tenant": platform, "a third tenant": globex, "the single tenant": tenant.Single} {
		if _, err := svc.VerifyAccess(tok, tid); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("an entered token for acme verified for %s: err = %v", name, err)
		}
	}
}

// An ordinary token carries no htid at all, and its actor tenant is its
// own tid.
func TestIssueAccess_HasNoHomeTenantClaim(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	svc := newTestJWT(t, "secret")
	svc.Testing().SetNow(func() time.Time { return now })

	tok, err := svc.IssueAccess("user-1", tenant.New("acme"), now.Unix(), ACRLocalPassword)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	if _, present := payloadKeys(t, tok)["htid"]; present {
		t.Fatal("an ordinary access token carries an htid claim")
	}
	claims, err := svc.ParseAccess(tok)
	if err != nil {
		t.Fatalf("ParseAccess: %v", err)
	}
	if claims.HomeTenantID != "" || claims.ActorTenantID() != "acme" {
		t.Errorf("htid=%q ActorTenantID=%q, want empty / acme", claims.HomeTenantID, claims.ActorTenantID())
	}

	single, err := svc.IssueAccess("user-1", tenant.Single, now.Unix(), ACRLocalPassword)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	keys := payloadKeys(t, single)
	if _, present := keys["htid"]; present {
		t.Error("a single-tenant token carries an htid claim")
	}
	if _, present := keys["tid"]; present {
		t.Error("a single-tenant token carries a tid claim")
	}
}

// An entered token always names two different real tenants.
func TestIssueAccessEntered_RefusesBadTenantPairs(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	svc := newTestJWT(t, "secret")
	svc.Testing().SetNow(func() time.Time { return now })
	acme, platform := tenant.New("acme"), tenant.New("platform")

	for _, tc := range []struct {
		name         string
		target, home tenant.ID
		want         error
	}{
		{"unset target", tenant.ID{}, platform, ErrTenantRequired},
		{"unset home", acme, tenant.ID{}, ErrTenantRequired},
		{"single target", tenant.Single, platform, ErrEnteredTenants},
		{"single home", acme, tenant.Single, ErrEnteredTenants},
		{"same tenant", acme, acme, ErrEnteredTenants},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tok, err := svc.IssueAccessEntered("admin-1", tc.target, tc.home, now.Unix(), ACRLocalPassword, 0)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if tok != "" {
				t.Errorf("a refused mint returned a token")
			}
		})
	}
}

// The lifetime can be shorter than the service TTL and never longer.
func TestIssueAccessEntered_TTL(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	svc := newTestJWT(t, "secret") // service TTL: one hour
	svc.Testing().SetNow(func() time.Time { return now })
	acme, platform := tenant.New("acme"), tenant.New("platform")

	for _, tc := range []struct {
		name string
		ttl  time.Duration
		want time.Duration
	}{
		{"zero means the service TTL", 0, time.Hour},
		{"negative means the service TTL", -time.Minute, time.Hour},
		{"shorter is honoured", 5 * time.Minute, 5 * time.Minute},
		{"longer is cut to the service TTL", 24 * time.Hour, time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tok, err := svc.IssueAccessEntered("admin-1", acme, platform, now.Unix(), ACRLocalPassword, tc.ttl)
			if err != nil {
				t.Fatalf("IssueAccessEntered: %v", err)
			}
			claims, err := svc.VerifyAccess(tok, acme)
			if err != nil {
				t.Fatalf("VerifyAccess: %v", err)
			}
			if got := claims.ExpiresAt.Sub(now); got != tc.want {
				t.Errorf("lifetime = %v, want %v", got, tc.want)
			}
		})
	}
}

// A token whose htid does not sit beside a different, non-empty tid was
// not minted by IssueAccessEntered. It is refused, so its htid can never
// reach an audit row.
func TestParseAccess_RefusesAnImpossibleHomeTenant(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	svc := newTestJWT(t, "secret")
	svc.Testing().SetNow(func() time.Time { return now })

	for name, pair := range map[string][2]string{
		"htid with no tid":  {"", "platform"},
		"htid equal to tid": {"acme", "acme"},
	} {
		tok, err := svc.issueAccess("admin-1", pair[0], pair[1], now.Unix(), ACRLocalPassword, time.Hour)
		if err != nil {
			t.Fatalf("%s: mint: %v", name, err)
		}
		if _, err := svc.ParseAccess(tok); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("%s: ParseAccess err = %v, want ErrInvalidToken", name, err)
		}
		if _, err := svc.VerifyAccess(tok, tenant.FromStored(pair[0])); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("%s: VerifyAccess err = %v, want ErrInvalidToken", name, err)
		}
	}
}
