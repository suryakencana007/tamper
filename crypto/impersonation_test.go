package crypto

import (
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/suryakencana007/tamper/tenant"
)

var (
	acme     = tenant.New("acme")
	platform = tenant.New("platform")
)

func impJWT(t *testing.T) *JWTService {
	t.Helper()
	return NewJWTService(JWTConfig{Secret: "tamper-crypto-impersonation-test", TTL: time.Hour, Issuer: "tamper-test"})
}

func TestIssueAccessImpersonated_CarriesTwoIdentities(t *testing.T) {
	j := impJWT(t)
	tok, err := j.IssueAccessImpersonated("bob", "ops", acme, platform, time.Now().Unix(), ACRLocalPassword, time.Hour)
	if err != nil {
		t.Fatalf("IssueAccessImpersonated: %v", err)
	}
	claims, err := j.ParseAccess(tok)
	if err != nil {
		t.Fatalf("ParseAccess: %v", err)
	}
	if claims.Subject != "bob" || claims.ActorID != "ops" {
		t.Fatalf("sub/act = %q/%q, want bob/ops (the request IS bob, the human is ops)", claims.Subject, claims.ActorID)
	}
	if claims.TenantID != acme.String() || claims.HomeTenantID != platform.String() {
		t.Fatalf("tid/htid = %q/%q, want acme/platform", claims.TenantID, claims.HomeTenantID)
	}
	if !claims.Impersonated() {
		t.Fatal("Impersonated() = false")
	}
	if claims.Entered() {
		t.Fatal("Entered() = true for an impersonated token; every entered gate would accept it")
	}
	if got := claims.ActorUserID(); got != "ops" {
		t.Fatalf("ActorUserID = %q, want the human", got)
	}
	if got := claims.ActorTenantID(); got != platform.String() {
		t.Fatalf("ActorTenantID = %q, want the human's home", got)
	}
}

func TestIssueAccessImpersonated_Refusals(t *testing.T) {
	j := impJWT(t)
	now := time.Now().Unix()
	cases := []struct {
		name           string
		target, actor  string
		tenantID, home tenant.ID
		want           error
	}{
		{"no target", "", "ops", acme, platform, ErrInvalidToken},
		{"no actor", "bob", "", acme, platform, ErrInvalidToken},
		{"self", "ops", "ops", acme, platform, ErrSelfImpersonation},
		{"unset tenant", "bob", "ops", tenant.ID{}, platform, ErrTenantRequired},
		{"unset home", "bob", "ops", acme, tenant.ID{}, ErrTenantRequired},
		{"single tenant", "bob", "ops", tenant.Single, platform, ErrEnteredTenants},
		{"single home", "bob", "ops", acme, tenant.Single, ErrEnteredTenants},
		{"same tenant", "bob", "ops", acme, acme, ErrEnteredTenants},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := j.IssueAccessImpersonated(tc.target, tc.actor, tc.tenantID, tc.home, now, ACRLocalPassword, time.Hour)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// An act is only ever minted beside an htid and a different sub. A token that
// says otherwise was not minted here, and its act would be recorded as the actor.
func TestParseAccess_RefusesAnActItCouldNotHaveMinted(t *testing.T) {
	j := impJWT(t)
	now := time.Now()

	base := func() AccessClaims {
		return AccessClaims{
			AuthTime: now.Unix(), ACR: ACRLocalPassword, Purpose: purposeAccess,
			TenantID: acme.String(), HomeTenantID: platform.String(),
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   "bob",
				Issuer:    j.issuer,
				IssuedAt:  jwt.NewNumericDate(now),
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			},
		}
	}

	t.Run("act without htid", func(t *testing.T) {
		c := base()
		c.ActorID = "ops"
		c.HomeTenantID = ""
		tok, err := j.sign(c)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if _, err := j.ParseAccess(tok); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("err = %v, want ErrInvalidToken", err)
		}
	})

	t.Run("act equal to sub", func(t *testing.T) {
		c := base()
		c.ActorID = "bob"
		tok, err := j.sign(c)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if _, err := j.ParseAccess(tok); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("err = %v, want ErrInvalidToken", err)
		}
	})
}

// An ordinary token is unchanged: no act on the wire, Entered()/Impersonated()
// both false, and the actor is the subject.
func TestActorUserID_OrdinaryToken(t *testing.T) {
	j := impJWT(t)
	tok, err := j.IssueAccess("ops", platform, time.Now().Unix(), ACRLocalPassword)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	claims, err := j.ParseAccess(tok)
	if err != nil {
		t.Fatalf("ParseAccess: %v", err)
	}
	if claims.Impersonated() || claims.Entered() {
		t.Fatalf("ordinary token: Impersonated=%v Entered=%v, want both false", claims.Impersonated(), claims.Entered())
	}
	if got := claims.ActorUserID(); got != "ops" {
		t.Fatalf("ActorUserID = %q, want the subject", got)
	}
}
