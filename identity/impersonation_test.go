package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/suryakencana007/tamper/crypto"
	"github.com/suryakencana007/tamper/tenant"
)

type policyFunc func(ctx context.Context, actorID string, tenantID tenant.ID, targetUserID string) (bool, error)

func (f policyFunc) MayImpersonate(ctx context.Context, actorID string, tenantID tenant.ID, targetUserID string) (bool, error) {
	return f(ctx, actorID, tenantID, targetUserID)
}

var (
	impAcme     = tenant.New("acme")
	impPlatform = tenant.New("platform")
)

// impCore builds a Core whose store holds ops@platform and bob@acme, with the
// policy given.
func impCore(t *testing.T, p ImpersonationPolicy, ttl time.Duration) (*Core, *MemStore, *crypto.JWTService) {
	t.Helper()
	store := NewMemStore()
	store.Seed(User{ID: "ops", TenantID: impPlatform.String(), Email: "ops@platform.example", Active: true})
	store.Seed(User{ID: "bob", TenantID: impAcme.String(), Email: "bob@acme.example", Active: true})
	store.Seed(User{ID: "gone", TenantID: impAcme.String(), Email: "gone@acme.example", Active: false})
	store.Seed(User{ID: "other", TenantID: tenant.New("globex").String(), Email: "o@globex.example", Active: true})

	jwt := crypto.NewJWTService(crypto.JWTConfig{Secret: "tamper-identity-impersonation-test", TTL: time.Hour, Issuer: "tamper-test"})
	core, err := New(store, jwt, WithImpersonation(p, ttl))
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}
	return core, store, jwt
}

// enteredSession is the caller's own token after entering acme: sub=ops,
// tid=acme, htid=platform. Impersonation happens as a step inside it.
func enteredSession(t *testing.T, jwt *crypto.JWTService) *crypto.AccessClaims {
	t.Helper()
	tok, err := jwt.IssueAccessEntered("ops", impAcme, impPlatform, time.Now().Unix(), crypto.ACRLocalPassword, time.Hour)
	if err != nil {
		t.Fatalf("IssueAccessEntered: %v", err)
	}
	claims, err := jwt.ParseAccess(tok)
	if err != nil {
		t.Fatalf("ParseAccess: %v", err)
	}
	return claims
}

func allowAll(context.Context, string, tenant.ID, string) (bool, error) { return true, nil }

func TestWithImpersonation_PanicsOnMisconfiguration(t *testing.T) {
	mustPanic := func(name string, fn func()) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Fatalf("%s: want panic, got none", name)
			}
		}()
		fn()
	}
	mustPanic("nil policy", func() { WithImpersonation(nil, time.Minute) })
	mustPanic("zero ttl", func() { WithImpersonation(policyFunc(allowAll), 0) })
}

func TestImpersonate_MintsTheHumanAndTheUser(t *testing.T) {
	core, _, jwt := impCore(t, policyFunc(allowAll), 5*time.Minute)

	tokens, err := core.Impersonate(context.Background(), enteredSession(t, jwt), "bob")
	if err != nil {
		t.Fatalf("Impersonate: %v", err)
	}
	if tokens.Refresh != "" {
		t.Fatal("an impersonated token came with a refresh session; ending it must be the TTL")
	}
	claims, err := jwt.ParseAccess(tokens.Access)
	if err != nil {
		t.Fatalf("ParseAccess: %v", err)
	}
	if claims.Subject != "bob" || claims.ActorID != "ops" {
		t.Fatalf("sub/act = %q/%q, want bob/ops", claims.Subject, claims.ActorID)
	}
	if claims.TenantID != impAcme.String() || claims.HomeTenantID != impPlatform.String() {
		t.Fatalf("tid/htid = %q/%q, want acme/platform", claims.TenantID, claims.HomeTenantID)
	}
	if !claims.Impersonated() || claims.Entered() {
		t.Fatalf("Impersonated=%v Entered=%v, want true/false", claims.Impersonated(), claims.Entered())
	}
	if claims.AuthTime == 0 || claims.ACR == "" {
		t.Fatal("step-up state was not carried from the session")
	}
}

func TestImpersonate_Refusals(t *testing.T) {
	noPolicy, _, jwtNoPolicy := impCore(t, policyFunc(allowAll), time.Minute)
	_ = noPolicy
	// A Core without the option.
	bare, err := New(NewMemStore(), jwtNoPolicy)
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}

	cases := []struct {
		name   string
		core   func(t *testing.T, jwt *crypto.JWTService) *Core
		target string
		want   error
	}{
		{"no policy", func(*testing.T, *crypto.JWTService) *Core { return bare }, "bob", ErrNoImpersonationPolicy},
		{"unknown target", func(*testing.T, *crypto.JWTService) *Core { return noPolicy }, "nobody", ErrNotFound},
		{"other tenant's user", func(*testing.T, *crypto.JWTService) *Core { return noPolicy }, "other", ErrNotFound},
		{"inactive target", func(*testing.T, *crypto.JWTService) *Core { return noPolicy }, "gone", ErrUserInactive},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.core(t, jwtNoPolicy)
			if _, err := c.Impersonate(context.Background(), enteredSession(t, jwtNoPolicy), tc.target); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestImpersonate_PolicyDecides(t *testing.T) {
	ctx := context.Background()

	t.Run("policy says no", func(t *testing.T) {
		core, _, jwt := impCore(t, policyFunc(func(context.Context, string, tenant.ID, string) (bool, error) {
			return false, nil
		}), time.Minute)
		if _, err := core.Impersonate(ctx, enteredSession(t, jwt), "bob"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("err = %v, want the same ErrNotFound a stranger gets", err)
		}
	})

	t.Run("policy error is not a yes", func(t *testing.T) {
		boom := errors.New("roster down")
		core, _, jwt := impCore(t, policyFunc(func(context.Context, string, tenant.ID, string) (bool, error) {
			return false, boom
		}), time.Minute)
		if _, err := core.Impersonate(ctx, enteredSession(t, jwt), "bob"); !errors.Is(err, boom) {
			t.Fatalf("err = %v, want the policy error", err)
		}
	})

	t.Run("policy sees the actor, tenant and target", func(t *testing.T) {
		var gotActor, gotTarget string
		var gotTenant tenant.ID
		core, _, jwt := impCore(t, policyFunc(func(_ context.Context, actor string, tid tenant.ID, target string) (bool, error) {
			gotActor, gotTenant, gotTarget = actor, tid, target
			return true, nil
		}), time.Minute)
		if _, err := core.Impersonate(ctx, enteredSession(t, jwt), "bob"); err != nil {
			t.Fatalf("Impersonate: %v", err)
		}
		if gotActor != "ops" || gotTarget != "bob" || gotTenant != impAcme {
			t.Fatalf("policy saw (%q, %q, %q), want (ops, acme, bob)", gotActor, gotTenant, gotTarget)
		}
	})
}

// No chaining: an impersonated session cannot impersonate further.
func TestImpersonate_NoChaining(t *testing.T) {
	core, _, jwt := impCore(t, policyFunc(allowAll), time.Minute)
	tokens, err := core.Impersonate(context.Background(), enteredSession(t, jwt), "bob")
	if err != nil {
		t.Fatalf("first Impersonate: %v", err)
	}
	second, err := jwt.ParseAccess(tokens.Access)
	if err != nil {
		t.Fatalf("ParseAccess: %v", err)
	}
	if _, err := core.Impersonate(context.Background(), second, "bob"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("chained impersonation: err = %v, want ErrNotFound", err)
	}
}

// A home session (no entered step) has the same tenant on both sides, so there is
// no human "from another tenant" to name.
func TestImpersonate_RefusesAHomeSession(t *testing.T) {
	core, _, jwt := impCore(t, policyFunc(allowAll), time.Minute)
	home, err := jwt.IssueAccess("ops", impPlatform, time.Now().Unix(), crypto.ACRLocalPassword)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	claims, err := jwt.ParseAccess(home)
	if err != nil {
		t.Fatalf("ParseAccess: %v", err)
	}
	if _, err := core.Impersonate(context.Background(), claims, "bob"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// A TTL longer than the access token's own is a boot failure, not a silent cut.
func TestNew_RefusesAnImpersonationTTLLongerThanTheToken(t *testing.T) {
	store := NewMemStore()
	jwt := crypto.NewJWTService(crypto.JWTConfig{Secret: "tamper-identity-impersonation-test", TTL: time.Minute, Issuer: "tamper-test"})
	if _, err := New(store, jwt, WithImpersonation(policyFunc(allowAll), time.Hour)); err == nil {
		t.Fatal("want New to refuse a ttl longer than the access token TTL, got nil")
	}
}
