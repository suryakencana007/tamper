package identity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/suryakencana007/tamper/tenant"
)

var (
	tAcme     = tenant.New("acme")
	tGlobex   = tenant.New("globex")
	tPlatform = tenant.New("platform")
)

// enterCore builds a Core whose MemStore is also its MembershipStore.
func enterCore(t *testing.T, opts ...Option) (*Core, *MemStore) {
	t.Helper()
	store := NewMemStore()
	base := []Option{
		WithRefreshTTL(30 * 24 * time.Hour),
		WithDefaultACR(testACR),
		WithMemberships(store),
	}
	c, err := New(store, testJWT(), append(base, opts...)...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, store
}

// platformAdmin registers a user in the platform tenant.
func platformAdmin(t *testing.T, c *Core) User {
	t.Helper()
	u, _, err := c.Register(context.Background(), tPlatform, "admin@platform.example", "correct-horse")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	return u
}

// A member gets an access token that is for the target tenant, says
// where the user is from, and has no refresh session behind it.
func TestEnterTenant_MemberGetsAnAccessTokenAndNoSession(t *testing.T) {
	ctx := context.Background()
	c, store := enterCore(t)
	admin := platformAdmin(t, c)
	store.AddMembership(admin.ID, tAcme)
	sessionsBefore := len(store.sessions)

	authTime := time.Now().Add(-10 * time.Minute).Unix()
	tok, err := c.EnterTenant(ctx, admin.ID, tAcme, authTime, "urn:test:auth:mfa")
	if err != nil {
		t.Fatalf("EnterTenant: %v", err)
	}

	claims, err := c.jwt.VerifyAccess(tok.Access, tAcme)
	if err != nil {
		t.Fatalf("the entered token does not verify for the tenant entered: %v", err)
	}
	if claims.Subject != admin.ID || claims.TenantID != "acme" || claims.HomeTenantID != "platform" {
		t.Errorf("sub=%q tid=%q htid=%q, want %q / acme / platform", claims.Subject, claims.TenantID, claims.HomeTenantID, admin.ID)
	}
	// Step-up state is carried over, not renewed.
	if claims.AuthTime != authTime || claims.ACR != "urn:test:auth:mfa" {
		t.Errorf("auth_time=%d acr=%q, want the caller's %d / urn:test:auth:mfa", claims.AuthTime, claims.ACR, authTime)
	}
	for name, tid := range map[string]tenant.ID{"home tenant": tPlatform, "another tenant": tGlobex} {
		if _, err := c.jwt.VerifyAccess(tok.Access, tid); err == nil {
			t.Errorf("the token entered into acme verified for the %s", name)
		}
	}

	// No refresh token, although this Core has refresh sessions on.
	if tok.Refresh != "" || !tok.RefreshExpiresAt.IsZero() {
		t.Errorf("EnterTenant returned a refresh token (expires %v)", tok.RefreshExpiresAt)
	}
	if after := len(store.sessions); after != sessionsBefore {
		t.Errorf("sessions %d -> %d: entering a tenant wrote a refresh session", sessionsBefore, after)
	}
}

// Without a membership the answer is the one a missing user gets.
func TestEnterTenant_NonMemberLooksLikeAMissingUser(t *testing.T) {
	ctx := context.Background()
	c, store := enterCore(t)
	admin := platformAdmin(t, c)
	store.AddMembership(admin.ID, tGlobex) // a member somewhere, not of acme

	tok, errNonMember := c.EnterTenant(ctx, admin.ID, tAcme, time.Now().Unix(), testACR)
	if !errors.Is(errNonMember, ErrNotFound) {
		t.Fatalf("non-member: err = %v, want ErrNotFound", errNonMember)
	}
	if tok.Access != "" {
		t.Fatal("a refused EnterTenant returned an access token")
	}

	_, errMissing := c.EnterTenant(ctx, "no-such-user", tAcme, time.Now().Unix(), testACR)
	if !errors.Is(errMissing, ErrNotFound) {
		t.Fatalf("missing user: err = %v, want ErrNotFound", errMissing)
	}
	a := strings.ReplaceAll(errNonMember.Error(), admin.ID, "<id>")
	b := strings.ReplaceAll(errMissing.Error(), "no-such-user", "<id>")
	if a != b {
		t.Errorf("a non-member and a missing user are told apart:\n  %q\n  %q", a, b)
	}
}

// Taking the membership away stops the next entry.
func TestEnterTenant_RemovedMembershipIsRefused(t *testing.T) {
	ctx := context.Background()
	c, store := enterCore(t)
	admin := platformAdmin(t, c)
	store.AddMembership(admin.ID, tAcme)

	if _, err := c.EnterTenant(ctx, admin.ID, tAcme, time.Now().Unix(), testACR); err != nil {
		t.Fatalf("EnterTenant while a member: %v", err)
	}
	store.RemoveMembership(admin.ID, tAcme)
	if _, err := c.EnterTenant(ctx, admin.ID, tAcme, time.Now().Unix(), testACR); !errors.Is(err, ErrNotFound) {
		t.Fatalf("EnterTenant after the membership was removed: err = %v, want ErrNotFound", err)
	}
}

// failingMemberships fails every lookup.
type failingMemberships struct{ err error }

func (f failingMemberships) IsMember(context.Context, string, tenant.ID) (bool, error) {
	return true, f.err // true on purpose: the error must win
}
func (f failingMemberships) MembershipsFor(context.Context, string) ([]tenant.ID, error) {
	return []tenant.ID{tAcme}, f.err
}

// A lookup that fails is a deny. It is not a "not found" either: the
// caller must be able to tell an outage from a refusal.
func TestEnterTenant_StoreErrorIsNeverAYes(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("membership table is down")
	store := NewMemStore()
	c, err := New(store, testJWT(), WithDefaultACR(testACR), WithMemberships(failingMemberships{err: boom}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	admin := platformAdmin(t, c)

	tok, err := c.EnterTenant(ctx, admin.ID, tAcme, time.Now().Unix(), testACR)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the store's error", err)
	}
	if errors.Is(err, ErrNotFound) {
		t.Error("a failed lookup was reported as not found")
	}
	if tok.Access != "" {
		t.Fatal("EnterTenant minted although the membership lookup failed")
	}
	if list, err := c.EnterableTenants(ctx, admin.ID); !errors.Is(err, boom) || list != nil {
		t.Errorf("EnterableTenants = %v, %v; want nil and the store's error", list, err)
	}
}

func TestEnterTenant_Refusals(t *testing.T) {
	ctx := context.Background()
	c, store := enterCore(t)
	admin := platformAdmin(t, c)
	store.AddMembership(admin.ID, tAcme)
	// Rows a careless store might hold. None of them may open a path.
	store.AddMembership(admin.ID, tPlatform)
	store.AddMembership(admin.ID, tenant.Single)

	single, _, err := c.Register(ctx, tenant.Single, "solo@example.com", "correct-horse")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	store.AddMembership(single.ID, tAcme)

	now := time.Now().Unix()
	for _, tc := range []struct {
		name     string
		userID   string
		target   tenant.ID
		authTime int64
		acr      string
		want     error
	}{
		{"unset target", admin.ID, tenant.ID{}, now, testACR, ErrTenantRequired},
		{"the user's own tenant", admin.ID, tPlatform, now, testACR, ErrInvalidInput},
		{"the single tenant as target", admin.ID, tenant.Single, now, testACR, ErrNotFound},
		{"a user stored in the single tenant", single.ID, tAcme, now, testACR, ErrNotFound},
		{"no auth_time", admin.ID, tAcme, 0, testACR, ErrInvalidInput},
		{"no acr", admin.ID, tAcme, now, "", ErrInvalidInput},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tok, err := c.EnterTenant(ctx, tc.userID, tc.target, tc.authTime, tc.acr)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if tok.Access != "" {
				t.Error("a refused EnterTenant returned an access token")
			}
		})
	}
}

// "Inactive" is said only about a tenant the user could have entered.
func TestEnterTenant_InactiveUser(t *testing.T) {
	ctx := context.Background()
	c, store := enterCore(t)
	admin := platformAdmin(t, c)
	store.AddMembership(admin.ID, tAcme)
	store.SetActive(admin.ID, false)

	if tok, err := c.EnterTenant(ctx, admin.ID, tAcme, time.Now().Unix(), testACR); !errors.Is(err, ErrUserInactive) || tok.Access != "" {
		t.Errorf("member, inactive: token=%q err=%v, want no token and ErrUserInactive", tok.Access, err)
	}
	if _, err := c.EnterTenant(ctx, admin.ID, tGlobex, time.Now().Unix(), testACR); !errors.Is(err, ErrNotFound) {
		t.Errorf("non-member, inactive: err = %v, want ErrNotFound", err)
	}
	if _, err := c.EnterableTenants(ctx, admin.ID); !errors.Is(err, ErrUserInactive) {
		t.Errorf("EnterableTenants for an inactive user: err = %v, want ErrUserInactive", err)
	}
}

// A membership does not loosen the ordinary mint: a full session is
// still only ever for the user's own tenant.
func TestMembership_DoesNotLoosenIssueTokensForUserInTenant(t *testing.T) {
	ctx := context.Background()
	c, store := enterCore(t)
	admin := platformAdmin(t, c)
	store.AddMembership(admin.ID, tAcme)

	if _, err := c.IssueTokensForUserInTenant(ctx, admin.ID, tAcme, 0, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("IssueTokensForUserInTenant into a tenant the user is only a member of: err = %v, want ErrNotFound", err)
	}
}

func TestEnterTenant_TTLOption(t *testing.T) {
	ctx := context.Background()
	c, store := enterCore(t, WithEnterTenantTTL(5*time.Minute)) // the JWT service TTL is one hour
	admin := platformAdmin(t, c)
	store.AddMembership(admin.ID, tAcme)

	tok, err := c.EnterTenant(ctx, admin.ID, tAcme, time.Now().Unix(), testACR)
	if err != nil {
		t.Fatalf("EnterTenant: %v", err)
	}
	claims, err := c.jwt.VerifyAccess(tok.Access, tAcme)
	if err != nil {
		t.Fatalf("VerifyAccess: %v", err)
	}
	if got := claims.ExpiresAt.Sub(claims.IssuedAt.Time); got != 5*time.Minute {
		t.Errorf("entered token lifetime = %v, want 5m", got)
	}
}

// The wiring errors are loud, and they fire at construction where they
// can.
func TestMemberships_Wiring(t *testing.T) {
	ctx := context.Background()

	t.Run("a Core without the store says so", func(t *testing.T) {
		c, _ := testCore(t)
		admin := platformAdmin(t, c)
		if _, err := c.EnterTenant(ctx, admin.ID, tAcme, time.Now().Unix(), testACR); !errors.Is(err, ErrNoMembershipStore) {
			t.Errorf("EnterTenant: err = %v, want ErrNoMembershipStore", err)
		}
		if _, err := c.EnterableTenants(ctx, admin.ID); !errors.Is(err, ErrNoMembershipStore) {
			t.Errorf("EnterableTenants: err = %v, want ErrNoMembershipStore", err)
		}
	})

	t.Run("a token-less Core says so", func(t *testing.T) {
		store := NewMemStore()
		c, err := New(store, nil, WithMemberships(store))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if _, err := c.EnterTenant(ctx, "u", tAcme, time.Now().Unix(), testACR); !errors.Is(err, ErrNoTokenService) {
			t.Errorf("err = %v, want ErrNoTokenService", err)
		}
	})

	for name, build := range map[string]func(){
		"WithMemberships(nil)":   func() { WithMemberships(nil) },
		"WithEnterTenantTTL(0)":  func() { WithEnterTenantTTL(0) },
		"WithEnterTenantTTL(-1)": func() { WithEnterTenantTTL(-time.Second) },
	} {
		t.Run(name+" panics", func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Errorf("%s did not panic", name)
				}
			}()
			build()
		})
	}
}

func TestEnterableTenants(t *testing.T) {
	ctx := context.Background()
	c, store := enterCore(t)
	admin := platformAdmin(t, c)
	for _, id := range []tenant.ID{tGlobex, tAcme, tPlatform, tenant.Single, {}} {
		store.AddMembership(admin.ID, id)
	}

	got, err := c.EnterableTenants(ctx, admin.ID)
	if err != nil {
		t.Fatalf("EnterableTenants: %v", err)
	}
	if len(got) != 2 || got[0] != tAcme || got[1] != tGlobex {
		t.Errorf("EnterableTenants = %v, want [acme globex]: sorted, without the home tenant, the single tenant or an unset id", got)
	}
	// Everything listed can be entered.
	for _, id := range got {
		if _, err := c.EnterTenant(ctx, admin.ID, id, time.Now().Unix(), testACR); err != nil {
			t.Errorf("EnterTenant(%s), which EnterableTenants listed: %v", id, err)
		}
	}

	single, _, err := c.Register(ctx, tenant.Single, "solo@example.com", "correct-horse")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	store.AddMembership(single.ID, tAcme)
	if got, err := c.EnterableTenants(ctx, single.ID); err != nil || len(got) != 0 {
		t.Errorf("a user stored in the single tenant: %v, %v; want an empty list", got, err)
	}

	if _, err := c.EnterableTenants(ctx, "no-such-user"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing user: err = %v, want ErrNotFound", err)
	}
}

// An entered token cannot be turned into a home session of the tenant
// entered: there is no refresh token to rotate, and the access token is
// not one.
func TestEnterTenant_AccessTokenIsNotARefreshToken(t *testing.T) {
	ctx := context.Background()
	c, store := enterCore(t)
	admin := platformAdmin(t, c)
	store.AddMembership(admin.ID, tAcme)

	tok, err := c.EnterTenant(ctx, admin.ID, tAcme, time.Now().Unix(), testACR)
	if err != nil {
		t.Fatalf("EnterTenant: %v", err)
	}
	if _, _, err := c.Refresh(ctx, tok.Access); !errors.Is(err, ErrInvalidSession) {
		t.Errorf("Refresh with an entered access token: err = %v, want ErrInvalidSession", err)
	}
}
