package identity

import (
	"context"
	"errors"
	"testing"

	tampercrypto "github.com/suryakencana007/tamper/crypto"
	"github.com/suryakencana007/tamper/tenant"
)

// Phase 13 slice 13b (TD-28). Every method here used to be keyed by a bare user id
// or a bare refresh token, so the tenant check lived in the ADAPTER and an adapter
// that forgot still compiled. These tests pin the check where it now lives.

var (
	acmeTenant   = tenant.New("acme")
	globexTenant = tenant.New("globex")
)

// foreignCore returns a Core whose store holds ONE user, in acme.
func foreignCore(t *testing.T) (*Core, *MemStore, User) {
	t.Helper()
	// With a keyset: the TOTP methods answer ErrNoKeySet before any lookup, which is a
	// wiring error rather than a per-request answer, so a keyless core cannot exercise
	// the check this test is about.
	c, store := testCore(t, WithKeySet(testKeySet(t)))
	u := User{ID: "u-acme", TenantID: "acme", Email: "frank@acme.com", PasswordHash: "x", Active: true}
	store.Seed(u)
	return c, store, u
}

// The invariant: a key from another tenant is a MISS, not a refusal. It answers
// exactly what an id that does not exist answers, so neither is an existence oracle.
func TestTenantKeys_ForeignUserIsIndistinguishableFromMissing(t *testing.T) {
	ctx := context.Background()
	c, _, user := foreignCore(t)

	for _, tc := range []struct {
		name string
		call func(userID string) error
	}{
		{"ListIdentities", func(id string) error { _, err := c.ListIdentities(ctx, globexTenant, id); return err }},
		{"Link", func(id string) error { _, err := c.Link(ctx, globexTenant, id, "google", "sub-1"); return err }},
		{"Unlink", func(id string) error { return c.Unlink(ctx, globexTenant, id, "ident-1") }},
		{"RevokeAllSessions", func(id string) error { return c.RevokeAllSessions(ctx, globexTenant, id) }},
		{"VerifyTOTP", func(id string) error { return c.VerifyTOTP(ctx, globexTenant, id, "000000") }},
		{"VerifyRecoveryCode", func(id string) error { return c.VerifyRecoveryCode(ctx, globexTenant, id, "code") }},
		{"StartTOTPEnrollment", func(id string) error { _, err := c.StartTOTPEnrollment(ctx, globexTenant, id); return err }},
		{"CompleteTOTPEnrollment", func(id string) error {
			_, _, err := c.CompleteTOTPEnrollment(ctx, globexTenant, id, "000000")
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			foreign := tc.call(user.ID)
			missing := tc.call("no-such-user")
			if !errors.Is(foreign, ErrNotFound) {
				t.Fatalf("foreign tenant: err = %v, want ErrNotFound", foreign)
			}
			if !errors.Is(missing, ErrNotFound) {
				t.Fatalf("missing user: err = %v, want ErrNotFound", missing)
			}
			// The CALLER supplied the id, so the message naming it is not a leak. What
			// must not differ is the classification: a foreign key may not surface as a
			// more specific sentinel than a missing one, or which sentinel fires becomes
			// the oracle.
			for _, sentinel := range []error{ErrUserInactive, ErrTOTPNotEnrolled, ErrTOTPAlreadyEnrolled, ErrInvalidTOTP, ErrLastAuthMethod} {
				if errors.Is(foreign, sentinel) != errors.Is(missing, sentinel) {
					t.Fatalf("classification differs: foreign matches %v, missing does not — "+
						"that difference is an existence oracle", sentinel)
				}
			}
		})
	}
}

// FromStored, not New: a stored "" is tenant.Single, a recorded fact. With New the
// single-tenant call would be refused.
func TestTenantKeys_SingleTenantValueMatchesAStoredEmptyTenant(t *testing.T) {
	ctx := context.Background()
	c, store := testCore(t)
	store.Seed(User{ID: "u-single", TenantID: "", Email: "s@example.com", PasswordHash: "x", Active: true})

	if _, err := c.ListIdentities(ctx, tenant.Single, "u-single"); err != nil {
		t.Fatalf("ListIdentities(Single) on a stored \"\": %v — the comparison must be "+
			"tenant.FromStored, so a recorded empty tenant equals Single", err)
	}
	// And Single is NOT the same as acme.
	if _, err := c.ListIdentities(ctx, acmeTenant, "u-single"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound: Single is not a wildcard", err)
	}
}

// A refresh session minted for another tenant is refused — and NOT revoked, because
// a route/tenant disagreement is a caller error, not corrupt data.
func TestRefresh_RoutingMismatchDoesNotRevoke(t *testing.T) {
	ctx := context.Background()
	c, store := testCore(t)
	user, tokens, err := c.Register(ctx, acmeTenant, "bob@acme.com", "correct-horse")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	_, _, err = c.Refresh(ctx, globexTenant, tokens.Refresh)
	if !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("err = %v, want ErrInvalidSession", err)
	}
	hash, _ := tampercrypto.HashRefreshToken(tokens.Refresh)
	s, ok := store.SessionByHash(hash)
	if !ok {
		t.Fatal("the session vanished")
	}
	if s.Revoked() {
		t.Fatal("the session was REVOKED by a routing mismatch — a route wired to the wrong " +
			"tenant must not be able to destroy valid sessions")
	}
	// The token still works on its own tenant's route afterwards.
	if _, _, err := c.Refresh(ctx, acmeTenant, tokens.Refresh); err != nil {
		t.Fatalf("the untouched session no longer rotates on its own route: %v", err)
	}
	if user.ID == "" {
		t.Fatal("fixture")
	}
}

func TestLogout_RoutingMismatchRefusesWithoutRevoking(t *testing.T) {
	ctx := context.Background()
	c, store := testCore(t)
	if _, tokens, err := c.Register(ctx, acmeTenant, "bob@acme.com", "correct-horse"); err != nil {
		t.Fatalf("Register: %v", err)
	} else {
		if err := c.Logout(ctx, globexTenant, tokens.Refresh); !errors.Is(err, ErrInvalidSession) {
			t.Fatalf("err = %v, want ErrInvalidSession for another tenant's token", err)
		}
		hash, _ := tampercrypto.HashRefreshToken(tokens.Refresh)
		if s, ok := store.SessionByHash(hash); !ok || s.Revoked() {
			t.Fatalf("the foreign logout revoked the session anyway: %+v", s)
		}
		// An UNKNOWN token stays nil — already logged out, and a stale cookie must
		// not produce an error the client cannot act on.
		if err := c.Logout(ctx, acmeTenant, "not-a-token"); err != nil {
			t.Fatalf("Logout with an unknown token = %v, want nil", err)
		}
		// Its own tenant still logs out.
		if err := c.Logout(ctx, acmeTenant, tokens.Refresh); err != nil {
			t.Fatalf("Logout on the right tenant: %v", err)
		}
	}
}

// D5: this one is legitimately cross-tenant, and a later slice must not "fix" it.
func TestEnterableTenants_StaysUnscoped(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	c, err := New(store, testJWT(), WithMemberships(store))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	user, _, err := c.Register(ctx, acmeTenant, "bob@acme.com", "correct-horse")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	// The point is the SIGNATURE: it takes a bare user id on purpose, because the
	// question is about the user across tenants. This call compiling is the
	// assertion, and so is passing acme's user with no tenant at all.
	if _, err := c.EnterableTenants(ctx, user.ID); err != nil {
		t.Fatalf("EnterableTenants: %v", err)
	}
	_ = globexTenant // the point is that NO tenant is passed here
}

// The capability D4 removed from Core is still the STORE's, which is why the port
// method did not disappear: DisableTOTP uses it.
func TestClearTOTP_LivesOnTheStoreNotCore(t *testing.T) {
	ctx := context.Background()
	c, store, userID := totpCore(t)
	enrollTOTP(t, c, ctx, userID)

	if err := store.ClearTOTP(ctx, userID); err != nil {
		t.Fatalf("store ClearTOTP: %v", err)
	}
	state, err := store.TOTPState(ctx, userID)
	if err != nil {
		t.Fatalf("TOTPState: %v", err)
	}
	if state.Enrolled || len(state.Envelope) != 0 {
		t.Fatalf("the factor survived: %+v", state)
	}
}
