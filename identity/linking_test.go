package identity

import (
	"context"
	"errors"
	"github.com/suryakencana007/tamper/tenant"
	"testing"
	"time"
)

// seedFederatedUser inserts a federated-only user (empty password hash)
// with one linked identity, mimicking a prior JIT provision.
func seedFederatedUser(t *testing.T, store *MemStore, userID, email, provider, subject string) {
	t.Helper()
	store.Seed(User{ID: userID, Email: email, Active: true, CreatedAt: time.Now().UTC()})
	if err := store.InsertIdentity(context.Background(), NewIdentity{
		ID: userID + "-id", UserID: userID, Provider: provider, Subject: subject, LinkedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed identity: %v", err)
	}
}

func TestResolveByIdentity(t *testing.T) {
	ctx := context.Background()

	t.Run("miss returns found=false, no error", func(t *testing.T) {
		c, _ := testCore(t)
		_, _, found, err := c.ResolveByIdentity(ctx, tenant.Single, "oidc-google", "sub-unknown")
		if err != nil || found {
			t.Fatalf("miss: found=%v err=%v, want false/nil", found, err)
		}
	})

	t.Run("hit gates on active BEFORE touching last_login, then bumps", func(t *testing.T) {
		c, store := testCore(t)
		seedFederatedUser(t, store, "u1", "a@example.com", "oidc-google", "sub-1")

		user, ident, found, err := c.ResolveByIdentity(ctx, tenant.Single, "oidc-google", "sub-1")
		if err != nil || !found || user.ID != "u1" {
			t.Fatalf("hit: %+v found=%v err=%v", user, found, err)
		}
		if ident.LastLoginAt == nil {
			t.Fatal("last_login must be bumped on a successful resolve")
		}

		// Deactivate: ErrUserInactive, and last_login must NOT advance.
		store.SetActive("u1", false)
		before, _ := store.IdentityByProviderSubject(ctx, tenant.Single, "oidc-google", "sub-1")
		_, _, _, err = c.ResolveByIdentity(ctx, tenant.Single, "oidc-google", "sub-1")
		if !errors.Is(err, ErrUserInactive) {
			t.Fatalf("deactivated: err=%v, want ErrUserInactive", err)
		}
		after, _ := store.IdentityByProviderSubject(ctx, tenant.Single, "oidc-google", "sub-1")
		if !after.LastLoginAt.Equal(*before.LastLoginAt) {
			t.Fatal("last_login must not advance when the active gate fails")
		}
	})
}

func TestProvisionUserWithIdentity(t *testing.T) {
	ctx := context.Background()

	t.Run("creates federated-only user + identity atomically, fires hook", func(t *testing.T) {
		var hookFirst []bool
		c, store := testCore(t, WithHooks(Hooks{
			OnProvisioned: func(_ context.Context, _ User, _ Identity, first bool) { hookFirst = append(hookFirst, first) },
		}))
		user, ident, err := c.ProvisionUserWithIdentity(ctx, tenant.Single, "fed@example.com", "oidc-google", "sub-x")
		if err != nil {
			t.Fatalf("Provision: %v", err)
		}
		if user.PasswordHash != "" || !user.Active {
			t.Fatalf("federated user must have empty password + active: %+v", user)
		}
		if ident.UserID != user.ID || ident.LastLoginAt == nil || !ident.LastLoginAt.Equal(ident.LinkedAt) {
			t.Fatalf("JIT identity: LinkedAt must equal LastLoginAt: %+v", ident)
		}
		if len(hookFirst) != 1 || hookFirst[0] != true {
			t.Fatalf("OnProvisioned firstUser = %v, want [true]", hookFirst)
		}
		// The identity resolves + the user is findable by email (veto parity).
		if _, _, found, _ := c.ResolveByIdentity(ctx, tenant.Single, "oidc-google", "sub-x"); !found {
			t.Fatal("provisioned identity must resolve")
		}
		if _, err := store.UserByEmail(ctx, tenant.Single, "fed@example.com"); err != nil {
			t.Fatalf("provisioned user must be findable by email: %v", err)
		}
	})

	t.Run("email collision surfaces ErrEmailTaken (race loser)", func(t *testing.T) {
		c, store := testCore(t)
		store.Seed(User{ID: "existing", Email: "dup@example.com", Active: true})
		if _, _, err := c.ProvisionUserWithIdentity(ctx, tenant.Single, "dup@example.com", "oidc-google", "sub-y"); !errors.Is(err, ErrEmailTaken) {
			t.Fatalf("err = %v, want ErrEmailTaken", err)
		}
	})

	t.Run("identity collision surfaces ErrIdentityTaken", func(t *testing.T) {
		c, store := testCore(t)
		seedFederatedUser(t, store, "u1", "a@example.com", "oidc-google", "sub-1")
		if _, _, err := c.ProvisionUserWithIdentity(ctx, tenant.Single, "new@example.com", "oidc-google", "sub-1"); !errors.Is(err, ErrIdentityTaken) {
			t.Fatalf("err = %v, want ErrIdentityTaken", err)
		}
		// Atomic: the losing provision must NOT have created the user.
		if _, err := store.UserByEmail(ctx, tenant.Single, "new@example.com"); !errors.Is(err, ErrNotFound) {
			t.Fatal("failed provision must not leave an orphan user (atomicity)")
		}
	})
}

func TestLink(t *testing.T) {
	ctx := context.Background()

	t.Run("links to a known user; idempotent same-user re-link", func(t *testing.T) {
		c, store := testCore(t)
		store.Seed(User{ID: "u1", Email: "a@example.com", PasswordHash: "hash", Active: true})
		ident, err := c.Link(ctx, "u1", "oidc-google", "sub-1")
		if err != nil {
			t.Fatalf("Link: %v", err)
		}
		if ident.LastLoginAt != nil {
			t.Fatal("explicit link must leave LastLoginAt nil")
		}
		again, err := c.Link(ctx, "u1", "oidc-google", "sub-1")
		if err != nil {
			t.Fatalf("idempotent re-link must succeed: %v", err)
		}
		if again.ID != ident.ID {
			t.Fatal("idempotent re-link must return the existing identity")
		}
	})

	t.Run("double race (insert taken, refetch gone) is ErrLinkConflict not ErrNotFound", func(t *testing.T) {
		store := &doubleRaceStore{MemStore: NewMemStore()}
		c, err := New(store, testJWT(), WithRefreshTTL(30*24*time.Hour), WithDefaultACR(testACR))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		store.Seed(User{ID: "u1", Email: "a@example.com", PasswordHash: "h", Active: true})
		if _, err := c.Link(ctx, "u1", "oidc-google", "sub-1"); !errors.Is(err, ErrLinkConflict) {
			t.Fatalf("err = %v, want ErrLinkConflict (a bare ErrNotFound reads as user-not-found to callers)", err)
		}
	})

	t.Run("cross-user link is ErrLinkConflict (no veto — link is remediation)", func(t *testing.T) {
		c, store := testCore(t)
		store.Seed(User{ID: "u1", Email: "a@example.com", PasswordHash: "h", Active: true})
		store.Seed(User{ID: "u2", Email: "b@example.com", PasswordHash: "h", Active: true})
		if _, err := c.Link(ctx, "u1", "oidc-google", "shared-sub"); err != nil {
			t.Fatalf("first link: %v", err)
		}
		if _, err := c.Link(ctx, "u2", "oidc-google", "shared-sub"); !errors.Is(err, ErrLinkConflict) {
			t.Fatalf("err = %v, want ErrLinkConflict", err)
		}
	})
}

func TestUnlink(t *testing.T) {
	ctx := context.Background()

	t.Run("federated-only user cannot unlink last identity", func(t *testing.T) {
		c, store := testCore(t)
		seedFederatedUser(t, store, "u1", "a@example.com", "oidc-google", "sub-1")
		if err := c.Unlink(ctx, "u1", "u1-id"); !errors.Is(err, ErrLastAuthMethod) {
			t.Fatalf("err = %v, want ErrLastAuthMethod", err)
		}
	})

	t.Run("password user MAY unlink their last identity", func(t *testing.T) {
		c, store := testCore(t)
		store.Seed(User{ID: "u1", Email: "a@example.com", PasswordHash: "hash", Active: true})
		linked, _ := c.Link(ctx, "u1", "oidc-google", "sub-1")
		if err := c.Unlink(ctx, "u1", linked.ID); err != nil {
			t.Fatalf("password user unlink last identity must succeed: %v", err)
		}
	})

	t.Run("federated user with 2 identities may unlink one", func(t *testing.T) {
		c, store := testCore(t)
		seedFederatedUser(t, store, "u1", "a@example.com", "oidc-google", "sub-1")
		second, _ := c.Link(ctx, "u1", "saml-corp", "sub-2")
		if err := c.Unlink(ctx, "u1", second.ID); err != nil {
			t.Fatalf("unlink one of two: %v", err)
		}
		// Now down to one — the guard bites again.
		if err := c.Unlink(ctx, "u1", "u1-id"); !errors.Is(err, ErrLastAuthMethod) {
			t.Fatalf("last remaining: err = %v, want ErrLastAuthMethod", err)
		}
	})

	t.Run("cross-user identity id is masked as ErrNotFound (IDOR)", func(t *testing.T) {
		c, store := testCore(t)
		seedFederatedUser(t, store, "u1", "a@example.com", "oidc-google", "sub-1")
		store.Seed(User{ID: "u2", Email: "b@example.com", PasswordHash: "h", Active: true})
		// u2 tries to unlink u1's identity.
		if err := c.Unlink(ctx, "u2", "u1-id"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("err = %v, want ErrNotFound (existence masking)", err)
		}
		// And u1's identity is untouched.
		if _, err := store.IdentityByID(ctx, "u1-id"); err != nil {
			t.Fatal("IDOR attempt must not delete the victim's identity")
		}
	})

	t.Run("unknown identity id is ErrNotFound", func(t *testing.T) {
		c, store := testCore(t)
		store.Seed(User{ID: "u1", Email: "a@example.com", PasswordHash: "h", Active: true})
		if err := c.Unlink(ctx, "u1", "nope"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("err = %v, want ErrNotFound", err)
		}
	})
}

func TestListIdentities(t *testing.T) {
	ctx := context.Background()
	c, store := testCore(t)
	store.Seed(User{ID: "u1", Email: "a@example.com", PasswordHash: "h", Active: true})

	empty, err := c.ListIdentities(ctx, "u1")
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("no identities must be empty non-nil: %v %v", empty, err)
	}

	// Link two with distinct LinkedAt via the injectable clock.
	now := time.Now().UTC()
	clock := now
	c2, store2 := testCore(t, WithClock(func() time.Time { return clock }))
	store2.Seed(User{ID: "u1", Email: "a@example.com", PasswordHash: "h", Active: true})
	if _, err := c2.Link(ctx, "u1", "oidc-google", "sub-1"); err != nil {
		t.Fatal(err)
	}
	clock = now.Add(time.Hour)
	if _, err := c2.Link(ctx, "u1", "saml-corp", "sub-2"); err != nil {
		t.Fatal(err)
	}
	list, err := c2.ListIdentities(ctx, "u1")
	if err != nil {
		t.Fatalf("ListIdentities: %v", err)
	}
	if len(list) != 2 || list[0].Provider != "oidc-google" || list[1].Provider != "saml-corp" {
		t.Fatalf("list must be oldest-first: %+v", list)
	}
}

// doubleRaceStore simulates the pathological Link interleaving: the
// insert loses a unique-violation race AND the winner unlinks before
// the refetch, so the lookup misses both before and after the insert.
type doubleRaceStore struct {
	*MemStore
}

func (s *doubleRaceStore) IdentityByProviderSubject(context.Context, tenant.ID, string, string) (Identity, error) {
	return Identity{}, ErrNotFound
}

func (s *doubleRaceStore) InsertIdentity(context.Context, NewIdentity) error {
	return ErrIdentityTaken
}
