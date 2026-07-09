package identity

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/suryakencana007/barista/packages/tamper/crypto"
)

func TestMain(m *testing.M) {
	crypto.Cost = 4 // drop bcrypt cost so fixtures don't take 200ms each
	m.Run()
}

func testJWT() *crypto.JWTService {
	return crypto.NewJWTService(crypto.JWTConfig{
		Secret: "test-secret-long-enough-for-signing",
		TTL:    time.Hour,
		Issuer: "tamper-test",
	})
}

// testCore builds a Core over a fresh MemStore with refresh enabled and
// a Barista-shaped custom ACR (proving the caller-supplied contract).
const testACR = "urn:test:auth:local-password"

func testCore(t *testing.T, opts ...Option) (*Core, *MemStore) {
	t.Helper()
	store := NewMemStore()
	base := []Option{
		WithRefreshTTL(30 * 24 * time.Hour),
		WithDefaultACR(testACR),
	}
	c, err := New(store, testJWT(), append(base, opts...)...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, store
}

func TestRegister(t *testing.T) {
	ctx := context.Background()

	t.Run("happy path mints tokens with the default ACR", func(t *testing.T) {
		c, store := testCore(t)
		user, tokens, err := c.Register(ctx, "  Alice@Example.COM ", "correct-horse")
		if err != nil {
			t.Fatalf("Register: %v", err)
		}
		if user.Email != "alice@example.com" {
			t.Fatalf("email not normalised: %q", user.Email)
		}
		if tokens.Access == "" || tokens.Refresh == "" {
			t.Fatalf("tokens incomplete: %+v", tokens)
		}
		claims, err := testJWT().VerifyAccess(tokens.Access)
		if err != nil {
			t.Fatalf("VerifyAccess: %v", err)
		}
		if claims.ACR != testACR {
			t.Fatalf("ACR = %q, want %q (caller-supplied, not the framework default)", claims.ACR, testACR)
		}
		hash, _ := crypto.HashRefreshToken(tokens.Refresh)
		session, ok := store.SessionByHash(hash)
		if !ok {
			t.Fatal("refresh session not persisted")
		}
		if session.ACR != testACR || session.AuthTime.IsZero() {
			t.Fatalf("session step-up columns wrong: %+v", session)
		}
	})

	t.Run("firstUser signal reaches store decision and hook", func(t *testing.T) {
		var hookCalls []bool
		c, _ := testCore(t, WithHooks(Hooks{
			OnRegistered: func(_ context.Context, _ User, first bool) {
				hookCalls = append(hookCalls, first)
			},
		}))
		if _, _, err := c.Register(ctx, "first@example.com", "password-1"); err != nil {
			t.Fatalf("Register first: %v", err)
		}
		if _, _, err := c.Register(ctx, "second@example.com", "password-2"); err != nil {
			t.Fatalf("Register second: %v", err)
		}
		if len(hookCalls) != 2 || hookCalls[0] != true || hookCalls[1] != false {
			t.Fatalf("hook firstUser signals = %v, want [true false]", hookCalls)
		}
	})

	t.Run("duplicate email", func(t *testing.T) {
		c, _ := testCore(t)
		if _, _, err := c.Register(ctx, "dup@example.com", "password-1"); err != nil {
			t.Fatalf("Register: %v", err)
		}
		if _, _, err := c.Register(ctx, "DUP@example.com", "password-2"); !errors.Is(err, ErrEmailTaken) {
			t.Fatalf("err = %v, want ErrEmailTaken", err)
		}
	})

	t.Run("policy rejections", func(t *testing.T) {
		c, _ := testCore(t)
		if _, _, err := c.Register(ctx, "not-an-email", "password-1"); !errors.Is(err, ErrInvalidEmail) {
			t.Fatalf("bad email: err = %v, want ErrInvalidEmail", err)
		}
		if _, _, err := c.Register(ctx, "a@b.example", "short"); !errors.Is(err, ErrPasswordPolicy) {
			t.Fatalf("short password: err = %v, want ErrPasswordPolicy", err)
		}
		if _, _, err := c.Register(ctx, "a@b.example", strings.Repeat("x", MaxPasswordLen+1)); !errors.Is(err, ErrPasswordPolicy) {
			t.Fatalf("long password: err = %v, want ErrPasswordPolicy", err)
		}
	})

	t.Run("refresh disabled yields access-only", func(t *testing.T) {
		store := NewMemStore()
		c, err := New(store, testJWT()) // TTL 0 default
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		_, tokens, err := c.Register(ctx, "solo@example.com", "password-1")
		if err != nil {
			t.Fatalf("Register: %v", err)
		}
		if tokens.Access == "" || tokens.Refresh != "" {
			t.Fatalf("tokens = %+v, want access-only", tokens)
		}
	})
}

func TestLogin(t *testing.T) {
	ctx := context.Background()

	setup := func(t *testing.T, opts ...Option) (*Core, *MemStore, User) {
		t.Helper()
		c, store := testCore(t, opts...)
		user, _, err := c.Register(ctx, "alice@example.com", "correct-horse")
		if err != nil {
			t.Fatalf("Register: %v", err)
		}
		return c, store, user
	}

	t.Run("happy path", func(t *testing.T) {
		c, _, _ := setup(t)
		user, tokens, err := c.Login(ctx, "ALICE@example.com", "correct-horse")
		if err != nil {
			t.Fatalf("Login: %v", err)
		}
		if user.Email != "alice@example.com" || tokens.Access == "" || tokens.Refresh == "" {
			t.Fatalf("unexpected result: %+v %+v", user, tokens)
		}
	})

	t.Run("every rejection collapses to ErrInvalidCredentials", func(t *testing.T) {
		c, store, user := setup(t)
		store.Seed(User{ID: "fed", Email: "fed@example.com", Active: true}) // federated-only: no hash

		cases := []struct{ name, email, password string }{
			{"wrong password", "alice@example.com", "wrong-password"},
			{"unknown email", "nobody@example.com", "correct-horse"},
			{"malformed email", "not-an-email", "correct-horse"},
			{"federated-only account", "fed@example.com", "any-password"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if _, _, err := c.Login(ctx, tc.email, tc.password); !errors.Is(err, ErrInvalidCredentials) {
					t.Fatalf("err = %v, want ErrInvalidCredentials", err)
				}
			})
		}

		store.SetActive(user.ID, false)
		if _, _, err := c.Login(ctx, "alice@example.com", "correct-horse"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("inactive: want ErrInvalidCredentials")
		}
	})

	t.Run("enrolled user gets ErrTOTPRequired with the user returned", func(t *testing.T) {
		c, store, _ := setup(t)
		store.Seed(User{
			ID: "totp-user", Email: "totp@example.com", Active: true, TOTPEnrolled: true,
			PasswordHash: mustHash(t, "correct-horse"),
		})
		user, tokens, err := c.Login(ctx, "totp@example.com", "correct-horse")
		if !errors.Is(err, ErrTOTPRequired) {
			t.Fatalf("err = %v, want ErrTOTPRequired", err)
		}
		if user.ID != "totp-user" || tokens.Access != "" {
			t.Fatalf("want user + zero tokens, got %+v %+v", user, tokens)
		}
	})

	t.Run("system-wide enforcement gates unenrolled users too", func(t *testing.T) {
		c, _, _ := setup(t, WithTOTPRequired(true))
		if _, _, err := c.Login(ctx, "alice@example.com", "correct-horse"); !errors.Is(err, ErrTOTPRequired) {
			t.Fatalf("err = %v, want ErrTOTPRequired under enforcement", err)
		}
	})

	t.Run("wrong password on enrolled user stays ErrInvalidCredentials", func(t *testing.T) {
		c, store, _ := setup(t)
		store.Seed(User{
			ID: "totp2", Email: "totp2@example.com", Active: true, TOTPEnrolled: true,
			PasswordHash: mustHash(t, "correct-horse"),
		})
		if _, _, err := c.Login(ctx, "totp2@example.com", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("password must be verified BEFORE the TOTP gate")
		}
	})
}

func TestRefresh(t *testing.T) {
	ctx := context.Background()

	t.Run("rotation revokes the old session", func(t *testing.T) {
		c, _ := testCore(t)
		_, first, err := c.Register(ctx, "alice@example.com", "correct-horse")
		if err != nil {
			t.Fatalf("Register: %v", err)
		}
		_, second, err := c.Refresh(ctx, first.Refresh)
		if err != nil {
			t.Fatalf("Refresh: %v", err)
		}
		if second.Refresh == first.Refresh {
			t.Fatal("rotation must mint a new refresh token")
		}
		// The old token is dead.
		if _, _, err := c.Refresh(ctx, first.Refresh); !errors.Is(err, ErrInvalidSession) {
			t.Fatalf("old token: err = %v, want ErrInvalidSession", err)
		}
		// The new one works.
		if _, _, err := c.Refresh(ctx, second.Refresh); err != nil {
			t.Fatalf("new token: %v", err)
		}
	})

	t.Run("carry-forward: rotation must NOT advance auth_time or ACR", func(t *testing.T) {
		c, store := testCore(t)
		user, _, err := c.Register(ctx, "alice@example.com", "correct-horse")
		if err != nil {
			t.Fatalf("Register: %v", err)
		}
		// A federated step-up session with explicit claims.
		const silver = "urn:mace:incommon:iap:silver"
		authTime := time.Now().Add(-2 * time.Hour).Unix()
		tokens, err := c.IssueTokensForUserWithACR(ctx, user.ID, authTime, silver)
		if err != nil {
			t.Fatalf("IssueTokensForUserWithACR: %v", err)
		}

		_, rotated, err := c.Refresh(ctx, tokens.Refresh)
		if err != nil {
			t.Fatalf("Refresh: %v", err)
		}
		claims, err := testJWT().VerifyAccess(rotated.Access)
		if err != nil {
			t.Fatalf("VerifyAccess: %v", err)
		}
		if claims.ACR != silver || claims.AuthTime != authTime {
			t.Fatalf("JWT claims advanced: acr=%q auth_time=%d, want %q/%d", claims.ACR, claims.AuthTime, silver, authTime)
		}
		hash, _ := crypto.HashRefreshToken(rotated.Refresh)
		session, ok := store.SessionByHash(hash)
		if !ok {
			t.Fatal("successor session missing")
		}
		if session.ACR != silver || session.AuthTime.Unix() != authTime {
			t.Fatalf("successor row advanced: %+v", session)
		}
	})

	t.Run("legacy row (zero auth_time) falls back to now + default ACR once", func(t *testing.T) {
		c, store := testCore(t)
		user, _, err := c.Register(ctx, "alice@example.com", "correct-horse")
		if err != nil {
			t.Fatalf("Register: %v", err)
		}
		plaintext, _ := crypto.NewRefreshToken()
		hash, _ := crypto.HashRefreshToken(plaintext)
		_ = store.CreateRefreshSession(ctx, RefreshSession{
			ID: "legacy", UserID: user.ID, TokenHash: hash,
			IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
			// AuthTime zero, ACR empty — the pre-carry-forward shape.
		})
		_, rotated, err := c.Refresh(ctx, plaintext)
		if err != nil {
			t.Fatalf("Refresh: %v", err)
		}
		claims, err := testJWT().VerifyAccess(rotated.Access)
		if err != nil {
			t.Fatalf("VerifyAccess: %v", err)
		}
		if claims.ACR != testACR || claims.AuthTime == 0 {
			t.Fatalf("legacy shim wrong: acr=%q auth_time=%d", claims.ACR, claims.AuthTime)
		}
	})

	t.Run("expired session rejects", func(t *testing.T) {
		now := time.Now()
		clock := now
		c, _ := testCore(t, WithClock(func() time.Time { return clock }))
		_, tokens, err := c.Register(ctx, "alice@example.com", "correct-horse")
		if err != nil {
			t.Fatalf("Register: %v", err)
		}
		clock = now.Add(31 * 24 * time.Hour) // past the 30d TTL
		if _, _, err := c.Refresh(ctx, tokens.Refresh); !errors.Is(err, ErrInvalidSession) {
			t.Fatalf("err = %v, want ErrInvalidSession", err)
		}
	})

	t.Run("unknown / malformed / disabled all collapse", func(t *testing.T) {
		c, _ := testCore(t)
		if _, _, err := c.Refresh(ctx, "completely-unknown-token-value-1234567890abcdef"); !errors.Is(err, ErrInvalidSession) {
			t.Fatalf("unknown: %v", err)
		}
		disabled, _ := New(NewMemStore(), testJWT()) // TTL 0
		if _, _, err := disabled.Refresh(ctx, "anything"); !errors.Is(err, ErrInvalidSession) {
			t.Fatalf("disabled: want ErrInvalidSession")
		}
	})

	t.Run("inactive user: ErrUserInactive and the presented session is revoked", func(t *testing.T) {
		c, store := testCore(t)
		user, tokens, err := c.Register(ctx, "alice@example.com", "correct-horse")
		if err != nil {
			t.Fatalf("Register: %v", err)
		}
		store.SetActive(user.ID, false)
		if _, _, err := c.Refresh(ctx, tokens.Refresh); !errors.Is(err, ErrUserInactive) {
			t.Fatalf("err = %v, want ErrUserInactive", err)
		}
		hash, _ := crypto.HashRefreshToken(tokens.Refresh)
		session, _ := store.SessionByHash(hash)
		if !session.Revoked() {
			t.Fatal("presented session must be revoked on the inactive verdict")
		}
	})
}

func TestLogout(t *testing.T) {
	ctx := context.Background()
	c, store := testCore(t)
	user, tokens, err := c.Register(ctx, "alice@example.com", "correct-horse")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if err := c.Logout(ctx, tokens.Refresh); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if n := store.LiveSessionCount(user.ID); n != 0 {
		t.Fatalf("live sessions = %d, want 0", n)
	}
	// Idempotent across every stale shape.
	for _, token := range []string{tokens.Refresh, "unknown-token", ""} {
		if err := c.Logout(ctx, token); err != nil {
			t.Fatalf("Logout(%q) must be idempotent: %v", token, err)
		}
	}
}

func TestRevokeAllSessions(t *testing.T) {
	ctx := context.Background()
	c, store := testCore(t)
	user, first, err := c.Register(ctx, "alice@example.com", "correct-horse")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	second, err := c.IssueTokensForUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("IssueTokensForUser: %v", err)
	}
	if n := store.LiveSessionCount(user.ID); n != 2 {
		t.Fatalf("live sessions = %d, want 2", n)
	}

	if err := c.RevokeAllSessions(ctx, user.ID); err != nil {
		t.Fatalf("RevokeAllSessions: %v", err)
	}
	if n := store.LiveSessionCount(user.ID); n != 0 {
		t.Fatalf("live sessions = %d, want 0 (sign out everywhere)", n)
	}
	for _, token := range []string{first.Refresh, second.Refresh} {
		if _, _, err := c.Refresh(ctx, token); !errors.Is(err, ErrInvalidSession) {
			t.Fatalf("revoked session must reject: %v", err)
		}
	}
}

func TestTokenlessCore(t *testing.T) {
	c, err := New(NewMemStore(), nil, WithRefreshTTL(time.Hour))
	if err != nil {
		t.Fatalf("New with nil jwt must construct (crypto-ops instances): %v", err)
	}
	if _, err := c.IssueTokensForUser(context.Background(), "u1"); !errors.Is(err, ErrNoTokenService) {
		t.Fatalf("err = %v, want ErrNoTokenService", err)
	}
}

func TestConcurrentUse(t *testing.T) {
	ctx := context.Background()
	c, _ := testCore(t)
	if _, _, err := c.Register(ctx, "alice@example.com", "correct-horse"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if _, _, err := c.Login(ctx, "alice@example.com", "correct-horse"); err != nil {
					t.Errorf("goroutine %d: %v", g, err)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

func mustHash(t *testing.T, password string) string {
	t.Helper()
	h, err := crypto.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	return h
}
