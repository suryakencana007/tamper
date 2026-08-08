package identity

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/suryakencana007/tamper/crypto"
)

// Slice 7j-1 — invitations.
//
// Two properties carry this slice, and both are the kind that pass by
// accident under sequential testing: an invitation is usable exactly
// once even when two people click at the same instant, and a dead
// invitation says nothing about WHY it is dead.

// invCore builds a tenancy-enabled Core with invitations wired.
func invCore(t *testing.T, opts ...Option) (*Core, *MemStore) {
	t.Helper()
	store := NewMemStore()
	base := []Option{
		WithRefreshTTL(30 * 24 * time.Hour),
		WithDefaultACR(testACR),
		WithTenancy(true),
		WithInvitations(store),
	}
	c, err := New(store, testJWT(), append(base, opts...)...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, store
}

// freshToken mints a well-formed token that was never issued — the
// "unknown but syntactically valid" probe.
func freshToken() (string, error) { return crypto.NewRefreshToken() }

// mustInvite issues an invitation and returns the plaintext token.
func mustInvite(t *testing.T, c *Core, tenantID, email string) (Invitation, string) {
	t.Helper()
	inv, token, err := c.Invite(context.Background(), tenantID, email, "admin-1", time.Hour)
	if err != nil {
		t.Fatalf("Invite: %v", err)
	}
	return inv, token
}

// --- the happy path ----------------------------------------------------

func TestInvitation_AcceptCreatesTheInvitedAccount(t *testing.T) {
	ctx := context.Background()
	c, _ := invCore(t)
	_, token := mustInvite(t, c, "acme", "bob@acme.example")

	user, tokens, err := c.AcceptInvitation(ctx, "acme", token, "correct-horse-battery")
	if err != nil {
		t.Fatalf("AcceptInvitation: %v", err)
	}
	if user.Email != "bob@acme.example" {
		t.Errorf("email = %q, want the INVITED address", user.Email)
	}
	if user.TenantID != "acme" {
		t.Errorf("tenant = %q, want acme", user.TenantID)
	}
	if tokens.Access == "" || tokens.Refresh == "" {
		t.Errorf("accepting did not mint a session: %+v", tokens)
	}

	// The account works.
	if _, _, err := c.LoginInTenant(ctx, "acme", "bob@acme.example", "correct-horse-battery"); err != nil {
		t.Errorf("login as the accepted user: %v", err)
	}
}

// TestInvitation_EmailIsNormalisedAndCarried: the account is created
// with the invitation's address, and the caller never supplies one. An
// accept that took an email argument would be a voucher to create ANY
// account inside the tenant.
func TestInvitation_EmailIsNormalisedAndCarried(t *testing.T) {
	ctx := context.Background()
	c, _ := invCore(t)
	inv, token := mustInvite(t, c, "acme", "  Bob@ACME.Example ")
	if inv.Email != "bob@acme.example" {
		t.Errorf("stored email = %q, want normalised", inv.Email)
	}
	user, _, err := c.AcceptInvitation(ctx, "acme", token, "correct-horse-battery")
	if err != nil {
		t.Fatalf("AcceptInvitation: %v", err)
	}
	if user.Email != "bob@acme.example" {
		t.Errorf("created account email = %q, want %q", user.Email, "bob@acme.example")
	}
}

// --- the token is a credential -----------------------------------------

// TestInvitation_PlaintextTokenIsNeverStored: the record is what an
// audit path will log. If the plaintext lived on it, inviting somebody
// would write a working credential into the log pipeline.
func TestInvitation_PlaintextTokenIsNeverStored(t *testing.T) {
	ctx := context.Background()
	c, store := invCore(t)
	inv, token := mustInvite(t, c, "acme", "bob@acme.example")

	if inv.TokenHash == token {
		t.Fatal("TokenHash holds the plaintext token")
	}
	if inv.TokenHash == "" {
		t.Fatal("TokenHash is empty; nothing was persisted to match against")
	}
	rendered := fmt.Sprintf("%+v", inv)
	if strings.Contains(rendered, token) {
		t.Errorf("the invitation record carries the plaintext token: %s", rendered)
	}

	stored, err := store.InvitationByHash(ctx, inv.TokenHash)
	if err != nil {
		t.Fatalf("InvitationByHash: %v", err)
	}
	if strings.Contains(stored.TokenHash, token) {
		t.Error("the stored row carries the plaintext token")
	}
}

// TestInvitation_TokensAreDistinct: a generator that returned a constant
// would pass every single-invitation test in this file and make one
// leaked link open every tenant.
func TestInvitation_TokensAreDistinct(t *testing.T) {
	c, _ := invCore(t)
	seen := make(map[string]bool)
	for i := range 50 {
		_, token := mustInvite(t, c, "acme", "bob@acme.example")
		if seen[token] {
			t.Fatalf("invitation %d reissued an existing token", i)
		}
		seen[token] = true
	}
}

// --- single use, including under concurrency ---------------------------

// TestInvitation_ConcurrentAcceptExactlyOneWins is the DoD line, and the
// reason MarkAccepted is a store-level compare-and-set rather than a
// check in the core. Two people clicking one link at the same instant
// must not produce two accounts.
//
// Run under -race. Sequentially this passes even with the check in the
// wrong place, which is exactly why the manifest asks for it here.
func TestInvitation_ConcurrentAcceptExactlyOneWins(t *testing.T) {
	ctx := context.Background()
	c, store := invCore(t)
	inv, token := mustInvite(t, c, "acme", "bob@acme.example")

	const racers = 16
	var (
		mu       sync.Mutex
		wins     int
		rejected int
		other    []error
		wg       sync.WaitGroup
	)
	start := make(chan struct{})
	for range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // release them together
			_, _, err := c.AcceptInvitation(ctx, "acme", token, "correct-horse-battery")
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				wins++
			case errors.Is(err, ErrInvitationInvalid):
				rejected++
			default:
				other = append(other, err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if wins != 1 {
		t.Errorf("%d of %d concurrent accepts succeeded, want exactly 1; "+
			"one invitation produced %d accounts", wins, racers, wins)
	}
	if rejected != racers-1 {
		t.Errorf("%d rejections, want %d — some losers failed for another reason: %v",
			rejected, racers-1, other)
	}
	if len(other) != 0 {
		t.Errorf("unexpected errors from the losing accepts: %v", other)
	}

	// And the invitation is spent, once.
	final, err := store.InvitationByHash(ctx, inv.TokenHash)
	if err != nil {
		t.Fatalf("InvitationByHash: %v", err)
	}
	if final.Pending() {
		t.Error("the invitation is still pending after a successful accept")
	}
}

// TestInvitation_SequentialReuseFails is the plain single-use case: a
// link that worked once must not work again an hour later.
func TestInvitation_SequentialReuseFails(t *testing.T) {
	ctx := context.Background()
	c, _ := invCore(t)
	_, token := mustInvite(t, c, "acme", "bob@acme.example")

	if _, _, err := c.AcceptInvitation(ctx, "acme", token, "correct-horse-battery"); err != nil {
		t.Fatalf("first accept: %v", err)
	}
	_, _, err := c.AcceptInvitation(ctx, "acme", token, "another-password-x")
	if !errors.Is(err, ErrInvitationInvalid) {
		t.Errorf("second accept err = %v, want ErrInvitationInvalid", err)
	}
}

// --- expiry and the indistinguishability invariant ---------------------

func TestInvitation_ExpiredIsRejected(t *testing.T) {
	ctx := context.Background()
	c, _ := invCore(t)
	now := time.Now()
	c.now = func() time.Time { return now }

	_, token := mustInvite(t, c, "acme", "bob@acme.example") // ttl 1h

	c.now = func() time.Time { return now.Add(time.Hour + time.Second) }
	if _, _, err := c.AcceptInvitation(ctx, "acme", token, "correct-horse-battery"); !errors.Is(err, ErrInvitationInvalid) {
		t.Errorf("expired accept err = %v, want ErrInvitationInvalid", err)
	}
}

// TestInvitation_ExpiryBoundary: the TTL instant itself is dead. An
// invitation "valid until T" that still works AT T is off by one in the
// direction that favours a stale link.
func TestInvitation_ExpiryBoundary(t *testing.T) {
	now := time.Now()
	inv := Invitation{ExpiresAt: now.Add(time.Hour)}

	if inv.Expired(now.Add(time.Hour - time.Nanosecond)) {
		t.Error("expired one nanosecond early")
	}
	if !inv.Expired(now.Add(time.Hour)) {
		t.Error("still usable AT the expiry instant")
	}
	if !inv.Expired(now.Add(time.Hour + time.Nanosecond)) {
		t.Error("still usable after expiry")
	}
}

// TestInvitation_ZeroExpiryIsDead: the zero value of a field an
// application fills in by hand must not be the permissive reading. A
// forgotten ExpiresAt would otherwise mint links that never die.
func TestInvitation_ZeroExpiryIsDead(t *testing.T) {
	var inv Invitation
	if !inv.Expired(time.Now()) {
		t.Error("a zero ExpiresAt reads as never-expires")
	}
	if inv.Usable(time.Now()) {
		t.Error("the zero Invitation is usable")
	}
}

// TestInvitation_ExpiredAndAcceptedAreIndistinguishable is the second
// DoD line. Telling the two apart tells whoever holds a stale link
// whether somebody ELSE already used it — a fact about another person's
// actions inside a tenant, disclosed to someone who by then has no
// standing at all.
//
// Compared as whole values, not just error identity: a future field that
// varied between the two would slip past an errors.Is check.
func TestInvitation_ExpiredAndAcceptedAreIndistinguishable(t *testing.T) {
	ctx := context.Background()
	c, _ := invCore(t)
	now := time.Now()
	c.now = func() time.Time { return now }

	// One invitation that will be accepted, one that will expire.
	_, acceptedTok := mustInvite(t, c, "acme", "accepted@acme.example")
	_, expiredTok := mustInvite(t, c, "acme", "expired@acme.example")

	if _, _, err := c.AcceptInvitation(ctx, "acme", acceptedTok, "correct-horse-battery"); err != nil {
		t.Fatalf("priming accept: %v", err)
	}
	c.now = func() time.Time { return now.Add(2 * time.Hour) } // both are now dead

	accUser, accTokens, accErr := c.AcceptInvitation(ctx, "acme", acceptedTok, "correct-horse-battery")
	expUser, expTokens, expErr := c.AcceptInvitation(ctx, "acme", expiredTok, "correct-horse-battery")

	if !reflect.DeepEqual(accUser, expUser) {
		t.Errorf("User differs: accepted %+v expired %+v", accUser, expUser)
	}
	if !reflect.DeepEqual(accTokens, expTokens) {
		t.Errorf("Tokens differ: accepted %+v expired %+v", accTokens, expTokens)
	}
	if accErr == nil || expErr == nil {
		t.Fatalf("a dead invitation was accepted: accepted %v expired %v", accErr, expErr)
	}
	if accErr.Error() != expErr.Error() {
		t.Errorf("the error MESSAGE distinguishes accepted from expired:\n"+
			"accepted: %q\n expired: %q", accErr.Error(), expErr.Error())
	}

	// ...and an outright unknown token is the same answer again, so a
	// probe cannot even learn that a token was ever issued.
	unknownTok, err := freshToken()
	if err != nil {
		t.Fatalf("freshToken: %v", err)
	}
	_, _, unkErr := c.AcceptInvitation(ctx, "acme", unknownTok, "correct-horse-battery")
	if unkErr == nil || unkErr.Error() != accErr.Error() {
		t.Errorf("an unknown token answers %v, differing from a spent one (%v)",
			unkErr, accErr)
	}

	// A malformed token too — "wrong shape" must not be its own answer.
	_, _, badErr := c.AcceptInvitation(ctx, "acme", "not-a-valid-token!!", "correct-horse-battery")
	if badErr == nil || badErr.Error() != accErr.Error() {
		t.Errorf("a malformed token answers %v, differing from a spent one (%v)",
			badErr, accErr)
	}
}

// --- tenancy -----------------------------------------------------------

// TestInvitation_WrongTenantIsAMiss: an invitation issued for acme must
// not be redeemable into globex, and the refusal must look exactly like
// an unknown token. §6.3 — a deny and a miss are indistinguishable, so a
// token cannot be used to confirm that some OTHER tenant exists.
func TestInvitation_WrongTenantIsAMiss(t *testing.T) {
	ctx := context.Background()
	c, _ := invCore(t)
	_, token := mustInvite(t, c, "acme", "bob@acme.example")

	_, _, wrongErr := c.AcceptInvitation(ctx, "globex", token, "correct-horse-battery")
	if !errors.Is(wrongErr, ErrInvitationInvalid) {
		t.Fatalf("cross-tenant accept err = %v, want ErrInvitationInvalid", wrongErr)
	}

	unknownTok, err := freshToken()
	if err != nil {
		t.Fatalf("freshToken: %v", err)
	}
	_, _, unkErr := c.AcceptInvitation(ctx, "globex", unknownTok, "correct-horse-battery")
	if unkErr.Error() != wrongErr.Error() {
		t.Errorf("a wrong-tenant token (%v) is distinguishable from an unknown one (%v); "+
			"holding a token confirms which tenant it belongs to", wrongErr, unkErr)
	}

	// And nothing was consumed: the real tenant can still redeem it.
	if _, _, err := c.AcceptInvitation(ctx, "acme", token, "correct-horse-battery"); err != nil {
		t.Errorf("a failed cross-tenant accept burned the invitation: %v", err)
	}
}

// TestInvitation_TenantGateApplies: the invitation verbs route through
// the same gate as every other tenant-aware call, so a tenancy-enabled
// Core cannot invite into the wildcard and a single-tenant Core cannot
// be handed a tenant it has no column for.
func TestInvitation_TenantGateApplies(t *testing.T) {
	ctx := context.Background()

	t.Run("tenancy on, empty tenant", func(t *testing.T) {
		c, _ := invCore(t)
		if _, _, err := c.Invite(ctx, "", "bob@acme.example", "admin-1", time.Hour); !errors.Is(err, ErrTenantRequired) {
			t.Errorf("Invite err = %v, want ErrTenantRequired", err)
		}
		if _, _, err := c.AcceptInvitation(ctx, "", "tok", "correct-horse-battery"); !errors.Is(err, ErrTenantRequired) {
			t.Errorf("Accept err = %v, want ErrTenantRequired", err)
		}
	})

	t.Run("tenancy off, tenant supplied", func(t *testing.T) {
		store := NewMemStore()
		c, err := New(store, testJWT(), WithDefaultACR(testACR), WithInvitations(store))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if _, _, err := c.Invite(ctx, "acme", "bob@acme.example", "admin-1", time.Hour); !errors.Is(err, ErrTenancyDisabled) {
			t.Errorf("Invite err = %v, want ErrTenancyDisabled", err)
		}
	})

	t.Run("single-tenant core round-trips the empty tenant", func(t *testing.T) {
		store := NewMemStore()
		c, err := New(store, testJWT(), WithRefreshTTL(time.Hour), WithDefaultACR(testACR),
			WithInvitations(store))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		_, token, err := c.Invite(ctx, "", "bob@example.com", "admin-1", time.Hour)
		if err != nil {
			t.Fatalf("Invite: %v", err)
		}
		user, _, err := c.AcceptInvitation(ctx, "", token, "correct-horse-battery")
		if err != nil {
			t.Fatalf("AcceptInvitation: %v", err)
		}
		if user.TenantID != "" {
			t.Errorf("tenant = %q, want the empty single-tenant value", user.TenantID)
		}
	})
}

// --- construction and configuration ------------------------------------

// TestInvitation_BootGuardFires. The standing rule: a configuration
// upgrade ships a guard AND a test that it fires.
func TestInvitation_NilStorePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("WithInvitations(nil) did not panic; the Core would believe it " +
				"can invite and fail on the first invitation an admin sends")
		}
	}()
	_ = WithInvitations(nil)
}

// TestInvitation_UnconfiguredCoreErrorsLoudly: a Core with no invitation
// store must say so, not silently do nothing that looks like an email
// delivery problem.
func TestInvitation_UnconfiguredCoreErrorsLoudly(t *testing.T) {
	ctx := context.Background()
	c, _ := testCore(t) // no WithInvitations
	if _, _, err := c.Invite(ctx, "", "bob@example.com", "admin-1", time.Hour); !errors.Is(err, ErrNoInvitationStore) {
		t.Errorf("Invite err = %v, want ErrNoInvitationStore", err)
	}
	if _, _, err := c.AcceptInvitation(ctx, "", "tok", "correct-horse-battery"); !errors.Is(err, ErrNoInvitationStore) {
		t.Errorf("Accept err = %v, want ErrNoInvitationStore", err)
	}
}

// TestInvitation_NonPositiveTTLGetsTheDefault: 0 must not read as
// "never expires". A forgotten argument becoming a permanent credential
// is the failure this guards.
func TestInvitation_NonPositiveTTLGetsTheDefault(t *testing.T) {
	ctx := context.Background()
	c, _ := invCore(t)
	now := time.Now()
	c.now = func() time.Time { return now }

	for _, ttl := range []time.Duration{0, -time.Hour} {
		inv, _, err := c.Invite(ctx, "acme", "bob@acme.example", "admin-1", ttl)
		if err != nil {
			t.Fatalf("Invite(ttl=%v): %v", ttl, err)
		}
		if want := now.Add(DefaultInvitationTTL); !inv.ExpiresAt.Equal(want) {
			t.Errorf("ttl %v produced ExpiresAt %v, want the default %v",
				ttl, inv.ExpiresAt, want)
		}
		if inv.Expired(now) {
			t.Errorf("ttl %v produced an already-dead invitation", ttl)
		}
	}
}

// --- the accept-time failure ordering ----------------------------------

// TestInvitation_WeakPasswordDoesNotBurnTheInvitation: the password is
// validated BEFORE the invitation is consumed. Burning the link on a
// typo turns every rejected password into a support ticket.
func TestInvitation_WeakPasswordDoesNotBurnTheInvitation(t *testing.T) {
	ctx := context.Background()
	c, _ := invCore(t)
	_, token := mustInvite(t, c, "acme", "bob@acme.example")

	if _, _, err := c.AcceptInvitation(ctx, "acme", token, "x"); !errors.Is(err, ErrPasswordPolicy) {
		t.Fatalf("weak-password accept err = %v, want ErrPasswordPolicy", err)
	}
	// The link still works.
	if _, _, err := c.AcceptInvitation(ctx, "acme", token, "correct-horse-battery"); err != nil {
		t.Errorf("a rejected password burned the invitation: %v", err)
	}
}

// --- the store contract -------------------------------------------------

// TestInvitationStore_MarkAcceptedIsCompareAndSet exercises the port
// directly, without the core. An implementation that read-then-wrote
// would let two callers both win here, and the core has no way to
// compensate for that.
func TestInvitationStore_MarkAcceptedIsCompareAndSet(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	inv := Invitation{
		ID: "inv-1", TenantID: "acme", Email: "bob@acme.example",
		TokenHash: "hash-1", ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := store.CreateInvitation(ctx, inv); err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}

	const racers = 32
	var mu sync.Mutex
	var wins int
	var wg sync.WaitGroup
	start := make(chan struct{})
	at := time.Now()
	for range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if err := store.MarkAccepted(ctx, "inv-1", at); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()

	if wins != 1 {
		t.Errorf("%d concurrent MarkAccepted calls succeeded, want exactly 1; "+
			"the store is a read-then-write, not a compare-and-set", wins)
	}
	if err := store.MarkAccepted(ctx, "inv-1", at); !errors.Is(err, ErrInvitationConsumed) {
		t.Errorf("re-accept err = %v, want ErrInvitationConsumed", err)
	}
	if err := store.MarkAccepted(ctx, "no-such-id", at); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown-id err = %v, want ErrNotFound", err)
	}
}

// TestInvitationStore_ByHashReturnsDeadRows: the store must not filter
// on expiry or accepted-ness. Filtering would turn "already accepted"
// into a not-found, and the core needs both paths to reach one collapsed
// error rather than two different ones.
func TestInvitationStore_ByHashReturnsDeadRows(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	past := time.Now().Add(-time.Hour)
	rows := []Invitation{
		{ID: "expired", TokenHash: "h-expired", ExpiresAt: past},
		{ID: "accepted", TokenHash: "h-accepted", ExpiresAt: time.Now().Add(time.Hour), AcceptedAt: past},
	}
	for _, r := range rows {
		if err := store.CreateInvitation(ctx, r); err != nil {
			t.Fatalf("CreateInvitation(%s): %v", r.ID, err)
		}
	}
	for _, r := range rows {
		got, err := store.InvitationByHash(ctx, r.TokenHash)
		if err != nil {
			t.Errorf("InvitationByHash(%s) = %v; the store filtered a dead row, so the "+
				"core cannot tell it apart from an unknown token", r.ID, err)
			continue
		}
		if got.ID != r.ID {
			t.Errorf("InvitationByHash(%s) returned %s", r.ID, got.ID)
		}
	}
}
