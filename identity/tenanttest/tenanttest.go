// Package tenanttest is the cross-tenant leak conformance harness for
// identity.Store.
//
// tamper cannot enforce tenant isolation: the query lives in the
// application's adapter. What it can do is state the obligation on the
// port (identity/store.go, the isolation contract) and ship the
// instrument that checks it. This package is that instrument, and it is
// the thing that replaces "Barista runs it in production" as the proof
// that pooled tenancy holds (sketch §3.3).
//
// Adapter authors run it against their own store:
//
//	func TestMyStoreIsolation(t *testing.T) {
//	    tenanttest.RunLeakSuite(t, func() identity.Store {
//	        return newMyStore(t) // fresh and EMPTY on every call
//	    })
//	}
//
// The suite has no opinion about your schema. It seeds through the port
// and reads through the port, so it works equally over row-level
// security, schema-per-tenant, a discriminator column, or separate
// databases.
//
// It never skips. A skipped case reports green and guards nothing, and
// there is deliberately no "my store is single-tenant" opt-out: nothing
// the suite can observe distinguishes a single-tenant store from a
// pooled one that leaks — seed two tenants, ask one for the other's
// row, and a store that ignores tenantID answers exactly like a store
// that has only ever had one tenant. An opt-out would therefore be a
// switch that silences the suite precisely when it has found the bug it
// exists to find. A single-tenant adapter has no isolation to prove and
// simply does not run this.
package tenanttest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/suryakencana007/tamper/identity"
	"github.com/suryakencana007/tamper/tenant"
)

// The two tenants every case is built from. They are opaque values, as
// tamper requires of any tenant id — nothing here parses them.
const (
	tenantA = "tenanttest-a"
	tenantB = "tenanttest-b"
)

// fixedTime pins every timestamp the suite writes. The suite has no
// wall-clock dependence and no sleeps: a conformance harness that fails
// intermittently teaches adapter authors to re-run it until it passes,
// which is the opposite of its purpose.
var fixedTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// RunLeakSuite asserts the isolation contract on a TenantScopedStore.
// newStore must return a FRESH, EMPTY store on each call — every case
// builds its own so no case can pass or fail because of another's rows.
//
// Every assertion has the same shape: seed tenant A and tenant B, then
// address B's object as A and require errors.Is(err, identity.ErrNotFound).
// Three outcomes are failures, for three different reasons:
//
//   - B's row comes back — the leak itself.
//   - a permission-shaped error comes back — it discloses that the
//     object exists, which is the 404-not-403 rule (sketch §6.3): a deny
//     and a miss must be indistinguishable, or the error becomes an
//     existence oracle.
//   - a zero value with a nil error — it discloses nothing, but it fails
//     OPEN, and a caller that checks only err will read it as success.
//
// The suite also asserts the positive direction, because isolation that
// works by returning nothing to everyone is not isolation: each tenant
// must still see its OWN rows.
func RunLeakSuite(t *testing.T, newStore func() identity.Store) {
	t.Helper()
	runLeakSuite(realT{t}, newStore)
}

// harnessT is the slice of *testing.T the suite uses. It exists so the
// package's own tests can drive the suite with a recorder and assert
// that a deliberately-leaky store FAILS — without that seam, "the suite
// bites" is an assertion nobody can check, which is the exact shape of
// a guard that is green and pointed at nothing.
type harnessT interface {
	Helper()
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
	Run(name string, f func(harnessT)) bool
}

// realT adapts *testing.T to harnessT. Run is redeclared because
// testing.T's takes func(*testing.T); the embedded Helper/Errorf/Fatalf
// are used as-is, so real runs keep real semantics (Fatalf still calls
// runtime.Goexit, failures still attribute to the right subtest).
type realT struct{ *testing.T }

func (r realT) Run(name string, f func(harnessT)) bool {
	return r.T.Run(name, func(sub *testing.T) { f(realT{sub}) })
}

func runLeakSuite(t harnessT, newStore func() identity.Store) {
	t.Helper()
	t.Run("UserByEmail", func(t harnessT) { userByEmailInTenant(t, newStore()) })
	t.Run("IdentityByProviderSubject", func(t harnessT) { identityByProviderSubjectInTenant(t, newStore()) })
	t.Run("CountUsers", func(t harnessT) { countUsersInTenant(t, newStore()) })
	t.Run("RefreshSessionByHash", func(t harnessT) { refreshSessionByHash(t, newStore()) })
	t.Run("RevokeAllRefreshSessionsForTenant", func(t harnessT) { revokeAllRefreshSessionsForTenant(t, newStore()) })
}

// requireNotFound is the shared verdict for every cross-tenant probe.
// found reports whether a non-zero value came back, so the fail-open
// case (zero value, nil error) is caught as well as the leak.
func requireNotFound(t harnessT, what string, found bool, err error) {
	t.Helper()
	switch {
	case err == nil && found:
		t.Errorf("%s: returned another tenant's row with a nil error — this is the leak", what)
	case err == nil:
		t.Errorf("%s: returned a zero value with a NIL error, want identity.ErrNotFound; "+
			"a caller that checks only err reads this as success, so it fails open", what)
	case !errors.Is(err, identity.ErrNotFound):
		t.Errorf("%s: returned %v, want identity.ErrNotFound; a permission-shaped error "+
			"discloses that the object exists (404-not-403, sketch §6.3)", what, err)
	}
}

func seedUser(t harnessT, s identity.Store, id, tenantID, email string) {
	t.Helper()
	err := s.CreateUser(context.Background(), identity.NewUser{
		ID: id, TenantID: tenantID, Email: email, PasswordHash: "x", CreatedAt: fixedTime,
	}, false)
	if err != nil {
		if errors.Is(err, identity.ErrEmailTaken) {
			t.Fatalf("seeding %q into tenant %q returned ErrEmailTaken: email is still unique "+
				"GLOBALLY, not per tenant. Two customers cannot both have this address — "+
				"that is blocker B1, and it is a store-schema problem, not a suite failure", email, tenantID)
			return
		}
		t.Fatalf("seeding user %q into tenant %q: %v", id, tenantID, err)
	}
}

func userByEmailInTenant(t harnessT, s identity.Store) {
	t.Helper()
	ctx := context.Background()
	const shared = "bob@example.com"

	// The same address in both tenants — two different people.
	seedUser(t, s, "a-bob", tenantA, shared)
	seedUser(t, s, "b-bob", tenantB, shared)
	// An address that exists ONLY in B, for the cross-tenant probe.
	seedUser(t, s, "b-only", tenantB, "onlyinb@example.com")

	got, err := s.UserByEmail(ctx, tenant.New(tenantA), shared)
	if err != nil {
		t.Errorf("tenant A cannot see its OWN user by email: %v", err)
	} else if got.ID != "a-bob" {
		t.Errorf("tenant A resolved %q for %s, want %q — the shared email crossed tenants",
			got.ID, shared, "a-bob")
	}
	got, err = s.UserByEmail(ctx, tenant.New(tenantB), shared)
	if err != nil {
		t.Errorf("tenant B cannot see its OWN user by email: %v", err)
	} else if got.ID != "b-bob" {
		t.Errorf("tenant B resolved %q for %s, want %q", got.ID, shared, "b-bob")
	}

	leaked, err := s.UserByEmail(ctx, tenant.New(tenantA), "onlyinb@example.com")
	requireNotFound(t, "UserByEmail(A, an email only tenant B has)", leaked.ID != "", err)
}

func identityByProviderSubjectInTenant(t harnessT, s identity.Store) {
	t.Helper()
	ctx := context.Background()
	const provider, subject = "google", "sub-shared"

	seedUser(t, s, "a-user", tenantA, "a@example.com")
	seedUser(t, s, "b-user", tenantB, "b@example.com")

	for _, seed := range []identity.NewIdentity{
		{ID: "a-ident", UserID: "a-user", TenantID: tenantA, Provider: provider, Subject: subject, LinkedAt: fixedTime},
		{ID: "b-ident", UserID: "b-user", TenantID: tenantB, Provider: provider, Subject: subject, LinkedAt: fixedTime},
		{ID: "b-only-ident", UserID: "b-user", TenantID: tenantB, Provider: provider, Subject: "sub-only-b", LinkedAt: fixedTime},
	} {
		if err := s.InsertIdentity(ctx, seed); err != nil {
			if errors.Is(err, identity.ErrIdentityTaken) {
				t.Fatalf("seeding identity %q into tenant %q returned ErrIdentityTaken: "+
					"(provider, subject) is still unique GLOBALLY, not per tenant, so two "+
					"tenants cannot federate with the same IdP", seed.ID, seed.TenantID)
				return
			}
			t.Fatalf("seeding identity %q: %v", seed.ID, err)
		}
	}

	got, err := s.IdentityByProviderSubject(ctx, tenant.New(tenantA), provider, subject)
	if err != nil {
		t.Errorf("tenant A cannot see its OWN identity: %v", err)
	} else if got.ID != "a-ident" {
		t.Errorf("tenant A resolved %q, want %q — the shared (provider, subject) crossed tenants", got.ID, "a-ident")
	}

	leaked, err := s.IdentityByProviderSubject(ctx, tenant.New(tenantA), provider, "sub-only-b")
	requireNotFound(t, "IdentityByProviderSubject(A, a subject only tenant B has)", leaked.ID != "", err)
}

func countUsersInTenant(t harnessT, s identity.Store) {
	t.Helper()
	ctx := context.Background()

	seedUser(t, s, "a-1", tenantA, "a1@example.com")
	seedUser(t, s, "a-2", tenantA, "a2@example.com")
	seedUser(t, s, "b-1", tenantB, "b1@example.com")
	seedUser(t, s, "b-2", tenantB, "b2@example.com")
	seedUser(t, s, "b-3", tenantB, "b3@example.com")

	if n, err := s.CountUsers(ctx, tenant.New(tenantA)); err != nil {
		t.Errorf("CountUsers(A): %v", err)
	} else if n != 2 {
		t.Errorf("CountUsers(A) = %d, want 2 — the count includes another tenant's users. "+
			"This drives the firstUser bootstrap signal, so a global count means tenant B's first "+
			"admin silently gets firstUser=false and no permissions (blocker B2)", n)
	}
	if n, err := s.CountUsers(ctx, tenant.New(tenantB)); err != nil {
		t.Errorf("CountUsers(B): %v", err)
	} else if n != 3 {
		t.Errorf("CountUsers(B) = %d, want 3", n)
	}

	// An unknown tenant is empty, not everything. A count is not a
	// lookup, so there is no row to withhold — but answering "all users"
	// for a tenant that does not exist is the wildcard reading that
	// deny-by-default forbids (sketch §6.2).
	if n, err := s.CountUsers(ctx, tenant.New("tenanttest-nonexistent")); err != nil {
		t.Errorf("CountUsers(unknown tenant): %v", err)
	} else if n != 0 {
		t.Errorf("CountUsers(unknown tenant) = %d, want 0 — an unknown tenant "+
			"resolved to every tenant's users", n)
	}
}

func refreshSessionByHash(t harnessT, s identity.Store) {
	t.Helper()
	ctx := context.Background()

	seedUser(t, s, "b-user", tenantB, "b@example.com")
	if err := s.CreateRefreshSession(ctx, identity.RefreshSession{
		ID: "b-sess", UserID: "b-user", TenantID: tenantB, TokenHash: "hash-b",
		IssuedAt: fixedTime, ExpiresAt: fixedTime.Add(time.Hour),
	}); err != nil {
		t.Fatalf("seeding tenant B session: %v", err)
	}

	// RefreshSessionByHash is keyed by an unguessable hash, so the leak
	// is not "A can read B's row by guessing" — it is that the row comes
	// back WITHOUT its tenant. An empty TenantID reads as the
	// single-tenant shape, so a caller that would have rejected a
	// cross-tenant refresh has nothing left to reject on, and the
	// session is usable from any tenant.
	got, err := s.RefreshSessionByHash(ctx, "hash-b")
	if err != nil {
		t.Fatalf("RefreshSessionByHash: %v", err)
	}
	if got.TenantID != tenantB {
		t.Errorf("session minted in tenant %q came back with TenantID %q; the store dropped the "+
			"tenant, so the session is no longer bound to one and any tenant can rotate it",
			tenantB, got.TenantID)
	}
}

func revokeAllRefreshSessionsForTenant(t harnessT, s identity.Store) {
	t.Helper()
	ctx := context.Background()

	seedUser(t, s, "a-user", tenantA, "a@example.com")
	seedUser(t, s, "b-user", tenantB, "b@example.com")
	for _, sess := range []identity.RefreshSession{
		{ID: "a-sess", UserID: "a-user", TenantID: tenantA, TokenHash: "hash-a", IssuedAt: fixedTime, ExpiresAt: fixedTime.Add(time.Hour)},
		{ID: "b-sess", UserID: "b-user", TenantID: tenantB, TokenHash: "hash-b", IssuedAt: fixedTime, ExpiresAt: fixedTime.Add(time.Hour)},
	} {
		if err := s.CreateRefreshSession(ctx, sess); err != nil {
			t.Fatalf("seeding session %q: %v", sess.ID, err)
		}
	}

	if err := s.RevokeAllRefreshSessionsForTenant(ctx, tenant.New(tenantA), fixedTime.Add(time.Minute)); err != nil {
		t.Fatalf("RevokeAllRefreshSessionsForTenant(A): %v", err)
	}

	a, err := s.RefreshSessionByHash(ctx, "hash-a")
	if err != nil {
		t.Fatalf("re-reading tenant A's session: %v", err)
	}
	if !a.Revoked() {
		t.Errorf("tenant A's session survived RevokeAllRefreshSessionsForTenant(A) — the revoke " +
			"did not reach its own tenant")
	}

	b, err := s.RefreshSessionByHash(ctx, "hash-b")
	if err != nil {
		t.Fatalf("re-reading tenant B's session: %v", err)
	}
	if b.Revoked() {
		t.Errorf("tenant B's session was revoked by RevokeAllRefreshSessionsForTenant(A) — the " +
			"revoke crossed the tenant boundary and signed out another customer")
	}
}
