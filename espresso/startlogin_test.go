package espresso

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/suryakencana007/tamper/identity"
	"github.com/suryakencana007/tamper/tenant"
)

// Slice 7f-2 — StartLogin. This endpoint is unauthenticated and takes an
// attacker-chosen email, so every test here is about the answer being
// the SAME answer, whichever fact it is hiding.

// --- fixtures ---------------------------------------------------------

type domainStore struct {
	recs map[string]tenant.DomainRecord
	err  error
}

var _ tenant.DomainStore = (*domainStore)(nil)

func (s *domainStore) ByDomain(_ context.Context, d string) (tenant.DomainRecord, error) {
	if s.err != nil {
		return tenant.DomainRecord{}, s.err
	}
	r, ok := s.recs[d]
	if !ok {
		return tenant.DomainRecord{}, fmt.Errorf("%w: domain %s", tenant.ErrNotFound, d)
	}
	return r, nil
}

func (s *domainStore) ListForTenant(context.Context, string) ([]tenant.DomainRecord, error) {
	return nil, nil
}

// recordingClock advances a fake clock by a caller-chosen amount per
// call and records what the timing floor asked to sleep. Nothing here
// touches the wall clock, so the suite has no timing dependence — the
// floor is asserted STRUCTURALLY, which is what the manifest demands.
type recordingClock struct {
	now      time.Time
	step     time.Duration
	slept    []time.Duration
	nowCalls int
}

func (c *recordingClock) Now() time.Time {
	c.nowCalls++
	t := c.now
	c.now = c.now.Add(c.step)
	return t
}

func (c *recordingClock) Sleep(d time.Duration) { c.slept = append(c.slept, d) }

func (c *recordingClock) totalSlept() time.Duration {
	var sum time.Duration
	for _, d := range c.slept {
		sum += d
	}
	return sum
}

// clockOpt wires a recordingClock that reports `cost` of elapsed work
// between the two Now() calls StartLogin makes.
func clockOpt(c *recordingClock, cost time.Duration) StartLoginOption {
	c.now = time.Unix(1700000000, 0).UTC()
	c.step = cost
	return WithStartLoginClock(c.Now, c.Sleep)
}

func verifiedBound(tenantID, domain, provider string) tenant.DomainRecord {
	return tenant.DomainRecord{TenantID: tenantID, Domain: domain, Verified: true, ProviderID: provider}
}

// --- the structural-identity property ---------------------------------

// TestStartLogin_MatchedAndUnmatchedAreStructurallyIdentical is the
// mutation target and the heart of the slice.
//
// Every non-match returns the ZERO result and a NIL error, so a caller —
// and therefore an attacker watching the caller — cannot tell an unknown
// domain from an unverified one, a public provider, a suspended tenant,
// or a customer who simply has no IdP. The five cases below are five
// different facts, and they must produce one byte-identical answer.
func TestStartLogin_MatchedAndUnmatchedAreStructurallyIdentical(t *testing.T) {
	ctx := context.Background()
	store := &domainStore{recs: map[string]tenant.DomainRecord{
		"acme.com": verifiedBound("t-acme", "acme.com", "okta"),
		// claimed but never proven
		"unverified.com": {TenantID: "t-x", Domain: "unverified.com", Verified: false, ProviderID: "okta"},
		// verified, but the tenant bound no IdP
		"noidp.com": {TenantID: "t-y", Domain: "noidp.com", Verified: true},
		// a suspended tenant's verified, IdP-bound domain
		"suspended.com": verifiedBound("t-susp", "suspended.com", "okta"),
	}}
	tenants := tenant.NewMemStore()
	tenants.Seed(tenant.Descriptor{ID: "t-acme", Slug: "acme", Status: tenant.StatusActive})
	tenants.Seed(tenant.Descriptor{ID: "t-y", Slug: "y", Status: tenant.StatusActive})
	tenants.Seed(tenant.Descriptor{ID: "t-susp", Slug: "susp", Status: tenant.StatusSuspended})

	opts := []StartLoginOption{WithStartLoginTenants(tenants), WithStartLoginFloor(0)}

	// The one positive match.
	matched, err := StartLogin(ctx, store, "bob@acme.com", opts...)
	if err != nil {
		t.Fatalf("matched: %v", err)
	}
	if matched.ProviderID != "okta" || matched.TenantID != "t-acme" || !matched.EnforceSSO {
		t.Fatalf("matched result = %+v, want t-acme/okta/enforced", matched)
	}

	// Five different facts, one answer.
	for _, tc := range []struct{ name, email string }{
		{"unknown domain", "bob@never-heard-of.com"},
		{"unverified claim", "bob@unverified.com"},
		{"public email provider", "bob@gmail.com"},
		{"suspended tenant", "bob@suspended.com"},
		{"verified but no IdP bound", "bob@noidp.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := StartLogin(ctx, store, tc.email, opts...)
			if err != nil {
				t.Fatalf("err = %v, want nil — a non-match is the fallback, not an error", err)
			}
			if !reflect.DeepEqual(got, StartLoginResult{}) {
				t.Errorf("result = %+v, want the zero value. This case is distinguishable "+
					"from the others, which makes the endpoint a tenant-enumeration oracle.", got)
			}
		})
	}
}

// TestStartLogin_UnmatchedCarriesNoTenantData: stated separately from
// the shape check because it is the property that survives someone
// later adding a field to the struct.
func TestStartLogin_UnmatchedCarriesNoTenantData(t *testing.T) {
	ctx := context.Background()
	store := &domainStore{recs: map[string]tenant.DomainRecord{
		"unverified.com": {TenantID: "secret-tenant", Domain: "unverified.com", Verified: false, ProviderID: "secret-idp"},
	}}

	got, err := StartLogin(ctx, store, "bob@unverified.com", WithStartLoginFloor(0))
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}
	// Walk every field reflectively, so a field added later is caught
	// rather than silently exempt.
	v := reflect.ValueOf(got)
	for i := range v.NumField() {
		f := v.Field(i)
		if f.Kind() == reflect.String && f.String() != "" {
			t.Errorf("field %s leaked %q on an unmatched domain",
				v.Type().Field(i).Name, f.String())
		}
		if f.Kind() == reflect.Bool && f.Bool() {
			t.Errorf("field %s is true on an unmatched domain", v.Type().Field(i).Name)
		}
	}
}

// TestStartLogin_SuspendedIsIndistinguishableFromUnknown pins the DoD
// line on its own, against a store where the suspended tenant's domain
// is otherwise perfectly resolvable.
func TestStartLogin_SuspendedIsIndistinguishableFromUnknown(t *testing.T) {
	ctx := context.Background()
	store := &domainStore{recs: map[string]tenant.DomainRecord{
		"suspended.com": verifiedBound("t-susp", "suspended.com", "okta"),
	}}
	tenants := tenant.NewMemStore()
	tenants.Seed(tenant.Descriptor{ID: "t-susp", Slug: "susp", Status: tenant.StatusSuspended})

	susp, sErr := StartLogin(ctx, store, "bob@suspended.com",
		WithStartLoginTenants(tenants), WithStartLoginFloor(0))
	unknown, uErr := StartLogin(ctx, store, "bob@nobody.com",
		WithStartLoginTenants(tenants), WithStartLoginFloor(0))

	if sErr != nil || uErr != nil {
		t.Fatalf("errors differ: suspended=%v unknown=%v", sErr, uErr)
	}
	if !reflect.DeepEqual(susp, unknown) {
		t.Errorf("suspended %+v differs from unknown %+v", susp, unknown)
	}
}

// TestStartLogin_PendingTenantAlsoDenied: only ACTIVE resolves. A
// pending tenant is mid-signup and must not yet capture logins.
func TestStartLogin_PendingTenantAlsoDenied(t *testing.T) {
	ctx := context.Background()
	store := &domainStore{recs: map[string]tenant.DomainRecord{
		"pending.com": verifiedBound("t-pend", "pending.com", "okta"),
	}}
	tenants := tenant.NewMemStore()
	tenants.Seed(tenant.Descriptor{ID: "t-pend", Slug: "pend", Status: tenant.StatusPending})

	got, err := StartLogin(ctx, store, "bob@pending.com",
		WithStartLoginTenants(tenants), WithStartLoginFloor(0))
	if err != nil || !reflect.DeepEqual(got, StartLoginResult{}) {
		t.Errorf("pending tenant resolved: (%+v, %v)", got, err)
	}
}

// --- the timing floor -------------------------------------------------

// TestStartLogin_TimingFloorPadsEveryPath is the timing invariant,
// asserted structurally: the fake clock reports how much work each path
// did, and the floor must top every one of them up to the same total.
// Nothing sleeps for real, so the test has no wall-clock dependence.
func TestStartLogin_TimingFloorPadsEveryPath(t *testing.T) {
	ctx := context.Background()
	store := &domainStore{recs: map[string]tenant.DomainRecord{
		"acme.com": verifiedBound("t-acme", "acme.com", "okta"),
	}}
	const floor = 50 * time.Millisecond

	// Each case reports a DIFFERENT amount of elapsed work, which is
	// exactly the signal the floor exists to erase.
	for _, tc := range []struct {
		name  string
		email string
		cost  time.Duration
	}{
		{"matched (store hit, slowest)", "bob@acme.com", 30 * time.Millisecond},
		{"unmatched (store miss)", "bob@nobody.com", 12 * time.Millisecond},
		{"public domain (no store call at all)", "bob@gmail.com", 1 * time.Millisecond},
		{"malformed email (rejected earliest)", "not-an-email", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &recordingClock{}
			_, _ = StartLogin(ctx, store, tc.email,
				WithStartLoginFloor(floor), clockOpt(c, tc.cost))

			if len(c.slept) != 1 {
				t.Fatalf("floor applied %d times, want exactly 1 — every return path must "+
					"be padded, including the error paths", len(c.slept))
			}
			// elapsed == cost (one clock step between the two Now calls),
			// so the pad must bring the total to the floor.
			if want := floor - tc.cost; c.totalSlept() != want {
				t.Errorf("padded by %v, want %v (floor %v minus %v of work)",
					c.totalSlept(), want, floor, tc.cost)
			}
		})
	}
}

// TestStartLogin_TimingFloorNotAppliedWhenWorkExceedsIt: a slow store
// must not be padded further; the floor is a minimum, not a fixed cost.
func TestStartLogin_TimingFloorNotAppliedWhenWorkExceedsIt(t *testing.T) {
	ctx := context.Background()
	store := &domainStore{recs: map[string]tenant.DomainRecord{}}
	c := &recordingClock{}
	_, _ = StartLogin(ctx, store, "bob@nobody.com",
		WithStartLoginFloor(10*time.Millisecond), clockOpt(c, 200*time.Millisecond))
	if len(c.slept) != 0 {
		t.Errorf("padded by %v when the work already exceeded the floor", c.totalSlept())
	}
}

// --- the rate-limit hook ----------------------------------------------

type stubThrottle struct {
	allow      bool
	retryAfter time.Duration
	keys       []string
}

func (s *stubThrottle) Allow(_ context.Context, key string) (bool, time.Duration) {
	s.keys = append(s.keys, key)
	return s.allow, s.retryAfter
}

func TestStartLogin_ThrottleRefusalIsReported(t *testing.T) {
	ctx := context.Background()
	store := &domainStore{recs: map[string]tenant.DomainRecord{
		"acme.com": verifiedBound("t-acme", "acme.com", "okta"),
	}}
	th := &stubThrottle{allow: false, retryAfter: 30 * time.Second}

	got, err := StartLogin(ctx, store, "bob@acme.com",
		WithStartLoginThrottle(th), WithStartLoginFloor(0))
	if !errors.Is(err, ErrThrottled) {
		t.Fatalf("err = %v, want ErrThrottled", err)
	}
	if got.RetryAfter != 30*time.Second {
		t.Errorf("RetryAfter = %v, want 30s", got.RetryAfter)
	}
	// Even refused, nothing about the tenant escapes.
	if got.TenantID != "" || got.ProviderID != "" || got.EnforceSSO {
		t.Errorf("a throttled response disclosed tenant data: %+v", got)
	}
}

// TestStartLogin_ThrottleKeysOnDomainNotAddress: the thing being
// enumerated is DOMAINS. Keying on the full address would let an
// attacker walk a domain one fresh local-part at a time and never trip
// the limit.
func TestStartLogin_ThrottleKeysOnDomainNotAddress(t *testing.T) {
	ctx := context.Background()
	store := &domainStore{recs: map[string]tenant.DomainRecord{}}
	th := &stubThrottle{allow: true}

	for _, email := range []string{"a@acme.com", "b@acme.com", "c@acme.com"} {
		if _, err := StartLogin(ctx, store, email,
			WithStartLoginThrottle(th), WithStartLoginFloor(0)); err != nil {
			t.Fatalf("StartLogin(%s): %v", email, err)
		}
	}
	for _, k := range th.keys {
		if k != "startlogin:acme.com" {
			t.Errorf("throttle key = %q, want the domain — keying on the address lets an "+
				"attacker walk a namespace without tripping the limit", k)
		}
	}
}

func TestStartLogin_NilThrottleIsAllowed(t *testing.T) {
	ctx := context.Background()
	store := &domainStore{recs: map[string]tenant.DomainRecord{
		"acme.com": verifiedBound("t-acme", "acme.com", "okta"),
	}}
	// Allowed so this slice can ship before 7k-1; documented as unsafe.
	got, err := StartLogin(ctx, store, "bob@acme.com", WithStartLoginFloor(0))
	if err != nil || got.ProviderID != "okta" {
		t.Errorf("nil throttle broke the happy path: (%+v, %v)", got, err)
	}
}

// --- deny-by-default on a degraded store -------------------------------

// TestStartLogin_StoreErrorIsNotAFallback: an outage must not silently
// route a tenant's users to a password form their SSO policy forbids.
// That would be a policy bypass caused by a database being slow (§6.2).
func TestStartLogin_StoreErrorIsNotAFallback(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("database is on fire")
	store := &domainStore{recs: map[string]tenant.DomainRecord{}, err: boom}

	got, err := StartLogin(ctx, store, "bob@acme.com", WithStartLoginFloor(0))
	if !errors.Is(err, boom) {
		t.Errorf("a store failure was swallowed into the fallback: (%+v, %v)", got, err)
	}
}

// TestStartLogin_MalformedEmailIsTheCallersOwnError: the one case that
// gets its own error, because it is a fact about the input rather than
// about any tenant.
func TestStartLogin_MalformedEmailIsTheCallersOwnError(t *testing.T) {
	ctx := context.Background()
	store := &domainStore{recs: map[string]tenant.DomainRecord{}}
	for _, bad := range []string{"", "not-an-email", "@acme.com", "bob@"} {
		if _, err := StartLogin(ctx, store, bad, WithStartLoginFloor(0)); !errors.Is(err, identity.ErrInvalidEmail) {
			t.Errorf("StartLogin(%q) err = %v, want ErrInvalidEmail", bad, err)
		}
	}
}

// TestStartLogin_UppercaseEmailResolves: normalisation happens at this
// edge, so a user typing Bob@ACME.com still reaches acme's IdP even
// though the tenant package itself would reject that domain.
func TestStartLogin_UppercaseEmailResolves(t *testing.T) {
	ctx := context.Background()
	store := &domainStore{recs: map[string]tenant.DomainRecord{
		"acme.com": verifiedBound("t-acme", "acme.com", "okta"),
	}}
	got, err := StartLogin(ctx, store, "  Bob@ACME.com ", WithStartLoginFloor(0))
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}
	if got.ProviderID != "okta" {
		t.Errorf("result = %+v — the edge must normalise before calling tenant", got)
	}
}
