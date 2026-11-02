package tenant

import (
	"context"
	"errors"
	"testing"
)

// domainStore is a claim lookup keyed by tenant id, with a call counter and a
// failure seam.
type domainStore struct {
	claims map[string][]DomainRecord
	calls  []ID
	err    error
}

func (d *domainStore) ByDomain(_ context.Context, domain string) (DomainRecord, error) {
	for _, recs := range d.claims {
		for _, rec := range recs {
			if rec.Domain == domain {
				return rec, nil
			}
		}
	}
	return DomainRecord{}, ErrNotFound
}

func (d *domainStore) ListForTenant(_ context.Context, tenantID string) ([]DomainRecord, error) {
	d.calls = append(d.calls, FromStored(tenantID))
	if d.err != nil {
		return nil, d.err
	}
	return d.claims[tenantID], nil
}

func claims(t *testing.T) *domainStore {
	t.Helper()
	return &domainStore{claims: map[string][]DomainRecord{
		"group": {
			{TenantID: "group", Domain: "acme.edu", Verified: true, ProviderID: "okta"},
			{TenantID: "group", Domain: "legacy.test", Verified: false, ProviderID: "entra"},
		},
	}}
}

func TestIsProperSubdomain(t *testing.T) {
	cases := []struct {
		child, parent string
		want          bool
		why           string
	}{
		{"sdn05.acme.edu", "acme.edu", true, "a real subdomain"},
		{"a.b.acme.edu", "acme.edu", true, "any depth"},
		{"x.sdn05.acme.edu", "sdn05.acme.edu", true, "the more specific parent"},
		{"acme.edu", "acme.edu", false, "the domain itself is not a subdomain of itself"},
		{"evilacme.edu", "acme.edu", false, "no dot boundary — the takeover this exists to stop"},
		{"notacme.edu", "acme.edu", false, "same"},
		{"acme.edu.evil.test", "acme.edu", false, "the victim's name as a label, not the suffix"},
		{"sdn05.acme.edu", "", false, "an empty parent matches nothing"},
		{"", "acme.edu", false, "an empty child is not a subdomain"},
		{"ACME.EDU", "acme.edu", false, "case matters: normalisation is the caller's job"},
	}
	for _, tc := range cases {
		if got := IsProperSubdomain(tc.child, tc.parent); got != tc.want {
			t.Errorf("IsProperSubdomain(%q, %q) = %v, want %v — %s", tc.child, tc.parent, got, tc.want, tc.why)
		}
	}
}

func TestInheritedDomainAuthority_VerifiedAncestorGrantsTheName(t *testing.T) {
	got, err := InheritedDomainAuthority(context.Background(), hierarchy(t), claims(t),
		New("team"), "sdn05.acme.edu")
	if err != nil {
		t.Fatalf("InheritedDomainAuthority: %v", err)
	}
	if got.Domain != "acme.edu" {
		t.Fatalf("Domain = %q, want the ancestor's verified acme.edu", got.Domain)
	}
	if got.AncestorID.String() != "group" {
		t.Fatalf("AncestorID = %q, want group — whose proof this is", got.AncestorID.String())
	}
	if got.ProviderID != "okta" {
		t.Fatalf("ProviderID = %q, want okta (the ancestor's binding)", got.ProviderID)
	}
}

// The authority is the ancestor's; the tenant is the child's, and the returned
// value carries no tenant at all so the two cannot be confused.
func TestInheritedDomainAuthority_ReturnsNoTenant(t *testing.T) {
	got, err := InheritedDomainAuthority(context.Background(), hierarchy(t), claims(t),
		New("team"), "sdn05.acme.edu")
	if err != nil {
		t.Fatalf("InheritedDomainAuthority: %v", err)
	}
	if got.AncestorID.IsSingle() || !got.AncestorID.Valid() {
		t.Fatalf("AncestorID = %q, want the named ancestor", got.AncestorID.String())
	}
	// The compile-time half of this property is the type itself: DomainAuthority
	// has no TenantID field, so a consumer cannot read the ancestor's tenant and
	// route the user into it. This asserts the runtime half.
	if got.AncestorID.String() != "group" {
		t.Fatalf("AncestorID = %q; the ancestor must be named, not the child", got.AncestorID.String())
	}
}

func TestInheritedDomainAuthority_Refusals(t *testing.T) {
	cases := []struct {
		name     string
		domain   string
		wantErr  error
		wantSays string
	}{
		{"the parent's own domain", "acme.edu", ErrNotFound, "equality is not a proper subdomain"},
		{"a lookalike without the dot", "evilacme.edu", ErrNotFound, "the takeover"},
		{"a public email domain", "gmail.com", ErrNotFound, "nobody owns gmail.com"},
		{"no ancestor claims it", "other.test", ErrNotFound, "nothing matches"},
		{"an unverified ancestor claim", "x.legacy.test", ErrNotFound, "an unproven claim is not authority"},
		{"unnormalised: uppercase", "SDN05.ACME.EDU", ErrDomainNotNormalised, "the caller normalises"},
		{"unnormalised: an address", "@acme.edu", ErrDomainNotNormalised, "pass the domain, not the address"},
		{"unnormalised: non-ascii", "sdn05.acmé.edu", ErrDomainNotNormalised, "punycode first"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := InheritedDomainAuthority(context.Background(), hierarchy(t), claims(t),
				New("team"), tc.domain)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v (%s)", err, tc.wantErr, tc.wantSays)
			}
		})
	}
}

// Nearest ancestor first: the org's own proof is the authority, not the group's.
func TestInheritedDomainAuthority_NearestAncestorWins(t *testing.T) {
	store := &domainStore{claims: map[string][]DomainRecord{
		"group": {{TenantID: "group", Domain: "acme.edu", Verified: true, ProviderID: "group-idp"}},
		"org":   {{TenantID: "org", Domain: "sdn.acme.edu", Verified: true, ProviderID: "org-idp"}},
	}}
	got, err := InheritedDomainAuthority(context.Background(), hierarchy(t), store,
		New("team"), "x.sdn.acme.edu")
	if err != nil {
		t.Fatalf("InheritedDomainAuthority: %v", err)
	}
	if got.AncestorID.String() != "org" || got.Domain != "sdn.acme.edu" || got.ProviderID != "org-idp" {
		t.Fatalf("authority = %+v, want the nearest ancestor's claim", got)
	}
}

// Within one ancestor, the longest matching domain wins — otherwise the answer
// depends on the order the application's store returned rows in.
func TestInheritedDomainAuthority_LongestMatchWithinOneAncestor(t *testing.T) {
	for _, order := range []string{"broad first", "specific first"} {
		t.Run(order, func(t *testing.T) {
			recs := []DomainRecord{
				{TenantID: "group", Domain: "acme.edu", Verified: true, ProviderID: "broad"},
				{TenantID: "group", Domain: "sub.acme.edu", Verified: true, ProviderID: "specific"},
			}
			if order == "specific first" {
				recs[0], recs[1] = recs[1], recs[0]
			}
			store := &domainStore{claims: map[string][]DomainRecord{"group": recs}}

			got, err := InheritedDomainAuthority(context.Background(), hierarchy(t), store,
				New("team"), "x.sub.acme.edu")
			if err != nil {
				t.Fatalf("InheritedDomainAuthority: %v", err)
			}
			if got.Domain != "sub.acme.edu" || got.ProviderID != "specific" {
				t.Fatalf("authority = %+v, want sub.acme.edu regardless of row order", got)
			}
		})
	}
}

// An unverified claim in the NEAREST ancestor does not stop the walk: the group's
// verified proof is still the authority. This is the shape a real rollout has —
// an org claiming its own subdomain before proving it, with the group's domain
// already verified.
func TestInheritedDomainAuthority_AnUnverifiedNearestClaimDoesNotBlockTheWalk(t *testing.T) {
	store := &domainStore{claims: map[string][]DomainRecord{
		"org":   {{TenantID: "org", Domain: "sdn.acme.edu", Verified: false}},
		"group": {{TenantID: "group", Domain: "acme.edu", Verified: true, ProviderID: "okta"}},
	}}
	got, err := InheritedDomainAuthority(context.Background(), hierarchy(t), store, New("team"), "x.sdn.acme.edu")
	if err != nil {
		t.Fatalf("InheritedDomainAuthority: %v", err)
	}
	if got.AncestorID.String() != "group" || got.Domain != "acme.edu" {
		t.Fatalf("authority = %+v, want the group's verified acme.edu", got)
	}
	if len(store.calls) != 2 {
		t.Fatalf("the claim store was read %d times, want 2 (org, then group)", len(store.calls))
	}
}

// A tenant with nothing above it has no inherited authority, and the domain store
// is never consulted.
func TestInheritedDomainAuthority_NoAncestorsNeverAsksForClaims(t *testing.T) {
	store := claims(t)
	_, err := InheritedDomainAuthority(context.Background(), hierarchy(t), store,
		New("group"), "sdn05.acme.edu")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound for a root tenant", err)
	}
	if len(store.calls) != 0 {
		t.Fatalf("the domain store was read %d times for a tenant with no ancestors", len(store.calls))
	}
}

func TestInheritedDomainAuthority_UnsetAndSingleNeverAskAnything(t *testing.T) {
	for name, id := range map[string]ID{"zero": {}, "single": Single} {
		t.Run(name, func(t *testing.T) {
			h, d := newSpyStore(), claims(t)
			h.inner.Seed(Descriptor{ID: "root", Status: StatusActive})

			if _, err := InheritedDomainAuthority(context.Background(), h, d, id, "x.acme.edu"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("err = %v, want ErrNotFound", err)
			}
			if h.calls != 0 || len(d.calls) != 0 {
				t.Fatalf("stores were read (hierarchy %d, domains %d); unset and single-tenant walk nothing",
					h.calls, len(d.calls))
			}
		})
	}
}

func TestInheritedDomainAuthority_ErrorsPropagate(t *testing.T) {
	t.Run("domain store", func(t *testing.T) {
		boom := errors.New("claims table is down")
		d := claims(t)
		d.err = boom
		_, err := InheritedDomainAuthority(context.Background(), hierarchy(t), d, New("team"), "x.acme.edu")
		if !errors.Is(err, boom) {
			t.Fatalf("err = %v, want the domain store's own error", err)
		}
	})

	t.Run("corrupt parentage", func(t *testing.T) {
		s := NewMemStore()
		s.Seed(Descriptor{ID: "team", ParentID: "vanished", Status: StatusActive})

		_, err := InheritedDomainAuthority(context.Background(), s, claims(t), New("team"), "x.acme.edu")
		if !errors.Is(err, ErrHierarchyDangling) {
			t.Fatalf("err = %v, want ErrHierarchyDangling rather than \"no authority\"", err)
		}
	})
}

// The D4 flow, end to end, with the application's half played out: the helper
// answers "the group's acme.edu covers this name", the application writes the
// child's OWN claim row after approval, and the login path's resolver then returns
// the CHILD — which is the fact the return type was shaped to protect.
func TestInheritedDomainAuthority_ProofThenResolvedAsTheChild(t *testing.T) {
	ancestorClaims := claims(t)
	child := New("team")

	authority, err := InheritedDomainAuthority(context.Background(), hierarchy(t), ancestorClaims,
		child, "sdn05.acme.edu")
	if err != nil {
		t.Fatalf("InheritedDomainAuthority: %v", err)
	}

	// What the application does after its group admin approves: a row of its own,
	// for its own tenant, carrying the provider the authority named.
	store := &domainStore{claims: map[string][]DomainRecord{
		"team": {{TenantID: "team", Domain: "sdn05.acme.edu", Verified: true, ProviderID: authority.ProviderID}},
	}}
	rec, err := ResolveDomain(context.Background(), store, "sdn05.acme.edu")
	if err != nil {
		t.Fatalf("ResolveDomain: %v", err)
	}
	if rec.TenantID != "team" {
		t.Fatalf("ResolveDomain returned tenant %q, want the CHILD — routing on the authority's "+
			"ancestor would send this user into the group", rec.TenantID)
	}
	if rec.BoundProviderID() != "okta" {
		t.Fatalf("provider = %q, want the authority's okta", rec.BoundProviderID())
	}

	// And before the application writes that row, the login path resolves nothing:
	// inherited authority is not itself a resolving claim.
	if _, err := ResolveDomain(context.Background(), ancestorClaims, "sdn05.acme.edu"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound — an inherited claim is authority, and the "+
			"child's own row is what the resolver believes", err)
	}
}

func TestInheritedDomainAuthority_PanicsOnMisconfiguration(t *testing.T) {
	t.Run("nil hierarchy", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("a nil hierarchy store did not panic")
			}
		}()
		_, _ = InheritedDomainAuthority(context.Background(), nil, claims(t), New("team"), "x.acme.edu")
	})
	t.Run("nil domain store", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("a nil domain store did not panic; every claim would look unverified")
			}
		}()
		_, _ = InheritedDomainAuthority(context.Background(), hierarchy(t), nil, New("team"), "x.acme.edu")
	})
}
