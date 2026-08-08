package tenant

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Slice 7f-1 — home-realm discovery. The security of this lookup is the
// security of the whole pooled deployment: whoever controls which tenant
// a domain resolves to controls where that domain's users authenticate.

// memDomainStore is the reference DomainStore for these tests. It stores
// what it is given, verbatim — no normalisation, matching the port's
// contract that the caller normalised already.
type memDomainStore struct{ byDomain map[string]DomainRecord }

var _ DomainStore = (*memDomainStore)(nil)

func newMemDomainStore(recs ...DomainRecord) *memDomainStore {
	s := &memDomainStore{byDomain: map[string]DomainRecord{}}
	for _, r := range recs {
		s.byDomain[r.Domain] = r
	}
	return s
}

func (s *memDomainStore) ByDomain(_ context.Context, domain string) (DomainRecord, error) {
	r, ok := s.byDomain[domain]
	if !ok {
		return DomainRecord{}, fmt.Errorf("%w: domain %s", ErrNotFound, domain)
	}
	return r, nil
}

func (s *memDomainStore) ListForTenant(_ context.Context, tenantID string) ([]DomainRecord, error) {
	out := make([]DomainRecord, 0)
	for _, r := range s.byDomain {
		if r.TenantID == tenantID {
			out = append(out, r)
		}
	}
	return out, nil
}

// --- the tenant-takeover boundary ------------------------------------

// TestResolveDomain_UnverifiedNeverBinds is the invariant, and the
// mutation target. Anyone can type a domain into a signup form; only
// someone who controls its DNS can make Verified true. A resolver that
// skips the check hands an attacker every login from a domain they do
// not own.
func TestResolveDomain_UnverifiedNeverBinds(t *testing.T) {
	ctx := context.Background()
	s := newMemDomainStore(
		DomainRecord{TenantID: "victim", Domain: "acme.com", Verified: true, ProviderID: "okta"},
		// An attacker claimed a domain they do not own. Unverified.
		DomainRecord{TenantID: "attacker", Domain: "microsoft.com", Verified: false, ProviderID: "evil-idp"},
	)

	// The verified claim resolves, IdP and all.
	got, err := ResolveDomain(ctx, s, "acme.com")
	if err != nil {
		t.Fatalf("verified domain did not resolve: %v", err)
	}
	if got.TenantID != "victim" || got.ProviderID != "okta" {
		t.Errorf("resolved to %+v, want victim/okta", got)
	}

	// The unverified claim resolves to NOTHING — not to the tenant, not
	// to the IdP. Resolving the tenant alone would already be takeover.
	unver, err := ResolveDomain(ctx, s, "microsoft.com")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("an UNVERIFIED domain resolved: (%+v, %v). Anyone can claim a domain; "+
			"only DNS control proves it. This is tenant takeover.", unver, err)
	}
	if unver.TenantID != "" || unver.ProviderID != "" {
		t.Errorf("the rejection still disclosed the claim: %+v", unver)
	}
}

// TestDomainRecord_BoundProviderIDGatesOnVerified: the record itself
// refuses to name an IdP for an unproven claim, so a caller that never
// goes through ResolveDomain still cannot bind one.
func TestDomainRecord_BoundProviderIDGatesOnVerified(t *testing.T) {
	unverified := DomainRecord{TenantID: "t", Domain: "acme.com", Verified: false, ProviderID: "okta"}
	if got := unverified.BoundProviderID(); got != "" {
		t.Errorf("BoundProviderID = %q for an unverified claim, want empty", got)
	}
	verified := unverified
	verified.Verified = true
	if got := verified.BoundProviderID(); got != "okta" {
		t.Errorf("BoundProviderID = %q for a verified claim, want okta", got)
	}
}

// TestResolveDomain_MissAndUnverifiedAreIndistinguishable: the endpoint
// downstream is unauthenticated, so "claimed but unverified" must not be
// separable from "never heard of it" — that difference tells an attacker
// which domains a competitor has claimed and how far along they are.
func TestResolveDomain_MissAndUnverifiedAreIndistinguishable(t *testing.T) {
	ctx := context.Background()
	s := newMemDomainStore(
		DomainRecord{TenantID: "t", Domain: "claimed.com", Verified: false, ProviderID: "okta"},
	)

	_, unverErr := ResolveDomain(ctx, s, "claimed.com")
	_, missErr := ResolveDomain(ctx, s, "never-heard-of.com")

	if !errors.Is(unverErr, ErrNotFound) || !errors.Is(missErr, ErrNotFound) {
		t.Fatalf("both must be ErrNotFound: unverified=%v miss=%v", unverErr, missErr)
	}
	// Scan the message with the domain redacted — the domain is echoed
	// back to the caller who supplied it, so it discloses nothing, and
	// leaving it in would match on the test's own fixture names.
	redacted := strings.ToLower(strings.ReplaceAll(unverErr.Error(), "claimed.com", "<domain>"))
	for _, leak := range []string{"unverified", "verify", "pending", "claim"} {
		if strings.Contains(redacted, leak) {
			t.Errorf("the unverified rejection discloses %q: %v", leak, unverErr)
		}
	}
	// The two messages must be identical once the echoed domain is out.
	missRedacted := strings.ReplaceAll(missErr.Error(), "never-heard-of.com", "<domain>")
	if unverRedacted := strings.ReplaceAll(unverErr.Error(), "claimed.com", "<domain>"); unverRedacted != missRedacted {
		t.Errorf("unverified and miss are distinguishable:\n  %s\n  %s", unverRedacted, missRedacted)
	}
}

// --- public domains ---------------------------------------------------

// TestIsPublicEmailDomain_Sample asserts a sample of the data, so the
// list being data rather than logic is itself checked.
func TestIsPublicEmailDomain_Sample(t *testing.T) {
	for _, d := range []string{
		"gmail.com", "outlook.com", "yahoo.com", "icloud.com",
		"proton.me", "aol.com", "qq.com", "mailinator.com",
	} {
		if !IsPublicEmailDomain(d) {
			t.Errorf("%s is not treated as a public email domain", d)
		}
	}
	for _, d := range []string{"acme.com", "globex.co.uk", "my-company.io"} {
		if IsPublicEmailDomain(d) {
			t.Errorf("%s was treated as a public email domain", d)
		}
	}
}

// TestResolveDomain_PublicDomainNeverResolves: no customer owns
// gmail.com, so a claim on it is either a mistake or an attempt to
// capture every Gmail user's login. Even a VERIFIED row must not resolve
// — verification of a public domain should be impossible, and if a row
// exists anyway the resolver refuses it.
func TestResolveDomain_PublicDomainNeverResolves(t *testing.T) {
	ctx := context.Background()
	s := newMemDomainStore(
		DomainRecord{TenantID: "attacker", Domain: "gmail.com", Verified: true, ProviderID: "evil-idp"},
	)
	got, err := ResolveDomain(ctx, s, "gmail.com")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("a public email domain resolved: (%+v, %v) — every Gmail user would be "+
			"routed to this tenant", got, err)
	}
}

// TestPublicEmailDomains_AreThemselvesNormalised: the list is compared
// by plain map lookup, so an entry that is not normalised can never
// match and would sit in the file looking like protection.
func TestPublicEmailDomains_AreThemselvesNormalised(t *testing.T) {
	for d := range publicEmailDomains {
		if err := RequireNormalisedDomain(d); err != nil {
			t.Errorf("public-domain entry %q is not normalised, so it can never match: %v", d, err)
		}
	}
}

// --- the normalisation contract ---------------------------------------

// TestRequireNormalisedDomain_RejectsRatherThanCoerces is the third
// invariant. tamper does not lowercase for you: two spellings stored as
// two rows means a verified row and an unverified row can exist for what
// a human reads as one domain, with the resolver picking whichever the
// caller happened to type.
func TestRequireNormalisedDomain_RejectsRatherThanCoerces(t *testing.T) {
	for _, tc := range []struct{ name, domain string }{
		{"empty", ""},
		{"leading @", "@acme.com"},
		{"uppercase", "ACME.com"},
		{"mixed case", "Acme.Com"},
		{"leading space", " acme.com"},
		{"trailing space", "acme.com "},
		{"embedded tab", "acme\t.com"},
		{"non-ascii", "acmé.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := RequireNormalisedDomain(tc.domain); !errors.Is(err, ErrDomainNotNormalised) {
				t.Errorf("RequireNormalisedDomain(%q) = %v, want ErrDomainNotNormalised", tc.domain, err)
			}
		})
	}
	for _, ok := range []string{"acme.com", "sub.acme.co.uk", "xn--80ak6aa92e.com"} {
		if err := RequireNormalisedDomain(ok); err != nil {
			t.Errorf("RequireNormalisedDomain(%q) = %v, want nil", ok, err)
		}
	}
}

// TestResolveDomain_UnnormalisedIsRejectedNotCoerced: the resolver
// refuses rather than quietly matching a differently-spelled row.
func TestResolveDomain_UnnormalisedIsRejectedNotCoerced(t *testing.T) {
	ctx := context.Background()
	s := newMemDomainStore(
		DomainRecord{TenantID: "t", Domain: "acme.com", Verified: true, ProviderID: "okta"},
	)
	if _, err := ResolveDomain(ctx, s, "ACME.com"); !errors.Is(err, ErrDomainNotNormalised) {
		t.Errorf("ResolveDomain(\"ACME.com\") = %v, want ErrDomainNotNormalised — coercing it "+
			"would let one domain exist as two rows with different verification states", err)
	}
	// The normalisation check runs BEFORE the store is consulted, so an
	// unnormalised public domain is still a normalisation error (the
	// caller's bug is named, not hidden behind a not-found).
	if _, err := ResolveDomain(ctx, s, "GMAIL.com"); !errors.Is(err, ErrDomainNotNormalised) {
		t.Errorf("expected the normalisation error first, got %v", err)
	}
}

// TestResolveDomain_StoreErrorPropagates: a degraded store must not read
// as "no claim, fall back to password". Deny-by-default: no error return
// may be read as allow (§6.2).
func TestResolveDomain_StoreErrorPropagates(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("database is on fire")
	s := &errDomainStore{err: boom}
	_, err := ResolveDomain(ctx, s, "acme.com")
	if !errors.Is(err, boom) {
		t.Errorf("a store failure was swallowed: %v", err)
	}
	if errors.Is(err, ErrNotFound) {
		t.Error("a store failure was reported as not-found, which a caller reads as " +
			"\"no claim\" and would fall back on")
	}
}

type errDomainStore struct{ err error }

func (s *errDomainStore) ByDomain(context.Context, string) (DomainRecord, error) {
	return DomainRecord{}, s.err
}
func (s *errDomainStore) ListForTenant(context.Context, string) ([]DomainRecord, error) {
	return nil, s.err
}

// TestDomainStore_ListForTenantIsScoped: the admin surface sees its own
// tenant's claims, verified or not, and no one else's.
func TestDomainStore_ListForTenantIsScoped(t *testing.T) {
	ctx := context.Background()
	s := newMemDomainStore(
		DomainRecord{TenantID: "acme", Domain: "acme.com", Verified: true},
		DomainRecord{TenantID: "acme", Domain: "acme.co.uk", Verified: false},
		DomainRecord{TenantID: "globex", Domain: "globex.com", Verified: true},
	)
	got, err := s.ListForTenant(ctx, "acme")
	if err != nil {
		t.Fatalf("ListForTenant: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("acme sees %d claims, want 2 (including the pending one)", len(got))
	}
	for _, r := range got {
		if r.TenantID != "acme" {
			t.Errorf("acme's list contains %s's claim", r.TenantID)
		}
	}
}
