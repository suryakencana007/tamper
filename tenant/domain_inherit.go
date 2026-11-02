package tenant

import (
	"context"
	"fmt"
	"strings"
)

// Inherited domain authority: may this tenant claim a name that sits under a
// domain one of its ancestors PROVED? (PHASE12-TENANT-INHERITANCE-SKETCH.md §4.3,
// decision D4.)
//
// This is the second consumer of [Ancestors], and like the first it is a helper
// over ports that already exist — no engine, no cache, no write path.

// DomainAuthority is the answer to "which ancestor's proof lets this tenant claim
// this name".
//
// It has NO tenant field, and that is the point rather than an omission. The
// obvious signature returns the matched [DomainRecord], whose TenantID is the
// ANCESTOR — and the consumer that matters is the login path, which reads
// `rec.TenantID` to decide who the user is logging in to (espresso's
// start-login). Handing back a record with the ancestor's tenant in it invites
// exactly one bug: an application passes it along and routes the user into the
// GROUP instead of the child. The misuse is prevented structurally, so there is
// nothing left to document.
type DomainAuthority struct {
	// AncestorID is whose verification this rests on. The application records it
	// as provenance when it writes the child's own claim row.
	AncestorID ID

	// Domain is that ancestor's verified domain the claimed name sits under —
	// the authority itself, not the claimed name.
	Domain string

	// ProviderID is the IdP the ancestor bound to Domain, or "" when none.
	//
	// Copied from [DomainRecord.BoundProviderID], so a binding from an unproven
	// claim cannot travel even if the verified filter below were removed. Empty is
	// a legitimate answer: the login path treats a verified domain with no IdP as
	// the password path, not as an error.
	ProviderID string
}

// InheritedDomainAuthority reports whether domain may be claimed by tenantID by
// inherited authority, and if so, on whose.
//
// It answers AUTHORITY, and nothing else. It does not approve, store, or audit.
// The application records the child's own claim row (`Verified: true`, plus
// whatever provenance columns it keeps) after the group's admin approves, and
// emits the audit row naming the group whose proof was borrowed. Two rules come
// with that and they are the application's:
//
//   - Write the row only after approval. A helper that returns authority is not a
//     licence to write an unverified-then-flipped row.
//   - Bind a provider only when the inheriting tenant's own registry resolves it
//     (sketch §4.4). An inherited claim whose ProviderID is an id from the GROUP's
//     records works for that tenant only if it also inherits providers; otherwise
//     leave ProviderID empty, which the login path already handles.
//
// The outcomes, and why each is what it is:
//
//	public email domain   ErrNotFound — same as ResolveDomain; nobody owns gmail.com
//	no matching ancestor  ErrNotFound — including an UNVERIFIED ancestor claim
//	unnormalised input    ErrDomainNotNormalised — a caller bug, said plainly
//
// The first two are indistinguishable on purpose, matching [ResolveDomain]: this
// runs on an admin path where the operator is authenticated, but the answer still
// should not tell one tenant which domains another has claimed.
//
// Two things it does NOT consult, and both are deliberate:
//
//   - The tenant's OWN claims. A name the tenant verified itself is
//     [ResolveDomain]'s business, and that path already believes it; asking here
//     would be a second answer to a question that has one.
//   - A claim whose stored domain is not normalised. The DomainStore contract puts
//     normalisation on the application, so an unnormalised row simply never
//     matches — `ACME.EDU` is not a suffix of `sdn05.acme.edu`. That is the
//     fail-closed reading, and the alternative (normalising the stored value here)
//     is exactly the silent repair tenant/domain.go refuses to do.
//
// Walking is nearest-ancestor-first, and within one ancestor the LONGEST matching
// domain wins. The second rule is not decoration: an ancestor may hold both
// `acme.com` and `sub.acme.com`, both match `x.sub.acme.com`, and only one of them
// is the authority the operator meant. Taking the first the store happened to
// return would make the answer depend on an application's row order, so the
// helper decides it instead — and with it, which provider is bound.
func InheritedDomainAuthority(ctx context.Context, s Store, domains DomainStore,
	tenantID ID, domain string,
) (DomainAuthority, error) {
	if s == nil {
		panic("tenant: InheritedDomainAuthority requires a Store — a nil one would resolve no " +
			"ancestors, and every claim would look uninheritable")
	}
	if domains == nil {
		panic("tenant: InheritedDomainAuthority requires a DomainStore — a nil one would make every " +
			"claim look un verified, which reads as \"no authority\" and denies")
	}
	if err := RequireNormalisedDomain(domain); err != nil {
		return DomainAuthority{}, err
	}
	if IsPublicEmailDomain(domain) {
		return DomainAuthority{}, fmt.Errorf("%w: domain %s", ErrNotFound, domain)
	}

	chain, err := Ancestors(ctx, s, tenantID)
	if err != nil {
		return DomainAuthority{}, err
	}
	for _, ancestor := range chain {
		claims, err := domains.ListForTenant(ctx, ancestor.String())
		if err != nil {
			return DomainAuthority{}, fmt.Errorf("tenant: domain authority for %q: %w", tenantID.String(), err)
		}
		var best DomainRecord
		for _, claim := range claims {
			// A public domain can never be an authority, however it came to be
			// marked verified. Checking the INPUT for it is not enough: `x.gmail.com`
			// is not itself a public domain, so a stored (and mistakenly verified)
			// `gmail.com` would otherwise confer authority over the whole of Gmail.
			// Skipped rather than reported, so a child's admin learns nothing about
			// which public domain another tenant claimed.
			if !claim.Verified || IsPublicEmailDomain(claim.Domain) || !IsProperSubdomain(domain, claim.Domain) {
				continue
			}
			// Longest parent wins, so the answer does not depend on the store's
			// row order. Strictly longer: two identical domains would be a
			// duplicate row, and either answer is the same authority anyway.
			if len(claim.Domain) > len(best.Domain) {
				// BoundProviderID rather than the raw field: with the Verified
				// filter above, the two are equal today, so this is defence in
				// depth rather than a behaviour — it is what keeps the unproven
				// binding out if that filter is ever widened, and it is the
				// documented way to ask (DomainRecord.BoundProviderID).
				best = claim
			}
		}
		if best.Domain != "" {
			return DomainAuthority{
				AncestorID: ancestor,
				Domain:     best.Domain,
				ProviderID: best.BoundProviderID(),
			}, nil
		}
	}
	return DomainAuthority{}, fmt.Errorf("%w: domain %s", ErrNotFound, domain)
}

// IsProperSubdomain reports whether child sits under parent — a strict subdomain,
// not the domain itself.
//
// The dot is the whole security property of this function, and it is why this is
// exported rather than inlined at its two call sites: without it,
// `evilacme.com` is a "subdomain" of `acme.com`, and anyone who can register a
// name that ends with a victim's domain could claim authority over it.
//
// Inputs are compared as given: no lowering, no punycode, no trailing-dot
// stripping. [RequireNormalisedDomain] is where that is asked for, and a caller
// that skipped it gets `false` rather than a silently repaired answer.
func IsProperSubdomain(child, parent string) bool {
	if child == "" || parent == "" {
		return false
	}
	return child != parent && strings.HasSuffix(child, "."+parent)
}
