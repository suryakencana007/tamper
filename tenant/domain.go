package tenant

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Home-realm discovery: which tenant — and which IdP — owns this email
// domain? This is the lookup that turns "bob@acme.com" into "send bob to
// acme's Okta", and it is the single most security-sensitive mapping in
// a pooled deployment, because whoever controls it controls where a
// customer's users authenticate.

var (
	// ErrDomainNotNormalised — the domain was not in the canonical form
	// this package compares on.
	//
	// tamper does NOT normalise. It rejects. Silently lowercasing
	// "ACME.com" would mean two spellings of one domain could be stored
	// as two rows, and then a verified row and an unverified row could
	// exist for what a human reads as the same domain — with the
	// resolver picking whichever the caller happened to spell. Rejection
	// makes the caller decide once, at the edge, where it has the
	// original input and can do punycode properly.
	ErrDomainNotNormalised = errors.New("tenant: domain is not normalised")

	// ErrPublicEmailDomain — the domain is a public email provider and
	// can never be verified for any tenant. Surfaced to ADMIN paths so an
	// operator gets a real explanation; the resolve path collapses it
	// onto ErrNotFound instead (see ResolveDomain).
	ErrPublicEmailDomain = errors.New("tenant: public email domain cannot be claimed")
)

// DomainRecord is one claimed email domain. The application owns the
// table; this is the projection tamper needs.
type DomainRecord struct {
	// TenantID is the tenant claiming the domain. Opaque, as always.
	TenantID string

	// Domain is the bare email domain ("acme.com"), lowercased and
	// punycode-normalised BY THE CALLER. See ErrDomainNotNormalised for
	// why tamper rejects rather than fixes.
	Domain string

	// Verified reports whether the claim was PROVEN — the DNS TXT record
	// was seen, or the operator confirmed ownership out of band.
	//
	// This field is the tenant-takeover boundary. Anyone can type
	// "microsoft.com" into a signup form; only someone who controls
	// microsoft.com's DNS can make this true. A resolver that ignores it
	// lets an attacker claim a victim's domain and capture every login
	// from it.
	Verified bool

	// ProviderID names the IdP this domain federates to; "" means no IdP
	// is bound and the caller falls back to password or invitation.
	ProviderID string
}

// BoundProviderID reports the IdP this domain federates to, and is the
// only safe way to ask. It returns "" for an UNVERIFIED domain no matter
// what ProviderID holds, so a caller that reaches for this instead of
// the raw field cannot bind an IdP to an unproven claim.
func (d DomainRecord) BoundProviderID() string {
	if !d.Verified {
		return ""
	}
	return d.ProviderID
}

// DomainStore is the verified-domain persistence port. The application
// implements it over its own table; tamper names no column.
//
// Sentinel contract: ByDomain returns an error matching ErrNotFound
// (errors.Is) when no row matches — never a permission error, and never
// a zero record with a nil error.
//
// Implementations MUST be safe for concurrent use.
type DomainStore interface {
	// ByDomain returns the claim for an exact, already-normalised
	// domain. ErrNotFound when none exists.
	//
	// Matching is on the stored value with no normalisation applied —
	// the caller normalised before storing and normalises before asking,
	// so the two agree.
	ByDomain(ctx context.Context, domain string) (DomainRecord, error)

	// ListForTenant returns every domain a tenant has claimed, verified
	// or not — the admin surface, which legitimately needs to see
	// pending claims. Empty (non-nil) slice for none.
	//
	// Isolation contract. The implementation MUST constrain the query to
	// tenantID and MUST return ErrNotFound — never a permission error and
	// never another tenant's row — when the addressed object belongs to a
	// different tenant. A "" tenantID selects the single-tenant table
	// shape. tamper cannot verify this; the cross-tenant leak suite
	// (§3.3) is the proof obligation that comes with implementing this
	// interface.
	ListForTenant(ctx context.Context, tenantID string) ([]DomainRecord, error)
}

// ResolveDomain is THE resolver path for home-realm discovery, and the
// place the verification check lives.
//
// The slice's invariant is that an unverified domain must never bind an
// IdP, and that the check belongs here rather than only in the admin
// path — because the admin path is the one an attacker does not use. A
// claim can be written by anyone; this is where it is believed or not.
//
// Four outcomes, and three of them are the same outcome on purpose:
//
//	unnormalised input   ErrDomainNotNormalised  — a caller bug, said plainly
//	public email domain  ErrNotFound
//	no such claim        ErrNotFound
//	unverified claim     ErrNotFound
//
// The last three are indistinguishable deliberately. This lookup sits
// behind an UNAUTHENTICATED endpoint (7f-2's StartLogin), so a
// distinguishable "that domain exists but is unverified" tells an
// attacker which domains a competitor has claimed and how far along
// their rollout is. Deny and miss look identical (§6.3).
//
// An unverified claim resolving to NOTHING — not merely to no IdP — is
// the stronger reading of the invariant, and the right one. If an
// unverified claim still resolved its tenant, an attacker who typed a
// victim's domain into their own signup form would capture that
// victim's users into the attacker's tenant, with no IdP needed.
func ResolveDomain(ctx context.Context, s DomainStore, emailDomain string) (DomainRecord, error) {
	if err := RequireNormalisedDomain(emailDomain); err != nil {
		return DomainRecord{}, err
	}
	if IsPublicEmailDomain(emailDomain) {
		// Collapsed onto not-found: the caller learns nothing about which
		// public domains tamper knows.
		return DomainRecord{}, fmt.Errorf("%w: domain %s", ErrNotFound, emailDomain)
	}
	rec, err := s.ByDomain(ctx, emailDomain)
	if err != nil {
		return DomainRecord{}, err
	}
	if !rec.Verified {
		return DomainRecord{}, fmt.Errorf("%w: domain %s", ErrNotFound, emailDomain)
	}
	return rec, nil
}

// RequireNormalisedDomain reports whether a domain is in the canonical
// form this package compares on, and returns ErrDomainNotNormalised
// describing the first violation otherwise.
//
// Canonical means: non-empty, no leading "@" (an email local part was
// probably passed by mistake), lowercase, ASCII only (punycode already
// applied), and no surrounding or embedded whitespace.
//
// It deliberately does NOT return a fixed-up domain. Handing back a
// corrected value would make it trivially tempting to ignore the error.
func RequireNormalisedDomain(domain string) error {
	switch {
	case domain == "":
		return fmt.Errorf("%w: empty", ErrDomainNotNormalised)
	case strings.HasPrefix(domain, "@"):
		return fmt.Errorf("%w: %q has a leading @ — pass the domain, not an address", ErrDomainNotNormalised, domain)
	case strings.ContainsAny(domain, " \t\r\n"):
		return fmt.Errorf("%w: %q contains whitespace", ErrDomainNotNormalised, domain)
	case domain != strings.ToLower(domain):
		return fmt.Errorf("%w: %q is not lowercase — the caller must lowercase, tamper will not", ErrDomainNotNormalised, domain)
	}
	for _, r := range domain {
		if r > 127 {
			return fmt.Errorf("%w: %q is not ASCII — apply punycode before storing or asking", ErrDomainNotNormalised, domain)
		}
	}
	return nil
}

// IsPublicEmailDomain reports whether a domain is a public email
// provider. A public domain can never be verified for any tenant: no
// customer owns gmail.com, so a claim on it is either a mistake or an
// attempt to capture every Gmail user's login.
//
// The domain must already be normalised; an unnormalised one will simply
// not match and read as not-public, which is why ResolveDomain checks
// normalisation FIRST.
func IsPublicEmailDomain(domain string) bool {
	_, ok := publicEmailDomains[domain]
	return ok
}

// publicEmailDomains is DATA, kept as a plain set so extending it is a
// one-line change with no logic to re-reason about. It is not meant to
// be exhaustive — no such list can be — and an operator with a
// deployment-specific addition should treat this as a starting point.
//
// Entries are normalised (lowercase, ASCII) exactly as
// RequireNormalisedDomain demands of a lookup, so a match is a plain map
// hit with no per-call transformation.
var publicEmailDomains = map[string]struct{}{
	// Google
	"gmail.com":      {},
	"googlemail.com": {},
	// Microsoft
	"outlook.com":   {},
	"hotmail.com":   {},
	"hotmail.co.uk": {},
	"live.com":      {},
	"msn.com":       {},
	// Yahoo
	"yahoo.com":      {},
	"yahoo.co.uk":    {},
	"ymail.com":      {},
	"rocketmail.com": {},
	// Apple
	"icloud.com": {},
	"me.com":     {},
	"mac.com":    {},
	// Privacy-focused
	"proton.me":      {},
	"protonmail.com": {},
	"tutanota.com":   {},
	"fastmail.com":   {},
	"hushmail.com":   {},
	// Other large consumer providers
	"aol.com":    {},
	"gmx.com":    {},
	"gmx.net":    {},
	"mail.com":   {},
	"mail.ru":    {},
	"yandex.com": {},
	"yandex.ru":  {},
	"zoho.com":   {},
	"qq.com":     {},
	"163.com":    {},
	"126.com":    {},
	"naver.com":  {},
	// Disposable / throwaway, which are the same problem with a shorter
	// half-life.
	"mailinator.com":    {},
	"guerrillamail.com": {},
	"10minutemail.com":  {},
	"yopmail.com":       {},
	"trashmail.com":     {},
	"sharklasers.com":   {},
}
