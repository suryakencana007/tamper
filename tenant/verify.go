package tenant

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
)

// Domain-ownership verification: the proof that turns a CLAIM on a
// domain into a VERIFIED one. Everything about home-realm discovery
// hangs off DomainRecord.Verified, so this is how that bit is earned.

var (
	// ErrVerificationFailed — the expected TXT record was not found.
	// Deliberately one error for every failure mode below it (no records,
	// wrong value, NXDOMAIN, resolver error): a caller retrying a
	// verification does not need to know which, and an attacker probing
	// for which domains are mid-verification should not learn it either.
	ErrVerificationFailed = errors.New("tenant: domain verification failed")
)

// verificationTokenBytes is the entropy behind a verification token.
// 32 bytes = 256 bits, the same order as a refresh token, because the
// consequence of guessing one is the same order too: a guessed token
// lets an attacker verify a domain they do not own.
const verificationTokenBytes = 32

// NewVerificationToken returns a fresh, URL-safe domain-verification
// token from crypto/rand.
//
// The token is the secret the operator publishes in DNS. It is URL-safe
// and unpadded so it survives being pasted into a TXT record, a config
// file, or a URL without escaping.
//
// It panics if the system CSPRNG fails. That is not a condition worth a
// second return value: crypto/rand.Read failing means the machine has no
// usable entropy source, and a caller who "handled" it by continuing
// would be issuing a guessable token — which is the whole thing this
// value exists not to be.
func NewVerificationToken() string {
	b := make([]byte, verificationTokenBytes)
	if _, err := rand.Read(b); err != nil {
		panic("tenant: crypto/rand failed, cannot mint a verification token: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// DNSVerifier checks the TXT proof for a domain claim.
//
// tamper ships NewDNSVerifier over net.Resolver; the APPLICATION decides
// WHEN to run it — at registration, from a cron that re-checks claims,
// or from an admin button. That timing is policy: how long a verified
// domain stays trusted without re-proof is a decision only the operator
// can make, and baking in an interval would impose one.
type DNSVerifier interface {
	// VerifyTXT returns nil when domain publishes a TXT record whose
	// value equals expectedToken, and ErrVerificationFailed otherwise.
	//
	// Any failure — no records, no match, NXDOMAIN, a resolver error —
	// is the same error. A caller must not be able to distinguish "this
	// domain has no TXT records" from "it has the wrong one".
	VerifyTXT(ctx context.Context, domain, expectedToken string) error
}

// dnsVerifier is the net.Resolver implementation.
type dnsVerifier struct {
	lookupTXT func(ctx context.Context, name string) ([]string, error)
	// prefix, when set, is prepended as a subdomain label — the
	// _acme-challenge style, so the record does not collide with SPF or
	// anything else on the apex.
	prefix string
}

var _ DNSVerifier = (*dnsVerifier)(nil)

// DNSVerifierOption configures the shipped verifier.
type DNSVerifierOption func(*dnsVerifier)

// WithTXTRecordPrefix puts the proof on a subdomain
// (prefix + "." + domain) rather than the apex. Most operators prefer
// this: the apex TXT record set is crowded with SPF, DMARC and vendor
// proofs, and a verifier that reads the apex has to sift them.
func WithTXTRecordPrefix(prefix string) DNSVerifierOption {
	return func(v *dnsVerifier) { v.prefix = strings.Trim(prefix, ".") }
}

// WithTXTLookup swaps the resolver. Test seam, and the escape hatch for
// a deployment that must resolve through something other than the system
// resolver.
func WithTXTLookup(fn func(ctx context.Context, name string) ([]string, error)) DNSVerifierOption {
	return func(v *dnsVerifier) {
		if fn != nil {
			v.lookupTXT = fn
		}
	}
}

// NewDNSVerifier returns the net.Resolver-backed DNSVerifier.
func NewDNSVerifier(opts ...DNSVerifierOption) DNSVerifier {
	v := &dnsVerifier{lookupTXT: net.DefaultResolver.LookupTXT}
	for _, o := range opts {
		o(v)
	}
	return v
}

func (v *dnsVerifier) VerifyTXT(ctx context.Context, domain, expectedToken string) error {
	// The domain is compared and queried in its normalised form, like
	// every other domain in this package.
	if err := RequireNormalisedDomain(domain); err != nil {
		return err
	}
	if expectedToken == "" {
		// An empty expected token would match an empty TXT record, which
		// is to say it would verify a domain against nothing.
		return fmt.Errorf("%w: no expected token supplied", ErrVerificationFailed)
	}
	name := domain
	if v.prefix != "" {
		name = v.prefix + "." + domain
	}
	records, err := v.lookupTXT(ctx, name)
	if err != nil {
		// Collapsed: a resolver error and a missing record are the same
		// answer to the caller. The underlying cause is not wrapped,
		// because it names the domain and the nameserver.
		return fmt.Errorf("%w: %s", ErrVerificationFailed, domain)
	}
	for _, got := range records {
		// Constant-time: the token is a secret, and a byte-at-a-time
		// comparison against attacker-published TXT records is a way to
		// learn it a byte at a time.
		if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(got)), []byte(expectedToken)) == 1 {
			return nil
		}
	}
	return fmt.Errorf("%w: %s", ErrVerificationFailed, domain)
}
