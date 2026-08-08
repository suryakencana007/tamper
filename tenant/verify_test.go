package tenant

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// --- token entropy -----------------------------------------------------

// TestNewVerificationToken_Entropy: this token is the secret an operator
// publishes in DNS, and guessing one lets an attacker verify a domain
// they do not own. It must be long, URL-safe, and never repeat.
func TestNewVerificationToken_Entropy(t *testing.T) {
	const n = 2000
	seen := make(map[string]struct{}, n)
	for range n {
		tok := NewVerificationToken()

		raw, err := base64.RawURLEncoding.DecodeString(tok)
		if err != nil {
			t.Fatalf("token is not raw-url base64: %q (%v)", tok, err)
		}
		if len(raw) != verificationTokenBytes {
			t.Fatalf("token carries %d bytes of entropy, want %d", len(raw), verificationTokenBytes)
		}
		// URL-safe and unpadded, so it survives a TXT record, a config
		// file or a URL without escaping.
		if strings.ContainsAny(tok, "+/=") {
			t.Errorf("token is not URL-safe/unpadded: %q", tok)
		}
		if _, dup := seen[tok]; dup {
			t.Fatalf("token repeated within %d draws: %q", n, tok)
		}
		seen[tok] = struct{}{}
	}
	if len(seen) != n {
		t.Errorf("got %d distinct tokens from %d draws", len(seen), n)
	}
}

// --- the DNS proof ----------------------------------------------------

func txtVerifier(t *testing.T, records map[string][]string, opts ...DNSVerifierOption) DNSVerifier {
	t.Helper()
	opts = append(opts, WithTXTLookup(func(_ context.Context, name string) ([]string, error) {
		recs, ok := records[name]
		if !ok {
			return nil, fmt.Errorf("no such host: %s", name)
		}
		return recs, nil
	}))
	return NewDNSVerifier(opts...)
}

func TestVerifyTXT_MatchingRecordVerifies(t *testing.T) {
	ctx := context.Background()
	token := NewVerificationToken()
	v := txtVerifier(t, map[string][]string{
		// A realistic apex: the proof sits alongside SPF and a vendor tag.
		"acme.com": {"v=spf1 include:_spf.google.com ~all", token, "other-vendor=abc"},
	})
	if err := v.VerifyTXT(ctx, "acme.com", token); err != nil {
		t.Fatalf("a published matching record did not verify: %v", err)
	}
}

func TestVerifyTXT_FailureModesAreIndistinguishable(t *testing.T) {
	ctx := context.Background()
	token := NewVerificationToken()
	v := txtVerifier(t, map[string][]string{
		"has-wrong.com": {"some-other-value"},
		"has-none.com":  {},
	})

	var msgs []string
	for _, tc := range []struct{ name, domain string }{
		{"wrong value", "has-wrong.com"},
		{"no records", "has-none.com"},
		{"nxdomain / resolver error", "does-not-exist.com"},
	} {
		err := v.VerifyTXT(ctx, tc.domain, token)
		if !errors.Is(err, ErrVerificationFailed) {
			t.Fatalf("%s: err = %v, want ErrVerificationFailed", tc.name, err)
		}
		// The message must not name the cause — a caller probing for
		// which domains are mid-verification learns nothing. Redact the
		// echoed domain first: it came from the caller, so it discloses
		// nothing, and leaving it in would match the fixture names.
		redacted := strings.ReplaceAll(err.Error(), tc.domain, "<domain>")
		low := strings.ToLower(redacted)
		for _, leak := range []string{"no such host", "nxdomain", "resolver", "wrong", "mismatch", "empty"} {
			if strings.Contains(low, leak) {
				t.Errorf("%s: error discloses %q: %v", tc.name, leak, err)
			}
		}
		msgs = append(msgs, redacted)
	}
	for i := 1; i < len(msgs); i++ {
		if msgs[i] != msgs[0] {
			t.Errorf("failure modes are distinguishable:\n  %s\n  %s", msgs[0], msgs[i])
		}
	}
}

// TestVerifyTXT_EmptyExpectedTokenNeverVerifies: an empty expected token
// would match an empty TXT record, which is to say it would verify a
// domain against nothing.
func TestVerifyTXT_EmptyExpectedTokenNeverVerifies(t *testing.T) {
	ctx := context.Background()
	v := txtVerifier(t, map[string][]string{"acme.com": {""}})
	if err := v.VerifyTXT(ctx, "acme.com", ""); !errors.Is(err, ErrVerificationFailed) {
		t.Errorf("an empty expected token verified: %v", err)
	}
}

// TestVerifyTXT_RejectsUnnormalisedDomain: the same contract the rest of
// the package enforces. Verifying "ACME.com" and storing "acme.com"
// would leave a claim that never matches at resolve time.
func TestVerifyTXT_RejectsUnnormalisedDomain(t *testing.T) {
	ctx := context.Background()
	v := txtVerifier(t, map[string][]string{"acme.com": {"tok"}})
	if err := v.VerifyTXT(ctx, "ACME.com", "tok"); !errors.Is(err, ErrDomainNotNormalised) {
		t.Errorf("err = %v, want ErrDomainNotNormalised", err)
	}
}

// TestVerifyTXT_PrefixQueriesTheSubdomain: most operators put the proof
// on a subdomain so it does not have to be sifted out of a crowded apex.
func TestVerifyTXT_PrefixQueriesTheSubdomain(t *testing.T) {
	ctx := context.Background()
	token := NewVerificationToken()
	v := txtVerifier(t,
		map[string][]string{
			"_tamper-verify.acme.com": {token},
			// The apex deliberately holds a DIFFERENT value, so a verifier
			// that ignored the prefix would fail rather than pass by luck.
			"acme.com": {"v=spf1 ~all"},
		},
		WithTXTRecordPrefix("_tamper-verify"),
	)
	if err := v.VerifyTXT(ctx, "acme.com", token); err != nil {
		t.Fatalf("prefixed verification failed: %v", err)
	}
}

// TestVerifyTXT_TrimsSurroundingWhitespace: resolvers and DNS UIs add
// stray whitespace; the token itself is base64 and contains none.
func TestVerifyTXT_TrimsSurroundingWhitespace(t *testing.T) {
	ctx := context.Background()
	token := NewVerificationToken()
	v := txtVerifier(t, map[string][]string{"acme.com": {"  " + token + "\n"}})
	if err := v.VerifyTXT(ctx, "acme.com", token); err != nil {
		t.Errorf("a padded record did not verify: %v", err)
	}
}
