package saml

import (
	"context"
	"net/url"
	"strings"
	"testing"

	crewjamsaml "github.com/crewjam/saml"
)

// These tests exist because the first version of the bound was provable and not proven. Both
// of its tests built a Provider literal WITH the limit set by hand, so removing the default
// from BuildProvider — leaving the field zero, which used to mean UNBOUNDED — kept the whole
// repository's suite green. The post-merge review ran exactly that mutant.
//
// Two things are asserted from now on: the default applies on every path into ParseAssertion
// (a literal and the real constructor), and zero cannot mean unbounded.
//
// Bodies here are oversized strings, not real assertions: the size check runs first, so these
// tests never pay for base64 or XML work. That is also why they stay fast at 1 MiB.

func oversizedBody() string {
	return strings.Repeat("A", DefaultMaxSAMLResponseBytes+1)
}

func sizeRefusal(err error) bool {
	return err != nil && strings.Contains(err.Error(), "exceeds")
}

func literalProvider(limit int) *Provider {
	return &Provider{
		Config: ProviderConfig{ID: "test"},
		// AcsURL is set because ParseAssertion reaches buildPostFormRequest once a response
		// is inside the bound, and that path dereferences it (parse.go:190). A literal with a
		// nil AcsURL panics there — outside safeParseResponse's recover barrier. Out of scope
		// for this fix (BuildProvider always sets it); recorded in the PR.
		SP:               &crewjamsaml.ServiceProvider{AcsURL: url.URL{Scheme: "https", Host: "sp.test", Path: "/acs"}},
		replay:           NoReplayDefence{},
		maxResponseBytes: limit,
	}
}

// The zero value must be the safe one. Before the review it was not: a literal meant
// "unbounded", so the bound existed only for callers who used BuildProvider.
func TestParseAssertion_ProviderLiteralIsBoundedByDefault(t *testing.T) {
	p := literalProvider(0)

	if _, err := p.ParseAssertion(context.Background(), oversizedBody(), "", ""); !sizeRefusal(err) {
		t.Fatalf("err = %v, want the size refusal — a Provider literal must not be unbounded", err)
	}
}

// The end-to-end wiring, which is what the surviving mutant removed: the provider that
// BuildProvider returns must carry the documented bound, and must honour an option that
// changes it.
func TestBuildProvider_AppliesTheDocumentedBound(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		p := buildProviderForSize(t)

		if _, err := p.ParseAssertion(context.Background(), oversizedBody(), "", ""); !sizeRefusal(err) {
			t.Fatalf("err = %v, want the size refusal — BuildProvider must apply the default", err)
		}
	})

	t.Run("option", func(t *testing.T) {
		p := buildProviderForSize(t, WithMaxResponseBytes(64))

		if _, err := p.ParseAssertion(context.Background(), strings.Repeat("A", 65), "", ""); !sizeRefusal(err) {
			t.Fatalf("err = %v, want the size refusal — the option must reach the provider", err)
		}
	})
}

// A bound is a boundary: at the limit the response is looked at, one byte over it is refused.
// The first version tested neither side of that line.
func TestParseAssertion_TheBoundIsExact(t *testing.T) {
	atLimit := strings.Repeat("A", 64)
	overLimit := strings.Repeat("A", 65)

	if _, err := literalProvider(64).ParseAssertion(context.Background(), atLimit, "", ""); sizeRefusal(err) {
		t.Fatalf("err = %v — a response of exactly the bound must be looked at, not refused", err)
	}
	if _, err := literalProvider(64).ParseAssertion(context.Background(), overLimit, "", ""); !sizeRefusal(err) {
		t.Fatalf("err = %v, want the size refusal one byte over the bound", err)
	}
}

// Unbounded is still reachable, and this is the only way to reach it — by name.
func TestParseAssertion_UnboundedIsExplicit(t *testing.T) {
	p := literalProvider(0)
	WithMaxResponseBytesUnbounded()(p)

	if _, err := p.ParseAssertion(context.Background(), oversizedBody(), "", ""); sizeRefusal(err) {
		t.Fatalf("err = %v — the bound was removed by name and must stay removed", err)
	}
}

// And a non-positive argument does NOT remove the bound, which is the one behaviour this fix
// deliberately changes: WithMaxResponseBytes(0) used to disable it, and now means the default.
// It is the safe direction, so it is not worth a deprecation cycle — but it is worth a test.
func TestWithMaxResponseBytes_NonPositiveKeepsTheDefault(t *testing.T) {
	p := literalProvider(0)
	WithMaxResponseBytes(0)(p)
	if p.maxResponseBytes != 0 {
		t.Fatalf("maxResponseBytes = %d, want 0 (the field keeps meaning 'use the default')", p.maxResponseBytes)
	}

	if _, err := p.ParseAssertion(context.Background(), oversizedBody(), "", ""); !sizeRefusal(err) {
		t.Fatalf("err = %v, want the size refusal — zero must not disable the bound", err)
	}
}

// buildProviderForSize is the real constructor, with the fixture the package already uses for
// provider-level tests — the point being that nothing here bypasses BuildProvider.
func buildProviderForSize(t *testing.T, opts ...ProviderOption) *Provider {
	t.Helper()
	certPEM, keyPEM := testCertKeyPEM(t)
	cert, key := parsePEMPair(t, certPEM, keyPEM)
	p, err := BuildProvider(ProviderConfig{
		ID:          "test",
		EntityID:    "https://panel.barista.test/saml/metadata",
		ACSURL:      "https://panel.barista.test/api/auth/saml/acs/test",
		MetadataURL: "https://idp.test/metadata",
		SPCert:      cert,
		SPKey:       key,
	}, fakeEntity(certPEM), NewMemAssertionReplayStore(), opts...)
	if err != nil {
		t.Fatalf("BuildProvider: %v", err)
	}
	return p
}
