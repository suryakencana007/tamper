package saml

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	crewjamsaml "github.com/crewjam/saml"
)

// An ACS URL is configuration, and configuration errors belong at New — which is the rule this
// package already follows for every other field. This one escaped it: url.Parse accepts
// "not a url" and "/acs", those reached buildPostFormRequest, and httptest.NewRequest panicked
// on them. A misconfigured provider took down its own login path, per request, with a stack
// trace, on the unauthenticated ACS route.
func TestBuildProvider_RefusesANonAbsoluteACSURL(t *testing.T) {
	cases := []struct {
		name string
		acs  string
	}{
		{"empty", ""},
		{"not a url at all", "not a url"},
		{"root-relative path", "/relative/acs"},
		{"bare segment", "acs"},
		{"scheme without a host", "mailto:ops@example.test"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := buildProviderWithACS(t, tc.acs)
			if err == nil {
				t.Fatalf("acs_url %q was accepted — it must fail at New, not on the request path", tc.acs)
			}
			if !strings.Contains(err.Error(), "acs_url") {
				t.Errorf("err = %v, want it to name acs_url", err)
			}
		})
	}
}

// The other side of the same gate, so "refuse everything" cannot pass as the fix.
func TestBuildProvider_AcceptsAnAbsoluteACSURL(t *testing.T) {
	if _, err := buildProviderWithACS(t, "https://panel.barista.test/api/auth/saml/acs/test"); err != nil {
		t.Fatalf("a well-formed ACS URL was refused: %v", err)
	}
}

// Defence in depth for a provider that did not come through the constructor. Before this, the
// same input panicked — the panic is the thing being fixed, so a test that only asserts
// "some error" would not notice its return.
func TestParseAssertion_MalformedACSURLIsAnErrorNotAPanic(t *testing.T) {
	p := &Provider{
		Config: ProviderConfig{ID: "test"},
		SP:     &crewjamsaml.ServiceProvider{AcsURL: url.URL{Path: "not a url"}},
		replay: NoReplayDefence{},
	}

	_, err := p.ParseAssertion(context.Background(), "AAAA", "", "")
	if err == nil {
		t.Fatal("a malformed ACS URL was accepted")
	}
	if !errors.Is(err, ErrAssertionInvalid) {
		t.Errorf("err = %v, want ErrAssertionInvalid (a generic parse failure, not a new oracle)", err)
	}
}

// The production-code dependency the panic came with: net/http/httptest is a test package, and
// it was linked into the shipped binary through this call site.
func TestBuildPostFormRequest_RefusesARelativeTarget(t *testing.T) {
	for _, target := range []string{"not a url", "/relative/acs", ""} {
		if _, err := buildPostFormRequest(context.Background(), target, "AAAA", ""); err == nil {
			t.Errorf("target %q was accepted — http.NewRequest does not police this, so this function must", target)
		}
	}

	r, err := buildPostFormRequest(context.Background(), "https://sp.example.test/acs", "AAAA", "")
	if err != nil {
		t.Fatalf("a valid ACS URL was refused: %v", err)
	}
	if got := r.PostForm.Get("SAMLResponse"); got != "AAAA" {
		t.Errorf("SAMLResponse = %q, want AAAA — the request must still carry the response", got)
	}
}

func buildProviderWithACS(t *testing.T, acs string) (*Provider, error) {
	t.Helper()
	certPEM, keyPEM := testCertKeyPEM(t)
	cert, key := parsePEMPair(t, certPEM, keyPEM)
	return BuildProvider(ProviderConfig{
		ID:          "test",
		EntityID:    "https://panel.barista.test/saml/metadata",
		ACSURL:      acs,
		MetadataURL: "https://idp.test/metadata",
		SPCert:      cert,
		SPKey:       key,
	}, fakeEntity(certPEM), NewMemAssertionReplayStore())
}
