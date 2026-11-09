package saml

import (
	"strings"
	"testing"
)

// metadata_url is refused at construction when it is not an absolute URL, for the same reason
// acs_url is: a misconfiguration fails at New, not later and somewhere less obvious. The twin
// check was left out on the reasoning that nothing dereferences it during request construction —
// true, and not the point. (#130)
func TestBuildProvider_RefusesANonAbsoluteMetadataURL(t *testing.T) {
	cases := []struct {
		name string
		url  string
	}{
		{"empty", ""},
		{"not a url at all", "not a url"},
		{"root-relative path", "/idp/metadata"},
		{"bare segment", "metadata"},
		{"scheme without a host", "mailto:ops@example.test"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := buildProviderWithMetadataURL(t, tc.url)
			if err == nil {
				t.Fatalf("metadata_url %q was accepted — it must fail at New, like acs_url", tc.url)
			}
			if !strings.Contains(err.Error(), "metadata_url") {
				t.Errorf("err = %v, want it to name metadata_url so an operator knows which field", err)
			}
		})
	}
}

// The other side, so "refuse everything" cannot pass as the fix.
func TestBuildProvider_AcceptsAnAbsoluteMetadataURL(t *testing.T) {
	if _, err := buildProviderWithMetadataURL(t, "https://idp.test/metadata"); err != nil {
		t.Fatalf("a well-formed metadata_url was refused: %v", err)
	}
}

func buildProviderWithMetadataURL(t *testing.T, metadataURL string) (*Provider, error) {
	t.Helper()
	certPEM, keyPEM := testCertKeyPEM(t)
	cert, key := parsePEMPair(t, certPEM, keyPEM)
	return BuildProvider(ProviderConfig{
		ID:          "test",
		EntityID:    "https://panel.barista.test/saml/metadata",
		ACSURL:      "https://panel.barista.test/api/auth/saml/acs/test",
		MetadataURL: metadataURL,
		SPCert:      cert,
		SPKey:       key,
	}, fakeEntity(certPEM), NewMemAssertionReplayStore())
}
