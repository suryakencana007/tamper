package saml

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"time"

	crewjamsaml "github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

// MetadataFetcher is the interface the app's registry-rebuild path
// drives to retrieve an IdP's metadata document. Tests inject a fake
// fetcher so multi-replica / rebuild tests don't require a live IdP.
// Production wires DefaultMetadataFetcher which wraps
// samlsp.FetchMetadata.
type MetadataFetcher func(ctx context.Context, metadataURL string) (*crewjamsaml.EntityDescriptor, error)

// DefaultMetadataFetcher is the production MetadataFetcher. Fetches
// the URL with a bounded timeout + parses via samlsp.ParseMetadata
// (handles both single EntityDescriptor and wrapped
// EntitiesDescriptor shapes -- Azure AD wraps, Keycloak doesn't).
//
// Returns ErrMetadataFetchFailed when the network call fails or the
// IdP returns a non-2xx; ErrMetadataInvalid when the response body
// fails XML parsing or is missing IDPSSODescriptor.
func DefaultMetadataFetcher(ctx context.Context, metadataURL string) (*crewjamsaml.EntityDescriptor, error) {
	u, err := url.Parse(metadataURL)
	if err != nil {
		return nil, fmt.Errorf("%w: parse url: %v", ErrMetadataInvalid, err)
	}
	// 30s budget covers slow IdP responses but doesn't let a hung
	// fetch block a registry rebuild indefinitely — a rebuild path
	// typically holds a service-level lock while this runs.
	fetchCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		// Use the default TLS config. Operators with self-signed
		// IdP certs in dev clusters should issue a real cert from
		// their dev-CA rather than disabling verification here.
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
	entity, err := samlsp.FetchMetadata(fetchCtx, httpClient, *u)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMetadataFetchFailed, err)
	}
	if entity == nil {
		return nil, fmt.Errorf("%w: empty entity descriptor", ErrMetadataInvalid)
	}
	if len(entity.IDPSSODescriptors) == 0 {
		return nil, fmt.Errorf("%w: no IDPSSODescriptor in metadata", ErrMetadataInvalid)
	}
	return entity, nil
}

// SetMaxClockSkew pins crewjam/saml's package-level MaxClockSkew to
// the operator-configured skew tolerance. The library uses this
// single global symmetrically across NotBefore / NotOnOrAfter
// assertion timing checks; there's no per-SP field, so the app must
// set it ONCE at boot — it is process-global mutable state.
//
// Bounds: a non-positive duration falls back to the library default
// (180s). Maximum: capped at 1 hour so a fat-fingered config value
// can't disable timing validation entirely (a 24-hour skew would
// make replays trivially valid).
func SetMaxClockSkew(d time.Duration) {
	const maxBound = time.Hour
	if d <= 0 {
		// Restore the library default by leaving the variable
		// alone -- callers passing zero almost certainly want the
		// out-of-the-box behaviour.
		return
	}
	if d > maxBound {
		d = maxBound
	}
	crewjamsaml.MaxClockSkew = d
}

// GenerateSPMetadata emits the SAML 2.0 SP metadata XML document
// describing this provider's EntityID + ACS URL + SP signing
// certificate. Operators paste the served metadata URL into their
// IdP's SP-registration form so the IdP can validate AuthnRequest
// signatures + match assertions to the SP.
//
// Wraps crewjam/saml's ServiceProvider.Metadata + serialises the
// resulting EntityDescriptor as XML with the standard SAML
// XML namespace. Content-Type at the HTTP layer:
// `application/samlmetadata+xml` (or `application/xml` -- IdP
// fetchers tolerate either).
func (p *Provider) GenerateSPMetadata() ([]byte, error) {
	if p == nil || p.SP == nil {
		return nil, fmt.Errorf("saml: provider service provider is nil")
	}
	descriptor := p.SP.Metadata()
	if descriptor == nil {
		return nil, fmt.Errorf("saml: provider %q: empty SP metadata descriptor", p.Config.ID)
	}
	body, err := xml.MarshalIndent(descriptor, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("saml: provider %q: marshal SP metadata: %w", p.Config.ID, err)
	}
	// Prepend the XML declaration so IdP-side metadata parsers that
	// strictly require it don't bail. Most IdPs accept either shape,
	// but Shibboleth's metadata-loader is stricter.
	out := append([]byte(xml.Header), body...)
	return out, nil
}
