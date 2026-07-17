package saml

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"net/url"
	"sync"
	"time"

	crewjamsaml "github.com/crewjam/saml"
)

// ProviderConfig is the in-memory shape of one SAML IdP entry. The
// app's service layer sources rows from its own store, decrypts the
// signing private key, parses the cert PEM, and builds one of these
// per row before calling BuildRegistryFromConfigs.
type ProviderConfig struct {
	// ID is the operator-chosen identifier (URL-path-safe). The app
	// uses it as the path segment of its login/ACS/metadata routes.
	ID string

	// IdPMetadataURL is the URL IdP metadata is fetched from.
	IdPMetadataURL string

	// EntityID is the SP-side SAML entity identifier the IdP knows
	// this SP by (operator-chosen at IdP registration time).
	EntityID string

	// ACSURL is the full URL of the app's AssertionConsumerService
	// endpoint for this provider.
	ACSURL string

	// MetadataURL is the full URL the app serves this provider's SP
	// metadata document from. Route shapes are the app's concern —
	// the package takes the endpoint as data rather than composing a
	// path. Required by BuildProvider.
	MetadataURL string

	// SPCert is the parsed X.509 certificate the SP presents in its
	// metadata. The app's service layer parses the PEM before calling
	// BuildRegistryFromConfigs.
	SPCert *x509.Certificate

	// SPKey is the parsed private signer matching SPCert. RSA or
	// ECDSA; crypto.Signer covers both. The app's service layer
	// decrypts + parses the PEM before calling
	// BuildRegistryFromConfigs.
	SPKey crypto.Signer

	// DisplayName is the UI-rendered button label.
	DisplayName string

	// AttributeMappingGroups / Email / Name are the SAML attribute
	// names this IdP emits for the corresponding internal claim.
	AttributeMappingGroups string
	AttributeMappingEmail  string
	AttributeMappingName   string

	// AllowIDPInitiated keeps the IdP-initiated SSO surface open when
	// true — common with Azure AD "My Apps" + Okta tiles. False
	// forces the SP-initiated flow only; the app's ACS handler should
	// reject assertions with an empty InResponseTo when this is false.
	AllowIDPInitiated bool

	// SkewTolerance is the absolute clock-skew tolerance applied to
	// SAML assertion NotBefore / NotOnOrAfter timing checks. NOTE:
	// crewjam/saml v0.5.x only supports a package-global skew (see
	// SetMaxClockSkew) — this field rides along as a forensic record
	// but is not threaded onto the per-SP struct.
	SkewTolerance time.Duration
}

// Provider bundles the per-IdP config with the constructed
// crewjam/saml ServiceProvider that handles AuthnRequest signing +
// metadata generation + assertion verification.
//
// Built once per registry-rebuild via BuildProvider; immutable across
// the cached registry's lifetime. A TTL-cache pattern at the app's
// service layer bounds how long any single Provider instance lives.
type Provider struct {
	// Config is the source-of-truth ProviderConfig the service layer
	// built this Provider from. Retained for diagnostic surfaces.
	Config ProviderConfig

	// SP is the crewjam/saml-side per-IdP ServiceProvider. Handles
	// AuthnRequest signing, SP metadata XML generation, and SAML
	// response signature verification. The app's ACS handler reaches
	// in for ParseResponse.
	SP *crewjamsaml.ServiceProvider
}

// ProviderRegistry is the request-time lookup surface. Built once per
// registry rebuild and cached by the app's service layer. An empty
// registry (no providers configured) is represented by a nil pointer
// so callers can gate the whole SAML surface on non-nil.
type ProviderRegistry struct {
	mu        sync.RWMutex
	providers map[string]*Provider
	// order preserves input order so List() returns providers
	// deterministically.
	order []string
}

// BuildProvider constructs a Provider from a populated
// ProviderConfig. Validates that ACSURL and MetadataURL parse, then
// assembles the crewjam/saml ServiceProvider.
//
// Note: this does NOT fetch IdP metadata. The app's rebuild path is
// responsible for the network call (via MetadataFetcher). Splitting
// the two responsibilities lets the metadata fetch be retried +
// degraded (partialOK pattern) without re-running the per-Provider
// validation.
func BuildProvider(cfg ProviderConfig, idpMetadata *crewjamsaml.EntityDescriptor) (*Provider, error) {
	if cfg.ID == "" {
		return nil, fmt.Errorf("saml: provider id is required")
	}
	if !validProviderID(cfg.ID) {
		return nil, fmt.Errorf("saml: provider id %q is not a URL-safe path segment", cfg.ID)
	}
	if cfg.SPCert == nil {
		return nil, fmt.Errorf("saml: provider %q: sp_cert is required", cfg.ID)
	}
	if cfg.SPKey == nil {
		return nil, fmt.Errorf("saml: provider %q: sp_key is required", cfg.ID)
	}
	if cfg.ACSURL == "" {
		return nil, fmt.Errorf("saml: provider %q: acs_url is required", cfg.ID)
	}
	acs, err := url.Parse(cfg.ACSURL)
	if err != nil {
		return nil, fmt.Errorf("saml: provider %q: parse acs_url: %w", cfg.ID, err)
	}
	if cfg.MetadataURL == "" {
		return nil, fmt.Errorf("saml: provider %q: metadata_url is required", cfg.ID)
	}
	metadataURL, err := url.Parse(cfg.MetadataURL)
	if err != nil {
		return nil, fmt.Errorf("saml: provider %q: parse metadata_url: %w", cfg.ID, err)
	}

	sp := &crewjamsaml.ServiceProvider{
		EntityID:    cfg.EntityID,
		Key:         cfg.SPKey,
		Certificate: cfg.SPCert,
		MetadataURL: *metadataURL,
		AcsURL:      *acs,
		IDPMetadata: idpMetadata,
		// ALWAYS true — this is NOT the policy toggle. TD-FUNC-26.
		//
		// crewjam uses this flag to decide whether to enforce
		// InResponseTo against a caller-supplied AuthnRequest allow-list
		// (service_provider.go validateRequestID). When it is false it
		// searches that list for a match — and callers without an
		// AuthnRequest tracker have no list to supply, so the search runs
		// over an empty slice and can NEVER match. The result is that
		// EVERY assertion is rejected, SP-initiated ones included, and
		// SAML sign-in stops working entirely. Threading
		// cfg.AllowIDPInitiated in here made the stricter, more
		// security-conscious setting the broken one.
		//
		// The honest reading: this flag means "I have a request-ID
		// tracker and want crewjam to police it". We do not, so we must
		// not ask. Setting it true tells crewjam to skip a check it
		// cannot perform for us — it does NOT open the IdP-initiated
		// surface.
		//
		// The policy itself is enforced ABOVE this layer, off
		// ParsedAssertion.IdPInitiated() (an empty InResponseTo IS the
		// definition of IdP-initiated), which is where cfg.
		// AllowIDPInitiated is read. That gate already existed; until now
		// it was unreachable dead code, because control never survived
		// this line to reach it.
		//
		// No security regression, and it is worth being exact about why:
		//
		//   - On the default (cfg.AllowIDPInitiated=true) crewjam already
		//     skipped this check. Identical behaviour.
		//   - On cfg.AllowIDPInitiated=false, InResponseTo was never
		//     actually VALIDATED either — with an empty allow-list the
		//     check could only ever REJECT, never match. So this removes
		//     a check that has never once passed, on a config where
		//     nothing worked at all.
		//
		// Setting it true ALSO disables crewjam's second, unhookable
		// InResponseTo check (the SubjectConfirmation loop in
		// validateAssertion), which has the same empty-list defect. That
		// is what clears the way for ValidateRequestID below to enforce
		// the correlation properly — the two crewjam checks are
		// all-or-nothing and broken; ours is neither.
		AllowIDPInitiated: true,

		// ValidateRequestID replaces crewjam's request-ID gate with one
		// that can actually be satisfied. It fully overrides
		// validateRequestID, and with AllowIDPInitiated=true above the
		// only other InResponseTo check is skipped — so this hook is the
		// single decision point.
		//
		//   - No ids supplied  => nothing to correlate against. Allow,
		//     and let the app's post-parse gate decide whether an
		//     IdP-initiated assertion is permitted at all
		//     (ParsedAssertion.IdPInitiated()). This is the
		//     missing-cookie -> LOGIN fallthrough that makes
		//     IdP-initiated SSO legitimate; rejecting here would break
		//     Okta tiles / Azure "My Apps".
		//   - Ids supplied     => the caller issued an AuthnRequest and
		//     stashed its ID. The assertion MUST answer that request.
		//
		// The second case is the replay defence SAML otherwise lacks
		// entirely: no nonce, no PKCE, and — before this — no
		// InResponseTo binding either, so any IdP-signed assertion was
		// accepted by any flow. That is benign-ish on the login leg
		// (the assertion still proves who the subject is) and dangerous
		// on the LINK leg, where the flow's own cookie decides WHOSE
		// account the identity attaches to.
		ValidateRequestID: func(response crewjamsaml.Response, possibleRequestIDs []string) error {
			if len(possibleRequestIDs) == 0 {
				return nil
			}
			for _, id := range possibleRequestIDs {
				if id != "" && response.InResponseTo == id {
					return nil
				}
			}
			return fmt.Errorf("saml: InResponseTo %q does not answer this flow's AuthnRequest",
				response.InResponseTo)
		},
		// Request EmailAddress NameID instead of crewjam's
		// TransientNameIDFormat default. The transient default mints a
		// per-session opaque subject, so every SAML round-trip stores a
		// different (provider, subject) identity row: the first login
		// JIT-creates a user, the second login's lookup-by-subject
		// misses and falls into the app's email-collision branch.
		// Email-as-NameID is stable across sessions (Persistent would
		// also be stable, but email matches the common IdP mapper
		// config). Load-bearing for any federate path that keys
		// identities on (provider, subject).
		AuthnNameIDFormat: crewjamsaml.EmailAddressNameIDFormat,
	}
	// NOTE on skew tolerance: crewjam/saml v0.5.x applies a package-
	// level `MaxClockSkew` variable (default 180s) symmetrically
	// across NotBefore / NotOnOrAfter checks; there's no per-SP
	// field. The app sets the global once at boot via SetMaxClockSkew
	// so every provider in the binary picks up the same tolerance.
	// cfg.SkewTolerance rides along as a forensic record (rebuilds may
	// inspect it) but is not threaded onto the SP struct.
	_ = cfg.SkewTolerance
	return &Provider{Config: cfg, SP: sp}, nil
}

// validProviderID accepts ASCII letters / digits / hyphen /
// underscore. Anything else would need URL-escaping in callback paths
// or invite IdP-side quirks.
func validProviderID(id string) bool {
	if id == "" {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_':
		default:
			return false
		}
	}
	return true
}

// Get returns the Provider with the given id, or ErrUnknownProvider
// when the id isn't in the registry. Thread-safe.
func (r *ProviderRegistry) Get(id string) (*Provider, error) {
	if r == nil {
		return nil, ErrUnknownProvider
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[id]
	if !ok {
		return nil, fmt.Errorf("%w: id %q", ErrUnknownProvider, id)
	}
	return p, nil
}

// ProviderSummary is the public summary a provider-list endpoint may
// return. Only id + display name leak; cert + key + entity id stay
// inside the binary.
type ProviderSummary struct {
	ID          string
	DisplayName string
}

// List returns the public summaries in registry order.
func (r *ProviderRegistry) List() []ProviderSummary {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]ProviderSummary, 0, len(r.order))
	for _, id := range r.order {
		p := r.providers[id]
		display := p.Config.DisplayName
		if display == "" {
			display = id
		}
		out = append(out, ProviderSummary{ID: id, DisplayName: display})
	}
	return out
}
