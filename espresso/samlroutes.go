package espresso

// Phase 4d-4c — the mountable SAML federation surface: login / acs /
// metadata / link-start.
//
// SHAPE — mirrors FederationRoutes (OIDC) and AuthRoutes: construct,
// then let the APP register the handler methods. There is no Mount, for
// the reason A10 gives: Espresso's Router has no sub-router and Use is
// positional, so one Mount call would register every route at one
// middleware position — while this surface spans the public trio
// (login/acs/metadata) AND the authed link-start.
//
// WHERE SAML GENUINELY DIVERGES FROM OIDC (everything else mirrors):
//
//   - The ACS is a cross-site POST (HTTP-POST binding), not a GET
//     callback. That forces SameSite=None (TD-FUNC-28) and means the
//     answer is a 302, not a JSON envelope — hence SAMLOutcome rather
//     than FederationOutcome: there is NO user payload to carry.
//   - The correlator is InResponseTo, not state+nonce. There is no
//     nonce and no PKCE. The AuthnRequest ID must be stashed at start
//     and handed back at the ACS, which is why the state cookie is read
//     BEFORE the parse.
//   - RelayState is a second redirect channel that round-trips through
//     the IdP — OIDC has no analogue, and it is attacker-controlled.
//   - There is an XML metadata endpoint. OIDC has none.
//   - A cookie-less ACS hit is LEGITIMATE (IdP-initiated SSO), where a
//     cookie-less OIDC exchange is an error.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	espressofw "github.com/suryakencana007/espresso/v2"

	"github.com/suryakencana007/tamper/identity"
	"github.com/suryakencana007/tamper/saml"
	"github.com/suryakencana007/tamper/tenant"
)

// samlStateCookieSlotName is the context slot the ACS reads the state
// cookie through. The app wires ReadStateCookie() so the two can't
// drift.
//
// NOTE the failure mode differs from OIDC's, and the difference is
// dangerous: an OIDC slot mismatch 401s every exchange — loud, and any
// test catches it. A SAML mismatch just makes hasState false, which is
// indistinguishable from legitimate IdP-initiated SSO, so link mode
// SILENTLY becomes login. That is TD-FUNC-28's exact symptom. The
// app-side end-to-end link test is what actually guards this.
const samlStateCookieSlotName = "tamper_saml_state"

// SAMLOutcome is what the app's post-assertion hook returns.
//
// Deliberately NOT FederationOutcome: the ACS answers with a 302, not
// JSON, so there is no user payload. Reusing the OIDC type would drag a
// dead User field through this path. The protocols differ at the wire;
// forcing a shared type is how a framework grows fields nobody sets.
type SAMLOutcome struct {
	// Tokens must be EMPTY on the link leg — the caller's session stays
	// valid, and a fresh mint would hand out credentials on a flow that
	// re-authenticated nobody.
	Tokens identity.Tokens
	// Redirect is the 302 target, trusted VERBATIM. The hook chose it by
	// provenance; tamper must not re-process it (A5).
	Redirect string
	// Linked marks the link leg EXPLICITLY — never inferred from empty
	// Tokens, which would conflate "the mint failed" with "this is a
	// link".
	Linked bool
}

// SAMLVerified is what tamper hands the hook once an assertion has
// validated.
type SAMLVerified struct {
	// Assertion is the validated, library-free view.
	Assertion *saml.ParsedAssertion
	// State is the signed state cookie's claims. Meaningful only when
	// HasState.
	State saml.StateCookieClaims
	// HasState is EXPLICIT: a cookie-less ACS hit is legitimate
	// IdP-initiated SSO, not an error, and the two must stay
	// distinguishable.
	HasState bool
	// RelayState is the IdP-echoed value. ATTACKER-CONTROLLED: it is a
	// plain form field under the HTTP-POST binding and is NOT covered by
	// the SAML signature. Any use of it as a redirect must be sanitized.
	RelayState string
}

// SAMLHooks are the app-policy seams.
type SAMLHooks struct {
	// Registry resolves the provider registry for this request.
	// (nil, nil) means "SAML is not configured" => 404. Required.
	Registry func(ctx context.Context, tenantID tenant.ID) (*saml.ProviderRegistry, error)

	// OnFederatedAssertion runs the whole post-assertion tail: the
	// IdP-initiated policy gate, attribute extraction, link-vs-login,
	// reconcile, mint, audits, redirect choice.
	//
	// It RECEIVES the resolved provider — never re-resolve from the
	// registry here. The assertion is single-use; a second lookup lands
	// after it is consumed, where a TTL rebuild can 404/500 a request
	// that already succeeded, with no retry path (A9). Required.
	OnFederatedAssertion func(ctx context.Context, p *saml.Provider, v SAMLVerified) (SAMLOutcome, error)

	// SanitizeRedirect gates the START leg's ?redirect= query param —
	// untrusted browser input. nil => deny-all-to-"/".
	//
	// tamper calls it exactly once, here. The app has its own call sites
	// and MUST: RelayState is attacker-controlled. The rule is
	// provenance, not arity (A5).
	SanitizeRedirect func(raw string) string

	// LinkRedirect returns the post-link target for a provider. SAML
	// needs this at START time (it is signed into the cookie), where
	// OIDC's equivalent is built later inside its hook — so unlike
	// FederationRoutes.LinkStart, this cannot be omitted. Required for
	// LinkStart.
	LinkRedirect func(providerID string) string

	// OnStepUpInitiated fires when a start leg carries step-up params.
	// One concrete callback, no event-sink interface (A3). Optional.
	OnStepUpInitiated func(ctx context.Context, callingUserID string, maxAge int64, acrValues []string)

	// CallingUserID resolves the audit actor on the start leg.
	// Optional; defaults to GetUserID.
	CallingUserID func(ctx context.Context) string
}

// SAMLConfig carries the app's branding + policy.
type SAMLConfig struct {
	// StateCookie is the state cookie's brand + policy. SameSite must be
	// set explicitly, and for SAML it must be None under Secure — the
	// ACS is a cross-site POST and Lax never arrives (TD-FUNC-28).
	StateCookie StateCookieConfig
	// StateSecret signs the state cookie. Required.
	StateSecret []byte
	// StateIssuer is the signed cookie's iss claim. Required.
	StateIssuer string
	// StateTTL bounds the signed claims' lifetime.
	StateTTL time.Duration
	// Cookies is the refresh-cookie branding for the login leg.
	Cookies CookieConfig
	// MountPrefix is the auth route prefix ("/api/auth"). The refresh
	// cookie's Path IS this value.
	MountPrefix string
	// Now is the clock seam. Optional; defaults to time.Now.
	Now func() time.Time
}

// SAMLRoutes is the SAML federation surface. Construct with
// NewSAMLRoutes; the app registers the methods.
type SAMLRoutes struct {
	cfg   SAMLConfig
	hooks SAMLHooks
}

// NewSAMLRoutes validates at wiring time, never at request time.
func NewSAMLRoutes(cfg SAMLConfig, hooks SAMLHooks) (*SAMLRoutes, error) {
	if hooks.Registry == nil {
		return nil, errors.New("tamper/espresso: saml routes require a Registry hook")
	}
	if hooks.OnFederatedAssertion == nil {
		return nil, errors.New("tamper/espresso: saml routes require an OnFederatedAssertion hook")
	}
	if !strings.HasPrefix(cfg.MountPrefix, "/") || strings.HasSuffix(cfg.MountPrefix, "/") {
		return nil, errors.New(`tamper/espresso: MountPrefix must start with "/" and not end with one`)
	}
	if cfg.StateCookie.BaseName == "" {
		return nil, errors.New("tamper/espresso: state cookie base name is required (the app's brand)")
	}
	if cfg.StateCookie.Secure && cfg.StateCookie.Path != "/" {
		return nil, errors.New(`tamper/espresso: a Secure state cookie uses the __Host- prefix, which requires Path="/"`)
	}
	// Same fence as FederationRoutes: a zero SameSite silently means Lax,
	// and Lax is FATAL here — the ACS is a cross-site POST, so the cookie
	// never arrives and link mode + step-up die silently in production
	// while login keeps working (TD-FUNC-28).
	if cfg.StateCookie.SameSite == 0 {
		return nil, errors.New("tamper/espresso: StateCookie.SameSite must be set explicitly — " +
			"the zero value silently means Lax, and the SAML ACS is a cross-site POST where Lax never arrives (TD-FUNC-28)")
	}
	if cfg.StateCookie.SameSite == http.SameSiteNoneMode && !cfg.StateCookie.Secure {
		return nil, errors.New("tamper/espresso: SameSite=None requires Secure — browsers reject the pair, and the cookie would silently never be set")
	}
	// NOTE a coupling this shape introduces: Metadata needs only the
	// registry — no secret, no cookie — yet it is a method on the same
	// adapter, so an app serving ONLY metadata is over-constrained by
	// these checks. That is accepted deliberately: every real consumer
	// serves all four routes, validation stays at wiring where it belongs
	// (not per-request), and splitting Metadata onto its own construction
	// path is speculative generality until a metadata-only consumer
	// exists. It surfaced in 4d-4c as a test whose config built a
	// JWTService but never set config.Auth.JWT.Secret — an arrangement
	// production cannot have, since the app will not boot without it.
	if len(cfg.StateSecret) == 0 {
		return nil, errors.New("tamper/espresso: state cookie signing secret is required")
	}
	if cfg.StateIssuer == "" {
		return nil, errors.New("tamper/espresso: state cookie issuer is required")
	}
	if cfg.StateTTL <= 0 {
		return nil, errors.New("tamper/espresso: state cookie TTL must be positive")
	}
	if cfg.Cookies.Name == "" {
		return nil, errors.New("tamper/espresso: refresh cookie name is required (the app's brand)")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if hooks.SanitizeRedirect == nil {
		hooks.SanitizeRedirect = denyAllRedirect
	}
	if hooks.CallingUserID == nil {
		hooks.CallingUserID = func(ctx context.Context) string {
			id, _ := GetUserID(ctx)
			return id
		}
	}
	return &SAMLRoutes{cfg: cfg, hooks: hooks}, nil
}

// ReadStateCookie is the middleware the app mounts on the ACS route.
// Wiring it through this method rather than the app naming the slot is
// what stops the reader and the handler disagreeing — a drift whose SAML
// symptom is silent (see samlStateCookieSlotName).
func (s *SAMLRoutes) ReadStateCookie() func(http.Handler) http.Handler {
	return ReadNamedCookie(samlStateCookieSlotName, s.cfg.StateCookie.Name())
}

// StateCookieName exposes the resolved cookie name for apps that wire
// their own reader.
func (s *SAMLRoutes) StateCookieName() string { return s.cfg.StateCookie.Name() }

// provider resolves a provider id, producing the two 404 shapes.
func (s *SAMLRoutes) provider(ctx context.Context, id string) (*saml.Provider, error) {
	tid, ok := TenantFromContext(ctx)
	if !ok {
		return nil, espressofw.ErrNotFound("provider not found").WithCode("SAML_PROVIDER_NOT_FOUND")
	}
	reg, err := s.hooks.Registry(ctx, tid)
	if err != nil {
		return nil, espressofw.ErrInternal("saml registry").Wrap(err)
	}
	if reg == nil {
		return nil, espressofw.ErrNotFound("saml is not configured").WithCode("SAML_NOT_CONFIGURED")
	}
	p, err := reg.Get(id)
	if err != nil {
		// A disabled row is absent from the registry, so "never existed"
		// and "exists but disabled" both land here. That is deliberate:
		// distinguishing them would leak provider ids to anonymous
		// callers, and operators investigating a missing button look at
		// the admin surface, not the login one.
		return nil, espressofw.ErrNotFound("saml provider not found").WithCode("SAML_PROVIDER_NOT_FOUND")
	}
	return p, nil
}

// SAMLStartParams carries the start leg's query surface.
type SAMLStartParams struct {
	// Redirect is the RAW ?redirect= value — untrusted browser input,
	// and the one thing SanitizeRedirect is applied to.
	Redirect string
	// MaxAge is ?max_age= in seconds. Negative reads as absent.
	MaxAge int64
	// ACRValues is the RAW ?acr_values= param; comma- or space-separated.
	ACRValues string
}

// Login handles GET {prefix}/saml/login/{id}: build + sign an
// AuthnRequest, stash its ID in a signed state cookie, and redirect the
// browser to the IdP.
func (s *SAMLRoutes) Login(ctx context.Context, providerID string, p SAMLStartParams) (Redirect, error) {
	prov, err := s.provider(ctx, providerID)
	if err != nil {
		return Redirect{}, err
	}

	// The ONE SanitizeRedirect call site (A5). This value rides in BOTH
	// the RelayState wire param and the signed cookie, so it must be
	// clean before either.
	relayState := s.hooks.SanitizeRedirect(p.Redirect)

	maxAge := p.MaxAge
	if maxAge < 0 {
		maxAge = 0
	}
	acrValues := SplitACRValues(p.ACRValues)
	isStepUp := maxAge > 0 || len(acrValues) > 0
	callingUserID := s.hooks.CallingUserID(ctx)

	opts := saml.AuthnRequestOptions{}
	if isStepUp {
		// SAML has no max_age primitive; ForceAuthn is the closest
		// semantic (the IdP MUST re-prompt). The satisfaction check at
		// the ACS is what actually enforces the bound — tamper owns both
		// halves (StepUpSatisfied), so shaping the request here keeps the
		// pair together.
		opts.ForceAuthn = true
	}
	if len(acrValues) > 0 {
		// crewjam's AuthnContextClassRef is a single string, so the
		// request pins the first/strongest value. That is lossy BY
		// DESIGN: ANY-of matching against the full requested set happens
		// at the ACS via StepUpSatisfied.
		opts.RequestedACRClass = acrValues[0]
	}

	idpURL, authnRequestID, err := saml.BuildAuthnRequestURL(prov, relayState, opts)
	if err != nil {
		return Redirect{}, espressofw.ErrInternal("build saml authn request").Wrap(err)
	}

	cookie, err := s.signState(saml.StateCookieClaims{
		ProviderID:             prov.Config.ID,
		RedirectAfterLogin:     relayState,
		RequestedMaxAgeSeconds: maxAge,
		RequestedACRValues:     acrValues,
		CallingUserID:          callingUserID,
		// The correlator. SAML has no nonce and no PKCE; the ACS hands
		// this back as the InResponseTo allow-list so only an assertion
		// answering THIS request is accepted (TD-FUNC-28).
		RequestID: authnRequestID,
	})
	if err != nil {
		return Redirect{}, err
	}

	if isStepUp && s.hooks.OnStepUpInitiated != nil {
		// Best-effort: an audit miss must never block the redirect.
		s.hooks.OnStepUpInitiated(ctx, callingUserID, maxAge, acrValues)
	}
	return Redirect{URL: idpURL.String(), Cookies: []*http.Cookie{cookie}}, nil
}

// LinkStart handles POST {prefix}/saml/link-start/{id} behind the app's
// auth gate: same signed-cookie shape as Login but mode=link + the
// caller's user id.
//
// Step-up is deliberately not offered on this leg: the user already has
// a live session and is proving they hold the federated subject.
func (s *SAMLRoutes) LinkStart(ctx context.Context, providerID, userID string) (espressofw.JSON[LinkStartRes], error) {
	var zero espressofw.JSON[LinkStartRes]
	prov, err := s.provider(ctx, providerID)
	if err != nil {
		return zero, err
	}
	if s.hooks.LinkRedirect == nil {
		return zero, espressofw.ErrInternal("tamper/espresso: LinkRedirect hook is required for LinkStart")
	}
	// SAML signs the post-link target into the cookie at START time,
	// which is why this is a hook rather than something the app's tail
	// builds later (OIDC's shape).
	target := s.hooks.LinkRedirect(prov.Config.ID)

	idpURL, authnRequestID, err := saml.BuildAuthnRequestURL(prov, target, saml.AuthnRequestOptions{})
	if err != nil {
		return zero, espressofw.ErrInternal("build saml authn request").Wrap(err)
	}
	cookie, err := s.signState(saml.StateCookieClaims{
		ProviderID:         prov.Config.ID,
		RedirectAfterLogin: target,
		Mode:               saml.ModeLink,
		UserID:             userID,
		CallingUserID:      userID,
		// Load-bearing most of all on THIS leg: the cookie decides whose
		// account the identity attaches to, so an assertion that does not
		// answer our request must not ride this flow.
		RequestID: authnRequestID,
	})
	if err != nil {
		return zero, err
	}
	return espressofw.JSON[LinkStartRes]{
		StatusCode: http.StatusOK,
		Data:       LinkStartRes{AuthURL: idpURL.String()},
		Cookies:    []*http.Cookie{cookie},
	}, nil
}

// signState signs + wraps the state cookie.
func (s *SAMLRoutes) signState(claims saml.StateCookieClaims) (*http.Cookie, error) {
	value, err := saml.SignStateCookieWithSecret(s.cfg.StateSecret, claims, s.cfg.StateIssuer, s.cfg.Now(), s.cfg.StateTTL)
	if err != nil {
		return nil, espressofw.ErrInternal("sign saml state cookie").Wrap(err)
	}
	return s.cfg.StateCookie.Set(value), nil
}

// readState pulls + verifies the signed state cookie.
//
// Returns (_, false) on ANY failure — missing, bad signature, expired,
// provider mismatch. That is not leniency: a cookie-less ACS hit is
// legitimate IdP-initiated SSO, so the caller treats false as "no prior
// request" and the app's policy gate decides whether that is allowed.
// Rejecting here would break Okta tiles / Azure "My Apps".
func (s *SAMLRoutes) readState(ctx context.Context, providerID string) (saml.StateCookieClaims, bool) {
	raw, ok := NamedCookieValue(ctx, samlStateCookieSlotName)
	if !ok || raw == "" {
		return saml.StateCookieClaims{}, false
	}
	claims, err := saml.VerifyStateCookieWithSecret(s.cfg.StateSecret, raw, s.cfg.StateIssuer, s.cfg.Now)
	if err != nil {
		return saml.StateCookieClaims{}, false
	}
	// A cookie minted for provider A must not be replayed against
	// provider B's ACS.
	if claims.ProviderID != providerID {
		return saml.StateCookieClaims{}, false
	}
	return claims, true
}

// SAMLAssertionForm is the ACS's form surface.
type SAMLAssertionForm struct {
	SAMLResponse string
	RelayState   string
}

// ACS handles POST {prefix}/saml/acs/{id} — the IdP's cross-site form
// POST carrying the assertion.
//
// Mount the ReadStateCookie middleware on this route.
func (s *SAMLRoutes) ACS(ctx context.Context, providerID string, form SAMLAssertionForm) (Redirect, error) {
	// Resolve ONCE, before the assertion is consumed (A9). This same
	// pointer goes to the hook.
	prov, err := s.provider(ctx, providerID)
	if err != nil {
		return Redirect{}, err
	}

	// The cookie is read BEFORE the parse: it carries the AuthnRequest ID
	// the parse needs as its correlator (TD-FUNC-28).
	claims, hasState := s.readState(ctx, prov.Config.ID)

	// The AuthnRequest ID THIS flow issued, or "" when it issued none (no
	// cookie, expired cookie, or a genuine IdP-initiated flow). A missing
	// cookie is still indistinguishable from IdP-initiated at THIS layer —
	// the captured-assertion replay closes one layer down, inside
	// ParseAssertion, on the signed SubjectConfirmationData. A present
	// cookie with an empty RequestID honestly reads as "no request".
	var expectedRequestID string
	if hasState {
		expectedRequestID = claims.RequestID
	}

	assertion, err := prov.ParseAssertion(ctx, form.SAMLResponse, form.RelayState, expectedRequestID)
	if err != nil {
		switch {
		case errors.Is(err, saml.ErrReplayStoreUnavailable):
			// The ledger is ours; a store outage is a 503, not a client 4xx.
			return Redirect{}, espressofw.ErrServiceUnavailable("saml replay store unavailable").
				WithCode("SAML_REPLAY_STORE_UNAVAILABLE").Wrap(err)
		case errors.Is(err, saml.ErrAssertionReplayed):
			return Redirect{}, espressofw.ErrBadRequest("saml assertion already consumed").
				WithCode("SAML_ASSERTION_REPLAYED")
		case errors.Is(err, saml.ErrUncorrelated), errors.Is(err, saml.ErrNoSubjectConfirmation):
			return Redirect{}, espressofw.ErrBadRequest("saml assertion does not answer this flow's request").
				WithCode("SAML_ASSERTION_UNCORRELATED")
		case errors.Is(err, saml.ErrIdPInitiatedDisabled):
			return Redirect{}, espressofw.ErrBadRequest("idp-initiated saml sso is disabled").
				WithCode("SAML_IDP_INITIATED_DISABLED")
		default:
			// Signature / timing / audience family stays collapsed — it is
			// oracle-sensitive, unlike the replay/correlation codes above
			// (which only tell a party already holding a valid assertion
			// something it already knows).
			return Redirect{}, espressofw.ErrBadRequest("saml assertion invalid").WithCode("SAML_ASSERTION_INVALID")
		}
	}

	// Mode dispatch. Empty mode reads as login so cookies signed before
	// the link flow existed still resolve during a rolling deploy; a
	// MISSING cookie also reads as login — the IdP-initiated fallthrough.
	mode := saml.ModeLogin
	if hasState && claims.Mode != "" {
		mode = claims.Mode
	}
	// A link cookie with no user id cannot say whose account to attach
	// to. Guarded here so the hook may assume it.
	if mode == saml.ModeLink && (!hasState || claims.UserID == "") {
		return Redirect{}, espressofw.ErrBadRequest("saml link cookie missing user id").WithCode("INVALID_STATE")
	}

	out, err := s.hooks.OnFederatedAssertion(ctx, prov, SAMLVerified{
		Assertion:  assertion,
		State:      claims,
		HasState:   hasState,
		RelayState: form.RelayState,
	})
	if err != nil {
		// No clear-cookie: every error exit returns the zero Redirect,
		// which carries no Set-Cookie. That reproduces the app exactly
		// (A4) — the cookie is single-use against an assertion already
		// consumed, and expires on its own TTL.
		return Redirect{}, err
	}

	// Fail closed if the link leg minted. The hook is app code and can
	// regress; a link response carrying a session would hand out
	// credentials on a flow that re-authenticated nobody.
	if out.Linked && (out.Tokens.Access != "" || out.Tokens.Refresh != "") {
		return Redirect{}, espressofw.ErrInternal("tamper/espresso: saml link leg minted tokens")
	}

	// Order is wire surface: espresso writes Set-Cookie in slice order —
	// refresh FIRST, state-clear SECOND.
	var cookies []*http.Cookie
	if !out.Linked {
		cookies = s.refreshCookies(out.Tokens)
	}
	cookies = append(cookies, s.cfg.StateCookie.Clear())

	// Verbatim — the hook already chose it by provenance (A5).
	return Redirect{URL: out.Redirect, Cookies: cookies}, nil
}

// Metadata handles GET {prefix}/saml/metadata/{id} — the SP descriptor
// an operator hands their IdP.
func (s *SAMLRoutes) Metadata(ctx context.Context, providerID string) (XML, error) {
	prov, err := s.provider(ctx, providerID)
	if err != nil {
		return XML{}, err
	}
	body, err := prov.GenerateSPMetadata()
	if err != nil {
		return XML{}, espressofw.ErrInternal("generate saml metadata").Wrap(err)
	}
	return XML{Body: body}, nil
}

// refreshCookies mirrors the OIDC/auth shape: Path == MountPrefix by
// construction, empty when refresh issuance is off.
func (s *SAMLRoutes) refreshCookies(tokens identity.Tokens) []*http.Cookie {
	if tokens.Refresh == "" {
		return nil
	}
	return []*http.Cookie{{
		Name:     s.cfg.Cookies.Name,
		Value:    tokens.Refresh,
		Path:     s.cfg.MountPrefix,
		HttpOnly: true,
		Secure:   s.cfg.Cookies.Secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   s.cfg.Cookies.MaxAgeSeconds,
	}}
}
