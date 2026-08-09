package espresso

// Phase 4d-3c — the mountable OIDC federation surface: start /
// callback / exchange / link-start.
//
// SHAPE — this mirrors AuthRoutes (4c) deliberately: construct with
// NewFederationRoutes, then let the APP register the handler methods on
// its own router. There is no Mount, for the same reason AuthRoutes has
// none: Espresso's Router has no sub-router and Use is positional
// (Get/Post snapshot the middleware stack at registration), so one
// Mount call registers every route at one middleware position — while
// this surface, like AuthRoutes, spans BOTH the public block
// (start/callback/exchange) and the authed block (link-start). Handing
// registration back to the app keeps the auth boundary legible at the
// call site and keeps route paths — which are app wire surface — app
// owned. See PHASE4D-BOUNDARY-DECISION.md §A10.
//
// OWNERSHIP — tamper owns the RFC/browser-shaped mechanics: the state
// cookie's sign/verify/set/clear, the IdP token exchange + ID-token
// verification, the landing-fragment bytes, mode dispatch, the wire
// envelope and its error codes. The app owns everything downstream of a
// verified assertion via ONE hook (OnFederatedExchange): upsert,
// group reconcile, mint, audit, projection, redirect policy. tamper
// never emits an audit row and never learns the app's user DTO.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	espressofw "github.com/suryakencana007/espresso/v2"

	"github.com/suryakencana007/tamper/identity"
	"github.com/suryakencana007/tamper/oidc"
	"github.com/suryakencana007/tamper/tenant"
)

// oidcStateCookieSlotName is the context slot the exchange route reads
// the state cookie through. The app wires ReadStateCookie() so the two
// can't drift — one slot, one owner (the 4c refresh-slot lesson).
const oidcStateCookieSlotName = "tamper_oidc_state"

// FederationOutcome is what the app's post-verify hook returns.
//
// Flattened rather than embedding AuthResult (which 4c uses): only
// Tokens was ever needed, and User here is the app's ALREADY-PROJECTED
// payload, not an *identity.User. That is amendment A2: the projection
// happens inside the hook where the app still holds its wide user row,
// so there is no narrow-then-re-widen round trip, no second store read,
// and no per-request cell for a boot-time-built struct to capture.
type FederationOutcome struct {
	// Tokens must be EMPTY on the link leg — the caller's existing
	// session stays valid, and a fresh mint would hand out an access
	// token on a flow that never re-authenticated anyone.
	Tokens identity.Tokens
	// User is the app's projected payload, emitted verbatim.
	User json.RawMessage
	// Redirect is trusted VERBATIM. tamper MUST NOT re-sanitize it —
	// see SanitizeRedirect's doc and amendment A5.
	Redirect string
	// Linked marks the link leg EXPLICITLY. Never inferred from empty
	// Tokens: that would make "the mint silently failed" and "this is a
	// link leg" indistinguishable, and they have opposite correct
	// responses.
	Linked bool
}

// FederationHooks are the app-policy seams.
type FederationHooks struct {
	// Registry resolves the provider registry for this request.
	// Returning (nil, nil) means "OIDC is not configured" => 404.
	// Required.
	Registry func(ctx context.Context, tenantID tenant.ID) (*oidc.ProviderRegistry, error)

	// OnFederatedExchange runs the entire post-verify tail: upsert ->
	// reconcile -> mint -> audit -> project -> redirect. It receives the
	// RESOLVED provider — never re-resolve it from OIDCVerified.ProviderID.
	//
	// The registry is not the cheap map read it looks like: it is a
	// TTL-cached read that falls through to a store list plus live
	// per-provider discovery, and a second lookup here would land AFTER
	// the IdP's single-use authorization code is burned, where a
	// rebuild failure 404s/500s a request that had already succeeded,
	// with no retry path. See amendment A9. Required.
	OnFederatedExchange func(ctx context.Context, p *oidc.Provider, v OIDCVerified) (FederationOutcome, error)

	// SanitizeRedirect gates the START leg's ?redirect= query param —
	// untrusted input from the browser. nil means deny-all-to-"/".
	//
	// TAMPER calls this exactly once, here, on that one param. The rule
	// is not "sanitize once globally" — it is:
	//
	//	sanitize every ATTACKER-CONTROLLED redirect input;
	//	never re-process a value the app already produced.
	//
	// So an app may well have its own call sites (Barista re-sanitizes
	// the state cookie's stored redirect inside its hook, and a SAML ACS
	// leg MUST sanitize an IdP-echoed RelayState — dropping that would
	// be an open redirect). What tamper must never do is apply this to
	// FederationOutcome.Redirect: that value is app-constructed (e.g.
	// "/account?linked=okta"), and a path-allowlist sanitizer truncates
	// at the first '?', silently dropping the query string with no error
	// anywhere. See amendment A5.
	SanitizeRedirect func(raw string) string

	// OnStepUpInitiated fires when a start leg carries step-up params.
	// One concrete callback rather than an event-sink interface: the app
	// shapes and stamps its own audit vocabulary, and tamper never
	// freezes an auth.* taxonomy it has no second consumer for
	// (amendment A3). Optional.
	OnStepUpInitiated func(ctx context.Context, callingUserID string, maxAge int64, acrValues []string)

	// CallingUserID resolves the audit actor on the start leg.
	// Anonymous starts return "". Optional; defaults to GetUserID.
	CallingUserID func(ctx context.Context) string
}

// FederationConfig carries the app's branding + policy.
type FederationConfig struct {
	// LandingPath is the SPA route the callback redirects to, carrying
	// the code/state in the fragment (e.g. "/auth/oidc/landing").
	// Required.
	LandingPath string
	// StateCookie is the state cookie's brand + policy.
	StateCookie StateCookieConfig
	// StateSecret signs the state cookie. Required.
	StateSecret []byte
	// StateIssuer is the signed cookie's iss claim. Required.
	StateIssuer string
	// Cookies is the refresh-cookie branding for the login leg.
	Cookies CookieConfig
	// MountPrefix is the auth route prefix ("/api/auth"). The refresh
	// cookie's Path IS this value — the CSRF fence derives by
	// construction rather than being separately settable.
	MountPrefix string
	// Now is the clock seam. Optional; defaults to time.Now.
	Now func() time.Time
}

// FederationRoutes is the OIDC federation surface. Construct with
// NewFederationRoutes; the app registers the methods.
type FederationRoutes struct {
	cfg   FederationConfig
	hooks FederationHooks
}

// NewFederationRoutes validates the config — at wiring time, never at
// request time.
func NewFederationRoutes(cfg FederationConfig, hooks FederationHooks) (*FederationRoutes, error) {
	if hooks.Registry == nil {
		return nil, errors.New("tamper/espresso: federation routes require a Registry hook")
	}
	if hooks.OnFederatedExchange == nil {
		return nil, errors.New("tamper/espresso: federation routes require an OnFederatedExchange hook")
	}
	if !strings.HasPrefix(cfg.LandingPath, "/") {
		return nil, errors.New(`tamper/espresso: LandingPath must start with "/"`)
	}
	if !strings.HasPrefix(cfg.MountPrefix, "/") || strings.HasSuffix(cfg.MountPrefix, "/") {
		return nil, errors.New(`tamper/espresso: MountPrefix must start with "/" and not end with one`)
	}
	if cfg.StateCookie.BaseName == "" {
		return nil, errors.New("tamper/espresso: state cookie base name is required (the app's brand)")
	}
	// __Host- requires Path=/ per the browser rule the prefix encodes.
	// A prefixed name on a non-root Path is silently DISCARDED at
	// Set-Cookie parse — in production only, since the dev tier ships
	// the bare name and keeps working. Reject it at wiring instead.
	if cfg.StateCookie.Secure && cfg.StateCookie.Path != "/" {
		return nil, errors.New(`tamper/espresso: a Secure state cookie uses the __Host- prefix, which requires Path="/"`)
	}
	// SameSite must be stated EXPLICITLY. The zero value resolves to Lax,
	// which is correct for OIDC and catastrophically wrong for SAML — and
	// a config written by copying the OIDC one omits the field, so the
	// wrong answer is what a copy-paste silently produces. That is
	// TD-FUNC-28's exact shape (SAML link + step-up dead on every
	// cross-domain IdP, login still working so nobody notices).
	//
	// Requiring the field costs one line per call site and makes the
	// silent-default trap unrepresentable — the same fence Secure/__Host-
	// already gets. If it were merely defaulted, the failure would be
	// production-only: dev runs HTTP where Lax works.
	if cfg.StateCookie.SameSite == 0 {
		return nil, errors.New("tamper/espresso: StateCookie.SameSite must be set explicitly — " +
			"the zero value silently means Lax, which breaks any flow whose IdP hands control back via cross-site POST (see TD-FUNC-28)")
	}
	// SameSite=None without Secure is rejected outright by browsers, so
	// the cookie would simply never be set — a silent, runtime-only
	// failure. Fail at wiring instead (TD-FUNC-28).
	if cfg.StateCookie.SameSite == http.SameSiteNoneMode && !cfg.StateCookie.Secure {
		return nil, errors.New("tamper/espresso: SameSite=None requires Secure — browsers reject the pair, and the cookie would silently never be set")
	}
	if len(cfg.StateSecret) == 0 {
		return nil, errors.New("tamper/espresso: state cookie signing secret is required")
	}
	if cfg.StateIssuer == "" {
		return nil, errors.New("tamper/espresso: state cookie issuer is required")
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
	return &FederationRoutes{cfg: cfg, hooks: hooks}, nil
}

// denyAllRedirect is the fail-closed default: an app that wires no
// allowlist gets every ?redirect= collapsed to the root rather than an
// open redirect.
func denyAllRedirect(string) string { return "/" }

// ReadStateCookie is the middleware the app mounts on the exchange
// route so the handler can read the state cookie through the context
// slot. Wiring it through this method (rather than the app naming the
// slot itself) is what stops the reader and the handler disagreeing —
// a drift whose only symptom is every exchange 401ing INVALID_STATE.
func (f *FederationRoutes) ReadStateCookie() func(http.Handler) http.Handler {
	return ReadNamedCookie(oidcStateCookieSlotName, f.cfg.StateCookie.Name())
}

// StateCookieName exposes the resolved cookie name for apps that wire
// their own reader.
func (f *FederationRoutes) StateCookieName() string { return f.cfg.StateCookie.Name() }

// provider resolves a provider id, producing the two 404 shapes.
func (f *FederationRoutes) provider(ctx context.Context, id string) (*oidc.Provider, error) {
	tid, ok := TenantFromContext(ctx)
	if !ok {
		// RequireTenant did not run. Fail closed and 404: a missing tenant
		// must be indistinguishable from a miss, never a distinct error that
		// tells a caller a tenant axis exists.
		return nil, espressofw.ErrNotFound("provider not found").WithCode("OIDC_PROVIDER_NOT_FOUND")
	}
	registry, err := f.hooks.Registry(ctx, tid)
	if err != nil {
		return nil, err
	}
	if registry == nil {
		return nil, espressofw.ErrNotFound("oidc is not configured").WithCode("OIDC_NOT_CONFIGURED")
	}
	p, err := registry.Get(id)
	if err != nil {
		return nil, espressofw.ErrNotFound("unknown oidc provider").WithCode("UNKNOWN_OIDC_PROVIDER")
	}
	return p, nil
}

// StartParams carries the start leg's query surface.
type StartParams struct {
	// Redirect is the RAW ?redirect= value — untrusted browser input.
	// It is the one thing SanitizeRedirect is applied to.
	Redirect string
	// MaxAge is ?max_age= in seconds (OIDC Core 1.0 §3.1.2.1).
	// Negative reads as absent.
	MaxAge int64
	// ACRValues is the RAW ?acr_values= param. Comma- or space-
	// separated; normalized here.
	ACRValues string
}

// Start handles GET {prefix}/oidc/start/{id}: sign a state cookie and
// redirect the browser to the IdP.
func (f *FederationRoutes) Start(ctx context.Context, providerID string, p StartParams) (Redirect, error) {
	prov, err := f.provider(ctx, providerID)
	if err != nil {
		return Redirect{}, err
	}

	maxAge := p.MaxAge
	if maxAge < 0 {
		maxAge = 0
	}
	acrValues := SplitACRValues(p.ACRValues)
	isStepUp := maxAge > 0 || len(acrValues) > 0
	callingUserID := f.hooks.CallingUserID(ctx)

	authURL, cookie, err := StartOIDCFlow(
		prov, f.cfg.StateSecret, f.cfg.StateIssuer, f.cfg.Now(), f.cfg.StateCookie,
		StartOptions{
			// The ONE SanitizeRedirect call site (A5).
			Redirect:      f.hooks.SanitizeRedirect(p.Redirect),
			MaxAge:        maxAge,
			ACRValues:     acrValues,
			Mode:          oidc.ModeLogin,
			CallingUserID: callingUserID,
		},
	)
	if err != nil {
		return Redirect{}, espressofw.ErrInternal("oidc start").Wrap(err)
	}

	// Best-effort: an audit miss must never block the redirect.
	if isStepUp && f.hooks.OnStepUpInitiated != nil {
		f.hooks.OnStepUpInitiated(ctx, callingUserID, maxAge, acrValues)
	}
	return Redirect{URL: authURL, Cookies: []*http.Cookie{cookie}}, nil
}

// LinkStart handles POST {prefix}/oidc/link-start/{id} behind the app's
// auth gate. Same signed-cookie shape as Start but mode=link + the
// caller's user id, so the exchange attaches the IdP identity to THIS
// user instead of provisioning a fresh one.
func (f *FederationRoutes) LinkStart(ctx context.Context, providerID, userID string) (espressofw.JSON[LinkStartRes], error) {
	prov, err := f.provider(ctx, providerID)
	if err != nil {
		return espressofw.JSON[LinkStartRes]{}, err
	}
	authURL, cookie, err := StartOIDCFlow(
		prov, f.cfg.StateSecret, f.cfg.StateIssuer, f.cfg.Now(), f.cfg.StateCookie,
		StartOptions{Mode: oidc.ModeLink, UserID: userID},
	)
	if err != nil {
		return espressofw.JSON[LinkStartRes]{}, espressofw.ErrInternal("oidc start").Wrap(err)
	}
	return espressofw.JSON[LinkStartRes]{
		StatusCode: http.StatusOK,
		Data:       LinkStartRes{AuthURL: authURL},
		Cookies:    []*http.Cookie{cookie},
	}, nil
}

// CallbackParams carries the IdP-returned query surface.
type CallbackParams struct {
	Code  string
	State string
	// Error is the IdP's rejection short-form (?error=).
	Error string
}

// Callback handles GET {prefix}/oidc/callback/{id}. The IdP redirects
// the browser here; this bounces it to the SPA landing route with the
// code + state in the URL FRAGMENT (never the query string — a
// fragment is not sent to servers, does not land in access logs, and
// is not carried on the Referer header).
//
// Emits no cookies on any path.
func (f *FederationRoutes) Callback(ctx context.Context, providerID string, p CallbackParams) (Redirect, error) {
	// Validate the provider exists before echoing its id into a
	// redirect.
	if _, err := f.provider(ctx, providerID); err != nil {
		return Redirect{}, err
	}
	if p.Error != "" {
		// The IdP's ?error= is attacker-influenceable, so it runs through
		// the SAME FragmentValue dropper as the success path — otherwise a
		// value like "denied&code=…" injects a sibling fragment parameter
		// into the landing page (TD-OIDC-FRAGMENT-ESCAPE, closed). Not a
		// session-forgery vector — an injected code/state still has to
		// survive the exchange's signed-state check, which an attacker
		// cannot forge — but the landing route parses these params, so the
		// error path must not bypass the defence the success path applies.
		return Redirect{URL: f.cfg.LandingPath + idpErrorFragment(p.Error, providerID)}, nil
	}
	if p.Code == "" || p.State == "" {
		return Redirect{URL: f.cfg.LandingPath + idpErrorFragment("missing_params", providerID)}, nil
	}
	return Redirect{URL: f.cfg.LandingPath + BuildLandingFragment(p.Code, p.State, providerID)}, nil
}

// idpErrorFragment builds the IdP-rejection landing fragment. Like
// BuildLandingFragment, every value runs through FragmentValue so a
// malicious IdP's ?error= cannot inject sibling fragment parameters into
// the landing page (TD-OIDC-FRAGMENT-ESCAPE). The '&'/'#'/'%' bytes that
// would open a new parameter are dropped, collapsing an injection attempt
// into the error value rather than a separate key. providerID is already
// validated (f.provider rejects unknown ids) but runs through the dropper
// too, for byte-parity with the success path.
func idpErrorFragment(errVal, providerID string) string {
	return "#error=" + FragmentValue(errVal) + "&provider=" + FragmentValue(providerID)
}

// BuildLandingFragment assembles the success fragment. Key names,
// their order, and the '&' separators are a wire contract with the
// SPA's landing route — it parses exactly these.
func BuildLandingFragment(code, state, providerID string) string {
	return "#code=" + FragmentValue(code) +
		"&state=" + FragmentValue(state) +
		"&provider=" + FragmentValue(providerID)
}

// FragmentValue strips the three bytes that would let a value break out
// of its fragment slot and inject sibling parameters.
//
// It is a DROPPER, not an escaper: it deletes '#', '&' and '%' and
// passes everything else through unchanged. It is deliberately NOT
// url.QueryEscape — the SPA reads these values raw, and percent-encoding
// them would change every code and state on the wire. It is not
// reversible; a value containing '%' is corrupted rather than encoded.
// That is acceptable because the inputs are IdP-issued base64url-ish
// tokens which do not contain any of the three.
func FragmentValue(s string) string {
	if !strings.ContainsAny(s, "#&%") {
		return s
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '#', '&', '%':
			continue
		}
		out = append(out, s[i])
	}
	return string(out)
}

// SplitACRValues parses an acr_values request param.
//
// Accepts comma-separated (the shape an SPA naturally sends, matching a
// STEP_UP_REQUIRED envelope) AND space-separated (the raw OIDC Core
// shape), so an operator pasting a URN list works either way. Trims
// whitespace and drops empty entries.
//
// Returns nil rather than an empty slice when nothing resolves: callers
// gate on len() == 0, and the state cookie's omitempty depends on nil.
//
// Exported because the SAML start leg needs the identical normalization
// for its AuthnContext class refs, and one implementation with no
// second copy is the point (a drifting duplicate is how these
// normalizers rot).
func SplitACRValues(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	// Normalise commas to spaces, then split on whitespace. Fields
	// handles every unicode space class and drops empties.
	fields := strings.Fields(strings.ReplaceAll(raw, ",", " "))
	if len(fields) == 0 {
		return nil
	}
	return fields
}

// refreshCookies mirrors AuthRoutes.refreshCookies: Path == MountPrefix
// by construction, empty when refresh issuance is off so no stray
// cookie ships.
func (f *FederationRoutes) refreshCookies(tokens identity.Tokens) []*http.Cookie {
	if tokens.Refresh == "" {
		return nil
	}
	return []*http.Cookie{{
		Name:     f.cfg.Cookies.Name,
		Value:    tokens.Refresh,
		Path:     f.cfg.MountPrefix,
		HttpOnly: true,
		Secure:   f.cfg.Cookies.Secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   f.cfg.Cookies.MaxAgeSeconds,
	}}
}

// Exchange handles POST {prefix}/oidc/exchange — the SPA posts back the
// code + state it read off the landing fragment.
//
// Mount the ReadStateCookie middleware on this route.
func (f *FederationRoutes) Exchange(ctx context.Context, req *espressofw.JSON[ExchangeReq]) (espressofw.JSON[ExchangeRes], error) {
	var zero espressofw.JSON[ExchangeRes]

	// Resolve the provider ONCE, before the exchange burns the code
	// (A9). This same pointer is handed to the hook.
	prov, err := f.provider(ctx, req.Data.ProviderID)
	if err != nil {
		return zero, err
	}

	cookieVal, ok := NamedCookieValue(ctx, oidcStateCookieSlotName)
	if !ok {
		return zero, espressofw.ErrUnauthorized("oidc state missing").WithCode("INVALID_STATE")
	}

	vres, err := VerifyOIDCCallback(ctx, prov, req.Data.Code, req.Data.State, cookieVal,
		f.cfg.StateSecret, f.cfg.StateIssuer, f.cfg.Now)
	if err != nil {
		return zero, mapFederationVerifyError(err)
	}

	// Mode dispatch. An empty mode reads as login so cookies signed
	// before the link flow existed still resolve during a rolling
	// deploy. These are 400s where the verify errors above are 401s —
	// see mapFederationVerifyError's doc.
	if vres.State.Mode == "" {
		vres.State.Mode = oidc.ModeLogin
	}
	switch vres.State.Mode {
	case oidc.ModeLink:
		// A link cookie with no user id cannot say whose account to
		// attach to. Guarded here so the hook may assume it.
		if vres.State.UserID == "" {
			return zero, espressofw.ErrBadRequest("link cookie missing user id").WithCode("INVALID_STATE")
		}
	case oidc.ModeLogin:
	default:
		return zero, espressofw.ErrBadRequest("unknown oidc state mode").WithCode("INVALID_STATE")
	}

	out, err := f.hooks.OnFederatedExchange(ctx, prov, vres)
	if err != nil {
		// NOTE: no clear-cookie here. Every error exit returns the zero
		// JSON[T], which structurally cannot carry Set-Cookie, so a
		// failed exchange leaves the state cookie in the browser. That
		// reproduces the proving app exactly (amendment A4); the cookie
		// is single-use against a code the IdP has already burned or
		// rejected, and expires on its own TTL. Clearing on error is a
		// wire change across every error path and ships as
		// TD-OIDC-CLEAR-ON-ERROR, not as a side effect of a lift.
		return zero, err
	}

	// Fail closed if the link leg minted. The hook is app code and can
	// regress; a link response carrying an access token would hand out
	// a session on a flow that never re-authenticated the user.
	if out.Linked && (out.Tokens.Access != "" || out.Tokens.Refresh != "") {
		return zero, espressofw.ErrInternal("tamper/espresso: link leg minted tokens")
	}

	// Cookie ORDER is wire surface: espresso writes Set-Cookie headers
	// in slice order, and the proving app ships refresh FIRST,
	// state-clear SECOND.
	var cookies []*http.Cookie
	if !out.Linked {
		cookies = f.refreshCookies(out.Tokens)
	}
	cookies = append(cookies, f.cfg.StateCookie.Clear())

	// Token is gated on Linked rather than read straight from
	// out.Tokens.Access, so even a hook that wrongly populated Tokens
	// on the link leg cannot leak one onto the wire.
	token := ""
	if !out.Linked {
		token = out.Tokens.Access
	}
	return espressofw.JSON[ExchangeRes]{
		StatusCode: http.StatusOK,
		Data: ExchangeRes{
			Token: token,
			User:  out.User,
			// Verbatim — never re-sanitized (A5).
			Redirect: out.Redirect,
		},
		Cookies: cookies,
	}, nil
}
