// Home-realm routing for the Tamper Espresso adapter.
//
// StartLogin answers the question a login form asks first: given an
// email address, does this user sign in with a password, or should the
// browser be sent to their company's IdP?
//
// TREAT THIS ENDPOINT AS HOSTILE. It is unauthenticated by necessity —
// the caller has not proven anything yet, that is the point — and it
// takes an attacker-chosen email. Everything below exists because an
// answer that varies by whether a domain is a customer turns it into a
// tenant-enumeration oracle: type a competitor's domain, watch the
// response, learn who has bought SSO and how far along their rollout is.

package espresso

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/suryakencana007/tamper/identity"
	"github.com/suryakencana007/tamper/tenant"
)

// ErrThrottled is returned when the supplied Throttle refused the
// request. The caller renders its own 429; StartLoginResult.RetryAfter
// carries the hint.
var ErrThrottled = errors.New("espresso: start-login throttled")

// Throttle is the rate-limit port.
//
// Defined here rather than waiting for 7k-1 because this endpoint needs
// it NOW: it is unauthenticated, it takes an arbitrary email, and it
// touches a store on every call. 7k-1 supplies the token-bucket
// implementation and wires the remaining surfaces; this is the interface
// they will share.
//
// Keys are CALLER-COMPOSED. tamper does not decide whether email, IP,
// domain or tenant is the right dimension to limit on — that is
// deployment-dependent, and a framework that picked one would be wrong
// for half its users.
type Throttle interface {
	// Allow reports whether the action may proceed and, when it may not,
	// how long until it may.
	Allow(ctx context.Context, key string) (ok bool, retryAfter time.Duration)
}

// Resolver is the port StartLogin resolves domains through.
//
// An ALIAS, not a defined type, so any tenant.DomainStore an application
// already has satisfies it without a conversion — the same aliasing
// discipline TAMPER-DESIGN's playbook step 3 requires of façade types,
// for the same reason: a defined type here would silently fail to accept
// the very implementations it exists to accept.
type Resolver = tenant.DomainStore

// StartLoginResult is what the caller acts on.
//
// Its ZERO VALUE is the fallback answer, and that is deliberate: every
// path that does not positively identify a verified, IdP-bound domain
// returns the zero value, so a forgotten branch falls back to password
// rather than leaking a tenant.
type StartLoginResult struct {
	// TenantID is the resolved tenant, or "" when none was resolved.
	//
	// It is populated ONLY on a positive match. A caller must not echo
	// it to an unauthenticated client — see the doc on StartLogin.
	TenantID string

	// ProviderID names the IdP to redirect to; "" means fall back to the
	// password or invitation path.
	ProviderID string

	// EnforceSSO reports that this domain must use its IdP.
	//
	// tamper has no separate enforce-SSO flag, and this is derived
	// rather than stored: a VERIFIED domain with an IdP bound to it IS
	// the enforcement signal. A tenant that wants password login
	// alongside SSO leaves the domain unbound and routes those users by
	// another means. If a deployment needs the two decisions separated,
	// that is a field on the app's own domain row plus its own branch
	// after this call — not a guess tamper makes for it.
	EnforceSSO bool

	// RetryAfter is set only alongside ErrThrottled.
	RetryAfter time.Duration
}

// defaultStartLoginFloor is the constant-time floor every call is padded
// to. Chosen to sit comfortably above the spread between a store hit, a
// store miss, and the no-store-call paths, without being a latency
// people notice on a login form.
const defaultStartLoginFloor = 50 * time.Millisecond

type startLoginConfig struct {
	tenants  tenant.Store
	throttle Throttle
	floor    time.Duration
	now      func() time.Time
	sleep    func(time.Duration)
	key      func(email string) string
}

// StartLoginOption configures StartLogin.
type StartLoginOption func(*startLoginConfig)

// WithStartLoginTenants supplies the tenant store so a SUSPENDED tenant
// can be treated exactly like an unknown one.
//
// Optional. Without it StartLogin cannot know a tenant's status, and the
// application becomes responsible for not returning rows for suspended
// tenants from its DomainStore. Supplying it is strongly preferred: the
// check then lives on the path an attacker actually uses.
func WithStartLoginTenants(s tenant.Store) StartLoginOption {
	return func(c *startLoginConfig) { c.tenants = s }
}

// WithStartLoginThrottle installs the rate limiter.
//
// NIL IS UNSAFE IN PRODUCTION and is allowed only so this slice can ship
// before 7k-1. Without a throttle, this endpoint will happily answer an
// unauthenticated caller as fast as the store can be read, which is a
// dictionary attack against your customer list — the timing floor below
// makes each guess cost the same, not cheap.
func WithStartLoginThrottle(t Throttle) StartLoginOption {
	return func(c *startLoginConfig) { c.throttle = t }
}

// WithStartLoginFloor overrides the constant-time floor. Zero disables
// it, which re-opens the timing oracle — do that only in tests.
func WithStartLoginFloor(d time.Duration) StartLoginOption {
	return func(c *startLoginConfig) { c.floor = d }
}

// WithStartLoginThrottleKey overrides how the throttle key is composed
// from the email. The default keys on the DOMAIN, not the address,
// because the thing being enumerated is domains — keying on the full
// address would let an attacker walk a domain's namespace one fresh
// local-part at a time without ever tripping the limit.
func WithStartLoginThrottleKey(fn func(email string) string) StartLoginOption {
	return func(c *startLoginConfig) {
		if fn != nil {
			c.key = fn
		}
	}
}

// WithStartLoginClock injects the clock and sleep used by the timing
// floor. Test seam only: it lets a test assert the floor was applied
// without spending real time, so the suite has no wall-clock dependence.
func WithStartLoginClock(now func() time.Time, sleep func(time.Duration)) StartLoginOption {
	return func(c *startLoginConfig) {
		if now != nil {
			c.now = now
		}
		if sleep != nil {
			c.sleep = sleep
		}
	}
}

// StartLogin resolves an email's domain to a tenant + IdP, or signals the
// password/invitation fallback.
//
// WHAT THE CALLER MAY DO WITH THE RESULT. On a match, redirect to the
// named provider. On a fallback, render the password form. What it must
// NOT do is echo TenantID, a tenant name, or a provider display name to
// an unauthenticated client — the result carries the tenant because the
// caller needs it server-side to build the redirect, not because it is
// safe to show. This function guarantees the two SHAPES are identical;
// only the caller can throw that away.
//
// EVERY non-match returns the ZERO result and a NIL error: unknown
// domain, unverified claim, public email domain, suspended tenant, a
// domain with no IdP bound. They are one answer because distinguishing
// them is the oracle. A malformed email is the single exception, and it
// is the caller's own input error rather than a fact about any tenant.
//
// TIMING. Every path is padded to a constant floor, including the error
// paths, because an early return is itself a signal. See the deferred
// pad below.
func StartLogin(ctx context.Context, r Resolver, email string, opts ...StartLoginOption) (StartLoginResult, error) {
	cfg := startLoginConfig{
		floor: defaultStartLoginFloor,
		now:   time.Now,
		sleep: time.Sleep,
		key:   defaultThrottleKey,
	}
	for _, o := range opts {
		o(&cfg)
	}

	// The floor is applied on EVERY return path, deliberately including
	// the malformed-email and throttled ones. An early return that
	// skipped the pad would make "this address is malformed" and "this
	// domain is not a customer" separable by latency, and the second is
	// the fact worth hiding. A defer is what makes that structural
	// rather than something each branch has to remember.
	start := cfg.now()
	defer func() {
		if cfg.floor <= 0 {
			return
		}
		if elapsed := cfg.now().Sub(start); elapsed < cfg.floor {
			cfg.sleep(cfg.floor - elapsed)
		}
	}()

	if cfg.throttle != nil {
		if ok, retryAfter := cfg.throttle.Allow(ctx, cfg.key(email)); !ok {
			return StartLoginResult{RetryAfter: retryAfter}, ErrThrottled
		}
	}

	// Normalisation happens HERE because this is the edge. tenant's
	// package contract is that it rejects unnormalised domains rather
	// than coercing them (ErrDomainNotNormalised), and the right place to
	// do the coercing once, with the original input in hand, is the
	// transport boundary.
	normalised, err := identity.NormaliseEmail(email)
	if err != nil {
		return StartLoginResult{}, err
	}
	at := strings.LastIndex(normalised, "@")
	if at < 0 || at == len(normalised)-1 {
		return StartLoginResult{}, identity.ErrInvalidEmail
	}
	domain := normalised[at+1:]

	// tenant.ResolveDomain owns the verification, public-domain and
	// normalisation gates. They are NOT re-implemented here — one
	// resolver path, so there is one place to get it wrong and one place
	// the mutation proofs point at.
	rec, err := tenant.ResolveDomain(ctx, r, domain)
	if err != nil {
		if errors.Is(err, tenant.ErrNotFound) || errors.Is(err, tenant.ErrDomainNotNormalised) {
			// Not a customer, not verified, or a public provider — one
			// answer, and it is the fallback.
			return StartLoginResult{}, nil
		}
		// A degraded store is NOT a fallback. Returning the zero result
		// here would silently route a tenant's users to a password form
		// their SSO policy forbids, which is a policy bypass caused by an
		// outage (§6.2: no error return may be read as allow).
		return StartLoginResult{}, err
	}

	// A suspended tenant behaves exactly like an unknown one. The check
	// is here, on the path an attacker uses, rather than only wherever
	// the app happens to look at Status.
	if cfg.tenants != nil {
		desc, terr := cfg.tenants.ByID(ctx, rec.TenantID)
		if terr != nil {
			if errors.Is(terr, tenant.ErrNotFound) {
				return StartLoginResult{}, nil
			}
			return StartLoginResult{}, terr
		}
		if desc.Status != tenant.StatusActive {
			return StartLoginResult{}, nil
		}
	}

	// BoundProviderID, not the raw field: it returns "" for an unverified
	// claim regardless of what is stored, so this cannot bind an IdP to
	// an unproven domain even if ResolveDomain's gate were bypassed.
	provider := rec.BoundProviderID()
	if provider == "" {
		// A verified domain with no IdP is a real, legitimate answer, and
		// it is the same answer as "not a customer": use the password
		// path. Returning the tenant here would disclose membership for
		// no benefit — the caller does not need a tenant to render a
		// password form.
		return StartLoginResult{}, nil
	}

	return StartLoginResult{
		TenantID:   rec.TenantID,
		ProviderID: provider,
		EnforceSSO: true,
	}, nil
}

// defaultThrottleKey keys on the email's DOMAIN. See
// WithStartLoginThrottleKey for why the address would be the wrong
// dimension.
func defaultThrottleKey(email string) string {
	lowered := strings.ToLower(strings.TrimSpace(email))
	if at := strings.LastIndex(lowered, "@"); at >= 0 {
		return "startlogin:" + lowered[at+1:]
	}
	return "startlogin:" + lowered
}
