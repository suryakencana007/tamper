package oauth2social

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/suryakencana007/tamper/oidc"
	"golang.org/x/oauth2"
)

// maxUserinfoBytes caps the userinfo response read.
//
// The body is attacker-influenced in the sense that a compromised or
// hostile provider controls it entirely, and json.Decode on an
// unbounded reader is a memory-exhaustion primitive. 1 MiB is orders of
// magnitude above any real identity document.
const maxUserinfoBytes = 1 << 20

// FetchIdentity spends the access token on the userinfo endpoint and
// maps the response onto [oidc.Claims].
//
// The returned value is the SAME type the OIDC path produces, so a
// consuming application's provisioning / veto / linking code is
// protocol-blind — see the package doc for why that matters.
//
// Order of operations is deliberate: the subject is resolved first
// (without it there is no account key and nothing else matters), then
// email presence, then verification. Each failure is a distinct
// sentinel so a caller can tell "this provider gave us nothing usable"
// from "this user needs to verify their address" — the second is
// recoverable by the user, the first never is.
func (p *Provider) FetchIdentity(ctx context.Context, token *oauth2.Token) (*oidc.Claims, error) {
	if p == nil {
		return nil, fmt.Errorf("%w: nil provider", ErrConfig)
	}
	if token == nil || token.AccessToken == "" {
		return nil, fmt.Errorf("%w: no access token to present", ErrUserinfo)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.Config.UserinfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %v", ErrUserinfo, err)
	}
	req.Header.Set("Accept", "application/json")
	// The oauth2 client attaches the bearer token and honours the
	// context deadline.
	res, err := p.OAuth2.Client(ctx, token).Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUserinfo, err)
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		// Body deliberately not echoed: it is provider-controlled and
		// may carry the token back at us in an error message.
		return nil, fmt.Errorf("%w: userinfo returned %d", ErrUserinfo, res.StatusCode)
	}

	raw, err := decodeUserinfo(io.LimitReader(res.Body, maxUserinfoBytes))
	if err != nil {
		return nil, err
	}
	return p.claimsFromUserinfo(raw)
}

// decodeUserinfo parses a userinfo document with NUMBERS PRESERVED AS
// TEXT (json.Number) rather than float64.
//
// This is not a style preference. encoding/json decodes every number
// into float64 by default, and float64 carries 53 bits of mantissa, so
// any integer above 2^53 (~9.0e15) is rounded to the nearest
// representable value. A Discord snowflake is a full 64-bit integer:
// 80351110224678912 decoded as float64 and rendered back reads
// 80351110224678910 — a DIFFERENT account key, silently. The account
// would still be created and still work; it would simply not be the
// same account on the next sign-in if the provider ever changed the
// JSON type, and two distinct users whose ids round to the same value
// would collide outright.
//
// Discord happens to send its snowflake as a string today, which masks
// the problem entirely. That is exactly why this is worth pinning: the
// package accepts numeric ids from other providers, and the failure is
// invisible in every test that uses a small id.
func decodeUserinfo(r io.Reader) (map[string]any, error) {
	dec := json.NewDecoder(r)
	dec.UseNumber()
	var raw map[string]any
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("%w: decode: %v", ErrUserinfo, err)
	}
	return raw, nil
}

// claimsFromUserinfo is the pure mapping half, split out so the fences
// are testable without an HTTP round trip.
func (p *Provider) claimsFromUserinfo(raw map[string]any) (*oidc.Claims, error) {
	cm := p.Config.ClaimMap

	sub := stringField(raw, cm.Subject)
	if sub == "" {
		return nil, fmt.Errorf("%w: provider %q: field %q", ErrNoSubject, p.Config.ID, cm.Subject)
	}

	email := strings.TrimSpace(stringField(raw, cm.Email))
	if email == "" && cm.RequireEmail {
		return nil, fmt.Errorf("%w: provider %q", ErrEmailRequired, p.Config.ID)
	}

	// An absent EmailVerified mapping reads as NOT verified. Construction
	// already refuses that combined with RejectUnverifiedEmail, so this
	// is the honest default for a provider that simply has no flag.
	verified := boolField(raw, cm.EmailVerified)
	if email != "" && cm.RejectUnverifiedEmail && !verified {
		return nil, fmt.Errorf("%w: provider %q", ErrEmailUnverified, p.Config.ID)
	}

	return &oidc.Claims{
		Sub:               sub,
		Email:             email,
		EmailVerified:     verified,
		Name:              stringField(raw, cm.Name),
		PreferredUsername: stringField(raw, cm.Username),
		// Raw carries the whole document forward exactly as the OIDC
		// path does, so a group/role mapper reading a configurable
		// claim name works identically across protocols.
		Raw: raw,
	}, nil
}

// stringField reads a field leniently as a string.
//
// Numbers are accepted and formatted because providers disagree about
// the JSON type of an id: Discord sends its snowflake as a string,
// GitHub sends its id as a number. Both are stable opaque identifiers,
// which is the only property the account key requires. Floats are
// rendered without exponent notation so a large id never becomes
// "1.234e+18" and silently changes the account key.
func stringField(raw map[string]any, field string) string {
	if field == "" {
		return ""
	}
	v, ok := raw[field]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		// The decoder path: the literal text as sent, exact at any
		// magnitude. This is what real userinfo produces.
		return t.String()
	case float64:
		// Only reachable when a caller hands claimsFromUserinfo a
		// hand-built map (tests, or an app pre-parsing its own JSON).
		// Formatted without exponent notation so it is at least
		// readable, but note it may ALREADY have lost precision before
		// arriving here -- see decodeUserinfo.
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	default:
		return ""
	}
}

// boolField reads a verification-style flag.
//
// Anything that is not a genuine true reads as FALSE — including a
// missing field, a null, and the strings providers sometimes send. This
// direction is not arbitrary: the only consumer is the
// verified-email fence, so an unparseable value must fail closed.
func boolField(raw map[string]any, field string) bool {
	if field == "" {
		return false
	}
	switch t := raw[field].(type) {
	case bool:
		return t
	case string:
		// Some providers stringify booleans. Parse, but only "true"
		// and friends count; anything else stays false.
		b, err := strconv.ParseBool(strings.TrimSpace(t))
		return err == nil && b
	default:
		return false
	}
}
