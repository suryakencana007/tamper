package saml

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	crewjamsaml "github.com/crewjam/saml"
)

// ErrAssertionInvalid wraps every ParseAssertion failure (signature,
// timing, audience, schema). Apps collapse it to a single generic
// 4xx — the parse error must never become a validation oracle.
var ErrAssertionInvalid = errors.New("saml: assertion invalid")

// ParsedAssertion is the tamper-owned view of a validated SAML
// assertion — everything an app's ACS handler consumes, with the
// library type kept private so the transport layer never imports the
// SAML library.
type ParsedAssertion struct {
	raw *crewjamsaml.Assertion
}

// ParseAssertion validates a SAML response POST body against this
// provider and returns the tamper-owned view. It runs, in order:
//
//  1. crewjam signature + timing + audience/destination validation
//     (p.SP.ParseResponse).
//  2. Layer 1 correlation on SIGNED material (correlate): rejects a
//     captured assertion presented with no flow, and enforces
//     AllowIDPInitiated. No I/O — fail-closed by construction.
//  3. Layer 2 single-use ledger (p.replay.ConsumeAssertion): for the
//     genuine IdP-initiated class this is the only replay defence.
//
// expectedRequestID is the AuthnRequest ID THIS flow issued, or "" when it
// issued none (a missing/expired state cookie, or a genuine IdP-initiated
// flow). It is a single value, not the former []string allow-list — the
// nil/empty ambiguity of that slice was the bypass: an empty list read as
// "nothing to check" rather than "no request issued", so a replay with no
// cookie sailed through.
//
// ctx flows to the ledger (a real store call on the request path).
//
// Failure semantics: correlation errors return their own sentinels
// (ErrUncorrelated / ErrIdPInitiatedDisabled / ErrNoSubjectConfirmation).
// A ledger outage returns ErrReplayStoreUnavailable — FAIL CLOSED, mapped
// to 503, never a silent accept. A consumed assertion returns
// ErrAssertionReplayed. Every other parse failure stays wrapped in the
// generic ErrAssertionInvalid so the signature/timing family cannot become
// an oracle.
func (p *Provider) ParseAssertion(ctx context.Context, samlResponse, relayState, expectedRequestID string) (*ParsedAssertion, error) {
	if p == nil || p.SP == nil {
		return nil, fmt.Errorf("%w: provider service provider is nil", ErrAssertionInvalid)
	}
	if p.replay == nil {
		// A Provider built through BuildProvider cannot reach here with a
		// nil ledger (BuildProvider refuses it). This guards a
		// hand-constructed literal — fail closed, never a silent accept.
		return nil, fmt.Errorf("%w: provider %q has no assertion replay store", ErrReplayStoreUnavailable, p.Config.ID)
	}

	// crewjam still gets the expected id as its 1-element allow-list so its
	// own (unsigned, advisory) checks behave; the authoritative check is
	// correlate() below, on signed bytes.
	possible := []string{}
	if expectedRequestID != "" {
		possible = []string{expectedRequestID}
	}
	req := buildPostFormRequest(p.SP.AcsURL.String(), samlResponse, relayState)
	assertion, err := p.SP.ParseResponse(req, possible)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAssertionInvalid, describeParseError(err))
	}

	// Layer 1: correlation on signed material. Rejects the captured-
	// assertion replay and enforces AllowIDPInitiated. Runs before the
	// ledger so a policy-rejected assertion never burns a ledger row.
	if err := correlate(assertion, expectedRequestID, p.Config.AllowIDPInitiated); err != nil {
		return nil, err
	}

	// Layer 2: single-use ledger. Reached only by assertions Layer 1
	// accepted. Consumed BEFORE the *ParsedAssertion escapes, so no caller
	// can reach the app hook (token mint, identity link) on a second copy.
	key, err := assertionReplayKey(p.Config.ID, assertion)
	if err != nil {
		return nil, err // unkeyable is not fresh — fail closed
	}
	fresh, err := p.replay.ConsumeAssertion(ctx, key, replayExpiry(assertion, time.Now()))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrReplayStoreUnavailable, err)
	}
	if !fresh {
		return nil, fmt.Errorf("%w: provider %q assertion %q", ErrAssertionReplayed, p.Config.ID, assertion.ID)
	}
	return &ParsedAssertion{raw: assertion}, nil
}

// describeParseError digs the real cause out of crewjam's error.
//
// crewjam wraps EVERY parse failure — bad signature, expired assertion,
// wrong audience, request-ID mismatch — in *InvalidResponseError, whose
// Error() is the fixed string "Authentication failed". The actual cause
// lives only in the unexported-by-convention PrivateErr field. Rendering
// the wrapper with %v therefore collapses every distinct failure into
// one useless line.
//
// That is not hypothetical: it is precisely why TD-FUNC-26 survived in
// the field. An operator who set allowIdPInitiated=false got a total
// SAML outage whose only log evidence was "Authentication failed" —
// nothing pointing at InResponseTo, the empty allow-list, or the config
// flag that caused it. The first draft of the repro test made the same
// mistake and PASSED against the live bug, because from outside every
// failure looks identical.
//
// The blanket "Authentication failed" exists to avoid leaking detail to
// the BROWSER. That reasoning does not extend to the server's own log:
// this value is only ever wrapped into ErrAssertionInvalid, which
// handlers map to a generic SAML_ASSERTION_INVALID before responding.
// The caller still gets nothing; the operator gets a cause.
func describeParseError(err error) error {
	var ire *crewjamsaml.InvalidResponseError
	if errors.As(err, &ire) && ire.PrivateErr != nil {
		return ire.PrivateErr
	}
	return err
}

// buildPostFormRequest stitches the form-extracted SAMLResponse +
// RelayState onto an *http.Request whose URL matches the SP's ACS
// URL — the library's parse path expects req.PostForm + req.URL to be
// populated, and typed form extractors have already consumed the
// original request body by the time the handler runs.
func buildPostFormRequest(acsURL, samlResponse, relayState string) *http.Request {
	body := url.Values{}
	body.Set("SAMLResponse", samlResponse)
	if relayState != "" {
		body.Set("RelayState", relayState)
	}
	r := httptest.NewRequest(http.MethodPost, acsURL, io.NopCloser(strings.NewReader(body.Encode())))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// ParseResponse calls r.ParseForm() internally; pre-populating
	// PostForm is also accepted.
	r.PostForm = body
	r.Form = body
	return r
}

// Attribute returns the first value of the named SAML attribute
// (Name or FriendlyName match), "" when absent.
func (pa *ParsedAssertion) Attribute(name string) string {
	return AttributeValue(pa.raw, name)
}

// AttributeValues returns every value of the named SAML attribute,
// handling both the multi-element and comma-separated emission
// shapes. Never nil.
func (pa *ParsedAssertion) AttributeValues(name string) []string {
	return AttributeValues(pa.raw, name)
}

// NameID returns the assertion Subject's NameID value, "" when the
// IdP didn't emit one (the app decides its fallback key).
func (pa *ParsedAssertion) NameID() string {
	return SubjectNameID(pa.raw)
}

// IdPInitiated reports whether the assertion was delivered without a
// preceding AuthnRequest — an empty (signed) InResponseTo. SP-initiated
// flows always echo the AuthnRequest ID, so a missing value means the IdP
// started the conversation (portal tiles, bookmarked links).
//
// Retained as an exported audit / defence-in-depth accessor. Note the
// authoritative policy decision now lives in ParseAssertion via correlate()
// — a consumer no longer has to call this gate to enforce
// AllowIDPInitiated; the parse already did. It reads the same signed
// SubjectConfirmationData as correlate() (via signedInResponseTo), so the
// two never disagree. An assertion with no SubjectConfirmation reports true
// here (nothing answered a request), but such an assertion is REJECTED by
// ParseAssertion with ErrNoSubjectConfirmation, so it never reaches an app
// hook that would consult this.
func (pa *ParsedAssertion) IdPInitiated() bool {
	got, err := signedInResponseTo(pa.raw)
	if err != nil {
		// No SubjectConfirmation — nothing echoes a request.
		return true
	}
	return got == ""
}

// AuthnTime returns the assertion's authentication instant as Unix
// seconds — AuthnInstant from the first AuthnStatement, falling back
// to the assertion's IssueInstant, finally to nowFn() so a token
// minted from it never carries auth_time=0 (which a fresh-auth gate
// would reject as infinitely stale).
func (pa *ParsedAssertion) AuthnTime(nowFn func() time.Time) int64 {
	a := pa.raw
	if a != nil && len(a.AuthnStatements) > 0 {
		if t := a.AuthnStatements[0].AuthnInstant; !t.IsZero() {
			return t.Unix()
		}
	}
	if a != nil && !a.IssueInstant.IsZero() {
		return a.IssueInstant.Unix()
	}
	return nowFn().Unix()
}

// ACR returns the AuthnContextClassRef from the first AuthnStatement,
// or fallback when the assertion doesn't carry one (most IdPs emit at
// least the Password URN; the fallback is the app's choice).
func (pa *ParsedAssertion) ACR(fallback string) string {
	a := pa.raw
	if a != nil && len(a.AuthnStatements) > 0 {
		if ref := a.AuthnStatements[0].AuthnContext.AuthnContextClassRef; ref != nil {
			if v := strings.TrimSpace(ref.Value); v != "" {
				return v
			}
		}
	}
	return fallback
}
