package saml

import (
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
// provider (signature via the IdP metadata cert, timing under the
// process clock-skew pin, audience/destination against the SP
// config) and returns the tamper-owned view.
//
// possibleRequestIDs is the InResponseTo allow-list. nil is
// NORMALIZED to a non-nil empty slice: the two diverge inside the
// library's request-ID hooks (an operator hook cannot distinguish
// "empty allow-list" from "the SP forgot to pass one" when handed
// nil), a walk-scarred foot-gun this API makes impossible rather
// than documents.
func (p *Provider) ParseAssertion(samlResponse, relayState string, possibleRequestIDs []string) (*ParsedAssertion, error) {
	if p == nil || p.SP == nil {
		return nil, fmt.Errorf("%w: provider service provider is nil", ErrAssertionInvalid)
	}
	if possibleRequestIDs == nil {
		possibleRequestIDs = []string{}
	}
	req := buildPostFormRequest(p.SP.AcsURL.String(), samlResponse, relayState)
	assertion, err := p.SP.ParseResponse(req, possibleRequestIDs)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAssertionInvalid, describeParseError(err))
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
// preceding AuthnRequest. The defining signature is an empty
// InResponseTo on every SubjectConfirmationData entry — SP-initiated
// flows always echo the AuthnRequest ID, so a missing value means the
// IdP started the conversation (portal tiles, bookmarked links). An
// assertion with no SubjectConfirmation at all reads as
// IdP-initiated so the policy gate still applies.
func (pa *ParsedAssertion) IdPInitiated() bool {
	a := pa.raw
	if a == nil || a.Subject == nil {
		return false
	}
	confs := a.Subject.SubjectConfirmations
	if len(confs) == 0 {
		return true
	}
	for _, c := range confs {
		if c.SubjectConfirmationData != nil && c.SubjectConfirmationData.InResponseTo != "" {
			return false
		}
	}
	return true
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
