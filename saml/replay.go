package saml

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	crewjamsaml "github.com/crewjam/saml"
)

// This file adds SAML assertion replay defence in two layers, both
// enforced INSIDE ParseAssertion so no caller can forget them:
//
//   Layer 1 — correlation (stateless). Reads the InResponseTo from the
//   SIGNED SubjectConfirmationData and rejects the one quadrant that has
//   no legitimate producer: "this flow issued no AuthnRequest, yet the
//   assertion answers one." That is the captured-assertion replay — an
//   attacker who POSTs a signed SAMLResponse to the ACS with no state
//   cookie. Fail-closed by construction: no I/O in the decision, so no
//   store-down coupling and no replica coupling. Correlation also finally
//   ENFORCES AllowIDPInitiated, the knob the package has always threaded
//   and never read.
//
//   Layer 2 — a single-use ledger (AssertionReplayStore). The genuine
//   IdP-initiated assertion has nothing to correlate against (no
//   InResponseTo, no nonce, no PKCE), so for that class the ledger is the
//   ONLY replay defence. One atomic compare-and-swap per assertion.
//
// Correlation runs before the ledger: it is cheap, deterministic, and
// never burns a ledger row on an assertion policy will reject anyway.

// ---- Layer 1 (stateless correlation) sentinels ----

// ErrUncorrelated is returned when the signed assertion does not answer
// the AuthnRequest this flow issued — it answers a different one, answers
// none when we issued one, or (the captured-assertion replay) answers one
// when we issued none. Handlers map to 400; it is not a validation oracle
// (producing it requires already holding a valid IdP-signed assertion).
var ErrUncorrelated = errors.New("saml: assertion does not answer this flow's AuthnRequest")

// ErrIdPInitiatedDisabled is returned when a genuine IdP-initiated
// assertion (answers no request, and this flow issued none) arrives at a
// provider configured AllowIDPInitiated=false. This is the framework
// enforcing the policy knob directly, rather than leaving each consumer to
// re-implement the gate. Handlers map to 400.
var ErrIdPInitiatedDisabled = errors.New("saml: idp-initiated sso is disabled for this provider")

// ErrNoSubjectConfirmation is returned when a parsed assertion carries no
// <SubjectConfirmation>. Defence in depth: crewjam's Recipient and
// NotOnOrAfter ACS-binding checks run inside the SubjectConfirmation loop,
// so an assertion that reached correlation with zero confirmations would
// have skipped those bindings. Handlers map to 400.
var ErrNoSubjectConfirmation = errors.New("saml: assertion carries no subject confirmation")

// ---- Layer 2 (ledger) sentinels ----

// ErrAssertionReplayed is returned when the ledger reports this assertion
// was already consumed. Distinct from ErrUncorrelated on purpose: the
// assertion is cryptographically perfect and correlation-clean; the SECOND
// presentation is the problem. Handlers map to 400. Not an oracle for the
// same reason as ErrUncorrelated.
var ErrAssertionReplayed = errors.New("saml: assertion already consumed")

// ErrReplayStoreUnavailable wraps a failure of the ledger itself.
// Deliberately NOT folded into any 4xx sentinel — a store outage is the
// SP's problem, not the caller's, and a fail-open control whose off-switch
// is "make the store slow" is not a control. Handlers map to 503.
var ErrReplayStoreUnavailable = errors.New("saml: assertion replay store unavailable")

// AssertionReplayStore is the single-use ledger the SAML substrate drives
// once per assertion, after signature and timing have passed. It has ONE
// method, an atomic compare-and-swap — deliberately not a Seen()/Mark()
// pair, which is a time-of-check/time-of-use race (tamper already shipped
// exactly that class of bug in identity refresh-token rotation).
//
// The app implements it over shared storage. A single-process reference
// implementation (MemAssertionReplayStore) ships for tests and
// single-replica deployments; NoReplayDefence is the explicit opt-out.
type AssertionReplayStore interface {
	// ConsumeAssertion atomically records key and reports whether THIS
	// call was the one that recorded it:
	//
	//   (true,  nil) — fresh. Proceed. Exactly one concurrent caller wins.
	//   (false, nil) — already consumed. Reject as a replay.
	//   (_,     err) — the store failed. The caller MUST ignore the bool
	//                  and fail closed (reject with ErrReplayStoreUnavailable).
	//
	// The zero return of a broken implementation is (false, nil) = "replay"
	// = reject, so a half-written implementation fails CLOSED. That decided
	// the signature: the inverse ("fresh unless told otherwise") would fail
	// open on a bug.
	//
	// key is opaque and fixed-width (64 hex chars); implementations MUST
	// treat it as a blob and MUST NOT parse it. Implement as a single
	// atomic statement — e.g. INSERT ... ON CONFLICT DO NOTHING and report
	// rows-affected == 1. expiresAt is the instant after which no process
	// will accept this assertion again, so the row may be garbage-collected;
	// GC is the app's existing infrastructure, not a method on this port.
	//
	// ConsumeAssertion is reached only after crewjam has verified the
	// signature and timing, so the ledger cannot be flooded without valid
	// IdP-signed material.
	ConsumeAssertion(ctx context.Context, key string, expiresAt time.Time) (fresh bool, err error)
}

// NoReplayDefence is the explicit, greppable opt-out: every assertion is
// reported fresh, forever. BuildProvider refuses a nil store, so the only
// way to run the SAML substrate without a ledger is to name this type in
// your wiring — where it shows up in review and in `grep NoReplayDefence`.
//
// Safe ONLY when every provider runs AllowIDPInitiated=false: Layer 1
// correlation then covers the whole surface with no state, because the
// IdP-initiated class (the only one that needs the ledger) is rejected
// outright. With AllowIDPInitiated=true this reopens the ~90s
// IdP-initiated replay window.
type NoReplayDefence struct{}

var _ AssertionReplayStore = NoReplayDefence{}

// ConsumeAssertion always reports fresh. See the type doc for when this is
// safe.
func (NoReplayDefence) ConsumeAssertion(context.Context, string, time.Time) (bool, error) {
	return true, nil
}

// assertionReplayKey derives the opaque ledger key from
// (providerID, issuer, assertionID). Kept unexported and crewjam-typed so
// what the ledger keys on can evolve without touching the port. The 0x00
// separators prevent boundary collisions such as ("ab","c") vs ("a","bc").
// A missing assertion ID is a hard error, never a "fresh" — an untrackable
// assertion must not be waved through.
func assertionReplayKey(providerID string, a *crewjamsaml.Assertion) (string, error) {
	if a == nil {
		return "", fmt.Errorf("%w: nil assertion cannot be tracked for replay", ErrAssertionInvalid)
	}
	id := strings.TrimSpace(a.ID)
	if id == "" {
		return "", fmt.Errorf("%w: assertion carries no ID, cannot be tracked for replay", ErrAssertionInvalid)
	}
	h := sha256.New()
	h.Write([]byte(providerID))
	h.Write([]byte{0})
	h.Write([]byte(strings.TrimSpace(a.Issuer.Value)))
	h.Write([]byte{0})
	h.Write([]byte(id))
	return hex.EncodeToString(h.Sum(nil)), nil
}

// replayExpiry is the instant after which no tamper process will accept
// this assertion again, so its ledger row stops mattering. It is read from
// crewjam's own timing globals — so it tracks SetMaxClockSkew — and NOT
// from the assertion body, so a hostile IdP cannot pin a row forever with a
// year-3000 NotOnOrAfter. Floored at now+skew so a stale IssueInstant
// cannot produce an already-expired row that a sweeper would delete before
// the assertion's own window closes.
func replayExpiry(a *crewjamsaml.Assertion, now time.Time) time.Time {
	base := now
	if a != nil && a.IssueInstant.After(now) {
		base = a.IssueInstant
	}
	exp := base.Add(crewjamsaml.MaxIssueDelay).Add(crewjamsaml.MaxClockSkew)
	if floor := now.Add(crewjamsaml.MaxClockSkew); exp.Before(floor) {
		exp = floor
	}
	return exp.UTC()
}

// ---- Layer 1 decision, on SIGNED material only ----

// signedInResponseTo reads the correlator from the assertion's
// SubjectConfirmationData — inside the assertion signature. It deliberately
// does NOT read Response.InResponseTo, which is a sibling of the signature
// and unsigned in the assertion-only-signing case (the Okta/Entra default),
// so an attacker could set it freely. Disagreement between confirmations is
// fatal rather than first-wins, so an attacker cannot splice a confirmation
// that answers our request onto one that answers a different one.
func signedInResponseTo(a *crewjamsaml.Assertion) (string, error) {
	if a == nil || a.Subject == nil || len(a.Subject.SubjectConfirmations) == 0 {
		return "", ErrNoSubjectConfirmation
	}
	var seen string
	for i, c := range a.Subject.SubjectConfirmations {
		v := ""
		if c.SubjectConfirmationData != nil {
			v = c.SubjectConfirmationData.InResponseTo
		}
		if i == 0 {
			seen = v
			continue
		}
		if v != seen {
			return "", fmt.Errorf("%w: subject confirmations disagree (%q vs %q)", ErrUncorrelated, seen, v)
		}
	}
	return seen, nil
}

// correlate is the flow-binding decision, over the full truth table of
// (did this flow issue an AuthnRequest?) x (does the signed assertion
// answer one?):
//
//	expected | signed InResponseTo | verdict
//	---------+---------------------+-------------------------------------
//	 "R"     | "R"                 | ACCEPT  — SP-initiated, correlated
//	 "R"     | "R'"                | REJECT  — answers a foreign/stripped flow
//	 "R"     | ""                  | REJECT  — correlator stripped
//	 ""      | "R'"                | REJECT  — *** captured-assertion replay ***
//	 ""      | ""                  | policy  — genuine IdP-initiated
//
// Row 4 is unconditional: AllowIDPInitiated=true does NOT reopen it. An
// operator who enables IdP-initiated SSO wants row 5 (answers no request),
// never row 4 (answers someone else's request without our cookie).
func correlate(a *crewjamsaml.Assertion, expectedRequestID string, allowIDPInitiated bool) error {
	got, err := signedInResponseTo(a)
	if err != nil {
		return err
	}
	switch {
	case expectedRequestID != "" && got == expectedRequestID:
		return nil
	case expectedRequestID != "":
		return fmt.Errorf("%w: this flow issued %q, assertion answers %q", ErrUncorrelated, expectedRequestID, got)
	case got != "":
		return fmt.Errorf("%w: this flow issued no AuthnRequest, assertion answers %q (captured-assertion replay)", ErrUncorrelated, got)
	case allowIDPInitiated:
		return nil // genuine IdP-initiated; the ledger is now its only defence
	default:
		return ErrIdPInitiatedDisabled
	}
}
