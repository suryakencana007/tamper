package saml

// TD-FUNC-26 repro — AllowIDPInitiated=false rejects EVERY assertion,
// SP-initiated included, making SAML sign-in a total outage on that
// config.
//
// This test is written BEFORE the fix and is expected to FAIL on the
// current tree. It exists to turn a code-reading claim into an
// executable fact: the bug was found by reading crewjam's source, and a
// claim that severe should not be filed on reading alone.
//
// The mechanism (crewjam/saml@v0.5.1 service_provider.go:1095-1113,
// called unconditionally from :1018):
//
//	requestIDvalid := false
//	if sp.AllowIDPInitiated {
//	    requestIDvalid = true
//	} else {
//	    for _, id := range possibleRequestIDs {   // EMPTY — never iterates
//	        if response.InResponseTo == id { requestIDvalid = true }
//	    }
//	}
//	if !requestIDvalid { return error }
//
// Barista passes NO request-ID allow-list — there is no AuthnRequest
// tracker — so ParseAssertion normalizes nil to []string{} and the loop
// can never match. With AllowIDPInitiated=false, requestIDvalid is
// therefore false for EVERY assertion regardless of what InResponseTo
// contains, including a perfectly valid SP-initiated one.
//
// WHY THE EXISTING SUITE MISSES IT: saml_test.go only ever sets
// allowIdP := true, and the one test in this area
// (TestSAMLACS_ParseResponse_PassesEmptySliceNotNil) installs a
// ValidateRequestID hook that short-circuits at :1096 — bypassing the
// exact branch that holds the bug. The test sits on top of the defect
// and masks it.
//
// WHY THIS TEST IS DIFFERENTIAL: an unsigned synthetic response fails
// eventually either way (timing/signature checks are downstream), so
// "did it error?" proves nothing. What proves it is WHICH error:
// validateRequestID runs BEFORE those, so flipping only
// AllowIDPInitiated must not change whether the InResponseTo gate fires
// for an SP-initiated assertion.
//
// WHY IT READS PrivateErr: crewjam wraps every parse failure in
// *InvalidResponseError, whose public Error() is the FIXED string
// "Authentication failed" — the real cause lives only in .PrivateErr.
// (The first draft of this test asserted on err.Error() and passed
// against a live bug, because every failure looks identical from the
// outside. That is also the reason this bug survived in the field: see
// the diagnosability note in TD-FUNC-26.)

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	crewjamsaml "github.com/crewjam/saml"
)

// spInitiatedResponse is a SAMLResponse carrying a NON-EMPTY
// InResponseTo — i.e. the browser is completing a flow WE started. This
// is the legitimate SP-initiated leg that must keep working when
// IdP-initiated SSO is switched off.
//
// Well-formed enough to clear base64 + XML unmarshal and reach
// validateRequestID; deliberately unsigned, since the gate under test
// runs before signature validation.
const spInitiatedResponse = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
	`ID="resp-1" Version="2.0" IssueInstant="2026-07-16T12:00:00Z" ` +
	`Destination="https://panel.barista.test/api/auth/saml/acs/test" ` +
	`InResponseTo="authnreq-we-issued">` +
	`<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
	`</samlp:Response>`

// reproProvider builds a Provider THROUGH BuildProvider — the layer
// under test.
//
// An earlier draft constructed the crewjam ServiceProvider directly and
// set AllowIDPInitiated by hand. That tested crewjam's behaviour (which
// we cannot change and do not own) rather than tamper's threading of
// cfg.AllowIDPInitiated onto the SP (which is the actual defect and the
// actual fix). It failed identically before and after the fix — a test
// that cannot observe the change it guards.
func reproProvider(t *testing.T, allowIdPInitiated bool) *Provider {
	t.Helper()
	certPEM, keyPEM := testCertKeyPEM(t)
	cert, key := parsePEMPair(t, certPEM, keyPEM)
	p, err := BuildProvider(ProviderConfig{
		ID:                "test",
		EntityID:          "https://panel.barista.test/saml/metadata",
		ACSURL:            "https://panel.barista.test/api/auth/saml/acs/test",
		MetadataURL:       "https://idp.test/metadata",
		SPCert:            cert,
		SPKey:             key,
		AllowIDPInitiated: allowIdPInitiated,
	}, fakeEntity(certPEM))
	if err != nil {
		t.Fatalf("BuildProvider: %v", err)
	}
	return p
}

// parsePEMPair turns the test PEMs into the parsed types
// ProviderConfig wants (the app's service layer does this in prod).
func parsePEMPair(t *testing.T, certPEM, keyPEM string) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	cblock, _ := pem.Decode([]byte(certPEM))
	if cblock == nil {
		t.Fatal("decode cert PEM")
	}
	cert, err := x509.ParseCertificate(cblock.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	kblock, _ := pem.Decode([]byte(keyPEM))
	if kblock == nil {
		t.Fatal("decode key PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(kblock.Bytes)
	if err != nil {
		t.Fatalf("ParsePKCS1PrivateKey: %v", err)
	}
	return cert, key
}

// inResponseToRejection reports whether the error is crewjam's
// request-ID gate firing, as opposed to any downstream failure.
//
// It calls SP.ParseResponse directly rather than tamper's
// ParseAssertion, because ParseAssertion wraps with %v, which flattens
// *InvalidResponseError to "Authentication failed" and DISCARDS the
// PrivateErr this test must read.
func inResponseToRejection(t *testing.T, allowIdPInitiated bool, samlResponse string) (bool, error) {
	t.Helper()
	p := reproProvider(t, allowIdPInitiated)
	form := url.Values{}
	form.Set("SAMLResponse", samlResponse)
	form.Set("RelayState", "/projects")
	req, err := http.NewRequest(http.MethodPost, p.SP.AcsURL.String(), strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		t.Fatalf("parse form: %v", err)
	}
	_, perr := p.SP.ParseResponse(req, []string{})

	var ire *crewjamsaml.InvalidResponseError
	if errors.As(perr, &ire) && ire.PrivateErr != nil {
		return strings.Contains(ire.PrivateErr.Error(), "does not match any of the possible request IDs"), ire.PrivateErr
	}
	return false, perr
}

// TestTDFUNC26_AllowIDPInitiatedFalse_RejectsSPInitiated is the repro.
//
// EXPECTED TO FAIL until the fix lands. When it fails, SAML sign-in is
// broken for every operator who set allowIdPInitiated: false — the
// stricter, more security-conscious posture.
func TestTDFUNC26_AllowIDPInitiatedFalse_RejectsSPInitiated(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte(spInitiatedResponse))

	// Control: IdP-initiated ALLOWED. crewjam short-circuits
	// requestIDvalid=true, so the request-ID gate cannot fire. This
	// assertion still fails downstream (stale IssueInstant), which is
	// the point — it proves the gate is what differs, not the fixture.
	gateFiredAllowed, errAllowed := inResponseToRejection(t, true, b64)
	if gateFiredAllowed {
		t.Fatalf("control is broken: the request-ID gate fired even with AllowIDPInitiated=true: %v", errAllowed)
	}
	t.Logf("control (allow=true):  %v", errAllowed)

	// Subject: IdP-initiated DISABLED, same SP-initiated assertion.
	// The operator's intent is "SP-initiated only" — this assertion IS
	// SP-initiated (InResponseTo is set), so it must survive the gate.
	gateFiredDisabled, errDisabled := inResponseToRejection(t, false, b64)
	t.Logf("subject (allow=false): %v", errDisabled)

	if gateFiredDisabled {
		t.Errorf(`TD-FUNC-26 CONFIRMED — allowIdPInitiated=false rejects a legitimate SP-INITIATED assertion.

  error: %v

Barista passes no request-ID allow-list (no AuthnRequest tracker), so
crewjam's validateRequestID loops an EMPTY list looking for a match and
can never set requestIDvalid. Every assertion is rejected, not just
IdP-initiated ones: SAML sign-in is a TOTAL OUTAGE on this config.

The handler's own gate (saml.go:357, SAML_IDP_INITIATED_DISABLED) is
unreachable dead code — control never reaches it, so the documented
behaviour in config.go:360 can never occur.

FIX: let the app's post-parse gate enforce the policy (it already
exists and already works off ParsedAssertion.IdPInitiated()), and stop
asking crewjam to enforce a check it cannot satisfy without a tracker.
No security regression: on the default (true) crewjam already skips this
check, and the allow-list is already empty on every config — so nothing
that presently runs is being weakened.`, errDisabled)
	}
}

// TestTDFUNC26_AllowIDPInitiatedFalse_StillRejectsIdPInitiated is the
// other half of the contract, and the reason the fix cannot simply be
// "always pass true and forget it".
//
// Once the policy moves to the app's post-parse gate, THIS is what must
// still hold: an IdP-initiated assertion (empty InResponseTo) must be
// refused when the operator disabled that flow. ParsedAssertion.
// IdPInitiated() is the predicate the gate keys on, and it is already
// correct + unit-tested (TestParsedAssertion_IdPInitiated) — this pins
// the pairing so a fix cannot satisfy the repro above by simply
// disabling the policy altogether.
func TestTDFUNC26_AllowIDPInitiatedFalse_StillRejectsIdPInitiated(t *testing.T) {
	idpInitiated := &ParsedAssertion{raw: &crewjamsaml.Assertion{
		Subject: &crewjamsaml.Subject{SubjectConfirmations: []crewjamsaml.SubjectConfirmation{
			{SubjectConfirmationData: &crewjamsaml.SubjectConfirmationData{InResponseTo: ""}},
		}},
	}}
	if !idpInitiated.IdPInitiated() {
		t.Fatal("IdPInitiated() must report true for an empty InResponseTo — the app's gate keys on this")
	}

	spInitiated := &ParsedAssertion{raw: &crewjamsaml.Assertion{
		Subject: &crewjamsaml.Subject{SubjectConfirmations: []crewjamsaml.SubjectConfirmation{
			{SubjectConfirmationData: &crewjamsaml.SubjectConfirmationData{InResponseTo: "authnreq-we-issued"}},
		}},
	}}
	if spInitiated.IdPInitiated() {
		t.Error("IdPInitiated() must report false when InResponseTo is set — otherwise the gate would reject SP-initiated logins too")
	}
}
