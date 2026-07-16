package saml

// TD-FUNC-28 (tracker half) — the AuthnRequest-ID correlation that SAML
// otherwise lacks entirely.
//
// SAML gives us no nonce and no PKCE. InResponseTo is the only link
// between the request we issued and the assertion that comes back, and
// until now nothing checked it: the ACS passed nil possibleRequestIDs,
// so ANY assertion the IdP signed was accepted by ANY flow.
//
// WHY THAT MATTERED, and why it pairs with the SameSite fix: on the
// LOGIN leg a foreign-but-signed assertion is mostly benign — it still
// proves who its subject is, and the worst case is signing in as that
// subject. On the LINK leg it is not: the flow's own state cookie
// decides WHOSE account the identity attaches to. An attacker who times
// a victim's ~5-minute link window and gets the victim's browser to POST
// an assertion for the ATTACKER's identity would have the ACS bind the
// attacker's IdP identity to the victim's account — and thereafter the
// attacker can sign in as the victim.
//
// That window was closed only by accident: SameSite=Lax meant the state
// cookie never arrived on the IdP's cross-site POST, so link mode never
// fired at all (TD-FUNC-28). Fixing SameSite without this tracker would
// have traded a broken feature for a live CSRF hole.
//
// These tests pin BOTH halves of the hook's contract, because a fix that
// satisfies one by breaking the other is the obvious wrong turn:
//   - ids supplied     => the assertion must answer OUR request;
//   - no ids supplied  => allow (IdP-initiated legitimacy), and let the
//     app's post-parse AllowIdPInitiated gate decide.

import (
	"testing"

	crewjamsaml "github.com/crewjam/saml"
)

// hook reaches the ValidateRequestID closure BuildProvider installs. It
// is the single decision point for request-ID correlation: with
// SP.AllowIDPInitiated forced true, crewjam's own two checks are
// disabled, so this closure IS the policy.
func hook(t *testing.T) func(crewjamsaml.Response, []string) error {
	t.Helper()
	p := reproProvider(t, true)
	if p.SP.ValidateRequestID == nil {
		t.Fatal("BuildProvider must install a ValidateRequestID hook — without it crewjam's own (unsatisfiable) gate runs")
	}
	return p.SP.ValidateRequestID
}

func TestRequestIDTracker_AcceptsAssertionAnsweringOurRequest(t *testing.T) {
	resp := crewjamsaml.Response{InResponseTo: "id-we-issued"}
	if err := hook(t)(resp, []string{"id-we-issued"}); err != nil {
		t.Errorf("assertion answering our own AuthnRequest must be accepted, got: %v", err)
	}
}

// TestRequestIDTracker_RejectsForeignAssertion is the security case: a
// perfectly valid, IdP-signed assertion that answers a DIFFERENT request
// must not be accepted by this flow. This is the link-CSRF fence.
func TestRequestIDTracker_RejectsForeignAssertion(t *testing.T) {
	resp := crewjamsaml.Response{InResponseTo: "id-the-attacker-obtained"}
	err := hook(t)(resp, []string{"id-we-issued"})
	if err == nil {
		t.Error("an assertion answering someone else's AuthnRequest must be REJECTED — " +
			"accepting it is the link-CSRF hole: an attacker's identity would bind to the victim's account")
	}
}

// TestRequestIDTracker_RejectsIdPInitiatedAssertionMidFlow closes the
// sharp edge of the above: an attacker cannot dodge the correlation by
// stripping InResponseTo. Once a flow has issued a request, an assertion
// with an EMPTY InResponseTo does not answer it.
func TestRequestIDTracker_RejectsIdPInitiatedAssertionMidFlow(t *testing.T) {
	resp := crewjamsaml.Response{InResponseTo: ""}
	if err := hook(t)(resp, []string{"id-we-issued"}); err == nil {
		t.Error("an IdP-initiated assertion must NOT satisfy a flow that issued an AuthnRequest — " +
			"otherwise dropping InResponseTo bypasses the whole tracker")
	}
}

// TestRequestIDTracker_AllowsGenuineIdPInitiated preserves the
// missing-cookie -> LOGIN fallthrough. No cookie means no request ID
// means nothing to correlate: allow, and let the app's post-parse
// AllowIdPInitiated gate decide whether IdP-initiated SSO is permitted.
//
// Rejecting here would break Okta tiles / Azure "My Apps" — the flows
// AllowIdPInitiated=true exists to support — and would re-create
// TD-FUNC-26 in a new place.
func TestRequestIDTracker_AllowsGenuineIdPInitiated(t *testing.T) {
	h := hook(t)
	for _, ids := range [][]string{nil, {}} {
		if err := h(crewjamsaml.Response{InResponseTo: ""}, ids); err != nil {
			t.Errorf("genuine IdP-initiated assertion (ids=%v) must pass the correlation gate "+
				"— the policy decision belongs to the app's post-parse gate, got: %v", ids, err)
		}
	}
}

// TestRequestIDTracker_EmptyIDInListCannotMatch guards a subtle
// fail-open: if a caller ever stashed an empty RequestID and handed back
// []string{""}, an IdP-initiated assertion (InResponseTo == "") would
// match it by string equality and silently satisfy a flow that expected
// a real correlation.
func TestRequestIDTracker_EmptyIDInListCannotMatch(t *testing.T) {
	if err := hook(t)(crewjamsaml.Response{InResponseTo: ""}, []string{""}); err == nil {
		t.Error(`an empty id in the allow-list must not match an empty InResponseTo — ` +
			`"" == "" would fail open and turn a stashed-empty-RequestID bug into a silent bypass`)
	}
}
