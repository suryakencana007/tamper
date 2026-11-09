package espresso

import (
	"errors"
	"fmt"
	"testing"

	espressofw "github.com/suryakencana007/espresso/v2"

	"github.com/suryakencana007/tamper/saml"
)

// The mapping from a SAML parse failure to a response, tested as a table.
//
// It exists because the comment beside the state-cookie slot claimed a slot
// mismatch was SILENT for months after it stopped being silent: the ACS reads
// the cookie before the parse (it supplies the correlator), so a drifted slot
// produces ErrUncorrelated and this function answers 400. Describing that in a
// comment was not enough; the description is now a call with a test on it.
//
// The two families are asserted differently on purpose. The replay/correlation
// codes are distinct and must stay distinct. The signature/timing/audience
// family must stay COLLAPSED: if one of those ever grows its own code, this test
// fails, because a caller that can tell "wrong signature" from "wrong audience"
// can use it as an oracle.
func TestSAMLACSFailure_MapsEveryFamily(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{
			"a replay-store outage is ours, not the caller's",
			fmt.Errorf("%w: ledger down", saml.ErrReplayStoreUnavailable),
			503, "SAML_REPLAY_STORE_UNAVAILABLE",
		},
		{
			"a consumed assertion is a 400, not a 503",
			fmt.Errorf("%w: already used", saml.ErrAssertionReplayed),
			400, "SAML_ASSERTION_REPLAYED",
		},
		{
			// THE case the stale comment denied: a slot mismatch lands here.
			"an uncorrelated assertion is LOUD (400), never a silent login",
			fmt.Errorf("%w: does not answer our request", saml.ErrUncorrelated),
			400, "SAML_ASSERTION_UNCORRELATED",
		},
		{
			"a missing SubjectConfirmation is the same loud answer",
			fmt.Errorf("%w: no confirmation", saml.ErrNoSubjectConfirmation),
			400, "SAML_ASSERTION_UNCORRELATED",
		},
		{
			"IdP-initiated SSO being off is a distinct, safe code",
			fmt.Errorf("%w: disabled", saml.ErrIdPInitiatedDisabled),
			400, "SAML_IDP_INITIATED_DISABLED",
		},
		{
			"everything else collapses to one generic error",
			errors.New("signature verification failed"),
			400, "SAML_ASSERTION_INVALID",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var httpErr *espressofw.Error
			if !errors.As(samlACSFailure(tc.err), &httpErr) {
				t.Fatal("the mapping did not return a framework error")
			}
			if httpErr.StatusCode != tc.wantStatus || httpErr.Code != tc.wantCode {
				t.Errorf("got %d %s, want %d %s", httpErr.StatusCode, httpErr.Code, tc.wantStatus, tc.wantCode)
			}
		})
	}

	t.Run("the oracle-sensitive family stays collapsed", func(t *testing.T) {
		oracleSensitive := []error{
			errors.New("signature verification failed"),
			errors.New("assertion expired"),
			errors.New("audience mismatch"),
			errors.New("clock skew"),
		}
		codes := map[string]bool{}
		for _, e := range oracleSensitive {
			var httpErr *espressofw.Error
			if !errors.As(samlACSFailure(e), &httpErr) {
				t.Fatal("the mapping did not return a framework error")
			}
			codes[httpErr.Code] = true
		}
		if len(codes) != 1 {
			t.Errorf("the signature/timing/audience family produced %d distinct codes (%v) — "+
				"a caller must not be able to tell which check failed", len(codes), codes)
		}
	})
}
