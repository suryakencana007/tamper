package saml

import (
	"errors"
	"testing"
	"time"

	crewjamsaml "github.com/crewjam/saml"
)

func TestParsedAssertion_IdPInitiated(t *testing.T) {
	cases := []struct {
		name   string
		confs  []crewjamsaml.SubjectConfirmation
		wantIP bool
	}{
		{
			name: "sp-initiated with InResponseTo",
			confs: []crewjamsaml.SubjectConfirmation{
				{SubjectConfirmationData: &crewjamsaml.SubjectConfirmationData{InResponseTo: "id-from-authnrequest"}},
			},
			wantIP: false,
		},
		{
			name: "idp-initiated empty InResponseTo",
			confs: []crewjamsaml.SubjectConfirmation{
				{SubjectConfirmationData: &crewjamsaml.SubjectConfirmationData{InResponseTo: ""}},
			},
			wantIP: true,
		},
		{name: "no confirmation", confs: nil, wantIP: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pa := &ParsedAssertion{raw: &crewjamsaml.Assertion{
				Subject: &crewjamsaml.Subject{SubjectConfirmations: tc.confs},
			}}
			if got := pa.IdPInitiated(); got != tc.wantIP {
				t.Errorf("IdPInitiated = %v, want %v", got, tc.wantIP)
			}
		})
	}
}

func TestParsedAssertion_AuthnTimeAndACR(t *testing.T) {
	authn := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	issue := time.Date(2026, 7, 12, 9, 0, 0, 0, time.UTC)
	now := func() time.Time { return time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC) }

	full := &ParsedAssertion{raw: &crewjamsaml.Assertion{
		IssueInstant: issue,
		AuthnStatements: []crewjamsaml.AuthnStatement{{
			AuthnInstant: authn,
			AuthnContext: crewjamsaml.AuthnContext{
				AuthnContextClassRef: &crewjamsaml.AuthnContextClassRef{Value: " urn:x:mfa "},
			},
		}},
	}}
	if got := full.AuthnTime(now); got != authn.Unix() {
		t.Errorf("AuthnTime = %d, want AuthnInstant", got)
	}
	if got := full.ACR("fallback"); got != "urn:x:mfa" {
		t.Errorf("ACR = %q, want trimmed ref", got)
	}

	noStmt := &ParsedAssertion{raw: &crewjamsaml.Assertion{IssueInstant: issue}}
	if got := noStmt.AuthnTime(now); got != issue.Unix() {
		t.Errorf("AuthnTime fallback = %d, want IssueInstant", got)
	}
	if got := noStmt.ACR("urn:fallback"); got != "urn:fallback" {
		t.Errorf("ACR fallback = %q", got)
	}

	empty := &ParsedAssertion{raw: &crewjamsaml.Assertion{}}
	if got := empty.AuthnTime(now); got != now().Unix() {
		t.Errorf("AuthnTime last-resort = %d, want now", got)
	}
}

func TestBuildPostFormRequest(t *testing.T) {
	r := buildPostFormRequest("https://sp.example.test/api/auth/saml/acs/abc", "AAAA", "/projects")
	if got := r.PostForm.Get("SAMLResponse"); got != "AAAA" {
		t.Errorf("PostForm[SAMLResponse] = %q, want AAAA", got)
	}
	if got := r.PostForm.Get("RelayState"); got != "/projects" {
		t.Errorf("PostForm[RelayState] = %q, want /projects", got)
	}
	if r.URL.Path != "/api/auth/saml/acs/abc" {
		t.Errorf("URL.Path = %q", r.URL.Path)
	}
	// Empty relay state omits the key entirely.
	r = buildPostFormRequest("https://sp.example.test/acs", "BBBB", "")
	if _, ok := r.PostForm["RelayState"]; ok {
		t.Error("empty RelayState must not be set")
	}
}

// TestWithParseRecover confirms the recover barrier converts a panic in the
// crewjam parse path into ErrAssertionInvalid (fail closed), so an
// IdP-signed-but-malformed assertion can never crash the ACS goroutine.
func TestWithParseRecover(t *testing.T) {
	t.Run("panic becomes ErrAssertionInvalid", func(t *testing.T) {
		a, err := withParseRecover(func() (*crewjamsaml.Assertion, error) {
			panic("crewjam nil-deref on a SubjectConfirmation with no data")
		})
		if a != nil {
			t.Errorf("assertion = %v, want nil on panic", a)
		}
		if !errors.Is(err, ErrAssertionInvalid) {
			t.Fatalf("err = %v, want ErrAssertionInvalid", err)
		}
	})
	t.Run("normal return passes through", func(t *testing.T) {
		want := &crewjamsaml.Assertion{ID: "a1"}
		a, err := withParseRecover(func() (*crewjamsaml.Assertion, error) {
			return want, nil
		})
		if err != nil || a != want {
			t.Fatalf("got (%v,%v), want (%v,nil)", a, err, want)
		}
	})
	t.Run("normal error passes through unchanged", func(t *testing.T) {
		sentinel := errors.New("boom")
		if _, err := withParseRecover(func() (*crewjamsaml.Assertion, error) {
			return nil, sentinel
		}); !errors.Is(err, sentinel) {
			t.Errorf("err = %v, want the passed-through sentinel", err)
		}
	})
}
