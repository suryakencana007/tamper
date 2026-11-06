package saml

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"

	crewjamsaml "github.com/crewjam/saml"
)

// GO-2026-6909: crewjam/saml (through v0.5.1, no fixed release) matches Subject's
// NameID by local name and ignores the namespace, so a foreign-namespace element can
// populate the subject identity. These are the shapes that separates.
func TestRejectForeignNameID(t *testing.T) {
	const response = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">%s</samlp:Response>`

	cases := []struct {
		name    string
		assert  string
		wantErr bool
	}{
		{
			name:   "saml-prefixed NameID is the subject's",
			assert: `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Subject><saml:NameID>bob</saml:NameID></saml:Subject></saml:Assertion>`,
		},
		{
			name:   "default-namespace NameID is also the subject's",
			assert: `<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion"><Subject><NameID>bob</NameID></Subject></Assertion>`,
		},
		{
			name:   "no NameID at all",
			assert: `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Subject/></saml:Assertion>`,
		},
		{
			name:    "foreign-namespace NameID is refused",
			assert:  `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Subject><evil:NameID xmlns:evil="urn:attacker">alice</evil:NameID></saml:Subject></saml:Assertion>`,
			wantErr: true,
		},
		{
			name:    "unprefixed NameID under a foreign default namespace is refused",
			assert:  `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Subject><Subject xmlns="urn:attacker"><NameID>alice</NameID></Subject></saml:Subject></saml:Assertion>`,
			wantErr: true,
		},
		{
			name:    "a foreign NameID anywhere in the document is refused, not just in Subject",
			assert:  `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><evil:NameID xmlns:evil="urn:attacker">alice</evil:NameID><saml:Subject><saml:NameID>bob</saml:NameID></saml:Subject></saml:Assertion>`,
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encoded := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(response, tc.assert)))
			err := rejectForeignNameID(encoded)
			if tc.wantErr {
				if !errors.Is(err, ErrAssertionInvalid) {
					t.Fatalf("err = %v, want ErrAssertionInvalid", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
		})
	}
}

// Undecodable input is left to the library: this guard must not become a second,
// differently-worded parse error that an attacker can use as an oracle.
func TestRejectForeignNameID_LeavesUndecodableInputToTheLibrary(t *testing.T) {
	if err := rejectForeignNameID("not base64 !!"); err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if err := rejectForeignNameID(base64.StdEncoding.EncodeToString([]byte("<not-xml"))); err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
}

// The guard is only worth anything if ParseAssertion actually calls it. This test fails
// closed on the foreign NameID BEFORE any signature work — which is both the desired
// order and the reason no valid signed fixture is needed here.
func TestParseAssertion_RefusesForeignNameIDBeforeVerification(t *testing.T) {
	p := &Provider{Config: ProviderConfig{ID: "test"}, SP: &crewjamsaml.ServiceProvider{}}
	body := base64.StdEncoding.EncodeToString([]byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Subject><evil:NameID xmlns:evil="urn:attacker">alice</evil:NameID></saml:Subject></saml:Assertion></samlp:Response>`))

	_, err := p.ParseAssertion(context.Background(), body, "", "")
	if !errors.Is(err, ErrAssertionInvalid) {
		t.Fatalf("err = %v, want ErrAssertionInvalid — ParseAssertion must call the guard", err)
	}
}

// The dangerous shape, and the one the guard exists for: BOTH NameIDs inside Subject,
// the legitimate one first and a foreign-namespace one second. encoding/xml keeps the
// LAST element for the field, so crewjam's Subject.NameID reads the foreign value
// (verified with a probe: it yielded "alice" for the saml-then-evil fixture). Before the
// guard, that signature was valid and the identity was the attacker's.
func TestRejectForeignNameID_LegitimateThenForeignInsideSubject(t *testing.T) {
	xmlDoc := `<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:evil="urn:attacker">` +
		`<Subject><NameID>bob</NameID><evil:NameID>alice</evil:NameID></Subject></Assertion>`
	if err := rejectForeignNameID(encodeAssertion(xmlDoc)); !errors.Is(err, ErrAssertionInvalid) {
		t.Fatalf("err = %v, want ErrAssertionInvalid — the foreign NameID would win in crewjam", err)
	}
}

// An encrypted subject is legitimate and carries no readable NameID; refusing it would
// break IdPs that encrypt the subject.
func TestRejectForeignNameID_AllowsEncryptedSubject(t *testing.T) {
	xmlDoc := `<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion">` +
		`<Subject><EncryptedID><x/></EncryptedID></Subject></Assertion>`
	if err := rejectForeignNameID(encodeAssertion(xmlDoc)); err != nil {
		t.Fatalf("err = %v, want nil for an encrypted subject", err)
	}
}

// Pinned on purpose: the guard refuses a foreign-local-name NameID ANYWHERE, including
// places crewjam never reads as the subject (SubjectConfirmation here). That is stricter
// than necessary and it is the chosen trade: a rejection an IdP can see, rather than a
// silent dependence on which element the library would have picked.
func TestRejectForeignNameID_RefusesForeignNameIDOutsideSubject(t *testing.T) {
	xmlDoc := `<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:evil="urn:attacker">` +
		`<Subject><NameID>bob</NameID><SubjectConfirmation><evil:NameID>alice</evil:NameID>` +
		`</SubjectConfirmation></Subject></Assertion>`
	if err := rejectForeignNameID(encodeAssertion(xmlDoc)); !errors.Is(err, ErrAssertionInvalid) {
		t.Fatalf("err = %v, want ErrAssertionInvalid (documented over-rejection)", err)
	}
}

func encodeAssertion(xmlDoc string) string {
	return base64.StdEncoding.EncodeToString([]byte(xmlDoc))
}
