package saml

import (
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
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
