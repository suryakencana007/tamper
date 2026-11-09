package saml

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"strings"
)

// assertionNS is the SAML 2.0 assertion namespace. A <NameID> element can only
// mean "the subject's NameID" when it lives in this namespace.
const assertionNS = "urn:oasis:names:tc:SAML:2.0:assertion"

// rejectForeignNameID fails an assertion that carries a <NameID> element outside the
// SAML assertion namespace.
//
// Why this exists (GO-2026-6909, `crewjam/saml` through v0.5.1, no fixed release as of
// 2026-11-06): that library declares Subject as `xml:"NameID"`, which matches the LOCAL
// name and ignores the namespace. A signed assertion that omits the real <saml:NameID>
// and instead carries <NameID> in a foreign namespace therefore populates
// Subject.NameID from the attacker's element. We hand that value to applications as
// SubjectNameID and they key their user_identities row on it, so the consequence is an
// identity that is legitimately signed but says something the IdP never meant.
//
// The panic half of the same advisory — a nil <Issuer> dereference — is covered
// elsewhere, and the reason matters because the advisory's wording does not match the
// code we ship. It says the dereference needs ExpectedIDPEntityID to be set; that field
// does not exist in crewjam/saml v0.5.1 at all (grep: zero occurrences). What
// validateAssertion actually does is `assertion.Issuer.Value != sp.IDPMetadata.EntityID`
// with no nil guard (service_provider.go:1185), so ANY signed assertion that omits
// <Issuer> panics — the precondition is not narrow, it is absent. Our protection is
// therefore the recover barrier in parse.go (withParseRecover) around ParseResponse, and
// nothing else; it turns the panic into ErrAssertionInvalid, fail closed.
//
// Fail closed: any foreign-namespace NameID rejects the whole assertion. Assertions
// with no NameID, or with one in the assertion namespace — prefixed `saml:` or via a
// default xmlns, which encoding/xml resolves either way — pass untouched.
func rejectForeignNameID(samlResponse string) error {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(samlResponse))
	if err != nil {
		// Not decodable here: crewjam's parse will fail the same assertion, and
		// duplicating its error taxonomy is not this function's job.
		return nil
	}
	dec := xml.NewDecoder(strings.NewReader(string(raw)))
	for {
		tok, err := dec.Token()
		if err != nil {
			// Malformed XML or EOF: again the library's call to make. Reaching EOF
			// without a foreign NameID means there is nothing to reject.
			return nil
		}
		start, ok := tok.(xml.StartElement)
		if !ok || !localNameMatchedElements[start.Name.Local] {
			continue
		}
		// The set below is the audit's result (#132): every element crewjam declares with a
		// LOCAL-NAME tag that carries something tamper or an application trusts. NameID was the
		// first fix; the same blindness applies to the rest, and three matter more than NameID:
		//
		//	Subject              the identity, and the parent of everything below it
		//	SubjectConfirmation  correlation, and the replay key
		//	AttributeValue       what applications key JIT provisioning and authorization on
		//
		// Issuer is deliberately NOT in the set: crewjam declares it
		// `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`, so it is namespace-qualified and
		// cannot be steered. Verified in the vendored source rather than assumed — a guard for a
		// field that is already safe is noise, and noise is what teaches people to widen guards.
		if start.Name.Space != assertionNS {
			return fmt.Errorf("%w: %s element in namespace %q is not the assertion's own",
				ErrAssertionInvalid, start.Name.Local, start.Name.Space)
		}
	}
}

// localNameMatchedElements are the elements crewjam/saml v0.5.1 declares with a LOCAL-NAME tag —
// no namespace — so a foreign-namespace element populates the same Go field. Each is either read
// by tamper (NameID, Subject, SubjectConfirmation, SubjectConfirmationData) or handed to an
// application that trusts it (Attribute, AttributeValue, AuthnStatement).
//
// It is an allow-list of names to CHECK, not of names to allow: anything unlisted is ignored by
// the scan. The listed elements must be in the assertion namespace, which is what the SAML spec
// requires of every one of them, so a legitimate IdP is unaffected — it writes them with a
// `saml:` prefix or a default xmlns, and encoding/xml resolves both. The test table proves that
// rather than asserting it.
var localNameMatchedElements = map[string]bool{
	"NameID":                  true,
	"Subject":                 true,
	"SubjectConfirmation":     true,
	"SubjectConfirmationData": true,
	"AttributeStatement":      true,
	"Attribute":               true,
	"AttributeValue":          true,
	"AuthnStatement":          true,
}
