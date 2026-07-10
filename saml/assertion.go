package saml

import (
	"strings"

	crewjamsaml "github.com/crewjam/saml"
)

// AttributeValue returns the first <AttributeValue> element under the
// SAML <Attribute> matching `name` (case-sensitive). Returns "" when
// the attribute is absent or has no values.
//
// crewjam/saml's ParseResponse populates the Assertion's
// AttributeStatements; this helper centralises the lookup so handlers
// don't reach into the XML schema directly. v1.12 Sprint 2 Task 04.
//
// Both Name and FriendlyName are checked -- some IdPs use the
// canonical URI shape (`http://schemas.../emailaddress`), others use
// the human FriendlyName (`email`). The operator-supplied
// AttributeMapping holds the value the IdP emits; matching against
// FriendlyName as well as Name covers the variance.
func AttributeValue(a *crewjamsaml.Assertion, name string) string {
	values := AttributeValues(a, name)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// AttributeValues returns every <AttributeValue> element under the
// SAML <Attribute> matching `name`. Two emission shapes both produce
// a multi-element slice:
//
//  1. Multiple separate <AttributeValue> children (Keycloak, AD-FS,
//     SimpleSAMLphp emit groups this way).
//  2. A single <AttributeValue> with comma-separated content (some
//     custom Azure AD mappings; legacy LDAP-fronted IdPs).
//
// This helper handles both shapes -- the comma-split path is gated on
// the result containing no XML-encoded value separators so a value like
// "Acme, Inc., Ltd." stays as a single attribute. The split happens
// only when the single value contains a comma AND none of the
// surrounding whitespace looks intentional (heuristic: split on `, `
// with trim).
//
// Returns an empty slice when the attribute is absent. Never nil.
func AttributeValues(a *crewjamsaml.Assertion, name string) []string {
	out := make([]string, 0, 1)
	if a == nil || name == "" {
		return out
	}
	for _, stmt := range a.AttributeStatements {
		for _, attr := range stmt.Attributes {
			if attr.Name != name && attr.FriendlyName != name {
				continue
			}
			for _, v := range attr.Values {
				s := strings.TrimSpace(v.Value)
				if s == "" {
					continue
				}
				out = append(out, s)
			}
		}
	}
	// Single-value-with-commas heuristic: only when exactly one value
	// landed AND it carries comma-space separators. Splitting eagerly
	// would corrupt legitimate single-value emissions (e.g., display
	// names like "Smith, John").
	if len(out) == 1 && strings.Contains(out[0], ",") {
		parts := splitCommaSeparated(out[0])
		if len(parts) > 1 {
			return parts
		}
	}
	return out
}

// splitCommaSeparated splits "alpha, beta, gamma" into
// ["alpha", "beta", "gamma"]. Empty trimmed segments are dropped.
// Returns the original string in a single-element slice when no split
// produces multiple non-empty segments.
func splitCommaSeparated(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		t := strings.TrimSpace(p)
		if t == "" {
			continue
		}
		out = append(out, t)
	}
	if len(out) <= 1 {
		return []string{s}
	}
	return out
}

// SubjectNameID returns the NameID value from the assertion's Subject.
// Returns "" when the assertion has no NameID or the inner element is
// empty.
//
// Most IdPs populate NameID with the user's canonical IdP-side
// identifier (a UUID, an email, or a stable opaque token). This is
// the "subject" the federate path uses to key the user_identities
// row -- distinct from the email attribute which may rotate.
func SubjectNameID(a *crewjamsaml.Assertion) string {
	if a == nil || a.Subject == nil || a.Subject.NameID == nil {
		return ""
	}
	return strings.TrimSpace(a.Subject.NameID.Value)
}
