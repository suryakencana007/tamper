package espresso

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// SCIM error-envelope helpers (RFC 7644 §3.12). The SCIMError struct +
// WriteSCIMError (the untyped 401 writer used by the service-account
// gate) live in sagate.go; this file adds the scimType vocabulary + the
// typed writer the resource handlers need. Phase 4e-3 lifted these from
// Barista's SCIM handler (handler/scim/errors.go), deduping its
// intentional copy of the envelope.

// SCIM scimType values from RFC 7644 §3.12.
const (
	SCIMTypeUniqueness    = "uniqueness"
	SCIMTypeInvalidValue  = "invalidValue"
	SCIMTypeInvalidFilter = "invalidFilter"
	SCIMTypeInvalidPath   = "invalidPath"
	SCIMTypeInvalidSyntax = "invalidSyntax"
	SCIMTypeMutability    = "mutability"
)

// WriteSCIMErrorTyped serialises a §3.12 error envelope with an optional
// scimType (RFC 7644 §3.12 enumerates uniqueness/invalidValue/…; pass ""
// for status-only errors like 404/500). Always application/scim+json;
// encode failures are best-effort (the status is already written).
func WriteSCIMErrorTyped(w http.ResponseWriter, status int, detail, scimType string) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(SCIMError{
		Schemas:  []string{scimErrSchema},
		Status:   strconv.Itoa(status),
		SCIMType: scimType,
		Detail:   detail,
	})
}
