package audit

// canonical_version=4 — the tenant-bearing, redactable canonical payload.
//
// Two changes from v3, and they are independent:
//
//  1. The TENANT ENTERS THE HASH. v4 adds `tenant_id` (the row's scope)
//     and `actor.tenant_id` (the actor's home tenant). Deliberately NOT
//     following the cluster_id precedent, which is documented as "purely
//     a query-time filter, not part of integrity" — cluster_id is a
//     visibility filter inside one trust domain, whereas a tenant IS the
//     trust boundary. An unhashed tenant column can be re-attributed
//     from A to B without breaking anything, and re-attribution is the
//     specific attack a pooled audit log has to be evidence against.
//     That is the whole justification for v4 existing.
//
//  2. PII FIELDS HASH AS STORED COMMITMENTS rather than as plaintext.
//     See redaction.go. This is what lets a row survive an erasure
//     request without breaking the chain, and a v4 that hashed
//     plaintext PII would be a version that cannot answer one.

// canonicalPayloadV4 encodes an event under the v4 shape.
//
// FIELD ORDER — v3's sequence, unchanged, with the two tenant fields
// inserted after request_id:
//
//	id, at, actor.user_id, actor.email*, actor.name*, actor.ip*,
//	actor.type, action, resource_type, resource_id, request_id,
//	tenant_id, actor.tenant_id, before*, after*, prev_hash
//
// Starred fields carry the stored 32-byte commitment, not the value.
// Everything else is byte-identical in shape to v3, using the same
// length-prefixed appenders, so the encoding difference between v3 and
// v4 is exactly the two new fields plus the five substitutions.
//
// The commitments are read from e.Commitments and NEVER derived from
// the plaintext here. That is the property redaction rests on: null the
// plaintext, drop the salt, keep the 32 bytes, and this function still
// produces the same payload it produced the day the row was written.
// A version of this function that fell back to hashing plaintext when a
// commitment was absent would silently un-redact the chain — so absent
// means absent, and encodes as a zero-length field.
func canonicalPayloadV4(e Event, prevHash []byte) []byte {
	var buf []byte
	buf = appendStringField(buf, "id", e.ID)
	buf = appendInt64Field(buf, "at", e.At.UnixNano())
	buf = appendStringField(buf, "actor.user_id", e.Actor.UserID)
	buf = appendBytesField(buf, "actor.email", e.Commitments.ActorEmail)
	buf = appendBytesField(buf, "actor.name", e.Commitments.ActorName)
	buf = appendBytesField(buf, "actor.ip", e.Commitments.ActorIP)
	t := string(e.Actor.Type)
	if t == "" {
		t = string(ActorTypeUser)
	}
	buf = appendStringField(buf, "actor.type", t)
	buf = appendStringField(buf, "action", string(e.Action))
	buf = appendStringField(buf, "resource_type", string(e.ResourceType))
	buf = appendStringField(buf, "resource_id", e.ResourceID)
	buf = appendStringField(buf, "request_id", e.RequestID)
	// The two new fields. Order fixed here forever: changing it is a
	// v5, not an edit.
	buf = appendStringField(buf, "tenant_id", e.TenantID)
	buf = appendStringField(buf, "actor.tenant_id", e.Actor.TenantID)
	buf = appendBytesField(buf, "before", e.Commitments.Before)
	buf = appendBytesField(buf, "after", e.Commitments.After)
	buf = appendBytesField(buf, "prev_hash", prevHash)
	return buf
}
