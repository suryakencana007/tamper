package scim

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// rfc7644PatchExamples reproduces the verbatim PATCH examples from RFC
// 7644 section 3.5.2. The applier MUST accept all three under the
// case-insensitive op normalisation + path-less merge semantics. Each
// case is structured as the SCIM resource pre-PATCH, the JSON-encoded
// PATCH ops, and the expected resource post-PATCH (compared via
// reflect.DeepEqual).
func TestRFC7644Section352Examples(t *testing.T) {
	cases := []struct {
		name    string
		initial map[string]any
		ops     string
		want    map[string]any
	}{
		{
			// RFC 7644 section 3.5.2.1 example — add a single complex
			// attribute (nickName) on a User. Path-less form: value is a
			// JSON object merged into the top of the resource.
			name: "rfc7644-3.5.2.1-add-nickname",
			initial: map[string]any{
				"schemas":  []any{"urn:ietf:params:scim:schemas:core:2.0:User"},
				"id":       "u1",
				"userName": "alice",
			},
			ops: `[{"op":"add","value":{"nickName":"Alice"}}]`,
			want: map[string]any{
				"schemas":  []any{"urn:ietf:params:scim:schemas:core:2.0:User"},
				"id":       "u1",
				"userName": "alice",
				"nickName": "Alice",
			},
		},
		{
			// RFC 7644 section 3.5.2.2 example — remove the attribute
			// "nickName" by path. Demonstrates the basic path-with-no-
			// filter remove case.
			name: "rfc7644-3.5.2.2-remove-nickname",
			initial: map[string]any{
				"schemas":  []any{"urn:ietf:params:scim:schemas:core:2.0:User"},
				"id":       "u1",
				"userName": "alice",
				"nickName": "Alice",
			},
			ops: `[{"op":"remove","path":"nickName"}]`,
			want: map[string]any{
				"schemas":  []any{"urn:ietf:params:scim:schemas:core:2.0:User"},
				"id":       "u1",
				"userName": "alice",
			},
		},
		{
			// RFC 7644 section 3.5.2.3 example — replace the userName.
			// Path-with-attribute replace on a singular attribute.
			name: "rfc7644-3.5.2.3-replace-userName",
			initial: map[string]any{
				"schemas":  []any{"urn:ietf:params:scim:schemas:core:2.0:User"},
				"id":       "u1",
				"userName": "alice",
			},
			ops: `[{"op":"replace","path":"userName","value":"alice@example.com"}]`,
			want: map[string]any{
				"schemas":  []any{"urn:ietf:params:scim:schemas:core:2.0:User"},
				"id":       "u1",
				"userName": "alice@example.com",
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ops := unmarshalOps(t, c.ops)
			if err := Apply(c.initial, ops); err != nil {
				t.Fatalf("Apply: %v", err)
			}
			if !reflect.DeepEqual(c.initial, c.want) {
				t.Fatalf("post-apply mismatch:\n got=%v\nwant=%v", c.initial, c.want)
			}
		})
	}
}

// TestOpCaseInsensitive ensures RFC 7644 section 3.5.2's
// case-insensitive op shape is honoured. Azure AD emits "Replace"
// (capitalised); Okta emits "replace" (lowercase). Both must dispatch
// the same way.
func TestOpCaseInsensitive(t *testing.T) {
	cases := []string{
		`[{"op":"add","path":"active","value":true}]`,
		`[{"op":"Add","path":"active","value":true}]`,
		`[{"op":"ADD","path":"active","value":true}]`,
		`[{"op":"replace","path":"active","value":true}]`,
		`[{"op":"Replace","path":"active","value":true}]`,
		`[{"op":"REPLACE","path":"active","value":true}]`,
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			target := map[string]any{"id": "u1", "active": false}
			ops := unmarshalOps(t, raw)
			if err := Apply(target, ops); err != nil {
				t.Fatalf("Apply: %v", err)
			}
			if target["active"] != true {
				t.Fatalf("active = %v, want true (op=%q)", target["active"], raw)
			}
		})
	}
}

// TestOpAddOnSingularBehavesAsReplace closes the foot-gun from the task
// file: Azure AD emits op=add for every non-array PATCH, expecting
// replace semantics. The applier must overwrite, not error.
func TestOpAddOnSingularBehavesAsReplace(t *testing.T) {
	target := map[string]any{
		"id":       "u1",
		"userName": "alice",
	}
	ops := unmarshalOps(t, `[{"op":"add","path":"userName","value":"alice@new.example.com"}]`)
	if err := Apply(target, ops); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if target["userName"] != "alice@new.example.com" {
		t.Fatalf("userName = %v, want %q", target["userName"], "alice@new.example.com")
	}
}

// TestOpAddOnMultiValuedAppends covers the multi-valued add behaviour:
// existing list + add of a list = concatenation. RFC 7644 section
// 3.5.2.1 paragraph 3 example with emails[].
func TestOpAddOnMultiValuedAppends(t *testing.T) {
	target := map[string]any{
		"id": "u1",
		"emails": []any{
			map[string]any{"value": "alice@example.com", "primary": true},
		},
	}
	ops := unmarshalOps(t, `[{"op":"add","path":"emails","value":[{"value":"alice@home.example.com","type":"home"}]}]`)
	if err := Apply(target, ops); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	got, ok := target["emails"].([]any)
	if !ok {
		t.Fatalf("emails is not []any: %T", target["emails"])
	}
	if len(got) != 2 {
		t.Fatalf("len(emails) = %d, want 2", len(got))
	}
}

// TestOpRemoveRequiresPath closes the foot-gun from the task file:
// op=remove with empty path must reject with INVALID_PATH, NOT be
// interpreted as "remove the entire resource."
func TestOpRemoveRequiresPath(t *testing.T) {
	target := map[string]any{"id": "u1", "userName": "alice"}
	ops := unmarshalOps(t, `[{"op":"remove"}]`)
	err := Apply(target, ops)
	if err == nil {
		t.Fatalf("expected error on remove with no path")
	}
	if !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("expected error wrapping ErrInvalidPath, got %v", err)
	}
}

// TestOpRemoveWithoutFilterPath covers the simple-path remove form
// (RFC 7644 section 3.5.2.2 paragraph 2 example A).
func TestOpRemoveWithoutFilterPath(t *testing.T) {
	target := map[string]any{"id": "u1", "userName": "alice", "active": true}
	ops := unmarshalOps(t, `[{"op":"remove","path":"active"}]`)
	if err := Apply(target, ops); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, ok := target["active"]; ok {
		t.Fatalf("active still present after remove: %v", target)
	}
}

// TestOpRemoveWithFilterPath covers the filtered-array remove form
// (RFC 7644 section 3.5.2.2 paragraph 2 example B).
func TestOpRemoveWithFilterPath(t *testing.T) {
	target := map[string]any{
		"id": "u1",
		"emails": []any{
			map[string]any{"value": "alice@work.example.com", "type": "work"},
			map[string]any{"value": "alice@home.example.com", "type": "home"},
		},
	}
	ops := unmarshalOps(t, `[{"op":"remove","path":"emails[type eq \"work\"]"}]`)
	if err := Apply(target, ops); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	got := target["emails"].([]any)
	if len(got) != 1 {
		t.Fatalf("len(emails) = %d after remove, want 1", len(got))
	}
	if got[0].(map[string]any)["type"] != "home" {
		t.Fatalf("surviving email type = %v, want home", got[0])
	}
}

// TestOpReplaceWithFilterPath covers the filtered-array replace form.
// Demonstrates that an existing element is updated in place rather
// than the whole list being replaced.
func TestOpReplaceWithFilterPath(t *testing.T) {
	target := map[string]any{
		"id": "g1",
		"members": []any{
			map[string]any{"value": "user-1", "type": "User", "display": "User One"},
			map[string]any{"value": "user-2", "type": "User", "display": "User Two"},
		},
	}
	ops := unmarshalOps(t, `[{"op":"replace","path":"members[value eq \"user-1\"].display","value":"Updated Display"}]`)
	if err := Apply(target, ops); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	got := target["members"].([]any)
	if len(got) != 2 {
		t.Fatalf("len(members) = %d, want 2 (must not drop unmatched)", len(got))
	}
	for _, m := range got {
		mm := m.(map[string]any)
		if mm["value"] == "user-1" && mm["display"] != "Updated Display" {
			t.Fatalf("matched element display not updated: %v", mm)
		}
		if mm["value"] == "user-2" && mm["display"] != "User Two" {
			t.Fatalf("unmatched element mutated: %v", mm)
		}
	}
}

// TestOpAddOnNested covers the dot-path navigation: name.familyName.
// Demonstrates that the parent map is created lazily when missing.
func TestOpAddOnNested(t *testing.T) {
	target := map[string]any{"id": "u1"}
	ops := unmarshalOps(t, `[{"op":"add","path":"name.familyName","value":"Doe"}]`)
	if err := Apply(target, ops); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	name := target["name"].(map[string]any)
	if name["familyName"] != "Doe" {
		t.Fatalf("familyName = %v, want Doe", name["familyName"])
	}
}

// TestOpsAppliedInOrder covers the locked "operations apply in order"
// invariant. A PATCH like [{add /a true}, {remove /a}] must reach an
// "a is removed" final state, not skip the add.
func TestOpsAppliedInOrder(t *testing.T) {
	target := map[string]any{"id": "u1"}
	ops := unmarshalOps(t, `[
		{"op":"add","path":"active","value":true},
		{"op":"remove","path":"active"},
		{"op":"add","path":"active","value":false}
	]`)
	if err := Apply(target, ops); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if target["active"] != false {
		t.Fatalf("active = %v, want false (the last op wins)", target["active"])
	}
}

// TestInvalidOpReturnsInvalidValue covers the dispatcher reject path
// for an unknown op string ("delete" is not a SCIM op; only the three
// constants are).
func TestInvalidOpReturnsInvalidValue(t *testing.T) {
	target := map[string]any{"id": "u1"}
	ops := unmarshalOps(t, `[{"op":"delete","path":"active"}]`)
	err := Apply(target, ops)
	if err == nil {
		t.Fatalf("expected error on unknown op")
	}
	if !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("expected error wrapping ErrInvalidValue, got %v", err)
	}
}

// TestEmptyOpReturnsInvalidValue covers the dispatcher reject path for
// a missing op field. Distinct from unknown op so the diagnostic
// message is unambiguous.
func TestEmptyOpReturnsInvalidValue(t *testing.T) {
	target := map[string]any{"id": "u1"}
	ops := unmarshalOps(t, `[{"path":"active","value":true}]`)
	err := Apply(target, ops)
	if err == nil {
		t.Fatalf("expected error on missing op")
	}
	if !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("expected error wrapping ErrInvalidValue, got %v", err)
	}
}

// TestParsePath_TopLevel covers the simplest path shape.
func TestParsePath_TopLevel(t *testing.T) {
	p, err := ParsePath("userName")
	if err != nil {
		t.Fatalf("ParsePath: %v", err)
	}
	if want := []string{"userName"}; !reflect.DeepEqual(p.Segments, want) {
		t.Fatalf("Segments = %v, want %v", p.Segments, want)
	}
	if p.Filter != nil {
		t.Fatalf("Filter = %v, want nil", p.Filter)
	}
	if p.SchemaURN != "" {
		t.Fatalf("SchemaURN = %q, want empty", p.SchemaURN)
	}
}

// TestParsePath_Nested covers the dot-separated path shape.
func TestParsePath_Nested(t *testing.T) {
	p, err := ParsePath("name.familyName")
	if err != nil {
		t.Fatalf("ParsePath: %v", err)
	}
	if want := []string{"name", "familyName"}; !reflect.DeepEqual(p.Segments, want) {
		t.Fatalf("Segments = %v, want %v", p.Segments, want)
	}
}

// TestParsePath_FilterSubExpression covers the bracketed-filter path
// shape with a sub-attribute selector.
func TestParsePath_FilterSubExpression(t *testing.T) {
	p, err := ParsePath(`members[type eq "User"].value`)
	if err != nil {
		t.Fatalf("ParsePath: %v", err)
	}
	if want := []string{"members", "value"}; !reflect.DeepEqual(p.Segments, want) {
		t.Fatalf("Segments = %v, want %v", p.Segments, want)
	}
	if p.FilterIndex != 0 {
		t.Fatalf("FilterIndex = %d, want 0", p.FilterIndex)
	}
	if p.Filter == nil {
		t.Fatalf("Filter is nil, want non-nil")
	}
}

// TestParsePath_FilterWithoutSubAttr covers the bracketed-filter path
// shape with no sub-attribute selector ("members[type eq \"User\"]").
func TestParsePath_FilterWithoutSubAttr(t *testing.T) {
	p, err := ParsePath(`members[type eq "User"]`)
	if err != nil {
		t.Fatalf("ParsePath: %v", err)
	}
	if want := []string{"members"}; !reflect.DeepEqual(p.Segments, want) {
		t.Fatalf("Segments = %v, want %v", p.Segments, want)
	}
	if p.Filter == nil {
		t.Fatalf("Filter is nil, want non-nil")
	}
}

// TestParsePath_SchemaURNPrefix covers the schema-qualified path shape.
// The URN prefix is stripped + preserved on SchemaURN; Segments holds
// only the bare attribute name.
func TestParsePath_SchemaURNPrefix(t *testing.T) {
	p, err := ParsePath("urn:ietf:params:scim:schemas:core:2.0:User:userName")
	if err != nil {
		t.Fatalf("ParsePath: %v", err)
	}
	if p.SchemaURN != "urn:ietf:params:scim:schemas:core:2.0:User" {
		t.Fatalf("SchemaURN = %q", p.SchemaURN)
	}
	if want := []string{"userName"}; !reflect.DeepEqual(p.Segments, want) {
		t.Fatalf("Segments = %v, want %v", p.Segments, want)
	}
}

// TestParsePath_Empty covers the reject path for an empty path string.
func TestParsePath_Empty(t *testing.T) {
	_, err := ParsePath("")
	if err == nil {
		t.Fatalf("expected error on empty path")
	}
	if !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("expected error wrapping ErrInvalidPath, got %v", err)
	}
}

// TestParsePath_MalformedFilter covers the filter-sub-expression error
// path: the bracket is opened but the contents aren't a valid filter.
// The task contract specifies that the wrapper sentinel is
// ErrInvalidPath (not ErrInvalidFilter) so the handler maps this to
// scimType=invalidPath.
func TestParsePath_MalformedFilter(t *testing.T) {
	_, err := ParsePath(`members[bogus]`)
	if err == nil {
		t.Fatalf("expected error on malformed filter sub-expression")
	}
	if !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("expected error wrapping ErrInvalidPath, got %v", err)
	}
}

// TestRedactedOps_Password covers the sensitive-attribute redaction
// foot-gun. The task contract specifies password is redacted to "***"
// in the audit log; the actual op value is not mutated in place (the
// applier still sees the raw value).
func TestRedactedOps_Password(t *testing.T) {
	ops := unmarshalOps(t, `[
		{"op":"add","path":"password","value":"hunter2"},
		{"op":"replace","path":"userName","value":"alice"}
	]`)
	redacted := RedactedOps(ops)
	// First op (password) redacted to "***"; second op (userName) intact.
	if string(redacted[0].Value) != `"***"` {
		t.Fatalf("password value = %q, want %q", string(redacted[0].Value), `"***"`)
	}
	if string(redacted[1].Value) != `"alice"` {
		t.Fatalf("userName value = %q, want %q", string(redacted[1].Value), `"alice"`)
	}
	// Original ops slice untouched — the redactor returns a copy.
	if string(ops[0].Value) != `"hunter2"` {
		t.Fatalf("original password value mutated: %q", string(ops[0].Value))
	}
}

// TestRedactedOps_SecretURN covers the urn:*:secret pattern. Any path
// ending in ":secret" is redacted.
func TestRedactedOps_SecretURN(t *testing.T) {
	ops := unmarshalOps(t, `[
		{"op":"replace","path":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:secret","value":"sensitive-token"}
	]`)
	redacted := RedactedOps(ops)
	if string(redacted[0].Value) != `"***"` {
		t.Fatalf("secret value = %q, want %q", string(redacted[0].Value), `"***"`)
	}
}

// TestRedactedOps_PathlessWithPasswordKey covers the path-less PATCH
// shape: value is a JSON object whose top-level keys include a
// sensitive attribute name. The merge-PATCH shape Azure AD occasionally
// uses for "set everything at once."
func TestRedactedOps_PathlessWithPasswordKey(t *testing.T) {
	ops := unmarshalOps(t, `[
		{"op":"add","value":{"userName":"alice","password":"hunter2"}}
	]`)
	redacted := RedactedOps(ops)
	var v map[string]any
	if err := json.Unmarshal(redacted[0].Value, &v); err != nil {
		t.Fatalf("unmarshal redacted value: %v", err)
	}
	if v["password"] != "***" {
		t.Fatalf("password = %v, want \"***\"", v["password"])
	}
	if v["userName"] != "alice" {
		t.Fatalf("userName = %v, want alice (non-sensitive must pass through)", v["userName"])
	}
}

// TestApply_NilTarget covers the safety net: a nil target map can't be
// mutated; Apply must reject cleanly rather than panic.
func TestApply_NilTarget(t *testing.T) {
	err := Apply(nil, []Operation{{Op: OpAdd, Path: "active", Value: json.RawMessage(`true`)}})
	if err == nil {
		t.Fatalf("expected error on nil target")
	}
	if !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("expected error wrapping ErrInvalidValue, got %v", err)
	}
}

// TestApply_FilteredAddWithNoMatch covers RFC 7644 section 3.5.2.1
// paragraph 5: a filtered add against a missing element appends a new
// element to the multi-valued attribute.
func TestApply_FilteredAddWithNoMatch(t *testing.T) {
	target := map[string]any{
		"id":      "g1",
		"members": []any{},
	}
	ops := unmarshalOps(t, `[{"op":"add","path":"members[value eq \"user-1\"].display","value":"User One"}]`)
	if err := Apply(target, ops); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	got := target["members"].([]any)
	if len(got) != 1 {
		t.Fatalf("len(members) = %d, want 1 (filtered add must append on no-match)", len(got))
	}
	elem := got[0].(map[string]any)
	if elem["value"] != "user-1" || elem["display"] != "User One" {
		t.Fatalf("seeded element = %v, want {value: user-1, display: User One}", elem)
	}
}

// TestApply_ErrorWrapsOperationIndex covers the diagnostic-context
// guarantee: a per-op failure surfaces with the op index + op + path
// so an operator can grep the audit log for the offending PATCH.
func TestApply_ErrorWrapsOperationIndex(t *testing.T) {
	target := map[string]any{"id": "u1"}
	ops := unmarshalOps(t, `[
		{"op":"add","path":"active","value":true},
		{"op":"remove"}
	]`)
	err := Apply(target, ops)
	if err == nil {
		t.Fatalf("expected error on op 1 (empty path on remove)")
	}
	if !strings.Contains(err.Error(), "operation 1") {
		t.Fatalf("error %v should mention operation 1", err)
	}
	// Op 0 (add active) DID apply before op 1 failed.
	if target["active"] != true {
		t.Fatalf("op 0 should have applied before op 1 failure; active = %v", target["active"])
	}
}

// TestFilterSubExpressionEvalsAgainstInMemory covers the foot-gun call-
// out in the task file: the filter sub-expression on PATCH paths
// operates on the in-memory JSON resource, not on a database query.
// Specifically, "members[value eq \"X\"]" must find element with
// value="X" in the resource's members list, never reach SQL.
func TestFilterSubExpressionEvalsAgainstInMemory(t *testing.T) {
	target := map[string]any{
		"id": "g1",
		"members": []any{
			map[string]any{"value": "alice-id", "type": "User"},
			map[string]any{"value": "bob-id", "type": "User"},
		},
	}
	ops := unmarshalOps(t, `[{"op":"remove","path":"members[value eq \"alice-id\"]"}]`)
	if err := Apply(target, ops); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	got := target["members"].([]any)
	if len(got) != 1 {
		t.Fatalf("len(members) = %d, want 1", len(got))
	}
	if got[0].(map[string]any)["value"] != "bob-id" {
		t.Fatalf("surviving member = %v, want value=bob-id", got[0])
	}
}

// TestPathLessReplaceMergesTopLevel covers RFC 7644 section 3.5.2.3
// paragraph 2: a path-less replace merges the value object's top-level
// keys into the target. Distinct from a path-less add only in how
// multi-valued attributes are handled (replace = overwrite array,
// add = append to array).
func TestPathLessReplaceMergesTopLevel(t *testing.T) {
	target := map[string]any{
		"id":       "u1",
		"userName": "alice",
		"active":   true,
	}
	ops := unmarshalOps(t, `[{"op":"replace","value":{"userName":"bob","active":false}}]`)
	if err := Apply(target, ops); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if target["userName"] != "bob" {
		t.Fatalf("userName = %v, want bob", target["userName"])
	}
	if target["active"] != false {
		t.Fatalf("active = %v, want false", target["active"])
	}
	// id (not in overlay) must pass through.
	if target["id"] != "u1" {
		t.Fatalf("id = %v, want u1 (overlay must not erase other fields)", target["id"])
	}
}

// unmarshalOps decodes the JSON-encoded ops list into a slice of
// Operation. Test helper.
func unmarshalOps(t *testing.T, raw string) []Operation {
	t.Helper()
	var ops []Operation
	if err := json.Unmarshal([]byte(raw), &ops); err != nil {
		t.Fatalf("unmarshal ops %q: %v", raw, err)
	}
	return ops
}
