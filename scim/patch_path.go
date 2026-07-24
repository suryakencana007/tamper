package scim

import (
	"encoding/json"
	"fmt"
	"strings"

	fp "github.com/scim2/filter-parser/v2"
)

// Path is the parsed RFC 7644 section 3.5.2.3 path. Mirrors the
// scim2/filter-parser/v2 fp.Path shape but adds the dot-separated
// segment list + the schema URN prefix as first-class fields so the
// apply walker doesn't have to re-parse.
//
// Grammar (RFC 7644 section 3.5.2.3):
//
//	PATH = ATTRNAME ( "." ATTRNAME )* ( "[" FILTER "]" )? ( "." ATTRNAME )*
//
// Examples:
//
//   - userName                                            -> Segments=[userName]
//   - name.familyName                                     -> Segments=[name, familyName]
//   - members                                             -> Segments=[members]
//   - members[type eq "User"]                             -> Segments=[members], Filter=...
//   - members[type eq "User"].value                       -> Segments=[members, value], Filter=...
//   - urn:ietf:params:scim:schemas:core:2.0:User:userName -> SchemaURN=urn:..., Segments=[userName]
//
// Filter is the parsed sub-expression (re-uses Task 00's library pin).
// Apply walks Filter against the in-memory list — Task 01's SQL
// translator is NOT used here, the filter applies to the JSON resource
// snapshot the applier holds, not to a database query.
type Path struct {
	// SchemaURN is the optional schema-URN prefix. Empty when the path
	// is unqualified. The applier ignores the URN when navigating
	// target (v1.0 + v1.13 are single-namespace core: schema).
	SchemaURN string
	// Segments is the dot-split attribute path. Includes both the
	// pre-filter segments AND the post-filter sub-attribute (if any).
	// Multi-valued attributes are anchored at the segment immediately
	// before the filter.
	Segments []string
	// FilterIndex is the index in Segments at which the filter applies.
	// 0-based; -1 when there is no filter. A filter at index N applies
	// to Segments[N] (which must resolve to a []any on target). Any
	// segment after FilterIndex is a sub-attribute selector inside the
	// matched element.
	FilterIndex int
	// Filter is the parsed bracketed filter expression. nil when there
	// is no filter. Uses pointer types throughout
	// (*fp.AttributeExpression etc.) per Task 00's library-surface
	// convention.
	Filter fp.Expression
}

// ParsePath parses a SCIM PATCH path string into a *Path. Uses the
// scim2/filter-parser/v2 ParsePath under the hood for the bracketed
// filter grammar, then wraps with the dot-split segment list the apply
// walker consumes.
//
// Returns a *PatchError wrapping ErrInvalidPath on grammar violations.
// Filter sub-expression errors also wrap *PatchError (not *FilterError)
// — the handler error mapping checks errors.Is(err, ErrInvalidPath)
// to differentiate from list-filter errors.
func ParsePath(s string) (*Path, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, newPathError("path is empty", nil)
	}
	schemaURN, rest := stripSchemaURN(s)
	libPath, err := fp.ParsePath([]byte(rest))
	if err != nil {
		return nil, newPathError(fmt.Sprintf("parse %q", s), err)
	}
	out := &Path{
		SchemaURN:   schemaURN,
		FilterIndex: -1,
	}
	// AttributePath always has the leading attribute name + an optional
	// sub-attribute (after the dot before any bracket).
	out.Segments = append(out.Segments, libPath.AttributePath.AttributeName)
	if libPath.AttributePath.SubAttribute != nil {
		out.Segments = append(out.Segments, *libPath.AttributePath.SubAttribute)
	}
	if libPath.ValueExpression != nil {
		// Filter anchors at the segment that was last appended before
		// the bracket — i.e. the AttributeName. Sub-attributes inside
		// the AttributePath before the bracket would be unusual (the
		// grammar puts the bracket right after AttributeName) but the
		// library only allows one pre-bracket segment, so FilterIndex
		// is always 0 in the canonical case.
		out.FilterIndex = 0
		out.Filter = libPath.ValueExpression
	}
	if libPath.SubAttribute != nil {
		out.Segments = append(out.Segments, *libPath.SubAttribute)
	}
	return out, nil
}

// stripSchemaURN looks for the RFC 7643 section 4 schema-URN prefix on
// path. SCIM URNs start with "urn:ietf:params:scim:schemas:" and are
// followed by a ":" + the bare attribute name. Returns ("", s) when
// there's no prefix to strip.
//
// Examples:
//
//	urn:ietf:params:scim:schemas:core:2.0:User:userName
//	  -> ("urn:ietf:params:scim:schemas:core:2.0:User", "userName")
//	userName
//	  -> ("", "userName")
//
// The applier ignores the URN when navigating target — v1.0 + v1.13 are
// single-namespace core: schema. The URN is preserved for audit-log
// fidelity (the IdP-emitted path round-trips into the audit entry).
func stripSchemaURN(s string) (string, string) {
	const prefix = "urn:ietf:params:scim:schemas:"
	if !strings.HasPrefix(s, prefix) {
		return "", s
	}
	// The URN is structured as "urn:...:User:userName" — the final ":"
	// separates the schema URN from the bare attribute path. The bare
	// path may itself contain "." and "[" but never ":".
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", s
	}
	return s[:i], s[i+1:]
}

// apply walks target according to p and dispatches op against the
// resolved attribute. value is the operation's raw value (nil for
// remove).
func (p *Path) apply(target map[string]any, value json.RawMessage, op Op) error {
	if len(p.Segments) == 0 {
		return newPathError("path has no attribute name", nil)
	}
	if p.Filter == nil {
		return p.applySimple(target, value, op)
	}
	return p.applyFiltered(target, value, op)
}

// applySimple handles dot-separated paths without a filter. The walker
// navigates to the parent map by following Segments[0..n-2], then sets
// / appends / deletes Segments[n-1] on that parent.
func (p *Path) applySimple(target map[string]any, value json.RawMessage, op Op) error {
	if len(p.Segments) == 1 {
		return applyLeaf(target, p.Segments[0], value, op)
	}
	parent, err := navigateOrCreate(target, p.Segments[:len(p.Segments)-1], op)
	if err != nil {
		return err
	}
	if parent == nil {
		// remove on a missing parent is a no-op (RFC 7644 doesn't
		// require erroring; matches Azure AD's tolerance for stale
		// PATCHes against partially-deleted resources).
		if op == OpRemove {
			return nil
		}
		return newPathError(fmt.Sprintf("parent path %q does not resolve to a map",
			strings.Join(p.Segments[:len(p.Segments)-1], ".")), nil)
	}
	return applyLeaf(parent, p.Segments[len(p.Segments)-1], value, op)
}

// resolveKey returns the key already present in m that case-insensitively
// equals name, or name unchanged when m holds no such key.
//
// RFC 7643 section 2.1 and RFC 7644 section 3.10 make SCIM attribute
// names case-INSENSITIVE, so an IdP may legitimately send "Active",
// "userName" or "ACTIVE" for the attribute stored as "active". Matching
// map keys byte-exactly meant such a PATCH wrote a *phantom* key that the
// caller's typed round-trip then discarded: the mutation was silently
// lost while the handler still answered 200 with the unchanged resource.
// For a deprovision ("replace active=false") that turns an offboarding
// request into a no-op the IdP records as success.
//
// Exact match wins first, so every PATCH that works today follows the
// identical path and the scan only runs for input that is currently a
// silent no-op. This mirrors what the package already does for the `op`
// field, which Operation.UnmarshalJSON lowercases for the same reason.
//
// When a map somehow holds two case-variants of one name the smallest by
// byte order is chosen, so behaviour does not depend on Go's randomised
// map iteration.
func resolveKey(m map[string]any, name string) string {
	if m == nil {
		return name
	}
	if _, ok := m[name]; ok {
		return name
	}
	best := ""
	for k := range m {
		if strings.EqualFold(k, name) && (best == "" || k < best) {
			best = k
		}
	}
	if best != "" {
		return best
	}
	return name
}

// applyLeaf sets / appends / deletes leaf on parent under the given op.
// The behaviour is type-driven on the existing value of parent[leaf]:
//
//   - OpRemove: delete the key. Multi-valued without filter wipes the
//     whole array per RFC 7644 section 3.5.2.2 paragraph 2 example.
//   - OpReplace: overwrite the key with the decoded value.
//   - OpAdd on a singular: same as OpReplace (RFC 7644 section 3.5.2.1
//     paragraph 4 — Azure AD emits add for every non-array PATCH).
//   - OpAdd on a multi-valued: append the incoming array (or one
//     scalar) to the existing slice.
func applyLeaf(parent map[string]any, leaf string, value json.RawMessage, op Op) error {
	// Case-insensitive per RFC 7643 section 2.1 — resolve once here and
	// every read/write/delete below lands on the stored key.
	leaf = resolveKey(parent, leaf)
	if op == OpRemove {
		delete(parent, leaf)
		return nil
	}
	var decoded any
	if err := json.Unmarshal(value, &decoded); err != nil {
		return newValueError(fmt.Sprintf("value for %q is not valid JSON", leaf), err)
	}
	existing, present := parent[leaf]
	if op == OpAdd && present {
		if existingSlice, ok := existing.([]any); ok {
			if incomingSlice, ok := decoded.([]any); ok {
				parent[leaf] = append(existingSlice, incomingSlice...)
				return nil
			}
			// Add of a scalar to an existing list — append the scalar.
			parent[leaf] = append(existingSlice, decoded)
			return nil
		}
	}
	parent[leaf] = decoded
	return nil
}

// navigateOrCreate walks the segment list, creating intermediate maps
// on add / replace and returning nil on remove against a missing
// intermediate. Each segment must resolve to a map; arrays in the
// middle of a simple (filterless) path are a grammar violation per RFC
// 7644 section 3.5.2.3 — the bracket-filter syntax is the canonical way
// to descend into arrays.
func navigateOrCreate(target map[string]any, segments []string, op Op) (map[string]any, error) {
	current := target
	for _, seg := range segments {
		seg = resolveKey(current, seg)
		next, ok := current[seg]
		if !ok {
			if op == OpRemove {
				return nil, nil
			}
			created := map[string]any{}
			current[seg] = created
			current = created
			continue
		}
		nextMap, ok := next.(map[string]any)
		if !ok {
			return nil, newPathError(
				fmt.Sprintf("intermediate segment %q is not an object", seg), nil)
		}
		current = nextMap
	}
	return current, nil
}

// applyFiltered handles bracketed paths like
// "members[type eq \"User\"].value". The walker:
//
//  1. Navigates to the multi-valued attribute (Segments[FilterIndex]).
//  2. For each element matching Filter, either:
//     - Op=remove: drop the element from the slice.
//     - Op=replace / add: if there's a sub-attribute selector after
//     the filter, set that sub-attr on the matched element; else
//     overwrite the matched element with value.
//  3. If no element matched + op == add: append a new element built
//     from value (or {sub-attr: value} when a sub-attr selector is
//     present). RFC 7644 section 3.5.2.1 paragraph 5: a filtered add
//     against a missing element creates one.
func (p *Path) applyFiltered(target map[string]any, value json.RawMessage, op Op) error {
	if p.FilterIndex < 0 || p.FilterIndex >= len(p.Segments) {
		return newPathError("filter index out of range", nil)
	}
	// Navigate to the parent map holding the multi-valued attribute.
	preFilter := p.Segments[:p.FilterIndex]
	arrayKey := p.Segments[p.FilterIndex]
	postFilter := p.Segments[p.FilterIndex+1:]

	parent := target
	if len(preFilter) > 0 {
		nav, err := navigateOrCreate(target, preFilter, op)
		if err != nil {
			return err
		}
		if nav == nil {
			if op == OpRemove {
				return nil
			}
			return newPathError("filter parent path does not resolve", nil)
		}
		parent = nav
	}
	arrayKey = resolveKey(parent, arrayKey)
	raw, present := parent[arrayKey]
	var arr []any
	if present {
		var ok bool
		arr, ok = raw.([]any)
		if !ok {
			return newPathError(
				fmt.Sprintf("filtered attribute %q is not a multi-valued list", arrayKey), nil)
		}
	}

	matched := 0
	newArr := make([]any, 0, len(arr))
	for _, elem := range arr {
		elemMap, ok := elem.(map[string]any)
		if !ok {
			// Non-object elements can't match a filter; preserve them.
			newArr = append(newArr, elem)
			continue
		}
		ok, err := evalFilter(p.Filter, elemMap)
		if err != nil {
			return err
		}
		if !ok {
			newArr = append(newArr, elem)
			continue
		}
		matched++
		switch op {
		case OpRemove:
			if len(postFilter) == 0 {
				// drop the element
				continue
			}
			// remove sub-attribute on the matched element.
			deletePath(elemMap, postFilter)
			newArr = append(newArr, elemMap)
		case OpReplace, OpAdd:
			if err := assignFiltered(elemMap, postFilter, value, op); err != nil {
				return err
			}
			newArr = append(newArr, elemMap)
		}
	}
	parent[arrayKey] = newArr

	// RFC 7644 section 3.5.2.1 paragraph 5: filtered add with no match
	// appends a new element. For replace the spec is quieter; we mirror
	// add's behaviour for parity with Azure AD's expectations.
	if matched == 0 && (op == OpAdd || op == OpReplace) {
		newElem, err := buildFilteredAppend(p.Filter, postFilter, value)
		if err != nil {
			return err
		}
		if newElem != nil {
			parent[arrayKey] = append(newArr, newElem)
		}
	}
	return nil
}

// deletePath walks segs on m and deletes the leaf. No-op on missing
// intermediate segments — remove tolerates a partially-stale resource.
func deletePath(m map[string]any, segs []string) {
	cur := m
	for i, seg := range segs {
		seg = resolveKey(cur, seg)
		if i == len(segs)-1 {
			delete(cur, seg)
			return
		}
		next, ok := cur[seg].(map[string]any)
		if !ok {
			return
		}
		cur = next
	}
}

// assignFiltered sets / appends a sub-attribute on a filter-matched
// element. When postFilter is empty, the entire matched element is
// replaced with the decoded value (which must be an object) — that's
// the "replace /members[id eq \"x\"]" shape.
func assignFiltered(elem map[string]any, postFilter []string, value json.RawMessage, op Op) error {
	if len(postFilter) == 0 {
		var decoded any
		if err := json.Unmarshal(value, &decoded); err != nil {
			return newValueError("value for filtered element is not valid JSON", err)
		}
		decodedMap, ok := decoded.(map[string]any)
		if !ok {
			return newValueError("value for filtered element must be a JSON object", nil)
		}
		for k, v := range decodedMap {
			elem[resolveKey(elem, k)] = v
		}
		return nil
	}
	// Sub-attribute path inside the matched element. Reuse applyLeaf
	// recursively after walking down.
	if len(postFilter) == 1 {
		return applyLeaf(elem, postFilter[0], value, op)
	}
	// Multi-level sub-attribute: navigate, then apply leaf.
	parent, err := navigateOrCreate(elem, postFilter[:len(postFilter)-1], op)
	if err != nil {
		return err
	}
	if parent == nil {
		return newPathError("sub-attribute parent missing", nil)
	}
	return applyLeaf(parent, postFilter[len(postFilter)-1], value, op)
}

// buildFilteredAppend constructs a new array element for a filtered add
// where no existing element matched. The new element seeds itself from
// the filter's attribute=value comparison (so "members[value eq \"x\"]"
// with sub-attr ".display" + value "Display X" produces
// {value: "x", display: "Display X"}).
//
// Returns (nil, nil) when the filter is too complex to project into a
// seed element (e.g., logical AND/OR). In that case the operation is a
// no-op on append.
func buildFilteredAppend(expr fp.Expression, postFilter []string, value json.RawMessage) (map[string]any, error) {
	attrExpr, ok := expr.(*fp.AttributeExpression)
	if !ok {
		return nil, nil // logical filters can't seed an append cleanly
	}
	if attrExpr.Operator != fp.EQ {
		return nil, nil
	}
	seed := map[string]any{
		canonicalAttrName(attrExpr.AttributePath): attrExpr.CompareValue,
	}
	if len(postFilter) == 0 {
		// Replace the seed entirely with the value object (if any).
		if len(value) == 0 {
			return seed, nil
		}
		var decoded any
		if err := json.Unmarshal(value, &decoded); err != nil {
			return nil, newValueError("value for filtered append is not valid JSON", err)
		}
		if m, ok := decoded.(map[string]any); ok {
			for k, v := range m {
				seed[k] = v
			}
			return seed, nil
		}
		// Non-object value can't merge into a seed; return seed alone.
		return seed, nil
	}
	// Sub-attribute selector: seed{subAttr: value}.
	if len(value) == 0 {
		return seed, nil
	}
	var decoded any
	if err := json.Unmarshal(value, &decoded); err != nil {
		return nil, newValueError("value for filtered append sub-attr is not valid JSON", err)
	}
	cur := seed
	for i, seg := range postFilter {
		if i == len(postFilter)-1 {
			cur[seg] = decoded
			break
		}
		next := map[string]any{}
		cur[seg] = next
		cur = next
	}
	return seed, nil
}

// evalFilter walks the parsed filter against elem (an in-memory
// resource element) and reports whether the element matches. Re-uses
// the scim2/filter-parser/v2 AST types but evaluates against a map
// rather than translating to SQL (which is Task 01's surface). The
// filter sub-expression on PATCH paths operates on the JSON resource
// snapshot the applier holds, never on a database query.
func evalFilter(expr fp.Expression, elem map[string]any) (bool, error) {
	switch e := expr.(type) {
	case *fp.AttributeExpression:
		return evalAttribute(e, elem)
	case *fp.LogicalExpression:
		left, err := evalFilter(e.Left, elem)
		if err != nil {
			return false, err
		}
		right, err := evalFilter(e.Right, elem)
		if err != nil {
			return false, err
		}
		switch e.Operator {
		case fp.AND:
			return left && right, nil
		case fp.OR:
			return left || right, nil
		default:
			return false, newPathError(
				fmt.Sprintf("unsupported logical operator %q in filter", e.Operator), nil)
		}
	case *fp.NotExpression:
		inner, err := evalFilter(e.Expression, elem)
		if err != nil {
			return false, err
		}
		return !inner, nil
	case *fp.ValuePath:
		return false, newPathError(
			"nested value-path filters are not supported in PATCH paths", nil)
	default:
		return false, newPathError(
			fmt.Sprintf("unknown expression node %T in filter", expr), nil)
	}
}

// evalAttribute evaluates a single leaf comparison against an
// in-memory element. Supports the same operator set as Task 01's SQL
// translator. Missing attributes evaluate to false (the "present" check
// short-circuits to PR=present-and-non-empty).
func evalAttribute(e *fp.AttributeExpression, elem map[string]any) (bool, error) {
	attrName := canonicalAttrName(e.AttributePath)
	// Filter sub-attribute paths inside PATCH brackets are dotted (e.g.
	// "name.familyName eq ..."). Navigate the dotted path.
	parts := strings.Split(attrName, ".")
	var raw any = elem
	for _, p := range parts {
		curMap, ok := raw.(map[string]any)
		if !ok {
			raw = nil
			break
		}
		raw, ok = curMap[resolveKey(curMap, p)]
		if !ok {
			raw = nil
			break
		}
	}
	if raw == nil {
		return e.Operator == fp.NE, nil
	}
	switch e.Operator {
	case fp.EQ:
		return equalValues(raw, e.CompareValue), nil
	case fp.NE:
		return !equalValues(raw, e.CompareValue), nil
	case fp.CO:
		return strings.Contains(asString(raw), asString(e.CompareValue)), nil
	case fp.SW:
		return strings.HasPrefix(asString(raw), asString(e.CompareValue)), nil
	case fp.EW:
		return strings.HasSuffix(asString(raw), asString(e.CompareValue)), nil
	case fp.GT:
		return cmpStrings(asString(raw), asString(e.CompareValue)) > 0, nil
	case fp.GE:
		return cmpStrings(asString(raw), asString(e.CompareValue)) >= 0, nil
	case fp.LT:
		return cmpStrings(asString(raw), asString(e.CompareValue)) < 0, nil
	case fp.LE:
		return cmpStrings(asString(raw), asString(e.CompareValue)) <= 0, nil
	case fp.PR:
		return asString(raw) != "", nil
	default:
		return false, newPathError(
			fmt.Sprintf("unsupported operator %q in filter", e.Operator), nil)
	}
}

// equalValues compares two decoded JSON values for SCIM eq semantics.
// JSON-decoded numbers all land as float64; bool, string, and nil are
// themselves. The library returns string-typed CompareValue for quoted
// literals, bool for true/false literals, float64 for unquoted numbers.
func equalValues(a, b any) bool {
	switch av := a.(type) {
	case string:
		if bv, ok := b.(string); ok {
			return av == bv
		}
		return av == asString(b)
	case bool:
		if bv, ok := b.(bool); ok {
			return av == bv
		}
		return asString(a) == asString(b)
	case float64:
		if bv, ok := b.(float64); ok {
			return av == bv
		}
	}
	return asString(a) == asString(b)
}

// asString coerces any to a string for the LIKE-family comparisons.
// json-decoded numbers (float64) format via fmt.Sprint so "co" / "sw"
// against a numeric attribute degrades gracefully.
func asString(v any) string {
	switch s := v.(type) {
	case string:
		return s
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

// cmpStrings is strings.Compare. Wrapped so the gt/ge/lt/le branches
// read uniformly + so unit tests don't need to import strings.
func cmpStrings(a, b string) int {
	return strings.Compare(a, b)
}
