package scim

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Op is one of "add", "remove", "replace" per RFC 7644 section 3.5.2.
//
// SCIM clients are case-insensitive on the JSON "op" field (Azure AD
// emits "Replace", Okta emits "replace"). The unmarshal hook on
// Operation normalises to lowercase before the dispatcher sees it so
// every consumer of this type compares against the lowercase constant.
type Op string

const (
	// OpAdd is the SCIM "add" operation. On singular attributes it
	// behaves as a replace (RFC 7644 section 3.5.2.1 paragraph 4 — Azure
	// AD emits add for every non-array PATCH). On multi-valued
	// attributes it appends. On filtered paths it matches existing
	// elements (adds to their sub-attribute) or appends a new element.
	OpAdd Op = "add"
	// OpRemove is the SCIM "remove" operation. RFC 7644 section 3.5.2.2
	// paragraph 1: the path field is REQUIRED for remove. A remove with
	// an empty path must reject with INVALID_PATH 400 (not be
	// interpreted as "remove the entire resource").
	OpRemove Op = "remove"
	// OpReplace is the SCIM "replace" operation. Singular: overwrite.
	// Multi-valued without filter: replace the whole array. Multi-valued
	// with filter: overwrite the matching element(s) in place.
	OpReplace Op = "replace"
)

// Operation is a single PATCH operation parsed from the request body.
// JSON shape per RFC 7644 section 3.5.2:
//
//	{ "op": "add", "path": "...", "value": ... }
//
// Op + Path are strings; Value is left as json.RawMessage because each
// operation's value shape depends on its target attribute (string, bool,
// list of complex objects, etc.) and the dispatcher's per-attribute
// helper does the typed decode.
type Operation struct {
	Op    Op              `json:"op"`
	Path  string          `json:"path,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

// UnmarshalJSON normalises op to lowercase. RFC 7644 section 3.5.2
// declares op as case-insensitive; Azure AD emits "Replace", Okta emits
// "replace". Doing the normalisation here keeps the dispatcher's switch
// case-sensitive (which keeps the foot-gun surface narrow — every other
// caller compares against the lowercase constants).
func (o *Operation) UnmarshalJSON(data []byte) error {
	// Defer to the default decoder via an alias so the recursive
	// UnmarshalJSON call doesn't infinite-loop.
	type rawOp Operation
	var raw rawOp
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	raw.Op = Op(strings.ToLower(string(raw.Op)))
	*o = Operation(raw)
	return nil
}

// Request is the SCIM PATCH request envelope per RFC 7644 section 3.5.2.
// Operations apply in declared order; op N's mutations are visible to
// op N+1. The dispatcher does NOT reorder or parallelise — that would
// violate spec (a PATCH like [{add /a}, {remove /a}] must reach an
// "a is removed" final state, not skip the add).
type Request struct {
	Schemas    []string    `json:"schemas"`
	Operations []Operation `json:"Operations"`
}

// PatchSchemaURN is the SCIM URN for the PATCH operations message. RFC
// 7644 section 3.5.2 declares this as the required "schemas" entry on
// the PATCH request envelope. Clients that omit it MAY be rejected; we
// accept the omission for parity with other servers (Azure AD, Okta
// occasionally elide it on small PATCHes).
const PatchSchemaURN = "urn:ietf:params:scim:api:messages:2.0:PatchOp"

// ErrInvalidPath is the sentinel every *PatchError wraps. Handlers gate
// on errors.Is(err, scim.ErrInvalidPath) to translate into the RFC 7644
// INVALID_PATH response (HTTP 400, scimType=invalidPath).
//
// Distinct from ErrInvalidFilter (Task 00 — list filter parser) so the
// handler can map PATCH path failures vs filter-sub-expression failures
// to the correct scimType. A PATCH "members[badattr eq 1]" error wraps
// ErrInvalidFilter (filter sub-expression is malformed); a PATCH with
// an empty path on remove wraps ErrInvalidPath (path grammar
// violation).
var ErrInvalidPath = errors.New("scim patch: invalid path")

// ErrInvalidValue is the sentinel for value-typing failures during
// apply. The body parsed cleanly + the path resolved, but the value
// could not be cast to the target attribute's type (e.g., a string
// where active expects a bool).
var ErrInvalidValue = errors.New("scim patch: invalid value")

// PatchError is the envelope handlers convert into the RFC 7644
// INVALID_PATH / INVALID_VALUE error response. Carries a free-form
// message, a kind sentinel (ErrInvalidPath / ErrInvalidValue), and an
// optional wrapped cause (library error, decode failure, etc.).
//
// The Is method reports true for the kind sentinel AND for any error
// the cause chain wraps. That lets handlers gate uniformly on
// errors.Is(err, ErrInvalidPath) regardless of whether the underlying
// cause is the bare sentinel, a wrapped library error, or both.
//
// Mirrors the *FilterError shape from filter.go intentionally — every
// SCIM error envelope (filter, path, value) follows the same Is +
// Unwrap pattern, so handler error mapping reads uniformly.
type PatchError struct {
	Kind    error // ErrInvalidPath or ErrInvalidValue — never nil
	Message string
	cause   error
}

// Error implements the error interface.
func (e *PatchError) Error() string {
	if e == nil {
		return ""
	}
	if e.cause != nil {
		return fmt.Sprintf("scim patch: %s: %v", e.Message, e.cause)
	}
	return "scim patch: " + e.Message
}

// Unwrap returns the wrapped cause so errors.Is walks the chain.
// Returns the Kind sentinel when there's no library-level cause so
// errors.Is(err, ErrInvalidPath) walks correctly even on bare-message
// paths.
func (e *PatchError) Unwrap() error {
	if e == nil {
		return nil
	}
	if e.cause != nil {
		return e.cause
	}
	return e.Kind
}

// Is reports whether target is this error's kind sentinel OR whether
// it appears in the wrapped cause chain. Lets handlers write
// errors.Is(err, ErrInvalidPath) over either shape.
func (e *PatchError) Is(target error) bool {
	if e == nil {
		return false
	}
	if target == e.Kind {
		return true
	}
	return errors.Is(e.cause, target)
}

func newPathError(msg string, cause error) *PatchError {
	return &PatchError{Kind: ErrInvalidPath, Message: msg, cause: cause}
}

func newValueError(msg string, cause error) *PatchError {
	return &PatchError{Kind: ErrInvalidValue, Message: msg, cause: cause}
}

// Apply walks ops in order and applies each against target. target is
// mutated in place (callers who need to roll back on partial failure
// must snapshot the resource map before calling). Returns the first
// operation error wrapped with operation index + op + path for
// diagnostic context.
//
// Resource representation is map[string]any — the JSON-decoded SCIM
// resource as the IdP would see it on a GET. Handlers marshal their
// typed userResource / groupResource into this shape via
// json.Marshal/Unmarshal, call Apply, then marshal back. Keeps the
// applier generic (User + Group share the same code path) and the
// dispatcher reflection-free.
//
// Operations apply in declared order per RFC 7644 section 3.5.2:
// op N's mutations are visible to op N+1. Don't parallelise; don't
// reorder "all adds before all removes."
func Apply(target map[string]any, ops []Operation) error {
	if target == nil {
		return newValueError("target resource is nil", nil)
	}
	for i, op := range ops {
		if err := applyOne(target, op); err != nil {
			return fmt.Errorf("operation %d (%s %q): %w", i, op.Op, op.Path, err)
		}
	}
	return nil
}

// applyOne dispatches a single PATCH operation. Path-less operations
// merge the whole value as a partial-resource overlay (RFC 7644 section
// 3.5.2.1 paragraph 2 for add; section 3.5.2.3 paragraph 2 for replace).
// Remove always requires a path (section 3.5.2.2 paragraph 1).
func applyOne(target map[string]any, op Operation) error {
	switch op.Op {
	case OpAdd:
		return applyAdd(target, op)
	case OpRemove:
		return applyRemove(target, op)
	case OpReplace:
		return applyReplace(target, op)
	case "":
		return newValueError(`"op" is required`, nil)
	default:
		return newValueError(fmt.Sprintf("unknown op %q", op.Op), nil)
	}
}

// applyAdd handles "add" per RFC 7644 section 3.5.2.1.
//
//   - path empty: value MUST be a JSON object; merge each top-level
//     attribute into the target (singular: replace; multi-valued: append).
//   - path simple: navigate to the parent + set / append by attribute type.
//   - path filtered: match-and-add-to-sub-attr OR append a new element.
func applyAdd(target map[string]any, op Operation) error {
	if op.Path == "" {
		return mergePartialResource(target, op.Value, mergeModeAdd)
	}
	p, err := ParsePath(op.Path)
	if err != nil {
		return err
	}
	return p.apply(target, op.Value, OpAdd)
}

// applyRemove handles "remove" per RFC 7644 section 3.5.2.2.
//
//   - path REQUIRED — empty path is INVALID_PATH 400 (NOT "wipe the whole
//     resource").
//   - path simple: delete the attribute from target (or set to []).
//   - path filtered: drop matching elements from the multi-valued attr.
func applyRemove(target map[string]any, op Operation) error {
	if op.Path == "" {
		return newPathError(`"path" is required for op=remove`, nil)
	}
	p, err := ParsePath(op.Path)
	if err != nil {
		return err
	}
	return p.apply(target, nil, OpRemove)
}

// applyReplace handles "replace" per RFC 7644 section 3.5.2.3.
//
//   - path empty: same merge behaviour as path-less add — top-level
//     attribute overlay, singular overwrite, multi-valued whole-array
//     replace.
//   - path simple: overwrite the attribute outright.
//   - path filtered: overwrite the matching element(s).
func applyReplace(target map[string]any, op Operation) error {
	if op.Path == "" {
		return mergePartialResource(target, op.Value, mergeModeReplace)
	}
	p, err := ParsePath(op.Path)
	if err != nil {
		return err
	}
	return p.apply(target, op.Value, OpReplace)
}

type mergeMode int

const (
	mergeModeAdd mergeMode = iota
	mergeModeReplace
)

// mergePartialResource overlays a JSON object onto target. Used by
// path-less add + path-less replace (RFC 7644 section 3.5.2.1 paragraph
// 2 + section 3.5.2.3 paragraph 2). For multi-valued attributes under
// mergeModeAdd, the incoming list is appended; under mergeModeReplace
// the existing list is wholesale replaced.
func mergePartialResource(target map[string]any, raw json.RawMessage, mode mergeMode) error {
	if len(raw) == 0 {
		return newValueError(`"value" is required for path-less op`, nil)
	}
	var overlay map[string]any
	if err := json.Unmarshal(raw, &overlay); err != nil {
		return newValueError("value is not a JSON object", err)
	}
	for k, v := range overlay {
		switch existing := target[k].(type) {
		case []any:
			incoming, isList := v.([]any)
			if mode == mergeModeAdd && isList {
				target[k] = append(existing, incoming...)
				continue
			}
			// Replace mode OR mismatched type — overwrite.
			target[k] = v
		default:
			target[k] = v
		}
	}
	return nil
}

// sensitiveAttrs is the list of attribute paths (lowercased) whose
// values get redacted in audit-log payloads. The list intentionally
// stays narrow:
//
//   - "password" — RFC 7643 section 4.1.1 — never to be persisted in
//     plaintext, must never leak into the audit chain.
//   - any path ending in ":secret" — convention for IdP-side secrets
//     under enterprise URN attributes (e.g., extension:enterprise:2.0:
//     User:secret).
//
// The RedactedOps function applies these rules at audit-emit time. The
// actual PATCH still mutates the resource normally; only the audit detail
// gets the "***" overlay so an operator inspecting the chain can see
// "this op happened" without seeing the secret material.
var sensitiveAttrs = []string{
	"password",
}

const sensitiveAttrSuffix = ":secret"

// RedactedOps returns a deep-copied slice of operations with sensitive
// attribute values overwritten with "***". Used by SCIM handlers when
// emitting audit events for PATCH — the audit detail captures the op
// + path but never the literal password / secret value.
//
// The redaction is path-driven: an op with path == "password" or path
// ending in ":secret" has its Value field replaced. A path-less op
// (path == "") with a value that is a JSON object whose top-level keys
// include sensitive attribute names has those keys redacted too — Azure
// AD style "merge the whole resource" PATCHes routinely embed password
// in the value object.
func RedactedOps(ops []Operation) []Operation {
	out := make([]Operation, len(ops))
	for i, op := range ops {
		out[i] = redactOp(op)
	}
	return out
}

func redactOp(op Operation) Operation {
	cp := op
	if isSensitivePath(op.Path) {
		cp.Value = json.RawMessage(`"***"`)
		return cp
	}
	if op.Path == "" && len(op.Value) > 0 {
		// Path-less op: peek inside the value object for sensitive
		// top-level keys + redact those specifically.
		var v map[string]any
		if err := json.Unmarshal(op.Value, &v); err != nil {
			// Not an object — leave the raw value untouched.
			return cp
		}
		changed := false
		for k := range v {
			if isSensitivePath(k) {
				v[k] = "***"
				changed = true
			}
		}
		if changed {
			redacted, err := json.Marshal(v)
			if err == nil {
				cp.Value = redacted
			}
		}
	}
	return cp
}

// isSensitivePath reports whether path names an attribute whose value
// must not appear verbatim in audit-log payloads. Match is
// case-insensitive on the bare attribute leaf; the URN prefix (if any)
// is stripped first so "urn:...:User:password" redacts the same way as
// the bare "password".
func isSensitivePath(path string) bool {
	if path == "" {
		return false
	}
	lower := strings.ToLower(path)
	// Strip schema URN prefix (everything before the final ':').
	leaf := lower
	if i := strings.LastIndex(lower, ":"); i >= 0 && strings.HasPrefix(lower, "urn:") {
		leaf = lower[i+1:]
	}
	for _, attr := range sensitiveAttrs {
		if leaf == attr {
			return true
		}
	}
	return strings.HasSuffix(lower, sensitiveAttrSuffix)
}
