package scim

import (
	"errors"
	"fmt"
	"strings"

	fp "github.com/scim2/filter-parser/v2"
)

// FilterError is the envelope handlers convert into the RFC 7644
// INVALID_FILTER error response. Carries the SCIM-defined scimType
// alongside a free-form message for operator-friendly diagnosis.
//
// The error wraps a sentinel (ErrInvalidFilter) so callers reach for
// errors.Is rather than type-asserting at every catch site.
type FilterError struct {
	Message string
	cause   error
}

// ErrInvalidFilter is the sentinel every *FilterError wraps. Handlers
// gate on errors.Is(err, scim.ErrInvalidFilter) to translate into the
// RFC 7644 INVALID_FILTER response (HTTP 400, scimType=invalidFilter).
var ErrInvalidFilter = errors.New("scim filter: invalid")

// Error implements the error interface.
func (e *FilterError) Error() string {
	if e == nil {
		return ""
	}
	if e.cause != nil {
		return fmt.Sprintf("scim filter: %s: %v", e.Message, e.cause)
	}
	return "scim filter: " + e.Message
}

// Unwrap returns the wrapped cause so errors.Is can chase the chain.
func (e *FilterError) Unwrap() error {
	if e == nil || e.cause == nil {
		return ErrInvalidFilter
	}
	return e.cause
}

// Is reports whether err is a *FilterError or the sentinel itself.
// Lets callers write errors.Is(err, scim.ErrInvalidFilter) regardless
// of whether they received the typed envelope or the bare sentinel.
func (e *FilterError) Is(target error) bool {
	return target == ErrInvalidFilter
}

func newFilterError(msg string, cause error) *FilterError {
	return &FilterError{Message: msg, cause: cause}
}

// Parse wraps the library parser and normalises errors into our
// *FilterError envelope. An empty / whitespace-only filter returns
// (nil, nil) so the calling List handler can short-circuit to a
// no-WHERE query.
//
// Handlers should translate any non-nil error to HTTP 400 with
// scimType=invalidFilter per RFC 7644 section 3.4.1.1.
func Parse(query string) (fp.Expression, error) {
	if strings.TrimSpace(query) == "" {
		return nil, nil
	}
	expr, err := fp.ParseFilter([]byte(query))
	if err != nil {
		return nil, newFilterError("parse", err)
	}
	return expr, nil
}

// Translate walks the parsed AST and emits a SQL WHERE fragment plus
// positional args. Caller is responsible for appending the fragment
// to its base query (typically "SELECT ... FROM users WHERE " +
// fragment) and forwarding args to the prepared statement.
//
// A nil expression returns ("", nil, nil) so the call site can fold
// the empty-filter path into the same code path as a list-all query.
// Any unsupported attribute, value-path at the top level, or unknown
// AST node type returns a *FilterError wrapping ErrInvalidFilter.
//
// The emitted SQL uses positional ? placeholders to match the
// modernc.org/sqlite driver convention used by the rest of the store
// layer. Args are appended in the same left-to-right walk order so
// the slice order matches the ? order.
func Translate(expr fp.Expression, m ColumnMapping) (where string, args []any, err error) {
	if expr == nil {
		return "", nil, nil
	}
	t := &translator{m: m}
	if err := t.walk(expr); err != nil {
		return "", nil, err
	}
	return t.sb.String(), t.args, nil
}

// translator is the AST walker. Private so the Parse + Translate
// surface is the entire export of this file; callers cannot reach
// into the walker's state.
// ColumnMapping is the caller-supplied attribute whitelist: SCIM
// attribute name -> SQL column for one resource type. Attribute names
// are matched via their canonical dotted form (camelCase preserved,
// e.g. "members.value"). Special maps an attribute onto a raw SQL fragment for shapes
// a plain column comparison can't express (e.g. a membership EXISTS
// subquery); special attributes accept ONLY the eq operator and the
// fragment must contain exactly one ? which receives the compare
// value. The mapping IS the app's schema — this package never names
// a table or column itself.
type ColumnMapping struct {
	// Name labels the resource in FilterError messages ("User").
	Name string
	// Attrs maps canonical SCIM attribute names to SQL columns.
	Attrs map[string]string
	// Special maps canonical SCIM attribute names to eq-only SQL
	// fragments with exactly one ? placeholder.
	Special map[string]string
}

type translator struct {
	m    ColumnMapping
	sb   strings.Builder
	args []any
}

// walk dispatches on the AST node type. The scim2/filter-parser/v2
// library returns pointer types (*AttributeExpression etc.); the
// task-file sketch used non-pointer types. Matches the library
// surface here.
func (t *translator) walk(expr fp.Expression) error {
	switch e := expr.(type) {
	case *fp.AttributeExpression:
		return t.emitAttribute(e)
	case *fp.LogicalExpression:
		return t.emitLogical(e)
	case *fp.NotExpression:
		return t.emitNot(e)
	case *fp.ValuePath:
		// Top-level value paths are SQL-injection-via-JSON-traversal
		// shaped; PATCH (Task 02) accepts these because it operates on
		// in-memory JSON resource snapshots, but the List filter path
		// has no equivalent traversal substrate. Reject cleanly.
		return newFilterError(
			fmt.Sprintf("value-path filters not supported at list level: %s", e.AttributePath.String()),
			nil,
		)
	default:
		return newFilterError(fmt.Sprintf("unknown expression node %T", expr), nil)
	}
}

// emitAttribute handles the leaf attribute comparison. Operator -> SQL
// mapping per RFC 7644 section 3.4.2.1:
//
//	eq  -> = ?            ne  -> <> ?
//	co  -> LIKE %?%       sw  -> LIKE ?%       ew  -> LIKE %?
//	gt  -> > ?            ge  -> >= ?
//	lt  -> < ?            le  -> <= ?
//	pr  -> IS NOT NULL AND <col> <> ''   (presence under SCIM is
//	                                       "non-null and non-empty")
//
// The presence operator emits a non-empty check on string columns
// because v1.0's schema defaults TEXT NOT NULL columns to the empty
// string rather than to NULL; a bare IS NOT NULL check would always
// pass for e.g. users.external_id. The two-clause form lands the
// SCIM "attribute is present" semantics correctly on either shape.
func (t *translator) emitAttribute(e *fp.AttributeExpression) error {
	attrName := canonicalAttrName(e.AttributePath)
	if sql, ok := t.m.Special[attrName]; ok {
		return t.emitSpecial(e, attrName, sql)
	}
	col, ok := t.m.Attrs[attrName]
	if !ok {
		return newFilterError(
			fmt.Sprintf("attribute %q is not filterable on %s", attrName, t.m.Name),
			nil,
		)
	}
	switch e.Operator {
	case fp.EQ:
		t.sb.WriteString(col + " = ?")
		t.args = append(t.args, e.CompareValue)
	case fp.NE:
		t.sb.WriteString(col + " <> ?")
		t.args = append(t.args, e.CompareValue)
	case fp.CO:
		t.sb.WriteString(col + " LIKE ?")
		t.args = append(t.args, "%"+stringValue(e.CompareValue)+"%")
	case fp.SW:
		t.sb.WriteString(col + " LIKE ?")
		t.args = append(t.args, stringValue(e.CompareValue)+"%")
	case fp.EW:
		t.sb.WriteString(col + " LIKE ?")
		t.args = append(t.args, "%"+stringValue(e.CompareValue))
	case fp.GT:
		t.sb.WriteString(col + " > ?")
		t.args = append(t.args, e.CompareValue)
	case fp.GE:
		t.sb.WriteString(col + " >= ?")
		t.args = append(t.args, e.CompareValue)
	case fp.LT:
		t.sb.WriteString(col + " < ?")
		t.args = append(t.args, e.CompareValue)
	case fp.LE:
		t.sb.WriteString(col + " <= ?")
		t.args = append(t.args, e.CompareValue)
	case fp.PR:
		// SCIM presence: non-null AND non-empty. See the function-level
		// comment for the v1.0-schema-default reasoning.
		t.sb.WriteString("(" + col + " IS NOT NULL AND " + col + " <> '')")
	default:
		return newFilterError(fmt.Sprintf("unsupported operator %q", e.Operator), nil)
	}
	return nil
}

// emitSpecial writes a caller-supplied SQL fragment for attributes a
// plain column comparison can't express (multi-valued refs like
// members.value map onto an EXISTS subquery). Equality only — the
// only meaningful filter against a multi-valued ref is "does it
// contain X" — and the fragment carries exactly one ? which receives
// the compare value.
func (t *translator) emitSpecial(e *fp.AttributeExpression, attrName, sql string) error {
	if e.Operator != fp.EQ {
		return newFilterError(
			fmt.Sprintf("%s supports only the eq operator, got %q", attrName, e.Operator),
			nil,
		)
	}
	t.sb.WriteString(sql)
	t.args = append(t.args, e.CompareValue)
	return nil
}

// emitLogical handles 'and' / 'or' with grouping parens. Always
// parenthesises both sides so precedence is unambiguous regardless of
// how the parser pre-grouped the AST.
func (t *translator) emitLogical(e *fp.LogicalExpression) error {
	t.sb.WriteByte('(')
	if err := t.walk(e.Left); err != nil {
		return err
	}
	switch e.Operator {
	case fp.AND:
		t.sb.WriteString(" AND ")
	case fp.OR:
		t.sb.WriteString(" OR ")
	default:
		return newFilterError(fmt.Sprintf("unsupported logical operator %q", e.Operator), nil)
	}
	if err := t.walk(e.Right); err != nil {
		return err
	}
	t.sb.WriteByte(')')
	return nil
}

// emitNot handles the unary 'not' operator. Always parenthesises the
// child so "NOT a AND b" cannot land as "NOT (a AND b)" by accident.
func (t *translator) emitNot(e *fp.NotExpression) error {
	t.sb.WriteString("NOT (")
	if err := t.walk(e.Expression); err != nil {
		return err
	}
	t.sb.WriteByte(')')
	return nil
}

// canonicalAttrName flattens an AttributePath into the dotted form
// our whitelist uses ("name.familyName", "emails.value", ...). The
// URI prefix is stripped — v1.13 supports the schema-qualified form
// "urn:...:User:userName" but maps it to the bare "userName" key
// because v1.0's schema is single-namespace.
func canonicalAttrName(p fp.AttributePath) string {
	if p.SubAttribute != nil {
		return p.AttributeName + "." + *p.SubAttribute
	}
	return p.AttributeName
}

// stringValue coerces the parsed CompareValue to a string for the
// LIKE-family operators. The library returns string-typed values for
// quoted literals; non-string types (int, float, bool) get formatted
// via fmt.Sprint so "co" / "sw" / "ew" against a numeric column
// degrades gracefully rather than panicking.
func stringValue(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}
