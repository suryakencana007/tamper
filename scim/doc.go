// Package scim is the SCIM 2.0 protocol substrate for Tamper
// consumers — the transport-agnostic RFC 7643/7644 mechanics an app's
// HTTP layer composes:
//
//   - Parse wraps github.com/scim2/filter-parser/v2's ParseFilter,
//     normalising errors into a *FilterError envelope handlers
//     translate to RFC 7644 INVALID_FILTER (HTTP 400).
//   - Translate walks the parsed AST and emits a SQL WHERE fragment +
//     positional args against a caller-supplied ColumnMapping — the
//     mapping IS the app's schema; this package never names a table
//     or column itself. Non-whitelisted attributes return
//     *FilterError per RFC 7644 §3.4.1.1.
//   - The PATCH applier (Request / Operation / Apply / ParsePath)
//     implements RFC 7644 §3.5.2 over in-memory map[string]any
//     resource snapshots, including filtered value-paths and
//     audit-time RedactedOps for sensitive attributes.
//   - DetectCycle guards group nesting against cyclic membership over
//     the GroupMemberQueries port.
//
// The hybrid library-plus-handwritten approach sheds the tokenizer +
// Pratt-parser surface onto a vetted library while keeping the SQL
// emission and PATCH semantics reviewable here.
package scim
