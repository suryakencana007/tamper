package tenant

import "context"

// tenantCtxKey is the context key used by WithTenant + FromContext.
// Defined as an unexported type to avoid context-key collisions per the
// stdlib context package guidance.
type tenantCtxKey struct{}

// WithTenant returns a derived context carrying the ACTIVE tenant id.
//
// Propagation ONLY — never authorization. A tenant in the context is a
// routing fact (the middleware that resolved this request to a tenant
// recorded its answer), not a grant.
//
// Port methods MUST take their tenant as an explicit argument and MUST
// NOT call FromContext to derive one. An implicit tenant is a silent
// cross-tenant leak waiting for a single missing WithTenant call, and
// it fails OPEN — the caller reads "", the store reads "" as the
// single-tenant table shape, and the query runs unscoped. That is the
// exact shape deny-by-default exists to prevent (sketch §4.3, §6.2).
//
// id is stored verbatim, including the empty string. tamper does not
// validate, parse or canonicalize a tenant id (§4.1), and "" is a legal
// value meaning the single-tenant deployment. So WithTenant(ctx, "")
// records that a tenant WAS resolved and it is the single-tenant one,
// which FromContext reports as ("", true) — a different fact from
// "nothing resolved a tenant for this request", which is ("", false).
func WithTenant(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, tenantCtxKey{}, id)
}

// FromContext returns the tenant id stashed by WithTenant and whether
// one was stashed at all. A bare context returns ("", false).
//
// The bool is not a permission check and must not be used as one — see
// WithTenant. It answers "did anything resolve a tenant for this
// request", which a middleware needs and a port method does not.
//
// Nesting follows context's own semantics: the innermost WithTenant
// wins.
func FromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(tenantCtxKey{}).(string)
	return id, ok
}
