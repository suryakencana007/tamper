// Package tenant is the tenancy vocabulary for pooled multi-tenant
// deployments — the neutral Descriptor record, the Store and Resolver
// persistence ports, the ErrNotFound / ErrSuspended sentinels, and the
// context helpers that propagate the active tenant across a request.
//
// A tenant id is an OPAQUE, app-defined string. tamper never validates,
// parses, namespaces or canonicalizes one; it compares ids for equality
// and passes them through. A UUID, a slug, a "realm/sub-realm" path —
// all fine, all the application's concern. This is the same shape ACR
// already has: a value the framework carries but never interprets.
//
// The empty string is a legal tenant id and selects single-tenant
// behavior. A deployment that never mentions a tenant behaves exactly
// as it did before tenancy existed, byte for byte.
//
// As with every other tamper port, this package names no table. The
// application owns the schema and maps its own wide tenant row onto
// Descriptor, the way identity.User projects the wide users row.
//
// Context propagation is propagation ONLY, never authorization. A
// tenant in the context is a routing fact, not a grant: port methods
// take their tenant as an explicit argument and must never derive one
// from the context. See WithTenant.
//
// Phase 7 slice 7a-1 ships this package with NO consumers — the
// vocabulary lands whole, in one place, before anything routes on it.
// See PHASE7-MULTITENANCY-SKETCH.md §4 and PHASE7-AGENT-MANIFEST.md.
package tenant
