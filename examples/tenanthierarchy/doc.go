// Package tenanthierarchy is the reference implementation for ADR-0001:
// a platform / tenant-group / organization hierarchy built ENTIRELY in the
// application layer, with zero changes to tamper core.
//
// The mechanism is eager per-tenant provisioning (ADR-0001). A tenant-group
// admin is a guest of each child organization: they hold one real binding in
// every child org scope, with the tenant-group as their home tenant. The
// expansion happens at provisioning time, never at query time, so
// authz.RBAC is used unchanged and no binding ever crosses a tenant boundary.
//
// Two kinds of row live in the store, in one table (ADR-0001 decision 1):
//
//   - the INTENT row — scope = the tenant-group, resource = {tenant_group,
//     <group>}, the group role. It is the source of truth for "who administers
//     this group".
//   - the MATERIALIZED rows — scope = each child organization, resource =
//     {organization, <org>}, the translated org role. They are the projection
//     the authorization engine reads.
//
// This package is the same kind of artifact as examples/multitenant: a
// proving ground a real application vendors, not shipped tamper code. It
// names its own tables; tamper still names none. The tenant-group's
// ParentID is read through this package's own hierarchy port, OUTSIDE
// tamper — tenant.Store deliberately never walks it (Phase 7 sketch §8 item
// 3).
//
// Slices land one at a time (TENANT-HIERARCHY-MANIFEST.md). This file set is
// slice 9a-1: the store and its idempotent, atomic writer. Nothing provisions
// yet.
package tenanthierarchy
