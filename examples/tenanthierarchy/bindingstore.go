// Package tenanthierarchy is a DRAFT reference implementation for
// ADR-0001 (ADR-0001-tenant-hierarchy-platform-tenantgroup-org.md) —
// showing how a consumer app builds the platform / tenant-group /
// organization hierarchy ENTIRELY on top of tamper's existing
// authz.BindingStore port, with zero changes to tamper core.
//
// NOT shipped tamper code. Lives under examples/ on purpose, the same
// status as examples/multitenant — a proving ground for the pattern,
// reviewed before any app vendors it. Delete or promote after review.
//
// What this file does NOT do, deliberately:
//   - It does not touch tenant.Descriptor.ParentID resolution. tamper's
//     own tenant.Store still never walks ParentID (Phase7 sketch §8
//     item 3, TestMemStore_ParentIDCarriedNotResolved). This package
//     reads ParentID itself, OUTSIDE tamper, through the OrgHierarchy
//     port below — which an app backs with its own tenant table query,
//     not with anything tamper resolves for it.
//   - It does not change authz.RBAC, authz.Authorizer, or the Check/
//     ListResources/ListSubjects call sites. Expansion happens entirely
//     inside the BindingStore the engine already calls — RBAC stays
//     "a dumb, auditable set test" (PHASE5-CUSTOM-ROLE-RBAC-SKETCH.md
//     §3.1) with no idea hierarchy exists.
package tenanthierarchy

import (
	"context"
	"fmt"

	"github.com/suryakencana007/tamper/authz"
)

// OrgHierarchy is the app-owned port this package needs to expand a
// tenant-group binding into the organizations under it. tamper's own
// tenant.Store deliberately does not expose this (ParentID is reserved
// there) — an app backs it with its own tenant table / cache, exactly
// the way authz.BindingStore itself is app-owned.
//
// Implementations MUST be safe for concurrent use and SHOULD be cheap
// or cached: ParentOf is on the Check hot path (§4a of ADR-0001).
type OrgHierarchy interface {
	// ParentOf returns the tenant-group id that owns orgID, and false
	// when orgID has no parent (a root tenant / tenant-group itself,
	// or an unknown id — the two are deliberately not distinguished
	// here; an unknown orgID simply expands to nothing, which is a
	// deny, not an error, matching tamper's own ErrNotFound-collapses
	// discipline).
	ParentOf(ctx context.Context, orgID string) (tenantGroupID string, ok bool, err error)

	// ChildrenOf returns every organization id that has tenantGroupID
	// as its parent. Empty (non-nil) slice for none. Fuel for
	// BindingsForSubject / BindingsOnResource expansion (§4a/§4b).
	ChildrenOf(ctx context.Context, tenantGroupID string) (orgIDs []string, err error)
}

// RoleMap translates a role held at one resource type into the role it
// is treated as holding at another. Needed because authz.Hierarchy
// ladders are independent per resource type (authz/policy.go:6-9) — a
// "tenant_group" ladder and an "organization" ladder are unrelated
// enums even if some names coincide, so an explicit map is safer than
// assuming identical role strings carry the same rank in both ladders.
//
// Keyed by the SOURCE role (as held on the tenant_group); value is the
// role to report as held on the expanded organization resource. A role
// absent from the map does NOT expand — fail closed, matching
// authz.Hierarchy.rank's "unknown role ranks 0" discipline. This is
// deliberate: a new tenant_group role added without updating the map
// grants NOTHING on organizations rather than something undefined.
type RoleMap map[authz.Role]authz.Role

// translate returns the mapped role and whether a mapping exists.
func (m RoleMap) translate(r authz.Role) (authz.Role, bool) {
	out, ok := m[r]
	return out, ok
}

// Store wraps a base authz.BindingStore — the one holding RAW bindings
// at all three scopes (system/platform, tenant_group, organization) —
// and expands tenant_group bindings onto the organizations under them
// at query time. It implements authz.BindingStore itself, so it drops
// into authz.NewRBAC(store, ...) with no change to any call site.
//
// Base is expected to store bindings exactly as granted:
//   - platform admin:    Binding{sub, Resource{"system", ""}, role}
//   - tenant-group admin: Binding{sub, Resource{"tenant_group", tgID}, role}
//   - organization admin: Binding{sub, Resource{"organization", orgID}, role}
//
// Store never writes; it only reads Base and OrgHierarchy to answer
// the three BindingStore methods. Granting/revoking bindings is the
// app's own concern against Base, same as today.
//
// Safe for concurrent use IFF Base and Hierarchy are.
type Store struct {
	base authz.BindingStore
	hier OrgHierarchy
	// OrgGroupRoles maps a role held on resource_type="tenant_group"
	// to the role it confers on every organization under that group.
	// Required to be non-nil at construction — see New.
	roles RoleMap
}

var _ authz.BindingStore = (*Store)(nil)

// New returns a Store. Panics-via-error (not a silent zero-value) on a
// nil base, nil hier, or empty roles map — tenancy misconfiguration
// fails at construction, never as a per-request denial that looks like
// ordinary traffic (the same posture tamper's own RequireTenant/
// PinTenant take on a nil resolver, espresso/tenantgate.go:90-98).
func New(base authz.BindingStore, hier OrgHierarchy, roles RoleMap) (*Store, error) {
	if base == nil {
		return nil, fmt.Errorf("tenanthierarchy: New requires a base BindingStore")
	}
	if hier == nil {
		return nil, fmt.Errorf("tenanthierarchy: New requires an OrgHierarchy")
	}
	if len(roles) == 0 {
		return nil, fmt.Errorf("tenanthierarchy: New requires a non-empty RoleMap — " +
			"an empty map would expand every tenant-group binding to nothing, " +
			"which is a silent lockout, not a loud boot failure")
	}
	return &Store{base: base, hier: hier, roles: roles}, nil
}

// BindingsFor implements authz.BindingStore.
//
// For any resource type OTHER than "organization", this is a pure
// passthrough to base — platform and tenant_group bindings are never
// themselves expanded further (no reseller-of-reseller in this draft;
// ADR-0001's "when to revisit" §(a) covers that extension).
//
// For "organization", returns the union of:
//  1. direct bindings on this exact org (base, unchanged — an org
//     admin's own binding keeps working exactly as it does today).
//  2. bindings the subject holds on the org's parent tenant_group,
//     RE-STAMPED with Resource = the asked org and Role translated
//     through roles. This re-stamping is what lets authz.RBAC.effective
//     (which requires an EXACT b.Resource == res match, authz/rbac.go
//     :192) see a tenant-group admin's grant as if it were a direct
//     org binding — the engine never learns a hierarchy exists.
//
// A role with no entry in roles is dropped (fail closed), not passed
// through verbatim — see RoleMap's doc.
func (s *Store) BindingsFor(ctx context.Context, sub authz.Subject, res authz.Resource) ([]authz.Binding, error) {
	direct, err := s.base.BindingsFor(ctx, sub, res)
	if err != nil {
		return nil, fmt.Errorf("tenanthierarchy: direct bindings: %w", err)
	}
	if res.Type != "organization" || res.ID == "" {
		return direct, nil
	}

	tgID, ok, err := s.hier.ParentOf(ctx, res.ID)
	if err != nil {
		return nil, fmt.Errorf("tenanthierarchy: resolve parent of %s: %w", res.ID, err)
	}
	if !ok {
		return direct, nil
	}

	groupBindings, err := s.base.BindingsFor(ctx, sub, authz.Resource{Type: "tenant_group", ID: tgID})
	if err != nil {
		return nil, fmt.Errorf("tenanthierarchy: tenant_group bindings: %w", err)
	}
	for _, b := range groupBindings {
		mapped, ok := s.roles.translate(b.Role)
		if !ok {
			continue // unmapped role: fail closed, grants nothing here
		}
		direct = append(direct, authz.Binding{
			Subject:  sub,
			Resource: res, // re-stamped to the asked org, NOT tenant_group
			Role:     mapped,
		})
	}
	return direct, nil
}

// BindingsForSubject implements authz.BindingStore.
//
// Fuel for authz.Authorizer.ListResources. For resourceType ==
// "organization", unions:
//  1. direct org bindings the subject holds (base, unchanged).
//  2. every org under every tenant_group the subject holds a MAPPED
//     role on, re-stamped the same way BindingsFor does per-resource.
//
// This is §4a's expand applied to the reverse-query shape. It is
// O(tenant-groups held × children per group) — fine for the common
// case (a subject holds a handful of tenant-group bindings), but see
// ADR-0001 "Negatif" on caching ChildrenOf if this subject ever holds
// many tenant-group bindings at once.
func (s *Store) BindingsForSubject(ctx context.Context, sub authz.Subject, resourceType string) ([]authz.Binding, error) {
	direct, err := s.base.BindingsForSubject(ctx, sub, resourceType)
	if err != nil {
		return nil, fmt.Errorf("tenanthierarchy: direct bindings for subject: %w", err)
	}
	if resourceType != "organization" {
		return direct, nil
	}

	groupBindings, err := s.base.BindingsForSubject(ctx, sub, "tenant_group")
	if err != nil {
		return nil, fmt.Errorf("tenanthierarchy: tenant_group bindings for subject: %w", err)
	}

	// Dedup on the FULL binding (resource AND role), never on the
	// resource alone. A subject may legitimately hold a LOW-ranked direct
	// org role AND a HIGHER-ranked role inherited from its tenant-group
	// (e.g. direct org_viewer + inherited org_admin). Deduping on resource
	// alone keeps whichever came first (the direct, lower one) and drops
	// the inherited, higher one, which makes authz.Authorizer.ListResources
	// under-report — it filters each binding by rank. RBAC takes the max
	// rank across everything the store returns, so keep every distinct
	// (resource, role) pair and let the engine pick.
	type bindingKey struct {
		res  authz.Resource
		role authz.Role
	}
	seen := make(map[bindingKey]bool, len(direct))
	for _, b := range direct {
		seen[bindingKey{b.Resource, b.Role}] = true
	}

	for _, gb := range groupBindings {
		mapped, ok := s.roles.translate(gb.Role)
		if !ok {
			continue
		}
		orgIDs, err := s.hier.ChildrenOf(ctx, gb.Resource.ID)
		if err != nil {
			return nil, fmt.Errorf("tenanthierarchy: children of %s: %w", gb.Resource.ID, err)
		}
		for _, orgID := range orgIDs {
			res := authz.Resource{Type: "organization", ID: orgID}
			key := bindingKey{res, mapped}
			if seen[key] {
				continue // exact (resource, role) already present; never drop a different role
			}
			seen[key] = true
			direct = append(direct, authz.Binding{Subject: sub, Resource: res, Role: mapped})
		}
	}
	return direct, nil
}

// BindingsOnResource implements authz.BindingStore.
//
// Fuel for authz.Authorizer.ListSubjects ("who can act on this org").
// For "organization", unions direct org-binding holders with every
// subject holding a mapped role on the org's parent tenant_group — the
// same re-stamping BindingsFor applies, now across subjects rather
// than for one.
func (s *Store) BindingsOnResource(ctx context.Context, res authz.Resource) ([]authz.Binding, error) {
	direct, err := s.base.BindingsOnResource(ctx, res)
	if err != nil {
		return nil, fmt.Errorf("tenanthierarchy: direct bindings on resource: %w", err)
	}
	if res.Type != "organization" || res.ID == "" {
		return direct, nil
	}

	tgID, ok, err := s.hier.ParentOf(ctx, res.ID)
	if err != nil {
		return nil, fmt.Errorf("tenanthierarchy: resolve parent of %s: %w", res.ID, err)
	}
	if !ok {
		return direct, nil
	}

	groupBindings, err := s.base.BindingsOnResource(ctx, authz.Resource{Type: "tenant_group", ID: tgID})
	if err != nil {
		return nil, fmt.Errorf("tenanthierarchy: tenant_group bindings on resource: %w", err)
	}

	// Dedup on the FULL binding (subject AND role), for the same reason
	// BindingsForSubject does: a subject holding a LOW-ranked direct org
	// role and a HIGHER-ranked inherited one must keep both, or
	// authz.Authorizer.ListSubjects under-reports (it filters by rank).
	type bindingKey struct {
		sub  authz.Subject
		role authz.Role
	}
	seen := make(map[bindingKey]bool, len(direct))
	for _, b := range direct {
		seen[bindingKey{b.Subject, b.Role}] = true
	}
	for _, gb := range groupBindings {
		mapped, ok := s.roles.translate(gb.Role)
		if !ok {
			continue
		}
		key := bindingKey{gb.Subject, mapped}
		if seen[key] {
			continue // exact (subject, role) already present; never drop a different role
		}
		seen[key] = true
		direct = append(direct, authz.Binding{Subject: gb.Subject, Resource: res, Role: mapped})
	}
	return direct, nil
}
