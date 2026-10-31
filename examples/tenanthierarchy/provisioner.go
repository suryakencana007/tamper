package tenanthierarchy

import (
	"context"
	"errors"
	"fmt"

	"github.com/suryakencana007/tamper/authz"
	"github.com/suryakencana007/tamper/tenant"
)

const (
	// ResourceTenantGroup and ResourceOrganization are the two resource types
	// the hierarchy uses. The tenant-group is the subject's home tenant; the
	// organization is the scope a request is authorized in.
	ResourceTenantGroup  = "tenant_group"
	ResourceOrganization = "organization"

	// DefaultMaxProvisionRows caps a single provisioning operation (ADR-0001
	// decision 3). It is a loud stop, never a silent split: an operation whose
	// projected row count exceeds it returns ErrTooManyRows and writes
	// nothing. See WithMaxProvisionRows.
	DefaultMaxProvisionRows = 100_000
)

var (
	// ErrUnmappedRole — the granted role has no entry in the RoleMap, so it
	// would expand to nothing. Fail closed.
	ErrUnmappedRole = errors.New("tenanthierarchy: role has no organization mapping")
	// ErrSubjectNotInGroup — the subject's home tenant is not the group the
	// grant is about. A tenant-group admin is a user stored in the group.
	ErrSubjectNotInGroup = errors.New("tenanthierarchy: subject home tenant is not the group")
	// ErrTooManyRows — the operation's projected row count exceeds the cap
	// (ADR-0001 decision 3). Nothing is written.
	ErrTooManyRows = errors.New("tenanthierarchy: provisioning would write too many rows")
	// ErrBadMembership — a membership change (AddOrg/MoveOrg/RemoveOrg) names
	// an unset tenant, or names the same tenant as both org and group.
	ErrBadMembership = errors.New("tenanthierarchy: invalid org/group membership change")
)

// Provisioner turns "grant this subject admin of this tenant-group" into real
// bindings, at provision time (ADR-0001 §3.3). It writes one INTENT row in the
// group's scope and one MATERIALIZED binding per child organization — each
// with the org's scope, the subject's home tenant, and the RoleMap-translated
// role — inside a single atomic Apply.
//
// Every row it writes carries GroupOrigin(group), so revoking the grant removes
// only its own contribution and leaves a direct grant on the same binding in
// place (the store's per-origin ref count, slice 9a-1).
type Provisioner struct {
	writer  BindingWriter
	hier    OrgHierarchy
	roles   RoleMap
	maxRows int
}

// ProvisionerOption configures a Provisioner.
type ProvisionerOption func(*Provisioner)

// WithMaxProvisionRows sets the cap a single operation may write. n <= 0 is
// rejected by NewProvisioner.
func WithMaxProvisionRows(n int) ProvisionerOption {
	return func(p *Provisioner) { p.maxRows = n }
}

// NewProvisioner returns a Provisioner.
//
// It errors on a nil writer, a nil hierarchy, an empty RoleMap, or a
// non-positive cap. Tenancy misconfiguration fails at construction, never as
// a per-request denial (standing rule 4). An empty RoleMap is refused for the
// same reason the store refuses an unset scope: it is a silent lockout, not a
// loud boot failure.
func NewProvisioner(w BindingWriter, h OrgHierarchy, roles RoleMap, opts ...ProvisionerOption) (*Provisioner, error) {
	if w == nil {
		return nil, fmt.Errorf("tenanthierarchy: NewProvisioner requires a BindingWriter")
	}
	if h == nil {
		return nil, fmt.Errorf("tenanthierarchy: NewProvisioner requires an OrgHierarchy")
	}
	if len(roles) == 0 {
		return nil, fmt.Errorf("tenanthierarchy: NewProvisioner requires a non-empty RoleMap — " +
			"an empty map would expand every tenant-group binding to nothing, which is a silent lockout")
	}
	p := &Provisioner{writer: w, hier: h, roles: roles, maxRows: DefaultMaxProvisionRows}
	for _, opt := range opts {
		opt(p)
	}
	if p.maxRows <= 0 {
		return nil, fmt.Errorf("tenanthierarchy: NewProvisioner requires MaxProvisionRows > 0, got %d", p.maxRows)
	}
	return p, nil
}

// GrantGroupAdmin writes the intent row in the group's scope and one
// materialized binding in every child organization's scope, in one atomic
// Apply. Granting twice with the same key is idempotent (one row each).
//
// The role is translated through RoleMap; an unmapped role fails the whole
// operation and writes nothing (fail closed). The subject's home tenant must
// be the group.
func (p *Provisioner) GrantGroupAdmin(ctx context.Context, sub authz.Subject, group tenant.ID, role authz.Role) error {
	if err := p.gate(sub, group); err != nil {
		return err
	}
	mapped, ok := p.roles.translate(role)
	if !ok {
		return fmt.Errorf("%w: %q held on %s", ErrUnmappedRole, role, group)
	}
	children, err := p.hier.ChildrenOf(ctx, group.String())
	if err != nil {
		return fmt.Errorf("tenanthierarchy: children of %s: %w", group, err)
	}
	if n := 1 + len(children); n > p.maxRows {
		return fmt.Errorf("%w: grant needs %d rows, cap %d", ErrTooManyRows, n, p.maxRows)
	}

	origin := GroupOrigin(group)
	return p.writer.Apply(ctx, func(tx Tx) error {
		if err := tx.GrantFrom(ctx, intentBinding(sub, group, role), origin); err != nil {
			return err
		}
		for _, orgID := range children {
			if err := tx.GrantFrom(ctx, materializedBinding(sub, orgID, mapped), origin); err != nil {
				return err
			}
		}
		return nil
	})
}

// RevokeGroupAdmin removes the group's contribution (GroupOrigin(group)) from
// the intent row and every materialized binding the subject holds under the
// group's children, in one atomic Apply.
//
// It reads inside the Apply, so the read and the removal are one atomic step —
// a concurrent grant cannot slip a row past the revoke. Because each row's
// removal is by origin, a direct grant on the same binding is left in place;
// only rows the group alone justified disappear.
func (p *Provisioner) RevokeGroupAdmin(ctx context.Context, sub authz.Subject, group tenant.ID) error {
	if err := p.gate(sub, group); err != nil {
		return err
	}
	children, err := p.hier.ChildrenOf(ctx, group.String())
	if err != nil {
		return fmt.Errorf("tenanthierarchy: children of %s: %w", group, err)
	}

	origin := GroupOrigin(group)
	return p.writer.Apply(ctx, func(tx Tx) error {
		var keys []BindingKey
		intents, err := tx.BindingsOnResource(ctx, group, authz.Resource{Type: ResourceTenantGroup, ID: group.String()})
		if err != nil {
			return fmt.Errorf("tenanthierarchy: read intent rows of %s: %w", group, err)
		}
		for _, b := range intents {
			if b.Subject == sub {
				keys = append(keys, keyOf(b))
			}
		}
		for _, orgID := range children {
			bs, err := tx.BindingsForSubject(ctx, tenant.New(orgID), sub, ResourceOrganization)
			if err != nil {
				return fmt.Errorf("tenanthierarchy: read bindings in %s: %w", orgID, err)
			}
			for _, b := range bs {
				keys = append(keys, keyOf(b))
			}
		}
		if len(keys) > p.maxRows {
			return fmt.Errorf("%w: revoke needs %d deletes, cap %d", ErrTooManyRows, len(keys), p.maxRows)
		}
		for _, k := range keys {
			if err := tx.RevokeFrom(ctx, k, origin); err != nil {
				return err
			}
		}
		return nil
	})
}

// AddOrg extends every grant of group onto org: one materialized binding in
// org's scope per intent row of group, carrying GroupOrigin(group). Atomic and
// idempotent.
//
// The caller has already attached org to group in its own tenant table; this
// makes the bindings match. The two writes are one transaction in a SQL
// adapter; in the in-memory example they are separate, and a crash in between
// leaves drift the reconciliation guard (slice 9c-1) reports.
func (p *Provisioner) AddOrg(ctx context.Context, group, org tenant.ID) error {
	if err := membershipGate(org, group); err != nil {
		return err
	}
	origin := GroupOrigin(group)
	return p.writer.Apply(ctx, func(tx Tx) error {
		admins, err := tx.BindingsFrom(ctx, group, origin)
		if err != nil {
			return fmt.Errorf("tenanthierarchy: read intent rows of %s: %w", group, err)
		}
		if len(admins) > p.maxRows {
			return fmt.Errorf("%w: AddOrg needs %d rows, cap %d", ErrTooManyRows, len(admins), p.maxRows)
		}
		return p.extendOnto(ctx, tx, group, org, admins)
	})
}

// MoveOrg detaches org from `from`'s grants and attaches it to `to`'s, in one
// atomic Apply: the from-group's contribution in org's scope is removed, and
// every grant of `to` is materialized onto org. Both halves, or neither.
func (p *Provisioner) MoveOrg(ctx context.Context, org, from, to tenant.ID) error {
	if err := membershipGate(org, from, to); err != nil {
		return err
	}
	return p.writer.Apply(ctx, func(tx Tx) error {
		fromRows, err := tx.BindingsFrom(ctx, org, GroupOrigin(from))
		if err != nil {
			return fmt.Errorf("tenanthierarchy: read %s bindings in %s: %w", from, org, err)
		}
		toAdmins, err := tx.BindingsFrom(ctx, to, GroupOrigin(to))
		if err != nil {
			return fmt.Errorf("tenanthierarchy: read intent rows of %s: %w", to, err)
		}
		if n := len(fromRows) + len(toAdmins); n > p.maxRows {
			return fmt.Errorf("%w: MoveOrg needs %d rows, cap %d", ErrTooManyRows, n, p.maxRows)
		}
		for _, b := range fromRows {
			if err := tx.RevokeFrom(ctx, keyOf(b), GroupOrigin(from)); err != nil {
				return err
			}
		}
		return p.extendOnto(ctx, tx, to, org, toAdmins)
	})
}

// RemoveOrg removes group's contribution (GroupOrigin(group)) from org's scope,
// in one atomic Apply. A direct grant on the same binding is left in place;
// rows only the group justified disappear.
func (p *Provisioner) RemoveOrg(ctx context.Context, org, group tenant.ID) error {
	if err := membershipGate(org, group); err != nil {
		return err
	}
	origin := GroupOrigin(group)
	return p.writer.Apply(ctx, func(tx Tx) error {
		rows, err := tx.BindingsFrom(ctx, org, origin)
		if err != nil {
			return fmt.Errorf("tenanthierarchy: read %s bindings in %s: %w", group, org, err)
		}
		if len(rows) > p.maxRows {
			return fmt.Errorf("%w: RemoveOrg needs %d deletes, cap %d", ErrTooManyRows, len(rows), p.maxRows)
		}
		for _, b := range rows {
			if err := tx.RevokeFrom(ctx, keyOf(b), origin); err != nil {
				return err
			}
		}
		return nil
	})
}

// extendOnto materializes every intent row of group into org's scope, with the
// RoleMap-translated role and GroupOrigin(group). An unmapped role fails the
// whole operation (fail closed), leaving no partial state.
func (p *Provisioner) extendOnto(ctx context.Context, tx Tx, group, org tenant.ID, admins []authz.Binding) error {
	for _, b := range admins {
		mapped, ok := p.roles.translate(b.Role)
		if !ok {
			return fmt.Errorf("%w: %q held on %s", ErrUnmappedRole, b.Role, group)
		}
		if err := tx.GrantFrom(ctx, materializedBinding(b.Subject, org.String(), mapped), GroupOrigin(group)); err != nil {
			return err
		}
	}
	return nil
}

// membershipGate refuses a membership change that names an unset tenant, or the
// same tenant as both org and group.
func membershipGate(org tenant.ID, groups ...tenant.ID) error {
	if !org.Valid() {
		return fmt.Errorf("%w: the org is unset", ErrBadMembership)
	}
	for _, g := range groups {
		if !g.Valid() {
			return fmt.Errorf("%w: a group is unset", ErrBadMembership)
		}
		if g == org {
			return fmt.Errorf("%w: %s cannot be its own group", ErrBadMembership, org)
		}
	}
	return nil
}

// gate refuses a grant/revoke whose group is unset, whose subject has no home
// tenant, or whose subject is stored in another tenant. The last is the
// hierarchy's own rule: a tenant-group admin is a user of the group.
func (p *Provisioner) gate(sub authz.Subject, group tenant.ID) error {
	if !group.Valid() {
		return fmt.Errorf("%w: the group is unset", authz.ErrTenantRequired)
	}
	if !sub.Tenant.Valid() {
		return fmt.Errorf("%w: subject %s:%s has no home tenant", authz.ErrTenantRequired, sub.Type, sub.ID)
	}
	if sub.Tenant != group {
		return fmt.Errorf("%w: subject home tenant %q is not the group %q", ErrSubjectNotInGroup, sub.Tenant, group)
	}
	return nil
}

// intentBinding is the source-of-truth row: the group scope, the group
// resource, the group role.
func intentBinding(sub authz.Subject, group tenant.ID, role authz.Role) authz.Binding {
	return authz.Binding{
		Tenant:   group,
		Subject:  sub,
		Resource: authz.Resource{Type: ResourceTenantGroup, ID: group.String()},
		Role:     role,
	}
}

// materializedBinding is the projection: the org scope, the concrete org
// resource, the translated role (ADR-0001 decision 2).
func materializedBinding(sub authz.Subject, orgID string, role authz.Role) authz.Binding {
	return authz.Binding{
		Tenant:   tenant.New(orgID),
		Subject:  sub,
		Resource: authz.Resource{Type: ResourceOrganization, ID: orgID},
		Role:     role,
	}
}
