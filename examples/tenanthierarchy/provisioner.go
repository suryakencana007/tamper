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
)

// BindingSource is the read+write surface provisioning needs.
//
// Writes alone are not enough: a revoke is keyed by role (BindingKey carries
// the Role), and RevokeGroupAdmin is not told the role — it must find what the
// subject actually holds and remove each row by its key. So the Provisioner
// reads through the same store it writes through. The 9a-1 Store satisfies
// this.
type BindingSource interface {
	authz.BindingStore
	BindingWriter
}

// Provisioner turns "grant this subject admin of this tenant-group" into real
// bindings, at provision time (ADR-0001 §3.3). It writes one INTENT row in the
// group's scope and one MATERIALIZED binding per child organization — each
// with the org's scope, the subject's home tenant, and the RoleMap-translated
// role — inside a single atomic Apply.
type Provisioner struct {
	src     BindingSource
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
// It errors on a nil source, a nil hierarchy, an empty RoleMap, or a
// non-positive cap. Tenancy misconfiguration fails at construction, never as
// a per-request denial (standing rule 4). An empty RoleMap is refused for the
// same reason the 9a-1 store refuses an unset scope: it is a silent lockout,
// not a loud boot failure.
func NewProvisioner(src BindingSource, h OrgHierarchy, roles RoleMap, opts ...ProvisionerOption) (*Provisioner, error) {
	if src == nil {
		return nil, fmt.Errorf("tenanthierarchy: NewProvisioner requires a BindingSource")
	}
	if h == nil {
		return nil, fmt.Errorf("tenanthierarchy: NewProvisioner requires an OrgHierarchy")
	}
	if len(roles) == 0 {
		return nil, fmt.Errorf("tenanthierarchy: NewProvisioner requires a non-empty RoleMap — " +
			"an empty map would expand every tenant-group binding to nothing, which is a silent lockout")
	}
	p := &Provisioner{src: src, hier: h, roles: roles, maxRows: DefaultMaxProvisionRows}
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

	return p.src.Apply(ctx, func(tx Tx) error {
		if err := tx.Grant(ctx, intentBinding(sub, group, role)); err != nil {
			return err
		}
		for _, orgID := range children {
			if err := tx.Grant(ctx, materializedBinding(sub, orgID, mapped)); err != nil {
				return err
			}
		}
		return nil
	})
}

// RevokeGroupAdmin removes the intent row and every materialized binding the
// subject holds under the group's children, in one atomic Apply.
//
// The materialized rows carry the translated org role, which the caller does
// not supply, so the provisioner reads what the subject actually holds and
// revokes each row by its key. (A SQL adapter reads inside the same
// transaction; the in-memory store reads just before Apply. The single
// provisioning path the design mandates is what keeps that sound — there is
// one writer.)
func (p *Provisioner) RevokeGroupAdmin(ctx context.Context, sub authz.Subject, group tenant.ID) error {
	if err := p.gate(sub, group); err != nil {
		return err
	}
	children, err := p.hier.ChildrenOf(ctx, group.String())
	if err != nil {
		return fmt.Errorf("tenanthierarchy: children of %s: %w", group, err)
	}

	var keys []BindingKey
	intents, err := p.src.BindingsOnResource(ctx, group, authz.Resource{Type: ResourceTenantGroup, ID: group.String()})
	if err != nil {
		return fmt.Errorf("tenanthierarchy: read intent rows of %s: %w", group, err)
	}
	for _, b := range intents {
		if b.Subject == sub {
			keys = append(keys, keyOf(b))
		}
	}
	for _, orgID := range children {
		bs, err := p.src.BindingsForSubject(ctx, tenant.New(orgID), sub, ResourceOrganization)
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

	return p.src.Apply(ctx, func(tx Tx) error {
		for _, k := range keys {
			if err := tx.Revoke(ctx, k); err != nil {
				return err
			}
		}
		return nil
	})
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
