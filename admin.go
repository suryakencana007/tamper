package tamper

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/suryakencana007/tamper/audit"
	"github.com/suryakencana007/tamper/identity"
	"github.com/suryakencana007/tamper/tenant"
)

// The audit vocabulary a lifecycle write uses. One chain for every tenant, so
// these are ordinary actions rather than a separate log.
const (
	ActionSuspendTenant audit.Action       = "tenant.suspend"
	ResourceTypeTenant  audit.ResourceType = "tenant"
)

// Admin composes what a tenant lifecycle write needs: the application's tenant
// table, the identity side that holds the sessions, and the audit chain.
//
// It exists because a suspension is two writes in two stores, and the framework
// cannot make them atomic. What it can do is fix the order and report a partial
// state instead of pretending: the status goes first, so the tenant stops
// serving, and the revocation second, so the token window closes.
type Admin struct {
	admin tenant.AdminStore
	core  *identity.Core
	log   audit.Logger
}

// NewAdmin returns an Admin. All three arguments are required.
//
// It panics on a nil AdminStore, a nil Core, or a nil Logger, each for the same
// reason: a composer missing one of them either sets a status and revokes
// nothing, revokes sessions for a tenant it never suspended, or suspends a
// tenant silently. Tenancy misconfiguration fails when the composer is built,
// never as a per-request denial (standing rule 4), and the guard ships with a
// test that proves it fires (rule 6). A deployment that wants no audit says so
// with audit.NewNoopLogger() — a decision, not an omission.
//
// A nil check cannot see through a typed nil: passing (*tenant.MemStore)(nil) as
// the AdminStore satisfies the interface, so the panic does not fire and the
// first write nil-derefs instead. That is the same limit authz.NewRBAC has, and
// the same reason: Go cannot distinguish the two without reflection, and a
// reflection check here would fail on any wrapper the application legitimately
// uses.
func NewAdmin(admin tenant.AdminStore, core *identity.Core, log audit.Logger) *Admin {
	switch {
	case admin == nil:
		panic("tamper: NewAdmin requires a tenant.AdminStore — " +
			"a composer with no tenant table would revoke sessions and suspend nothing")
	case core == nil:
		panic("tamper: NewAdmin requires an *identity.Core — " +
			"a composer with no identity side would suspend a tenant and leave every session live")
	case log == nil:
		panic("tamper: NewAdmin requires an audit.Logger — " +
			"a nil here would suspend tenants silently; pass audit.NewNoopLogger() to mean it")
	}
	return &Admin{admin: admin, core: core, log: log}
}

// Suspend suspends a tenant and revokes its refresh sessions, IN THAT ORDER.
//
// The order is the contract, not an implementation detail. A status write that
// fails leaves everything untouched. A revocation that fails leaves the tenant
// suspended — not serving — with its sessions possibly alive; the returned error
// says exactly that, because the alternative is an operator believing a
// suspension completed when half of it did not.
//
// Refusals come from the status write, before anything else happens:
// tenant.ErrNotFound for an unknown tenant, tenant.ErrSingleTenant for
// tenant.Single, tenant.ErrInvalidDescriptor for a status this version does not
// know, or the store's own error. None of them revoke a session.
//
// The audit row is written after the status change, scoped to the SUSPENDED
// tenant rather than to whatever the caller's request was routed to: a console
// is typically untenanted, and espresso's Auditor derives a row's scope from the
// routed tenant — so a row written there would carry an empty scope and be
// invisible to the tenant's own export.
func (a *Admin) Suspend(ctx context.Context, id tenant.ID) error {
	if err := a.admin.SetStatus(ctx, id, tenant.StatusSuspended); err != nil {
		return fmt.Errorf("tamper: suspend %s: %w", id, err)
	}

	revokeErr := a.core.RevokeAllSessionsForTenant(ctx, id)
	auditErr := a.emitSuspend(ctx, id)
	if revokeErr == nil && auditErr == nil {
		return nil
	}

	var parts []error
	if revokeErr != nil {
		parts = append(parts, fmt.Errorf("refresh sessions may remain: %w", revokeErr))
	}
	if auditErr != nil {
		parts = append(parts, fmt.Errorf("the audit row is missing: %w", auditErr))
	}
	return fmt.Errorf("tamper: tenant %s IS suspended, but %w", id, errors.Join(parts...))
}

// emitSuspend writes the one audit row a suspension produces.
//
// Two tenants per event, and they are different facts: TenantID is the row's
// SCOPE — the tenant whose log this belongs to — while Actor.TenantID is where
// the operator is from. That split is what puts the row in the suspended
// tenant's export and still says who did it.
//
// ID and At are stamped here rather than injected: a lifecycle write happens
// once, at a real moment, and tests assert on the event's structure — scope,
// actor, action, resource — not on a fixed timestamp. A clock seam would invite
// a caller to backdate the record.
func (a *Admin) emitSuspend(ctx context.Context, id tenant.ID) error {
	_, err := a.log.Log(ctx, audit.Event{
		ID:           uuid.NewString(),
		At:           time.Now(),
		Actor:        audit.ActorFromContext(ctx),
		Action:       ActionSuspendTenant,
		ResourceType: ResourceTypeTenant,
		ResourceID:   id.String(),
		TenantID:     id.String(),
	})
	return err
}
