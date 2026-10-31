package tenanthierarchy

import (
	"context"
	"log"
	"time"

	"github.com/suryakencana007/tamper/audit"
	"github.com/suryakencana007/tamper/tenant"
)

// The provisioning actions recorded on the audit chain. One chain — there is no
// per-tenant-group chain (ADR-0001 §3.6), so these differ from org mutations
// only by Action and by the scope they are written under.
const (
	ActionGrantGroupAdmin  audit.Action = "tenanthierarchy.group_admin.grant"
	ActionRevokeGroupAdmin audit.Action = "tenanthierarchy.group_admin.revoke"
	ActionAddOrg           audit.Action = "tenanthierarchy.org.add"
	ActionMoveOrg          audit.Action = "tenanthierarchy.org.move"
	ActionRemoveOrg        audit.Action = "tenanthierarchy.org.remove"
)

// auditResourceType is the audit resource type a provisioning event names: the
// membership change is about a tenant-group.
const auditResourceType audit.ResourceType = "tenant_group"

// EventLogger is the slice of audit.Logger provisioning needs. The full
// audit.Logger satisfies it, and so does a test capture.
type EventLogger interface {
	Log(ctx context.Context, e audit.Event) (audit.Event, error)
}

// WithAudit makes the Provisioner record every provisioning operation on the
// application's single audit chain.
//
// The event's SCOPE (Event.TenantID) is the tenant-group being granted over, and
// its ACTOR is the operator from the context — audit.ActorFromContext, which
// RequireAuth filled from the token. The admin LEVEL is never stamped into
// Actor.Type: that stays the subject type (user), and the level is read from the
// scope and the role (decision 6, ADR-0001 §3.6).
func WithAudit(logger EventLogger) ProvisionerOption {
	return func(p *Provisioner) { p.audit = logger }
}

// WithClock overrides the provisioning event clock. Test support.
func WithClock(now func() time.Time) ProvisionerOption {
	return func(p *Provisioner) {
		if now != nil {
			p.now = now
		}
	}
}

// recordProvisioning appends one provisioning event. Best-effort, the posture
// espresso.Auditor takes: the store write has already committed, so a Log
// failure is reported and does not undo it.
func (p *Provisioner) recordProvisioning(ctx context.Context, action audit.Action, group tenant.ID, resourceID string) {
	if p.audit == nil {
		return
	}
	ev := audit.Event{
		ID:           p.newID(),
		At:           p.now(),
		Actor:        audit.ActorFromContext(ctx),
		Action:       action,
		ResourceType: auditResourceType,
		ResourceID:   resourceID,
		// The row's scope: the tenant-group the grant is over.
		TenantID: group.String(),
	}
	if _, err := p.audit.Log(ctx, ev); err != nil {
		log.Printf("tenanthierarchy: audit %s on %s: %v (the change is already applied)",
			action, group, err)
	}
}
