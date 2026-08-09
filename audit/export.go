package audit

import (
	"context"
	"fmt"

	"github.com/suryakencana007/tamper/tenant"
)

// Tenant-scoped export.
//
// WHAT AN EXPORT MAY HONESTLY CLAIM is the entire design problem here,
// and getting it wrong is worse than not shipping one: a customer who
// believes they hold a complete, contiguous, verifiable log will treat a
// gap as evidence of tampering, or — far worse — treat its absence as
// evidence of innocence.
//
// Under one chain (sketch §8 item 1) consecutive rows belonging to ONE
// tenant do not link to each other. The links run through other
// tenants' rows. So a tenant slice can prove a great deal, and cannot
// prove one specific thing:
//
//	MAY claim — per-row AUTHENTICITY and POSITION. Each row ships its
//	own prev_hash and hash, recomputable from the row alone without
//	access to anyone else's data. And because the tenant is INSIDE the
//	v4 payload, attribution cannot have been reassigned after the fact:
//	moving a row from tenant A to tenant B changes its hash.
//
//	MAY NOT claim — COMPLETENESS or CONTIGUITY. Nothing in the slice
//	demonstrates that no row was withheld from it, and consecutive
//	exported rows are not chain-adjacent.
//
// The honest fix for contiguity — shipping the intervening hashes as a
// hash path — is deliberately NOT offered, and not because it is hard.
// It would disclose every other tenant's event volume and timing to
// whoever holds the export. This phase spends an entire slice keeping
// StartLogin from being an enumeration oracle; shipping one with a
// signature on it would be a strange way to finish.

// ExportCompleteness labels how much an export's row set can vouch for
// itself. Wire-stable — a consumer branches on it.
const (
	// CompletenessIssuerAttested means the row set's boundaries rest on
	// the issuer's word, not on cryptography. Every tenant-filtered
	// export from a shared chain is this.
	CompletenessIssuerAttested = "issuer-attested"
)

// TenantExport is a tenant's slice of the audit log.
type TenantExport struct {
	// TenantID is the tenant the slice was taken for.
	TenantID string `json:"tenant_id"`

	// Events are the tenant's rows, oldest first, each carrying its own
	// prev_hash and hash.
	Events []Event `json:"events"`

	// IsChain is ALWAYS false and is serialised anyway.
	//
	// A field that is always false looks like a candidate for deletion
	// until you ask what its absence would mean: a consumer that finds
	// no such field has no way to distinguish "this is not a chain" from
	// "this export predates the question". Stating it explicitly is the
	// difference between a document that is honest and one that is
	// merely not lying.
	IsChain bool `json:"is_chain"`

	// Completeness is CompletenessIssuerAttested. See the package
	// comment above for exactly what that concedes.
	Completeness string `json:"completeness"`
}

// ExportForTenant returns every row scoped to tenantID, oldest first.
//
// FILTERS ON Event.TenantID — the row's scope — and NOT on
// Actor.TenantID. They are different facts, and the difference is the
// whole reason both are in the v4 payload: a support engineer or a
// system actor belonging to tenant A, acting on tenant B's resource,
// has actor-tenant A and event-tenant B. Filtering on the actor's tenant
// silently omits exactly the cross-tenant administrative actions a
// customer most wants to see in their own log. A filter that "worked" in
// every test written by someone with only same-tenant fixtures is
// exactly how that ships.
//
// Rows are returned AS STORED. Nothing is renumbered, nothing is
// re-hashed, and no row is synthesised to fill a gap — the export is a
// projection of the chain, not a new one. An export that re-hashed its
// slice into a self-consistent chain would be manufacturing evidence
// that the original never contained.
//
// An UNSET tenant is an error, not an empty export. Before v0.4.0 this
// took a string and "" returned no rows, because "" was ambiguous between
// "the single-tenant scope" and "the caller forgot" and deny-by-default
// won. tenant.ID resolves the ambiguity: the zero value errors, and
// tenant.Single is a real scope — it exports exactly the rows STAMPED
// with the single-tenant value, which in a pooled DB is the pre-tenancy
// legacy segment and in a single-tenant DB is the whole log. A scope,
// not a wildcard: it never returns another tenant's rows.
func (l *SQLiteLogger) ExportForTenant(ctx context.Context, tenantID tenant.ID) (TenantExport, error) {
	if !tenantID.Valid() {
		return TenantExport{}, fmt.Errorf("audit: export: tenant is required (unset tenant.ID)")
	}
	out := TenantExport{
		TenantID:     tenantID.String(),
		Events:       []Event{},
		IsChain:      false,
		Completeness: CompletenessIssuerAttested,
	}
	if l == nil || l.store == nil {
		return out, nil
	}
	rows, err := l.store.Queries.ListEventsByTenant(ctx, tenantID.String())
	if err != nil {
		return TenantExport{}, fmt.Errorf("audit: export for tenant: %w", err)
	}
	for _, r := range rows {
		e := fromRow(r)
		// Belt and braces. The WHERE clause is the control; this is the
		// assertion that it did what it says, because a leak here is a
		// cross-customer disclosure and the cost of one comparison is
		// nothing against that.
		if e.TenantID != tenantID.String() {
			return TenantExport{}, fmt.Errorf(
				"audit: export for tenant %q returned a row scoped to %q (event %s)",
				tenantID, e.TenantID, e.ID)
		}
		out.Events = append(out.Events, e)
	}
	return out, nil
}
