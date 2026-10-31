package tenanthierarchy

import (
	"context"
	"fmt"
	"sort"

	"github.com/suryakencana007/tamper/authz"
	"github.com/suryakencana007/tamper/identity"
	"github.com/suryakencana007/tamper/tenant"
)

// IntentReader is the store surface a derived membership needs: the intent rows
// of a known group, and the groups a subject administers when the scope is not
// known in advance. *Store implements it.
//
// (The manifest's block names authz.BindingStore, which does not expose the
// intent rows; membership has to read them by origin, because a direct grant on
// the group resource is not a group-admin grant.)
type IntentReader interface {
	BindingsFrom(ctx context.Context, scope tenant.ID, origin Origin) ([]authz.Binding, error)
	IntentGroupsForSubject(ctx context.Context, userID string) ([]tenant.ID, error)
}

// Membership is an identity.MembershipStore derived from the intent rows and
// the OrgHierarchy: a user may enter an org iff a tenant-group grant covers it.
// Nothing is materialized, so there is no second set to drift.
type Membership struct {
	store IntentReader
	hier  OrgHierarchy
}

var _ identity.MembershipStore = (*Membership)(nil)

// NewMembership returns a Membership. It panics on a nil store or hierarchy:
// tenancy misconfiguration fails at construction, never as a per-request
// denial (standing rule 4).
func NewMembership(store IntentReader, hier OrgHierarchy) *Membership {
	if store == nil {
		panic("tenanthierarchy: NewMembership requires an IntentReader")
	}
	if hier == nil {
		panic("tenanthierarchy: NewMembership requires an OrgHierarchy")
	}
	return &Membership{store: store, hier: hier}
}

// IsMember reports whether userID may enter target: an intent row exists in the
// scope of target's parent tenant-group. A root org (no parent) and an unknown
// org have no group, so there is nothing to be a member of and the answer is
// false. An OrgHierarchy error is returned, never read as allow.
func (m *Membership) IsMember(ctx context.Context, userID string, target tenant.ID) (bool, error) {
	if userID == "" || !target.Valid() || target.IsSingle() {
		return false, nil
	}
	groupID, ok, err := m.hier.ParentOf(ctx, target.String())
	if err != nil {
		return false, fmt.Errorf("tenanthierarchy: resolve parent of %s: %w", target, err)
	}
	if !ok {
		return false, nil
	}
	group := tenant.New(groupID)
	if !group.Valid() || group.IsSingle() {
		return false, nil
	}
	intents, err := m.store.BindingsFrom(ctx, group, GroupOrigin(group))
	if err != nil {
		return false, fmt.Errorf("tenanthierarchy: intent rows of %s: %w", group, err)
	}
	for _, b := range intents {
		if b.Subject.ID == userID {
			return true, nil
		}
	}
	return false, nil
}

// MembershipsFor lists every child org of every tenant-group in which userID
// holds an intent row, sorted. It never returns a tenant the user cannot
// actually enter: the orgs come from the groups the user administers.
func (m *Membership) MembershipsFor(ctx context.Context, userID string) ([]tenant.ID, error) {
	if userID == "" {
		return nil, nil
	}
	groups, err := m.store.IntentGroupsForSubject(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("tenanthierarchy: groups for %s: %w", userID, err)
	}
	seen := make(map[tenant.ID]bool)
	var out []tenant.ID
	for _, group := range groups {
		children, err := m.hier.ChildrenOf(ctx, group.String())
		if err != nil {
			return nil, fmt.Errorf("tenanthierarchy: children of %s: %w", group, err)
		}
		for _, id := range children {
			org := tenant.New(id)
			if !org.Valid() || org.IsSingle() || seen[org] {
				continue
			}
			seen[org] = true
			out = append(out, org)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out, nil
}
