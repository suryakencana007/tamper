package tenanthierarchy

import (
	"context"
	"fmt"
	"sort"

	"github.com/suryakencana007/tamper/authz"
	"github.com/suryakencana007/tamper/identity"
	"github.com/suryakencana007/tamper/tenant"
)

// DefaultUserSubjectType is the authz subject type Membership treats as a
// user when no WithUserSubjectType is given. It matches the example's
// subjects and identity.ActorTypeUser.
const DefaultUserSubjectType = "user"

// IntentReader is the store surface a derived membership needs: the intent rows
// of a known group, and the groups a subject administers when the scope is not
// known in advance. *Store implements it.
//
// (The manifest's block names authz.BindingStore, which does not expose the
// intent rows; membership has to read them by origin, because a direct grant on
// the group resource is not a group-admin grant.)
type IntentReader interface {
	BindingsFrom(ctx context.Context, scope tenant.ID, origin Origin) ([]authz.Binding, error)
	IntentGroupsForSubject(ctx context.Context, subjectType, userID string) ([]tenant.ID, error)
}

// Membership is an identity.MembershipStore derived from the intent rows and
// the OrgHierarchy: a user may enter an org iff a tenant-group grant covers it.
// Nothing is materialized, so there is no second set to drift.
type Membership struct {
	store    IntentReader
	hier     OrgHierarchy
	userType string
}

var _ identity.MembershipStore = (*Membership)(nil)

// MembershipOption configures a Membership.
type MembershipOption func(*Membership)

// WithUserSubjectType sets the authz subject type that counts as a user. The
// default is DefaultUserSubjectType. Set it when the application's taxonomy
// names users something else, so a service_account (or any other type) that
// shares an id cannot satisfy a user membership.
func WithUserSubjectType(subjectType string) MembershipOption {
	return func(m *Membership) { m.userType = subjectType }
}

// NewMembership returns a Membership. It panics on a nil store or hierarchy,
// or an empty user subject type: tenancy misconfiguration fails at
// construction, never as a per-request denial (standing rule 4).
func NewMembership(store IntentReader, hier OrgHierarchy, opts ...MembershipOption) *Membership {
	if store == nil {
		panic("tenanthierarchy: NewMembership requires an IntentReader")
	}
	if hier == nil {
		panic("tenanthierarchy: NewMembership requires an OrgHierarchy")
	}
	m := &Membership{store: store, hier: hier, userType: DefaultUserSubjectType}
	for _, opt := range opts {
		opt(m)
	}
	if m.userType == "" {
		panic("tenanthierarchy: NewMembership requires a non-empty user subject type")
	}
	return m
}

// IsMember reports whether userID may enter target: a user intent row exists in
// the scope of target's parent tenant-group. A root org (no parent) and an
// unknown org have no group, so there is nothing to be a member of and the
// answer is false. The row's subject type must be the configured user type, so
// another subject of the same id is not a membership. An OrgHierarchy error is
// returned, never read as allow.
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
		if b.Subject.Type == m.userType && b.Subject.ID == userID {
			return true, nil
		}
	}
	return false, nil
}

// MembershipsFor lists every child org of every tenant-group in which userID
// holds a user intent row, sorted. It never returns a tenant the user cannot
// actually enter: the orgs come from the groups the user administers.
func (m *Membership) MembershipsFor(ctx context.Context, userID string) ([]tenant.ID, error) {
	if userID == "" {
		return nil, nil
	}
	groups, err := m.store.IntentGroupsForSubject(ctx, m.userType, userID)
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
