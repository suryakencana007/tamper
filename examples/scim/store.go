package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	fp "github.com/scim2/filter-parser/v2"

	"github.com/google/uuid"

	"github.com/suryakencana007/barista/packages/tamper/audit"
	"github.com/suryakencana007/barista/packages/tamper/scim"
)

// This file implements the two persistence ports the SCIM transport calls —
// scim.UserStore and scim.GroupStore — over in-memory maps. In a real app
// these are your database (Barista: internal/scimstore over SQLite/Postgres).
//
// The load-bearing pattern here is the AUDIT CROSSING (amendment A3): the
// transport emits NO audit rows — the port implementation does, because only
// the app knows the actor + the before/after. The actor rides in on the
// context that RequireServiceAccount stashed (audit.ActorFromContext), and the
// pre-write "Before" snapshot is threaded down via WriteMeta (never a second
// read, which would race a concurrent write).

// SCIM audit actions. tamper/audit ships no scim.* action constants (those are
// the app's vocabulary), so the example defines its own — the transport is
// vocabulary-agnostic.
const (
	actionUserCreate  = audit.Action("scim.user.create")
	actionUserReplace = audit.Action("scim.user.replace")
	actionUserDelete  = audit.Action("scim.user.delete")
	actionUserPatch   = audit.Action("scim.user.patch")
	actionUserList    = audit.Action("scim.user.list")

	actionGroupCreate  = audit.Action("scim.group.create")
	actionGroupReplace = audit.Action("scim.group.replace")
	actionGroupDelete  = audit.Action("scim.group.delete")
	actionGroupPatch   = audit.Action("scim.group.patch")
	actionGroupList    = audit.Action("scim.group.list")
)

// tamper/audit has ResourceUser but no ResourceGroup — groups are app-scoped.
const resourceGroup = audit.ResourceType("group")

// ---------------------------------------------------------------------------
// User store
// ---------------------------------------------------------------------------

type memUserStore struct {
	mu    sync.Mutex
	users map[string]scim.UserRecord
	audit audit.Logger
}

var _ scim.UserStore = (*memUserStore)(nil)

func newUserStore(a audit.Logger) *memUserStore {
	return &memUserStore{users: map[string]scim.UserRecord{}, audit: a}
}

// Count exposes the row count for the example's persistence assertions.
func (s *memUserStore) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.users)
}

func (s *memUserStore) exists(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.users[id]
	return ok
}

func (s *memUserStore) Create(ctx context.Context, w scim.UserWrite, _ scim.WriteMeta) (scim.UserRecord, error) {
	s.mu.Lock()
	for _, rec := range s.users {
		if rec.UserName == w.UserName {
			s.mu.Unlock()
			return scim.UserRecord{}, fmt.Errorf("%w: userName %q already exists", scim.ErrConflict, w.UserName)
		}
	}
	rec := userFromWrite(uuid.NewString(), w, time.Now().UTC(), time.Now().UTC())
	s.users[rec.ID] = rec
	s.mu.Unlock()

	s.emitUser(ctx, actionUserCreate, &rec, nil, false)
	return rec, nil
}

func (s *memUserStore) Get(_ context.Context, id string) (scim.UserRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.users[id]
	if !ok {
		return scim.UserRecord{}, scim.ErrNotFound
	}
	return rec, nil
}

func (s *memUserStore) Replace(ctx context.Context, id string, w scim.UserWrite, meta scim.WriteMeta) (scim.UserRecord, error) {
	s.mu.Lock()
	existing, ok := s.users[id]
	if !ok {
		s.mu.Unlock()
		return scim.UserRecord{}, scim.ErrNotFound
	}
	if w.UserName != existing.UserName {
		for oid, rec := range s.users {
			if oid != id && rec.UserName == w.UserName {
				s.mu.Unlock()
				return scim.UserRecord{}, fmt.Errorf("%w: userName %q already exists", scim.ErrConflict, w.UserName)
			}
		}
	}
	// Replace is a FULL overwrite (it resets the name columns) — preserve only
	// the immutable Created.
	rec := userFromWrite(id, w, existing.Created, time.Now().UTC())
	s.users[id] = rec
	s.mu.Unlock()

	s.emitUser(ctx, actionUserReplace, &rec, meta.Before, meta.IfMatchPresent)
	return rec, nil
}

func (s *memUserStore) Delete(ctx context.Context, id string, meta scim.WriteMeta) error {
	s.mu.Lock()
	if _, ok := s.users[id]; !ok {
		s.mu.Unlock()
		return scim.ErrNotFound
	}
	delete(s.users, id)
	s.mu.Unlock()

	s.emitUser(ctx, actionUserDelete, nil, meta.Before, meta.IfMatchPresent)
	return nil
}

// SavePatch is the PATCH persist. Unlike Replace it is a PARTIAL update — the
// transport pre-applies the ops and hands us a UserWrite carrying only
// UserName/ExternalID/Active; FamilyName/GivenName are zero and MUST be left
// untouched (resetting them here would wipe the user's name on every PATCH).
func (s *memUserStore) SavePatch(ctx context.Context, id string, w scim.UserWrite, ops []scim.Operation) (scim.UserRecord, error) {
	s.mu.Lock()
	existing, ok := s.users[id]
	if !ok {
		s.mu.Unlock()
		return scim.UserRecord{}, scim.ErrNotFound
	}
	rec := existing // copy; keep FamilyName/GivenName
	rec.UserName = w.UserName
	rec.ExternalID = w.ExternalID
	rec.Active = w.Active
	rec.Emails = []scim.Email{{Value: w.UserName, Primary: true, Type: "work"}}
	rec.Updated = time.Now().UTC()
	s.users[id] = rec
	s.mu.Unlock()

	s.emitUserPatch(ctx, id, ops)
	return rec, nil
}

func (s *memUserStore) List(_ context.Context, startIndex, count int) (scim.UserPage, error) {
	s.mu.Lock()
	all := sortedUsers(s.users)
	s.mu.Unlock()
	page := pageUsers(all, startIndex, count)
	return scim.UserPage{Users: page, Total: len(all)}, nil
}

func (s *memUserStore) ListFiltered(ctx context.Context, startIndex, count int, filter string) (scim.UserPage, error) {
	// A real adapter runs scim.Parse + scim.Translate to a SQL WHERE against
	// its ColumnMapping. In-memory, we walk the AST for the one clause the
	// example supports; anything else folds to ErrInvalidFilter (→ 400).
	want, matchAll, err := parseEqFilter(filter, "userName")
	if err != nil {
		return scim.UserPage{}, err
	}
	s.mu.Lock()
	all := sortedUsers(s.users)
	s.mu.Unlock()

	matched := all[:0:0]
	for _, u := range all {
		if matchAll || u.UserName == want {
			matched = append(matched, u)
		}
	}
	total := len(matched) // FILTERED total for totalResults, not the page length
	page := pageUsers(matched, startIndex, count)

	s.emitUserList(ctx, filter, total)
	return scim.UserPage{Users: page, Total: total}, nil
}

func userFromWrite(id string, w scim.UserWrite, created, updated time.Time) scim.UserRecord {
	return scim.UserRecord{
		ID:         id,
		UserName:   w.UserName,
		FamilyName: w.FamilyName,
		GivenName:  w.GivenName,
		Active:     w.Active,
		ExternalID: w.ExternalID,
		// v1.0 convention: exactly one email, and it IS the userName.
		Emails:  []scim.Email{{Value: w.UserName, Primary: true, Type: "work"}},
		Created: created,
		Updated: updated,
	}
}

func sortedUsers(m map[string]scim.UserRecord) []scim.UserRecord {
	out := make([]scim.UserRecord, 0, len(m))
	for _, r := range m {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID }) // deterministic paging
	return out
}

func pageUsers(all []scim.UserRecord, startIndex, count int) []scim.UserRecord {
	lo := startIndex - 1 // startIndex is 1-based (RFC 7644 §3.4.2)
	if lo < 0 {
		lo = 0
	}
	if lo >= len(all) {
		return nil
	}
	hi := lo + count
	if count <= 0 || hi > len(all) {
		hi = len(all)
	}
	return all[lo:hi]
}

// --- user audit (A3: the port impl emits; the transport emits nothing) ---

func (s *memUserStore) emitUser(ctx context.Context, action audit.Action, after, before *scim.UserRecord, ifMatch bool) {
	if s.audit == nil {
		return
	}
	ev := audit.Event{
		ID:           uuid.NewString(),
		At:           time.Now().UTC(),
		Actor:        audit.ActorFromContext(ctx), // the RequireServiceAccount-stashed service account
		Action:       action,
		ResourceType: audit.ResourceUser,
	}
	if after != nil {
		ev.ResourceID = after.ID
	} else if before != nil {
		ev.ResourceID = before.ID
	}
	if before != nil {
		ev.Before, _ = json.Marshal(userPayload(before))
	}
	switch {
	case after != nil:
		p := userPayload(after)
		if action == actionUserReplace {
			p["if_match_present"] = ifMatch
		}
		ev.After, _ = json.Marshal(p)
	case action == actionUserDelete:
		ev.After, _ = json.Marshal(map[string]any{"if_match_present": ifMatch})
	}
	_, _ = s.audit.Log(ctx, ev) // best-effort: an audit miss must never fail the mutation
}

func (s *memUserStore) emitUserPatch(ctx context.Context, userID string, ops []scim.Operation) {
	if s.audit == nil {
		return
	}
	after, _ := json.Marshal(map[string]any{
		"operations":      scim.RedactedOps(ops), // values redacted — a PATCH can carry secrets
		"operation_count": len(ops),
	})
	_, _ = s.audit.Log(ctx, audit.Event{
		ID: uuid.NewString(), At: time.Now().UTC(), Actor: audit.ActorFromContext(ctx),
		Action: actionUserPatch, ResourceType: audit.ResourceUser, ResourceID: userID, After: after,
	})
}

func (s *memUserStore) emitUserList(ctx context.Context, filter string, total int) {
	if s.audit == nil {
		return
	}
	after, _ := json.Marshal(map[string]any{"filter": filter, "total_results": total})
	_, _ = s.audit.Log(ctx, audit.Event{
		ID: uuid.NewString(), At: time.Now().UTC(), Actor: audit.ActorFromContext(ctx),
		Action: actionUserList, ResourceType: audit.ResourceUser, After: after,
	})
}

func userPayload(r *scim.UserRecord) map[string]any {
	return map[string]any{"id": r.ID, "email": r.UserName, "external_id": r.ExternalID, "active": r.Active}
}

// ---------------------------------------------------------------------------
// Group store
// ---------------------------------------------------------------------------

type memGroupStore struct {
	mu     sync.Mutex
	groups map[string]scim.GroupRecord
	users  *memUserStore // to validate User-typed members exist
	audit  audit.Logger
}

var _ scim.GroupStore = (*memGroupStore)(nil)

func newGroupStore(a audit.Logger, u *memUserStore) *memGroupStore {
	return &memGroupStore{groups: map[string]scim.GroupRecord{}, users: u, audit: a}
}

// Count exposes the row count for the example's persistence assertions.
func (s *memGroupStore) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.groups)
}

// resolveMembersLocked validates each member exists + normalises its type
// (empty type ⇒ "User"). Caller holds s.mu; s.users.exists self-locks the
// user store (no reverse dependency ⇒ no deadlock).
func (s *memGroupStore) resolveMembersLocked(members []scim.MemberRef) (userIDs, groupIDs []string, err error) {
	for _, m := range members {
		id := strings.TrimSpace(m.Value)
		switch strings.ToLower(strings.TrimSpace(m.Type)) {
		case "group":
			if _, ok := s.groups[id]; !ok {
				return nil, nil, fmt.Errorf("%w: member references unknown group %s", scim.ErrInvalidInput, id)
			}
			groupIDs = append(groupIDs, id)
		default: // "" or "user" ⇒ User
			if !s.users.exists(id) {
				return nil, nil, fmt.Errorf("%w: member references unknown user %s", scim.ErrInvalidInput, id)
			}
			userIDs = append(userIDs, id)
		}
	}
	return userIDs, groupIDs, nil
}

func (s *memGroupStore) ValidateMembers(_ context.Context, members []scim.MemberRef) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _, err := s.resolveMembersLocked(members)
	return err
}

func (s *memGroupStore) Create(ctx context.Context, w scim.GroupWrite, _ scim.GroupWriteMeta) (scim.GroupRecord, error) {
	s.mu.Lock()
	rec, err := s.buildGroupLocked(ctx, uuid.NewString(), w, time.Now().UTC())
	if err != nil {
		s.mu.Unlock()
		return scim.GroupRecord{}, err
	}
	s.groups[rec.ID] = rec
	s.mu.Unlock()

	s.emitGroup(ctx, actionGroupCreate, &rec, nil, false)
	return rec, nil
}

func (s *memGroupStore) Get(_ context.Context, id string) (scim.GroupRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.groups[id]
	if !ok {
		return scim.GroupRecord{}, scim.ErrNotFound
	}
	return rec, nil
}

func (s *memGroupStore) Replace(ctx context.Context, id string, w scim.GroupWrite, meta scim.GroupWriteMeta) (scim.GroupRecord, error) {
	if w.ActorServiceAccountID == "" {
		return scim.GroupRecord{}, fmt.Errorf("%w: missing service-account actor", scim.ErrInvalidInput)
	}
	s.mu.Lock()
	existing, ok := s.groups[id]
	if !ok {
		s.mu.Unlock()
		return scim.GroupRecord{}, scim.ErrNotFound
	}
	rec, err := s.buildGroupLocked(ctx, id, w, existing.Created)
	if err != nil {
		s.mu.Unlock()
		return scim.GroupRecord{}, err
	}
	s.groups[id] = rec
	s.mu.Unlock()

	s.emitGroup(ctx, actionGroupReplace, &rec, meta.Before, meta.IfMatchPresent)
	return rec, nil
}

func (s *memGroupStore) Delete(ctx context.Context, id string, meta scim.GroupWriteMeta) error {
	s.mu.Lock()
	if _, ok := s.groups[id]; !ok {
		s.mu.Unlock()
		return scim.ErrNotFound
	}
	delete(s.groups, id)
	s.mu.Unlock()

	s.emitGroup(ctx, actionGroupDelete, nil, meta.Before, meta.IfMatchPresent)
	return nil
}

func (s *memGroupStore) SavePatch(ctx context.Context, id string, w scim.GroupWrite, ops []scim.Operation) (scim.GroupRecord, error) {
	s.mu.Lock()
	existing, ok := s.groups[id]
	if !ok {
		s.mu.Unlock()
		return scim.GroupRecord{}, scim.ErrNotFound
	}
	rec, err := s.buildGroupLocked(ctx, id, w, existing.Created)
	if err != nil {
		s.mu.Unlock()
		return scim.GroupRecord{}, err
	}
	s.groups[id] = rec
	s.mu.Unlock()

	s.emitGroupPatch(ctx, id, ops)
	return rec, nil
}

func (s *memGroupStore) List(_ context.Context, startIndex, count int) (scim.GroupPage, error) {
	s.mu.Lock()
	all := sortedGroups(s.groups)
	s.mu.Unlock()
	return scim.GroupPage{Groups: pageGroups(all, startIndex, count), Total: len(all)}, nil
}

func (s *memGroupStore) ListFiltered(ctx context.Context, startIndex, count int, filter string) (scim.GroupPage, error) {
	want, matchAll, err := parseEqFilter(filter, "displayName")
	if err != nil {
		return scim.GroupPage{}, err
	}
	s.mu.Lock()
	all := sortedGroups(s.groups)
	s.mu.Unlock()

	matched := all[:0:0]
	for _, g := range all {
		if matchAll || g.DisplayName == want {
			matched = append(matched, g)
		}
	}
	total := len(matched)
	s.emitGroupList(ctx, filter, total)
	return scim.GroupPage{Groups: pageGroups(matched, startIndex, count), Total: total}, nil
}

// buildGroupLocked validates members, runs the nested-group cycle check for
// each group-typed member, and assembles the record. Caller holds s.mu.
func (s *memGroupStore) buildGroupLocked(ctx context.Context, id string, w scim.GroupWrite, created time.Time) (scim.GroupRecord, error) {
	userIDs, groupIDs, err := s.resolveMembersLocked(w.Members)
	if err != nil {
		return scim.GroupRecord{}, err
	}
	q := s.parentEdgesLocked()
	for _, child := range groupIDs {
		// A candidate edge id -> child must not close a cycle.
		if cerr := scim.DetectCycle(ctx, q, id, child); cerr != nil {
			return scim.GroupRecord{}, cerr // ErrCyclicGroup, unchanged → CIRCULAR_GROUP_REFERENCE
		}
	}
	members := make([]scim.MemberRef, 0, len(userIDs)+len(groupIDs))
	for _, uid := range userIDs {
		members = append(members, scim.MemberRef{Value: uid, Type: "User"})
	}
	for _, gid := range groupIDs {
		members = append(members, scim.MemberRef{Value: gid, Type: "Group"})
	}
	return scim.GroupRecord{
		ID: id, DisplayName: w.DisplayName, ExternalID: w.ExternalID,
		Members: members, Created: created, Updated: time.Now().UTC(),
	}, nil
}

// parentQuery answers scim.DetectCycle's "which groups have B as a direct
// member" over the in-memory group map.
type parentQuery map[string][]string

func (p parentQuery) ListParentGroupsOf(_ context.Context, memberGroupID sql.NullString) ([]string, error) {
	return p[memberGroupID.String], nil
}

func (s *memGroupStore) parentEdgesLocked() parentQuery {
	pq := parentQuery{}
	for _, g := range s.groups {
		for _, m := range g.Members {
			if strings.EqualFold(m.Type, "group") {
				pq[m.Value] = append(pq[m.Value], g.ID)
			}
		}
	}
	return pq
}

func sortedGroups(m map[string]scim.GroupRecord) []scim.GroupRecord {
	out := make([]scim.GroupRecord, 0, len(m))
	for _, r := range m {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func pageGroups(all []scim.GroupRecord, startIndex, count int) []scim.GroupRecord {
	lo := startIndex - 1
	if lo < 0 {
		lo = 0
	}
	if lo >= len(all) {
		return nil
	}
	hi := lo + count
	if count <= 0 || hi > len(all) {
		hi = len(all)
	}
	return all[lo:hi]
}

func (s *memGroupStore) emitGroup(ctx context.Context, action audit.Action, after, before *scim.GroupRecord, ifMatch bool) {
	if s.audit == nil {
		return
	}
	ev := audit.Event{
		ID: uuid.NewString(), At: time.Now().UTC(), Actor: audit.ActorFromContext(ctx),
		Action: action, ResourceType: resourceGroup,
	}
	if after != nil {
		ev.ResourceID = after.ID
	} else if before != nil {
		ev.ResourceID = before.ID
	}
	if before != nil {
		ev.Before, _ = json.Marshal(groupPayload(before))
	}
	switch {
	case after != nil:
		p := groupPayload(after)
		if action == actionGroupReplace {
			p["if_match_present"] = ifMatch
		}
		ev.After, _ = json.Marshal(p)
	case action == actionGroupDelete:
		ev.After, _ = json.Marshal(map[string]any{"if_match_present": ifMatch})
	}
	_, _ = s.audit.Log(ctx, ev)
}

func (s *memGroupStore) emitGroupPatch(ctx context.Context, groupID string, ops []scim.Operation) {
	if s.audit == nil {
		return
	}
	after, _ := json.Marshal(map[string]any{"operations": scim.RedactedOps(ops), "operation_count": len(ops)})
	_, _ = s.audit.Log(ctx, audit.Event{
		ID: uuid.NewString(), At: time.Now().UTC(), Actor: audit.ActorFromContext(ctx),
		Action: actionGroupPatch, ResourceType: resourceGroup, ResourceID: groupID, After: after,
	})
}

func (s *memGroupStore) emitGroupList(ctx context.Context, filter string, total int) {
	if s.audit == nil {
		return
	}
	after, _ := json.Marshal(map[string]any{"filter": filter, "total_results": total})
	_, _ = s.audit.Log(ctx, audit.Event{
		ID: uuid.NewString(), At: time.Now().UTC(), Actor: audit.ActorFromContext(ctx),
		Action: actionGroupList, ResourceType: resourceGroup, After: after,
	})
}

func groupPayload(r *scim.GroupRecord) map[string]any {
	return map[string]any{"id": r.ID, "display_name": r.DisplayName, "external_id": r.ExternalID, "member_count": len(r.Members)}
}

// ---------------------------------------------------------------------------
// Shared filter helper
// ---------------------------------------------------------------------------

// parseEqFilter supports exactly `<attr> eq "value"` (and an empty filter =
// match-all). A real store runs scim.Parse + scim.Translate to SQL over its
// ColumnMapping; this walks the AST for the one clause the example handles and
// folds anything else to scim.ErrInvalidFilter (→ 400 invalidFilter).
func parseEqFilter(filter, attr string) (want string, matchAll bool, err error) {
	expr, perr := scim.Parse(filter)
	if perr != nil {
		return "", false, fmt.Errorf("%w: %w", scim.ErrInvalidFilter, perr)
	}
	if expr == nil { // empty filter
		return "", true, nil
	}
	ae, ok := expr.(*fp.AttributeExpression)
	if !ok || ae.Operator != fp.EQ || ae.AttributePath.AttributeName != attr {
		return "", false, fmt.Errorf("%w: this example supports only %s eq \"...\"", scim.ErrInvalidFilter, attr)
	}
	want, _ = ae.CompareValue.(string)
	return want, false, nil
}
