package espresso

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	scim "github.com/suryakencana007/barista/packages/tamper/scim"
)

// SCIM Groups write-CRUD transport (Phase 4e-5c). Mirrors scimusers.go for
// Groups over scim.GroupStore. The port impl owns member resolution +
// nesting + the source='scim' filter + the scim.group.* audit (A3 — the
// transport emits no audit row; the generic group.* events stay in
// GroupService). The transport parses the RFC wire, resolves the SA
// Principal into GroupWrite.ActorServiceAccountID, checks If-Match, maps the
// §3.12 errors (incl. CIRCULAR_GROUP_REFERENCE), and renders the DTO.
//
// List + PATCH stay on the app handler until their own 4e slices.

// GroupsCreate serves POST {prefix}/Groups. Required: displayName. Optional:
// externalId, members[] (User or Group type; unknown ids → 400). 201 with
// the Group shape + Location + ETag.
func (s *SCIMRoutes) GroupsCreate(w http.ResponseWriter, r *http.Request) {
	body, err := readSCIMGroupBody(r)
	if err != nil {
		WriteSCIMErrorTyped(w, http.StatusBadRequest, err.Error(), SCIMTypeInvalidSyntax)
		return
	}
	displayName := strings.TrimSpace(body.DisplayName)
	if displayName == "" {
		WriteSCIMErrorTyped(w, http.StatusBadRequest, "displayName is required", SCIMTypeInvalidValue)
		return
	}
	rec, err := s.groups.Create(r.Context(), scim.GroupWrite{
		DisplayName:           displayName,
		ExternalID:            body.ExternalID,
		Members:               groupMemberRefs(body.Members),
		ActorServiceAccountID: MustGetPrincipal(r.Context()).ID,
	}, scim.GroupWriteMeta{})
	if err != nil {
		s.writeGroupStoreErr(w, err)
		return
	}
	base := ResolveBaseURL(r, s.cfg.BaseURL)
	w.Header().Set("Location", base+s.cfg.Prefix+"/Groups/"+rec.ID)
	WriteETagHeader(w, ResourceETag(rec.Updated))
	WriteSCIMJSON(w, http.StatusCreated, groupRecordToResource(rec, base, s.cfg.Prefix))
}

// GroupsGet serves GET {prefix}/Groups/{id}. Non-SCIM rows fold to 404 (the
// impl refuses them), so a SCIM client can't peek at admin/OIDC groups.
func (s *SCIMRoutes) GroupsGet(w http.ResponseWriter, r *http.Request) {
	id := scimTrailingSegment(r.URL.Path)
	if id == "" {
		WriteSCIMErrorTyped(w, http.StatusNotFound, "group not found", "")
		return
	}
	rec, err := s.groups.Get(r.Context(), id)
	if err != nil {
		s.writeGroupStoreErr(w, err)
		return
	}
	base := ResolveBaseURL(r, s.cfg.BaseURL)
	WriteETagHeader(w, ResourceETag(rec.Updated))
	WriteSCIMJSON(w, http.StatusOK, groupRecordToResource(rec, base, s.cfg.Prefix))
}

// GroupsReplace serves PUT {prefix}/Groups/{id}. Full-replace on the
// SCIM-sourced membership (manual/OIDC untouched). Honors the If-Match
// precondition against the pre-write state + emits an ETag.
func (s *SCIMRoutes) GroupsReplace(w http.ResponseWriter, r *http.Request) {
	id := scimTrailingSegment(r.URL.Path)
	if id == "" {
		WriteSCIMErrorTyped(w, http.StatusNotFound, "group not found", "")
		return
	}
	body, err := readSCIMGroupBody(r)
	if err != nil {
		WriteSCIMErrorTyped(w, http.StatusBadRequest, err.Error(), SCIMTypeInvalidSyntax)
		return
	}
	displayName := strings.TrimSpace(body.DisplayName)
	if displayName == "" {
		WriteSCIMErrorTyped(w, http.StatusBadRequest, "displayName is required", SCIMTypeInvalidValue)
		return
	}
	// Validate members BEFORE the existence + If-Match checks so a bad member
	// reports 400 invalidValue ahead of a 404/412, matching the pre-lift
	// handler's ordering (member resolution ran before the before-Get there).
	if err := s.groups.ValidateMembers(r.Context(), groupMemberRefs(body.Members)); err != nil {
		s.writeGroupStoreErr(w, err)
		return
	}
	before, err := s.groups.Get(r.Context(), id)
	if err != nil {
		s.writeGroupStoreErr(w, err)
		return
	}
	ifMatchPresent := r.Header.Get("If-Match") != ""
	if ok, _, _ := CheckIfMatch(r, ResourceETag(before.Updated)); !ok {
		WriteSCIMErrorTyped(w, http.StatusPreconditionFailed, "If-Match precondition failed", "")
		return
	}
	rec, err := s.groups.Replace(r.Context(), id, scim.GroupWrite{
		DisplayName:           displayName,
		ExternalID:            body.ExternalID,
		Members:               groupMemberRefs(body.Members),
		ActorServiceAccountID: MustGetPrincipal(r.Context()).ID,
	}, scim.GroupWriteMeta{IfMatchPresent: ifMatchPresent, Before: &before})
	if err != nil {
		s.writeGroupStoreErr(w, err)
		return
	}
	base := ResolveBaseURL(r, s.cfg.BaseURL)
	WriteETagHeader(w, ResourceETag(rec.Updated))
	WriteSCIMJSON(w, http.StatusOK, groupRecordToResource(rec, base, s.cfg.Prefix))
}

// GroupsDelete serves DELETE {prefix}/Groups/{id}. Hard-deletes (cascades
// group_members + group_roles). Honors the If-Match precondition. 204.
func (s *SCIMRoutes) GroupsDelete(w http.ResponseWriter, r *http.Request) {
	id := scimTrailingSegment(r.URL.Path)
	if id == "" {
		WriteSCIMErrorTyped(w, http.StatusNotFound, "group not found", "")
		return
	}
	before, err := s.groups.Get(r.Context(), id)
	if err != nil {
		s.writeGroupStoreErr(w, err)
		return
	}
	ifMatchPresent := r.Header.Get("If-Match") != ""
	if ok, _, _ := CheckIfMatch(r, ResourceETag(before.Updated)); !ok {
		WriteSCIMErrorTyped(w, http.StatusPreconditionFailed, "If-Match precondition failed", "")
		return
	}
	if err := s.groups.Delete(r.Context(), id, scim.GroupWriteMeta{IfMatchPresent: ifMatchPresent, Before: &before}); err != nil {
		s.writeGroupStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// writeGroupStoreErr maps a scim.GroupStore sentinel onto the §3.12
// envelope, matching the pre-lift handler's writeGroupServiceError /
// writeServiceError. ErrCyclicGroup is checked FIRST → 400
// CIRCULAR_GROUP_REFERENCE; then ErrNotFound → 404 (fixed "group not found");
// ErrConflict → 409 uniqueness; ErrInvalidInput → 400 invalidValue (detail
// recovered from the folded error); else 500.
func (s *SCIMRoutes) writeGroupStoreErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, scim.ErrCyclicGroup):
		WriteSCIMErrorTyped(w, http.StatusBadRequest, "CIRCULAR_GROUP_REFERENCE: "+err.Error(), SCIMTypeInvalidValue)
	case errors.Is(err, scim.ErrNotFound):
		WriteSCIMErrorTyped(w, http.StatusNotFound, "group not found", "")
	case errors.Is(err, scim.ErrConflict):
		WriteSCIMErrorTyped(w, http.StatusConflict, scimStoreDetail(err), SCIMTypeUniqueness)
	case errors.Is(err, scim.ErrInvalidInput):
		WriteSCIMErrorTyped(w, http.StatusBadRequest, scimStoreDetail(err), SCIMTypeInvalidValue)
	default:
		WriteSCIMErrorTyped(w, http.StatusInternalServerError, "internal error", "")
	}
}

// readSCIMGroupBody decodes the JSON body into a GroupCreateOrReplace and
// closes the body.
func readSCIMGroupBody(r *http.Request) (*GroupCreateOrReplace, error) {
	defer func() { _ = r.Body.Close() }()
	body := &GroupCreateOrReplace{}
	if err := json.NewDecoder(r.Body).Decode(body); err != nil {
		return nil, err
	}
	return body, nil
}

// groupMemberRefs maps the RFC members[] into neutral MemberRefs (Value +
// Type); the port impl resolves + validates them. $ref / display are ignored
// on a write (readOnly / server-derived).
func groupMemberRefs(members []GroupMember) []scim.MemberRef {
	if len(members) == 0 {
		return nil
	}
	out := make([]scim.MemberRef, 0, len(members))
	for _, m := range members {
		out = append(out, scim.MemberRef{Value: m.Value, Type: m.Type})
	}
	return out
}

// groupRecordToResource renders a neutral scim.GroupRecord into the RFC 7643
// core:Group wire shape — byte-identical to the pre-lift handler's
// groupToResource. members[].$ref is built from Type (User→/Users, Group→
// /Groups) + Value; the record's members are already User-first-then-Group
// and SCIM-filtered by the impl.
func groupRecordToResource(rec scim.GroupRecord, baseURL, prefix string) GroupResource {
	created := rec.Created.UTC().Format(time.RFC3339)
	lastModified := rec.Updated.UTC().Format(time.RFC3339)
	if rec.Updated.IsZero() {
		lastModified = created
	}
	version := ResourceETag(rec.Updated)
	if version == "" {
		version = `W/"` + created + `"`
	}
	var members []GroupMember
	for _, m := range rec.Members {
		ref := baseURL + prefix + "/Users/" + m.Value
		if m.Type == "Group" {
			ref = baseURL + prefix + "/Groups/" + m.Value
		}
		members = append(members, GroupMember{Value: m.Value, Ref: ref, Type: m.Type})
	}
	return GroupResource{
		Schemas:     []string{SchemaGroup},
		ID:          rec.ID,
		ExternalID:  rec.ExternalID,
		DisplayName: rec.DisplayName,
		Members:     members,
		Meta: ResourceMeta{
			ResourceType: "Group",
			Created:      created,
			LastModified: lastModified,
			Location:     baseURL + prefix + "/Groups/" + rec.ID,
			Version:      version,
		},
	}
}
