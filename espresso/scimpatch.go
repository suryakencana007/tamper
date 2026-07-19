package espresso

import (
	"encoding/json"
	"errors"
	"net/http"

	scim "github.com/suryakencana007/barista/packages/tamper/scim"
)

// SCIM PATCH transport (Phase 4e-5d). RFC 7644 §3.5.2 PATCH on Users +
// Groups. The transport applies the ops to a map snapshot of the resource (a
// reflection-free generic apply shared by both), extracts the persisted
// fields, and hands them to the port's SavePatch; the port impl persists +
// emits the redacted-ops audit (A3 — the transport emits none). PATCH is a
// partial update, distinct from Replace (it doesn't reset the name columns).

// UsersPatch serves PATCH {prefix}/Users/{id}. Applies the ops, persists via
// SavePatch, 200 + ETag. Ops against attributes Barista doesn't store are
// visible in the audit (redacted) but don't reach the store.
func (s *SCIMRoutes) UsersPatch(w http.ResponseWriter, r *http.Request) {
	id := scimTrailingSegment(r.URL.Path)
	if id == "" {
		WriteSCIMErrorTyped(w, http.StatusNotFound, "user not found", "")
		return
	}
	rec, err := s.users.Get(r.Context(), id)
	if err != nil {
		s.writeUserStoreErr(w, err)
		return
	}
	base := ResolveBaseURL(r, s.cfg.BaseURL)
	current := userRecordToResource(rec, base, s.cfg.Prefix)

	// If-Match against the pre-mutation state (matches Replace/Delete).
	if ok, _, _ := CheckIfMatch(r, ResourceETag(rec.Updated)); !ok {
		WriteSCIMErrorTyped(w, http.StatusPreconditionFailed, "If-Match precondition failed", "")
		return
	}

	req, err := decodeSCIMPatch(r)
	if err != nil {
		WriteSCIMErrorTyped(w, http.StatusBadRequest, err.Error(), SCIMTypeInvalidSyntax)
		return
	}
	if len(req.Operations) == 0 {
		WriteSCIMErrorTyped(w, http.StatusBadRequest, "Operations is required and must be non-empty", SCIMTypeInvalidValue)
		return
	}

	patched, err := applyToUserResource(current, req.Operations)
	if err != nil {
		writePatchApplyError(w, err)
		return
	}
	saved, err := s.users.SavePatch(r.Context(), id, scim.UserWrite{
		UserName:   patched.UserName,
		ExternalID: patched.ExternalID,
		Active:     patched.Active,
	}, req.Operations)
	if err != nil {
		s.writeUserStoreErr(w, err)
		return
	}
	WriteETagHeader(w, ResourceETag(saved.Updated))
	WriteSCIMJSON(w, http.StatusOK, userRecordToResource(saved, base, s.cfg.Prefix))
}

// GroupsPatch serves PATCH {prefix}/Groups/{id}. Applies the ops, then
// persists via SavePatch — member resolution + nested-group cycle detection
// run in the impl (after this If-Match, matching the pre-lift PATCH order).
func (s *SCIMRoutes) GroupsPatch(w http.ResponseWriter, r *http.Request) {
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
	current := groupRecordToResource(rec, base, s.cfg.Prefix)

	if ok, _, _ := CheckIfMatch(r, ResourceETag(rec.Updated)); !ok {
		WriteSCIMErrorTyped(w, http.StatusPreconditionFailed, "If-Match precondition failed", "")
		return
	}

	req, err := decodeSCIMPatch(r)
	if err != nil {
		WriteSCIMErrorTyped(w, http.StatusBadRequest, err.Error(), SCIMTypeInvalidSyntax)
		return
	}
	if len(req.Operations) == 0 {
		WriteSCIMErrorTyped(w, http.StatusBadRequest, "Operations is required and must be non-empty", SCIMTypeInvalidValue)
		return
	}

	patched, err := applyToGroupResource(current, req.Operations)
	if err != nil {
		writePatchApplyError(w, err)
		return
	}
	saved, err := s.groups.SavePatch(r.Context(), id, scim.GroupWrite{
		DisplayName:           patched.DisplayName,
		ExternalID:            patched.ExternalID,
		Members:               groupMemberRefs(patched.Members),
		ActorServiceAccountID: MustGetPrincipal(r.Context()).ID,
	}, req.Operations)
	if err != nil {
		s.writeGroupStoreErr(w, err)
		return
	}
	WriteETagHeader(w, ResourceETag(saved.Updated))
	WriteSCIMJSON(w, http.StatusOK, groupRecordToResource(saved, base, s.cfg.Prefix))
}

// decodeSCIMPatch reads the PATCH envelope (RFC 7644 §3.5.2). The op field is
// lowercased by scim.Operation's UnmarshalJSON hook, so the applier's
// dispatcher sees only add/remove/replace.
func decodeSCIMPatch(r *http.Request) (*scim.Request, error) {
	defer func() { _ = r.Body.Close() }()
	req := &scim.Request{}
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		return nil, err
	}
	return req, nil
}

// applyToUserResource marshals the typed resource to a map, applies the ops
// via scim.Apply, and unmarshals back — the map shape mirrors the RFC wire
// JSON exactly (the DTO's json tags emit it), so the applier stays generic +
// reflection-free and Users/Groups share it.
func applyToUserResource(current UserResource, ops []scim.Operation) (UserResource, error) {
	m, err := resourceToMap(current)
	if err != nil {
		return UserResource{}, err
	}
	if err := scim.Apply(m, ops); err != nil {
		return UserResource{}, err
	}
	var out UserResource
	if err := mapToResource(m, &out); err != nil {
		return UserResource{}, err
	}
	return out, nil
}

func applyToGroupResource(current GroupResource, ops []scim.Operation) (GroupResource, error) {
	m, err := resourceToMap(current)
	if err != nil {
		return GroupResource{}, err
	}
	if err := scim.Apply(m, ops); err != nil {
		return GroupResource{}, err
	}
	var out GroupResource
	if err := mapToResource(m, &out); err != nil {
		return GroupResource{}, err
	}
	return out, nil
}

func resourceToMap(v any) (map[string]any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func mapToResource(m map[string]any, out any) error {
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

// writePatchApplyError maps a scim.Apply error onto the §3.12 envelope:
// ErrInvalidPath → 400 invalidPath; ErrInvalidValue → 400 invalidValue;
// anything else → 500 (matches the pre-lift writePatchApplyError). The applier
// returns wrapped sentinels, so errors.Is reads the chain.
func writePatchApplyError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, scim.ErrInvalidPath):
		WriteSCIMErrorTyped(w, http.StatusBadRequest, err.Error(), SCIMTypeInvalidPath)
	case errors.Is(err, scim.ErrInvalidValue):
		WriteSCIMErrorTyped(w, http.StatusBadRequest, err.Error(), SCIMTypeInvalidValue)
	default:
		WriteSCIMErrorTyped(w, http.StatusInternalServerError, "internal error", "")
	}
}
