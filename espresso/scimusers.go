package espresso

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	scim "github.com/suryakencana007/barista/packages/tamper/scim"
)

// SCIM Users write-CRUD transport (Phase 4e-5b). These methods lift the
// pre-lift Barista handler (internal/api/handler/scim/users.go) into the
// framework: they own the RFC 7643 wire parse + render, the RFC 7232
// ETag/If-Match precondition, and the RFC 7644 §3.12 error mapping, and
// route persistence through the scim.UserStore port. The port impl
// (app-side) owns Barista's projection AND the audit emission (amendment
// A3 — the transport emits no audit row); the transport-only
// if_match_present fact threads down via scim.WriteMeta so the audit row
// stays byte-identical to the pre-lift handler.
//
// The full Users verb set now routes here — Create/Get/Replace/Delete
// (4e-5b), PATCH (scimpatch.go, 4e-5d), List (scimlist.go, 4e-5e). Phase
// 4e-6 deleted the app-side Users handler entirely; nothing stays app-side
// but the /Me + Bulk surfaces (A2/A3) and the scim.UserStore port impl.

// UsersCreate serves POST {prefix}/Users. Required: userName (or a primary
// emails[] value when userName is omitted). Optional: externalId, active
// (default true), name. password is ignored (SCIM users authenticate via
// OIDC + linking). 201 with the User shape + Location + ETag.
func (s *SCIMRoutes) UsersCreate(w http.ResponseWriter, r *http.Request) {
	body, err := readSCIMUserBody(r)
	if err != nil {
		WriteSCIMErrorTyped(w, http.StatusBadRequest, err.Error(), SCIMTypeInvalidSyntax)
		return
	}
	userName := pickSCIMUserName(body)
	if userName == "" {
		WriteSCIMErrorTyped(w, http.StatusBadRequest, "userName is required", SCIMTypeInvalidValue)
		return
	}
	active := true
	if body.Active != nil {
		active = *body.Active
	}
	familyName, givenName := pickSCIMNameParts(body)
	rec, err := s.users.Create(r.Context(), scim.UserWrite{
		UserName:   userName,
		FamilyName: familyName,
		GivenName:  givenName,
		Active:     active,
		ExternalID: body.ExternalID,
	}, scim.WriteMeta{IfMatchPresent: false})
	if err != nil {
		s.writeUserStoreErr(w, err)
		return
	}
	base := ResolveBaseURL(r, s.cfg.BaseURL)
	w.Header().Set("Location", base+s.cfg.Prefix+"/Users/"+rec.ID)
	WriteETagHeader(w, ResourceETag(rec.Updated))
	WriteSCIMJSON(w, http.StatusCreated, userRecordToResource(rec, base, s.cfg.Prefix))
}

// UsersGet serves GET {prefix}/Users/{id}. Returns 200 even when
// active=false — soft-disabled users stay reachable (Azure AD's
// "deleted=disabled" mode reads correctly). Emits an ETag header.
func (s *SCIMRoutes) UsersGet(w http.ResponseWriter, r *http.Request) {
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
	WriteETagHeader(w, ResourceETag(rec.Updated))
	WriteSCIMJSON(w, http.StatusOK, userRecordToResource(rec, base, s.cfg.Prefix))
}

// UsersReplace serves PUT {prefix}/Users/{id}. Full-replace semantics:
// fields absent from the body reset to zero (active absent → false). Honors
// the If-Match precondition (RFC 7644 §3.14) against the pre-write state +
// emits an ETag on the response.
func (s *SCIMRoutes) UsersReplace(w http.ResponseWriter, r *http.Request) {
	id := scimTrailingSegment(r.URL.Path)
	if id == "" {
		WriteSCIMErrorTyped(w, http.StatusNotFound, "user not found", "")
		return
	}
	body, err := readSCIMUserBody(r)
	if err != nil {
		WriteSCIMErrorTyped(w, http.StatusBadRequest, err.Error(), SCIMTypeInvalidSyntax)
		return
	}
	userName := pickSCIMUserName(body)
	if userName == "" {
		WriteSCIMErrorTyped(w, http.StatusBadRequest, "userName is required", SCIMTypeInvalidValue)
		return
	}
	before, err := s.users.Get(r.Context(), id)
	if err != nil {
		s.writeUserStoreErr(w, err)
		return
	}
	// If-Match against the PRE-write state (before.Updated), so a stale
	// validator fails before the mutation runs. ifMatchPresent rides down to
	// the port impl for the audit row.
	ifMatchPresent := r.Header.Get("If-Match") != ""
	if ok, _, _ := CheckIfMatch(r, ResourceETag(before.Updated)); !ok {
		WriteSCIMErrorTyped(w, http.StatusPreconditionFailed, "If-Match precondition failed", "")
		return
	}
	active := false
	if body.Active != nil {
		active = *body.Active
	}
	familyName, givenName := pickSCIMNameParts(body)
	rec, err := s.users.Replace(r.Context(), id, scim.UserWrite{
		UserName:   userName,
		FamilyName: familyName,
		GivenName:  givenName,
		Active:     active,
		ExternalID: body.ExternalID,
	}, scim.WriteMeta{IfMatchPresent: ifMatchPresent, Before: &before})
	if err != nil {
		s.writeUserStoreErr(w, err)
		return
	}
	base := ResolveBaseURL(r, s.cfg.BaseURL)
	WriteETagHeader(w, ResourceETag(rec.Updated))
	WriteSCIMJSON(w, http.StatusOK, userRecordToResource(rec, base, s.cfg.Prefix))
}

// UsersDelete serves DELETE {prefix}/Users/{id}. Soft-disables (a later GET
// returns 200 with active=false). Honors the If-Match precondition. 204.
func (s *SCIMRoutes) UsersDelete(w http.ResponseWriter, r *http.Request) {
	id := scimTrailingSegment(r.URL.Path)
	if id == "" {
		WriteSCIMErrorTyped(w, http.StatusNotFound, "user not found", "")
		return
	}
	before, err := s.users.Get(r.Context(), id)
	if err != nil {
		s.writeUserStoreErr(w, err)
		return
	}
	ifMatchPresent := r.Header.Get("If-Match") != ""
	if ok, _, _ := CheckIfMatch(r, ResourceETag(before.Updated)); !ok {
		WriteSCIMErrorTyped(w, http.StatusPreconditionFailed, "If-Match precondition failed", "")
		return
	}
	if err := s.users.Delete(r.Context(), id, scim.WriteMeta{IfMatchPresent: ifMatchPresent, Before: &before}); err != nil {
		s.writeUserStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// writeUserStoreErr maps a scim.UserStore sentinel onto the §3.12 envelope,
// matching the pre-lift handler's writeAuthSvcError/writeServiceError:
// ErrNotFound → 404 (fixed "user not found" detail); ErrConflict → 409
// uniqueness; ErrInvalidInput → 400 invalidValue; anything else → 500. The
// uniqueness/invalidValue details recover the app's original message so they
// stay byte-identical.
func (s *SCIMRoutes) writeUserStoreErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, scim.ErrNotFound):
		WriteSCIMErrorTyped(w, http.StatusNotFound, "user not found", "")
	case errors.Is(err, scim.ErrConflict):
		WriteSCIMErrorTyped(w, http.StatusConflict, scimStoreDetail(err), SCIMTypeUniqueness)
	case errors.Is(err, scim.ErrInvalidInput):
		WriteSCIMErrorTyped(w, http.StatusBadRequest, scimStoreDetail(err), SCIMTypeInvalidValue)
	default:
		WriteSCIMErrorTyped(w, http.StatusInternalServerError, "internal error", "")
	}
}

// scimStoreDetail recovers the app's original error message from a folded
// store error. Barista's adapter folds via fmt.Errorf("%w: %w", sentinel,
// orig), which exposes Unwrap() []error; the last element is the original
// AuthService error whose message the pre-lift handler rendered as the
// §3.12 detail. Falls back to the full error string if the shape differs.
func scimStoreDetail(err error) string {
	if u, ok := err.(interface{ Unwrap() []error }); ok {
		if parts := u.Unwrap(); len(parts) > 0 {
			return parts[len(parts)-1].Error()
		}
	}
	return err.Error()
}

// readSCIMUserBody decodes the JSON body into a UserCreateOrReplace and
// closes the body. Used by UsersCreate + UsersReplace.
func readSCIMUserBody(r *http.Request) (*UserCreateOrReplace, error) {
	defer func() { _ = r.Body.Close() }()
	body := &UserCreateOrReplace{}
	if err := json.NewDecoder(r.Body).Decode(body); err != nil {
		return nil, err
	}
	return body, nil
}

// pickSCIMUserName resolves the userName for create/replace: RFC 7644 lets
// the IdP send the email in userName OR the primary emails[] entry. Prefer
// userName, fall back to the first non-empty email value.
func pickSCIMUserName(body *UserCreateOrReplace) string {
	if body == nil {
		return ""
	}
	if v := strings.TrimSpace(body.UserName); v != "" {
		return v
	}
	for _, e := range body.Emails {
		if v := strings.TrimSpace(e.Value); v != "" {
			return v
		}
	}
	return ""
}

// pickSCIMNameParts pulls familyName / givenName from the body's optional
// name. Empty body / nil name → ("", "") so the port impl skips the name
// write on create and resets both columns on full-replace.
func pickSCIMNameParts(body *UserCreateOrReplace) (familyName, givenName string) {
	if body == nil || body.Name == nil {
		return "", ""
	}
	return strings.TrimSpace(body.Name.FamilyName), strings.TrimSpace(body.Name.GivenName)
}

// scimTrailingSegment returns the final path segment (everything after the
// last "/"), used by the {id}-bearing routes.
func scimTrailingSegment(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}

// userRecordToResource renders a neutral scim.UserRecord into the RFC 7643
// core:User wire shape. Byte-identical to the pre-lift handler's
// userToResource: meta.lastModified comes from Updated (or Created when
// Updated is zero); meta.version is the weak ETag of Updated (falling back
// to a Created-based weak ETag on a zero Updated so version stays non-empty);
// name is surfaced only when populated; the single work email is the record's
// projection.
func userRecordToResource(rec scim.UserRecord, baseURL, prefix string) UserResource {
	created := rec.Created.UTC().Format(time.RFC3339)
	lastModified := rec.Updated.UTC().Format(time.RFC3339)
	if rec.Updated.IsZero() {
		lastModified = created
	}
	var emails []UserEmail
	for _, e := range rec.Emails {
		emails = append(emails, UserEmail{Value: e.Value, Primary: e.Primary, Type: e.Type})
	}
	var name *UserName
	if rec.FamilyName != "" || rec.GivenName != "" {
		name = &UserName{FamilyName: rec.FamilyName, GivenName: rec.GivenName}
		if rec.FamilyName != "" && rec.GivenName != "" {
			name.Formatted = rec.GivenName + " " + rec.FamilyName
		}
	}
	version := ResourceETag(rec.Updated)
	if version == "" {
		version = `W/"` + created + `"`
	}
	return UserResource{
		Schemas:    []string{SchemaUser},
		ID:         rec.ID,
		ExternalID: rec.ExternalID,
		UserName:   rec.UserName,
		Name:       name,
		Emails:     emails,
		Active:     rec.Active,
		Meta: ResourceMeta{
			ResourceType: "User",
			Created:      created,
			LastModified: lastModified,
			Location:     baseURL + prefix + "/Users/" + rec.ID,
			Version:      version,
		},
	}
}
