package espresso

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	scim "github.com/suryakencana007/tamper/scim"
)

// SCIM List transport (Phase 4e-5e). GET {prefix}/Users + /Groups with
// startIndex / count / filter. The RAW filter passes to the port's
// ListFiltered — the impl owns Parse+Translate AND emits the read-audit (A3).
// A filter error folds to scim.ErrInvalidFilter → 400 invalidFilter.

// UsersList serves GET {prefix}/Users.
func (s *SCIMRoutes) UsersList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	startIndex, count := s.parsePagination(q)
	page, err := s.userListFiltered(r.Context(), startIndex, count, q.Get("filter"))
	if err != nil {
		writeListErr(w, err)
		return
	}
	base := s.baseURL(r)
	resources := make([]json.RawMessage, 0, len(page.Users))
	for i := range page.Users {
		raw, err := json.Marshal(userRecordToResource(page.Users[i], base, s.cfg.Prefix))
		if err != nil {
			WriteSCIMErrorTyped(w, http.StatusInternalServerError, "internal error", "")
			return
		}
		resources = append(resources, raw)
	}
	WriteSCIMJSON(w, http.StatusOK, ListResponse{
		Schemas:      []string{SchemaListResponse},
		TotalResults: page.Total,
		StartIndex:   startIndex,
		ItemsPerPage: len(resources),
		Resources:    resources,
	})
}

// GroupsList serves GET {prefix}/Groups.
func (s *SCIMRoutes) GroupsList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	startIndex, count := s.parsePagination(q)
	page, err := s.groupListFiltered(r.Context(), startIndex, count, q.Get("filter"))
	if err != nil {
		writeListErr(w, err)
		return
	}
	base := s.baseURL(r)
	resources := make([]json.RawMessage, 0, len(page.Groups))
	for i := range page.Groups {
		raw, err := json.Marshal(groupRecordToResource(page.Groups[i], base, s.cfg.Prefix))
		if err != nil {
			WriteSCIMErrorTyped(w, http.StatusInternalServerError, "internal error", "")
			return
		}
		resources = append(resources, raw)
	}
	WriteSCIMJSON(w, http.StatusOK, ListResponse{
		Schemas:      []string{SchemaListResponse},
		TotalResults: page.Total,
		StartIndex:   startIndex,
		ItemsPerPage: len(resources),
		Resources:    resources,
	})
}

// writeListErr maps a List error: scim.ErrInvalidFilter → 400 invalidFilter
// (impl-wrapped detail recovered via scimStoreDetail); anything else → 500.
// Matches the pre-lift handleList (Parse/Translate/domain.ErrInvalid →
// invalidFilter; else internalError).
func writeListErr(w http.ResponseWriter, err error) {
	if errors.Is(err, scim.ErrInvalidFilter) {
		WriteSCIMErrorTyped(w, http.StatusBadRequest, scimStoreDetail(err), SCIMTypeInvalidFilter)
		return
	}
	WriteSCIMErrorTyped(w, http.StatusInternalServerError, "internal error", "")
}

// parsePagination reads SCIM startIndex (1-based, default 1) + count (default
// 20, capped at cfg.MaxResults — the enforced ceiling also advertised as
// filter.maxResults, 4e-4). Mirrors the pre-lift handler's parsePagination.
func (s *SCIMRoutes) parsePagination(q map[string][]string) (startIndex, count int) {
	startIndex = 1
	count = 20
	if v := firstQueryValue(q, "startIndex"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			startIndex = n
		}
	}
	if v := firstQueryValue(q, "count"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			if n < 0 {
				n = 0
			}
			if n > s.cfg.MaxResults {
				n = s.cfg.MaxResults
			}
			count = n
		}
	}
	return startIndex, count
}

func firstQueryValue(q map[string][]string, key string) string {
	if v, ok := q[key]; ok && len(v) > 0 {
		return v[0]
	}
	return ""
}
