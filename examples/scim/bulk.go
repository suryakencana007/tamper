package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"time"

	"github.com/google/uuid"

	espresso "github.com/suryakencana007/espresso/v2"

	"github.com/suryakencana007/barista/packages/tamper/audit"
	tamperespresso "github.com/suryakencana007/barista/packages/tamper/espresso"
)

// Bulk (RFC 7644 §3.7) is APP-SIDE — tamper ships no Bulk route method, because
// the per-operation transactional semantics + the envelope-level audit are the
// app's policy. This mirrors how Barista composes it: re-dispatch each sub-op
// through an inner router that shares the outer request's context, so the
// service-account actor stays stamped on every per-op audit row the stores emit.

const bulkPrefix = "/scim/v2"
const actionBulk = audit.Action("scim.bulk")

type bulkRequest struct {
	Schemas      []string        `json:"schemas"`
	FailOnErrors int             `json:"failOnErrors,omitempty"`
	Operations   []bulkOperation `json:"Operations"`
}

type bulkOperation struct {
	Method  string          `json:"method"`
	BulkID  string          `json:"bulkId,omitempty"`
	Path    string          `json:"path"`
	Data    json.RawMessage `json:"data,omitempty"`
	Version string          `json:"version,omitempty"` // If-Match
}

type bulkResponse struct {
	Schemas    []string              `json:"schemas"`
	Operations []bulkOperationResult `json:"Operations"`
}

type bulkOperationResult struct {
	Method   string          `json:"method"`
	BulkID   string          `json:"bulkId,omitempty"`
	Location string          `json:"location,omitempty"`
	Status   string          `json:"status"`
	Response json.RawMessage `json:"response,omitempty"`
}

type bulkHandler struct {
	inner http.Handler // the 12 CRUD routes (NO /Bulk — that would recurse)
	max   int
	audit audit.Logger
}

// registerBulk wires POST /scim/v2/Bulk behind the same gate as the rest.
func registerBulk(r *espresso.Router, sc *tamperespresso.SCIMRoutes, guard func(http.Handler) http.Handler, a audit.Logger, max int) {
	bh := &bulkHandler{inner: buildInnerSCIMRouter(sc), max: max, audit: a}
	r.Post("/scim/v2/Bulk", guard(http.HandlerFunc(bh.handleBulk)))
}

// buildInnerSCIMRouter routes the CRUD methods for the Bulk re-dispatch. It
// carries NO middleware (the outer /Bulk route is already gated) and, crucially,
// NO /Bulk route (or a bulk op targeting /Bulk would recurse infinitely).
func buildInnerSCIMRouter(sc *tamperespresso.SCIMRoutes) http.Handler {
	ir := espresso.Portafilter()
	ir.Post("/scim/v2/Users", http.HandlerFunc(sc.UsersCreate))
	ir.Get("/scim/v2/Users/{id}", http.HandlerFunc(sc.UsersGet))
	ir.Put("/scim/v2/Users/{id}", http.HandlerFunc(sc.UsersReplace))
	ir.Patch("/scim/v2/Users/{id}", http.HandlerFunc(sc.UsersPatch))
	ir.Delete("/scim/v2/Users/{id}", http.HandlerFunc(sc.UsersDelete))
	ir.Post("/scim/v2/Groups", http.HandlerFunc(sc.GroupsCreate))
	ir.Get("/scim/v2/Groups/{id}", http.HandlerFunc(sc.GroupsGet))
	ir.Put("/scim/v2/Groups/{id}", http.HandlerFunc(sc.GroupsReplace))
	ir.Patch("/scim/v2/Groups/{id}", http.HandlerFunc(sc.GroupsPatch))
	ir.Delete("/scim/v2/Groups/{id}", http.HandlerFunc(sc.GroupsDelete))
	return ir
}

func (b *bulkHandler) handleBulk(w http.ResponseWriter, r *http.Request) {
	var req bulkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		tamperespresso.WriteSCIMErrorTyped(w, http.StatusBadRequest, "malformed bulk request", "invalidSyntax")
		return
	}
	if b.max > 0 && len(req.Operations) > b.max {
		tamperespresso.WriteSCIMErrorTyped(w, http.StatusRequestEntityTooLarge, "too many bulk operations", "tooMany")
		return
	}

	results := make([]bulkOperationResult, 0, len(req.Operations))
	for _, op := range req.Operations {
		var body io.Reader
		if len(op.Data) > 0 {
			body = bytes.NewReader(op.Data)
		}
		// Share the OUTER request context so the service-account actor the gate
		// stashed stays stamped on the per-op audit the store emits.
		sub := httptest.NewRequest(op.Method, bulkPrefix+op.Path, body).WithContext(r.Context())
		sub.Header.Set("Content-Type", "application/scim+json")
		if op.Version != "" {
			sub.Header.Set("If-Match", op.Version)
		}

		rec := httptest.NewRecorder()
		b.inner.ServeHTTP(rec, sub)

		res := bulkOperationResult{Method: op.Method, BulkID: op.BulkID, Status: strconv.Itoa(rec.Code)}
		if loc := rec.Header().Get("Location"); loc != "" {
			res.Location = loc
		}
		if rec.Body.Len() > 0 {
			res.Response = json.RawMessage(append([]byte(nil), rec.Body.Bytes()...))
		}
		results = append(results, res)
	}

	b.emitBulk(r.Context(), len(req.Operations))

	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(bulkResponse{
		Schemas:    []string{"urn:ietf:params:scim:api:messages:2.0:BulkResponse"},
		Operations: results,
	})
}

func (b *bulkHandler) emitBulk(ctx context.Context, n int) {
	if b.audit == nil {
		return
	}
	after, _ := json.Marshal(map[string]any{"operation_count": n})
	_, _ = b.audit.Log(ctx, audit.Event{
		ID: uuid.NewString(), At: time.Now().UTC(), Actor: audit.ActorFromContext(ctx),
		Action: actionBulk, ResourceType: audit.ResourceType("scim"), After: after,
	})
}
