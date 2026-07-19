package espresso

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	scim "github.com/suryakencana007/barista/packages/tamper/scim"
)

// stubUserStore is a no-op scim.UserStore for the discovery + validation
// tests, which never route through the Users CRUD methods. The Users CRUD
// behaviour is covered app-side by the SCIM handler golden suite (through
// the real Barista adapter).
type stubUserStore struct{}

func (stubUserStore) Create(context.Context, scim.UserWrite, scim.WriteMeta) (scim.UserRecord, error) {
	return scim.UserRecord{}, nil
}
func (stubUserStore) Get(context.Context, string) (scim.UserRecord, error) {
	return scim.UserRecord{}, nil
}
func (stubUserStore) Replace(context.Context, string, scim.UserWrite, scim.WriteMeta) (scim.UserRecord, error) {
	return scim.UserRecord{}, nil
}
func (stubUserStore) Delete(context.Context, string, scim.WriteMeta) error { return nil }
func (stubUserStore) SavePatch(context.Context, string, scim.UserWrite, []scim.Operation) (scim.UserRecord, error) {
	return scim.UserRecord{}, nil
}
func (stubUserStore) List(context.Context, int, int) (scim.UserPage, error) {
	return scim.UserPage{}, nil
}
func (stubUserStore) ListFiltered(context.Context, int, int, string, []any) (scim.UserPage, error) {
	return scim.UserPage{}, nil
}

// stubGroupStore is the GroupStore twin of stubUserStore.
type stubGroupStore struct{}

func (stubGroupStore) Create(context.Context, scim.GroupWrite, scim.GroupWriteMeta) (scim.GroupRecord, error) {
	return scim.GroupRecord{}, nil
}
func (stubGroupStore) Get(context.Context, string) (scim.GroupRecord, error) {
	return scim.GroupRecord{}, nil
}
func (stubGroupStore) Replace(context.Context, string, scim.GroupWrite, scim.GroupWriteMeta) (scim.GroupRecord, error) {
	return scim.GroupRecord{}, nil
}
func (stubGroupStore) Delete(context.Context, string, scim.GroupWriteMeta) error { return nil }
func (stubGroupStore) ValidateMembers(context.Context, []scim.MemberRef) error  { return nil }
func (stubGroupStore) SavePatch(context.Context, string, scim.GroupWrite, []scim.Operation) (scim.GroupRecord, error) {
	return scim.GroupRecord{}, nil
}
func (stubGroupStore) List(context.Context, int, int) (scim.GroupPage, error) {
	return scim.GroupPage{}, nil
}
func (stubGroupStore) ListFiltered(context.Context, int, int, string, []any) (scim.GroupPage, error) {
	return scim.GroupPage{}, nil
}

func testSCIMRoutes(t *testing.T) *SCIMRoutes {
	t.Helper()
	rt, err := NewSCIMRoutes(SCIMConfig{
		Prefix:                "/scim/v2",
		BaseURL:               "https://panel.test",
		BulkMaxOperations:     50,
		MaxResults:            100,
		DocumentationURI:      "https://docs.test",
		AuthSchemeDescription: "bearer via CLI",
	}, stubUserStore{}, stubGroupStore{})
	if err != nil {
		t.Fatalf("NewSCIMRoutes: %v", err)
	}
	return rt
}

func TestNewSCIMRoutes_Validation(t *testing.T) {
	if _, err := NewSCIMRoutes(SCIMConfig{MaxResults: 100}, stubUserStore{}, stubGroupStore{}); err == nil {
		t.Error("empty Prefix must be rejected at wiring")
	}
	if _, err := NewSCIMRoutes(SCIMConfig{Prefix: "/scim/v2"}, stubUserStore{}, stubGroupStore{}); err == nil {
		t.Error("non-positive MaxResults must be rejected at wiring")
	}
	if _, err := NewSCIMRoutes(SCIMConfig{Prefix: "/scim/v2", MaxResults: 100}, nil, stubGroupStore{}); err == nil {
		t.Error("a nil UserStore must be rejected at wiring")
	}
	if _, err := NewSCIMRoutes(SCIMConfig{Prefix: "/scim/v2", MaxResults: 100}, stubUserStore{}, nil); err == nil {
		t.Error("a nil GroupStore must be rejected at wiring")
	}
	if _, err := NewSCIMRoutes(SCIMConfig{Prefix: "/scim/v2", MaxResults: 100}, stubUserStore{}, stubGroupStore{}); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
}

func TestSCIMRoutes_ServiceProviderConfig(t *testing.T) {
	rt := testSCIMRoutes(t)
	rec := httptest.NewRecorder()
	rt.ServiceProviderConfig(rec, httptest.NewRequest(http.MethodGet, "/scim/v2/ServiceProviderConfig", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/scim+json" {
		t.Errorf("Content-Type = %q, want application/scim+json", ct)
	}
	var spc ServiceProviderConfig
	if err := json.Unmarshal(rec.Body.Bytes(), &spc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// filter.maxResults advertises the injected cap verbatim.
	if !spc.Filter.Supported || spc.Filter.MaxResults != 100 {
		t.Errorf("filter = %+v, want supported + maxResults 100", spc.Filter)
	}
	if !spc.Patch.Supported || !spc.Bulk.Supported || !spc.ETag.Supported {
		t.Errorf("patch/bulk/etag must be supported: %+v", spc)
	}
	if spc.ChangePassword.Supported || spc.Sort.Supported {
		t.Error("changePassword/sort must be unsupported")
	}
	// The branding literals come from the injected config, not tamper.
	if spc.DocumentationURI != "https://docs.test" {
		t.Errorf("documentationUri = %q, want the injected value", spc.DocumentationURI)
	}
	if len(spc.AuthenticationSchemes) != 1 || spc.AuthenticationSchemes[0].Description != "bearer via CLI" {
		t.Errorf("auth scheme description must come from cfg: %+v", spc.AuthenticationSchemes)
	}
	if spc.Bulk.MaxOperations != 50 {
		t.Errorf("bulk.maxOperations = %d, want the injected 50", spc.Bulk.MaxOperations)
	}
	if spc.Meta.Location != "https://panel.test/scim/v2/ServiceProviderConfig" {
		t.Errorf("meta.location = %q", spc.Meta.Location)
	}
}

func TestSCIMRoutes_ResourceTypesAndSchemas(t *testing.T) {
	rt := testSCIMRoutes(t)

	rec := httptest.NewRecorder()
	rt.ResourceTypes(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	var rtResp ListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &rtResp); err != nil {
		t.Fatalf("decode ResourceTypes: %v (body=%s)", err, rec.Body.String())
	}
	if rtResp.TotalResults != 2 || len(rtResp.Resources) != 2 {
		t.Errorf("ResourceTypes: want 2 entries (User+Group), got total=%d len=%d", rtResp.TotalResults, len(rtResp.Resources))
	}

	rec = httptest.NewRecorder()
	rt.Schemas(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	var schResp ListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &schResp); err != nil {
		t.Fatalf("decode Schemas: %v (body=%s)", err, rec.Body.String())
	}
	if schResp.TotalResults != 2 || len(schResp.Resources) != 2 {
		t.Errorf("Schemas: want 2 (User+Group), got total=%d len=%d", schResp.TotalResults, len(schResp.Resources))
	}
}

// ResolveBaseURL: override wins; else scheme+host, honoring X-Forwarded-*.
func TestResolveBaseURL(t *testing.T) {
	if got := ResolveBaseURL(httptest.NewRequest(http.MethodGet, "http://h/x", nil), "https://override"); got != "https://override" {
		t.Errorf("override should win, got %q", got)
	}
	r := httptest.NewRequest(http.MethodGet, "http://ignored/x", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "panel.example")
	if got := ResolveBaseURL(r, ""); got != "https://panel.example" {
		t.Errorf("forwarded headers should win, got %q", got)
	}
}
