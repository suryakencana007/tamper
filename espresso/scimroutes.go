package espresso

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	scim "github.com/suryakencana007/tamper/scim"
)

// SCIM transport surface (Phase 4e-5). SCIMRoutes carries the app's
// branding/policy (SCIMConfig) and the persistence ports, and exposes the
// route handler methods; the app registers them on its own router under the
// RequireServiceAccount wrap — no Mount, per amendment A10. 4e-5a shipped
// the three discovery endpoints; 4e-5b adds the Users write-CRUD methods
// (Create/Get/Replace/Delete) over scim.UserStore. Groups + List + PATCH
// follow in later 4e slices.

// SCIMConfig is the app-injected branding + policy. The literal VALUES
// (documentation URI, auth-scheme text, base URL, caps) stay app-owned;
// tamper renders them.
type SCIMConfig struct {
	// Prefix is the route prefix ("/scim/v2"), app wire surface.
	Prefix string
	// BaseURL is the operator's chart override for meta.location; empty
	// derives the prefix from each request's scheme + host.
	BaseURL string
	// BulkMaxOperations is advertised in ServiceProviderConfig.bulk.
	BulkMaxOperations int
	// MaxResults is the enforced List page cap, advertised verbatim as
	// filter.maxResults (the 4e-4 no-drift invariant).
	MaxResults int
	// MaxPayloadBytes caps the request body every SCIM write handler will
	// read, and is advertised verbatim as bulk.maxPayloadSize — same
	// no-drift invariant as MaxResults above, because an advertised limit
	// nothing enforces is worse than no limit at all.
	//
	// Zero or negative selects defaultSCIMMaxPayloadBytes. It is NOT a
	// required field: the espresso framework's own 1 MiB cap lives inside
	// its extractor decode path, which these handlers do not use (they
	// decode straight off r.Body), so without this every SCIM write was
	// unbounded — one large POST could exhaust the process.
	MaxPayloadBytes int64
	// DocumentationURI + AuthSchemeDescription are app strings rendered
	// into ServiceProviderConfig.
	DocumentationURI      string
	AuthSchemeDescription string

	// Tenancy turns on pooled multi-tenancy for the SCIM surface. False
	// (the default) is byte-identical to a pre-Phase-7 build: the shims
	// call the original store methods and nothing reads a tenant.
	//
	// When true, BOTH stores must implement their tenant-scoped form or
	// NewSCIMRoutes fails, naming the type. Every read and write is then
	// constrained to the tenant on the VALIDATED PRINCIPAL — see
	// Principal.TenantID for why it can only come from there.
	Tenancy bool
}

// SCIMRoutes is the SCIM transport. Construct with NewSCIMRoutes.
type SCIMRoutes struct {
	cfg    SCIMConfig
	users  scim.UserStore
	groups scim.GroupStore

	// tenantUsers / tenantGroups are the scoped forms, settled ONCE at
	// construction. Non-nil exactly when SCIMConfig.Tenancy is on, so the
	// per-request shims below branch on a boot-time decision rather than
	// re-asserting a type on every call — the Phase 0c lesson.
	tenantUsers  scim.TenantScopedUserStore
	tenantGroups scim.TenantScopedGroupStore
}

// NewSCIMRoutes validates the wiring at construction time (never at request
// time), matching the NewFederationRoutes/NewAuthRoutes shape. users +
// groups are the app's persistence ports (Barista: internal/scimstore) —
// required because the CRUD methods route through them; the app that
// registers the routes always has both to supply.
func NewSCIMRoutes(cfg SCIMConfig, users scim.UserStore, groups scim.GroupStore) (*SCIMRoutes, error) {
	if cfg.Prefix == "" {
		return nil, errors.New("tamper/espresso: SCIMConfig.Prefix is required")
	}
	if cfg.MaxResults <= 0 {
		return nil, errors.New("tamper/espresso: SCIMConfig.MaxResults must be positive")
	}
	if users == nil {
		return nil, errors.New("tamper/espresso: SCIMConfig requires a UserStore")
	}
	if groups == nil {
		return nil, errors.New("tamper/espresso: SCIMConfig requires a GroupStore")
	}
	// Default rather than reject: MaxPayloadBytes was added after the
	// config shipped, so a caller built against the earlier shape leaves it
	// zero and must still get a bounded — not unbounded — surface.
	if cfg.MaxPayloadBytes <= 0 {
		cfg.MaxPayloadBytes = defaultSCIMMaxPayloadBytes
	}
	s := &SCIMRoutes{cfg: cfg, users: users, groups: groups}
	// The optional-interface upgrade is checked HERE, once, and the
	// result stored. A store that cannot scope by tenant is a
	// misconfiguration, and discovering it on the first cross-tenant read
	// means discovering it in production (§6.4). The message names the
	// concrete type, because "SCIM tenancy doesn't work" with nothing to
	// grep for is the Phase 0c experience.
	if cfg.Tenancy {
		tu, ok := users.(scim.TenantScopedUserStore)
		if !ok {
			return nil, fmt.Errorf(
				"tamper/espresso: SCIMConfig.Tenancy requires a scim.UserStore that implements "+
					"scim.TenantScopedUserStore; %T does not", users)
		}
		tg, ok := groups.(scim.TenantScopedGroupStore)
		if !ok {
			return nil, fmt.Errorf(
				"tamper/espresso: SCIMConfig.Tenancy requires a scim.GroupStore that implements "+
					"scim.TenantScopedGroupStore; %T does not", groups)
		}
		s.tenantUsers, s.tenantGroups = tu, tg
	}
	return s, nil
}

// scimTenant returns the tenant this request acts in.
//
// It reads the VALIDATED PRINCIPAL and nothing else. Not a path segment,
// not a header, not a query parameter — see Principal.TenantID for why
// those are a horizontal-privilege-escalation bug with extra steps. This
// is the only function in the SCIM surface that answers the question, so
// it is the only place that could get it wrong.
//
// A request that reached a SCIM handler without a principal has no
// business being served: MustGetPrincipal panics, which is correct for a
// route mounted outside RequireServiceAccount (a programmer error, not a
// runtime condition).
func scimTenant(ctx context.Context) string {
	return MustGetPrincipal(ctx).TenantID
}

// --- store routing shims ---------------------------------------------
//
// One shim per store method the TRANSPORT calls, so the
// scoped-vs-unscoped decision exists in exactly one place per call site,
// each individually mutation-testable, and no handler branches on
// tenancy.
//
// There is no shim for List: both List handlers call ListFiltered
// unconditionally, passing the client's filter (empty when absent), so
// the plain List is never reached from here. Its tenant-scoped form
// still exists on the port — an application calling List directly must
// have a scoped option — it simply has no transport caller to wrap. With Tenancy off these are the original
// calls, unchanged, which is what keeps the single-tenant path
// byte-identical.

func (s *SCIMRoutes) userCreate(ctx context.Context, w scim.UserWrite, meta scim.WriteMeta) (scim.UserRecord, error) {
	if s.tenantUsers != nil {
		return s.tenantUsers.CreateInTenant(ctx, scimTenant(ctx), w, meta)
	}
	return s.users.Create(ctx, w, meta)
}

func (s *SCIMRoutes) userGet(ctx context.Context, id string) (scim.UserRecord, error) {
	if s.tenantUsers != nil {
		return s.tenantUsers.GetInTenant(ctx, scimTenant(ctx), id)
	}
	return s.users.Get(ctx, id)
}

func (s *SCIMRoutes) userReplace(ctx context.Context, id string, w scim.UserWrite, meta scim.WriteMeta) (scim.UserRecord, error) {
	if s.tenantUsers != nil {
		return s.tenantUsers.ReplaceInTenant(ctx, scimTenant(ctx), id, w, meta)
	}
	return s.users.Replace(ctx, id, w, meta)
}

func (s *SCIMRoutes) userDelete(ctx context.Context, id string, meta scim.WriteMeta) error {
	if s.tenantUsers != nil {
		return s.tenantUsers.DeleteInTenant(ctx, scimTenant(ctx), id, meta)
	}
	return s.users.Delete(ctx, id, meta)
}

func (s *SCIMRoutes) userSavePatch(ctx context.Context, id string, w scim.UserWrite, ops []scim.Operation) (scim.UserRecord, error) {
	if s.tenantUsers != nil {
		return s.tenantUsers.SavePatchInTenant(ctx, scimTenant(ctx), id, w, ops)
	}
	return s.users.SavePatch(ctx, id, w, ops)
}

func (s *SCIMRoutes) userListFiltered(ctx context.Context, startIndex, count int, filter string) (scim.UserPage, error) {
	if s.tenantUsers != nil {
		return s.tenantUsers.ListFilteredInTenant(ctx, scimTenant(ctx), startIndex, count, filter)
	}
	return s.users.ListFiltered(ctx, startIndex, count, filter)
}

func (s *SCIMRoutes) groupCreate(ctx context.Context, w scim.GroupWrite, meta scim.GroupWriteMeta) (scim.GroupRecord, error) {
	if s.tenantGroups != nil {
		return s.tenantGroups.CreateInTenant(ctx, scimTenant(ctx), w, meta)
	}
	return s.groups.Create(ctx, w, meta)
}

func (s *SCIMRoutes) groupGet(ctx context.Context, id string) (scim.GroupRecord, error) {
	if s.tenantGroups != nil {
		return s.tenantGroups.GetInTenant(ctx, scimTenant(ctx), id)
	}
	return s.groups.Get(ctx, id)
}

func (s *SCIMRoutes) groupReplace(ctx context.Context, id string, w scim.GroupWrite, meta scim.GroupWriteMeta) (scim.GroupRecord, error) {
	if s.tenantGroups != nil {
		return s.tenantGroups.ReplaceInTenant(ctx, scimTenant(ctx), id, w, meta)
	}
	return s.groups.Replace(ctx, id, w, meta)
}

func (s *SCIMRoutes) groupDelete(ctx context.Context, id string, meta scim.GroupWriteMeta) error {
	if s.tenantGroups != nil {
		return s.tenantGroups.DeleteInTenant(ctx, scimTenant(ctx), id, meta)
	}
	return s.groups.Delete(ctx, id, meta)
}

func (s *SCIMRoutes) groupSavePatch(ctx context.Context, id string, w scim.GroupWrite, ops []scim.Operation) (scim.GroupRecord, error) {
	if s.tenantGroups != nil {
		return s.tenantGroups.SavePatchInTenant(ctx, scimTenant(ctx), id, w, ops)
	}
	return s.groups.SavePatch(ctx, id, w, ops)
}

func (s *SCIMRoutes) groupValidateMembers(ctx context.Context, members []scim.MemberRef) error {
	if s.tenantGroups != nil {
		return s.tenantGroups.ValidateMembersInTenant(ctx, scimTenant(ctx), members)
	}
	return s.groups.ValidateMembers(ctx, members)
}

func (s *SCIMRoutes) groupListFiltered(ctx context.Context, startIndex, count int, filter string) (scim.GroupPage, error) {
	if s.tenantGroups != nil {
		return s.tenantGroups.ListFilteredInTenant(ctx, scimTenant(ctx), startIndex, count, filter)
	}
	return s.groups.ListFiltered(ctx, startIndex, count, filter)
}

// defaultSCIMMaxPayloadBytes is the request-body cap applied when
// SCIMConfig.MaxPayloadBytes is unset. 1 MiB matches both the value
// ServiceProviderConfig used to advertise unconditionally and the espresso
// framework's own extractor limit, so the default changes no advertised
// number — it only makes the advertised number true.
const defaultSCIMMaxPayloadBytes int64 = 1 << 20

// ResolveBaseURL returns the absolute URL prefix used to build SCIM
// meta.location values. A non-empty override (operator chart-config)
// wins; otherwise it derives the prefix from the request's scheme + host.
// Scheme prefers X-Forwarded-Proto (Traefik on TLS-terminated routes),
// then r.TLS, else http; host prefers X-Forwarded-Host, else r.Host.
func ResolveBaseURL(r *http.Request, override string) string {
	if override != "" {
		return override
	}
	scheme := "http"
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	} else if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if hf := r.Header.Get("X-Forwarded-Host"); hf != "" {
		host = hf
	}
	return scheme + "://" + host
}

// WriteSCIMJSON marshals body as application/scim+json with the given
// status. Marshal failures are best-effort (the status is already sent).
func WriteSCIMJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", ContentTypeSCIM)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// ServiceProviderConfig serves GET {prefix}/ServiceProviderConfig — the
// static capability payload IdPs read on connector validation. filter +
// etag + patch + bulk are supported; changePassword + sort are not.
// filter.maxResults advertises the enforced cap verbatim (4e-4).
func (s *SCIMRoutes) ServiceProviderConfig(w http.ResponseWriter, r *http.Request) {
	WriteSCIMJSON(w, http.StatusOK, ServiceProviderConfig{
		Schemas:          []string{SchemaServiceProviderConfig},
		DocumentationURI: s.cfg.DocumentationURI,
		Patch:            SPCSupported{Supported: true},
		Bulk:             SPCBulk{Supported: true, MaxOperations: s.cfg.BulkMaxOperations, MaxPayloadSize: int(s.cfg.MaxPayloadBytes)},
		Filter:           SPCFilter{Supported: true, MaxResults: s.cfg.MaxResults},
		ChangePassword:   SPCSupported{Supported: false},
		Sort:             SPCSupported{Supported: false},
		ETag:             SPCSupported{Supported: true},
		AuthenticationSchemes: []SPCAuthScheme{
			{
				Type:        "oauthbearertoken",
				Name:        "OAuth Bearer Token",
				Description: s.cfg.AuthSchemeDescription,
				Primary:     true,
			},
		},
		Meta: ResourceMeta{
			ResourceType: "ServiceProviderConfig",
			Location:     ResolveBaseURL(r, s.cfg.BaseURL) + s.cfg.Prefix + "/ServiceProviderConfig",
		},
	})
}

// ResourceTypes serves GET {prefix}/ResourceTypes — the User + Group
// resource-type entries. Per RFC the entries carry no base-URL-derived
// links, so it's request-independent.
func (s *SCIMRoutes) ResourceTypes(w http.ResponseWriter, r *http.Request) {
	entries := []ResourceTypeEntry{
		{Schemas: []string{SchemaResourceType}, ID: "User", Name: "User", Endpoint: "/Users", Schema: SchemaUser},
		{Schemas: []string{SchemaResourceType}, ID: "Group", Name: "Group", Endpoint: "/Groups", Schema: SchemaGroup},
	}
	resources := make([]json.RawMessage, 0, len(entries))
	for i := range entries {
		b, err := json.Marshal(entries[i])
		if err != nil {
			WriteSCIMErrorTyped(w, http.StatusInternalServerError, "internal error", "")
			return
		}
		resources = append(resources, b)
	}
	WriteSCIMJSON(w, http.StatusOK, ListResponse{
		Schemas:      []string{SchemaListResponse},
		TotalResults: len(entries),
		StartIndex:   1,
		ItemsPerPage: len(entries),
		Resources:    resources,
	})
}

// Schemas serves GET {prefix}/Schemas — the bundled User + Group core
// schema definitions (RFC 7643 §8.7 / §8.8), the subset Barista accepts.
func (s *SCIMRoutes) Schemas(w http.ResponseWriter, r *http.Request) {
	userRaw, err := json.Marshal(userSchemaResource())
	if err != nil {
		WriteSCIMErrorTyped(w, http.StatusInternalServerError, "internal error", "")
		return
	}
	groupRaw, err := json.Marshal(groupSchemaResource())
	if err != nil {
		WriteSCIMErrorTyped(w, http.StatusInternalServerError, "internal error", "")
		return
	}
	WriteSCIMJSON(w, http.StatusOK, ListResponse{
		Schemas:      []string{SchemaListResponse},
		TotalResults: 2,
		StartIndex:   1,
		ItemsPerPage: 2,
		Resources:    []json.RawMessage{userRaw, groupRaw},
	})
}

func userSchemaResource() map[string]any {
	return map[string]any{
		"id":          SchemaUser,
		"name":        "User",
		"description": "Barista SCIM 2.0 User resource (minimal).",
		"attributes": []map[string]any{
			{
				"name":        "userName",
				"type":        "string",
				"multiValued": false,
				"required":    true,
				"caseExact":   false,
				"mutability":  "readWrite",
				"returned":    "default",
				"uniqueness":  "server",
			},
			{
				"name":        "externalId",
				"type":        "string",
				"multiValued": false,
				"required":    false,
				"caseExact":   true,
				"mutability":  "readWrite",
				"returned":    "default",
				"uniqueness":  "none",
			},
			{
				"name":        "active",
				"type":        "boolean",
				"multiValued": false,
				"required":    false,
				"mutability":  "readWrite",
				"returned":    "default",
			},
			{
				"name":        "emails",
				"type":        "complex",
				"multiValued": true,
				"required":    false,
				"mutability":  "readWrite",
				"returned":    "default",
			},
		},
		"meta": map[string]any{
			"resourceType": "Schema",
			"location":     "/scim/v2/Schemas/" + SchemaUser,
		},
	}
}

func groupSchemaResource() map[string]any {
	return map[string]any{
		"id":          SchemaGroup,
		"name":        "Group",
		"description": "Barista SCIM 2.0 Group resource (minimal).",
		"attributes": []map[string]any{
			{
				"name":        "displayName",
				"type":        "string",
				"multiValued": false,
				"required":    true,
				"mutability":  "readWrite",
				"returned":    "default",
				"uniqueness":  "server",
			},
			{
				"name":        "externalId",
				"type":        "string",
				"multiValued": false,
				"required":    false,
				"caseExact":   true,
				"mutability":  "readWrite",
				"returned":    "default",
				"uniqueness":  "none",
			},
			{
				"name":        "members",
				"type":        "complex",
				"multiValued": true,
				"required":    false,
				"mutability":  "readWrite",
				"returned":    "default",
				"subAttributes": []map[string]any{
					{
						"name":            "type",
						"type":            "string",
						"required":        false,
						"caseExact":       false,
						"mutability":      "readWrite",
						"returned":        "default",
						"canonicalValues": []string{"User", "Group"},
					},
					{
						"name":       "value",
						"type":       "string",
						"required":   true,
						"mutability": "readWrite",
						"returned":   "default",
					},
					{
						"name":       "$ref",
						"type":       "reference",
						"required":   false,
						"mutability": "readOnly",
						"returned":   "default",
					},
				},
			},
		},
		"meta": map[string]any{
			"resourceType": "Schema",
			"location":     "/scim/v2/Schemas/" + SchemaGroup,
		},
	}
}
