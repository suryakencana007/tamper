package espresso

import "encoding/json"

// SCIM 2.0 wire shapes (RFC 7643 schema / RFC 7644 protocol), lifted from
// Barista's SCIM handler in Phase 4e-3. The RFC DTOs are standard, so they
// belong in the transport (amendment A2): the SCIM routes render
// app-supplied neutral records (tamper/scim.UserRecord / GroupRecord) into
// these. The discovery-endpoint shapes (ServiceProviderConfig etc.) lift
// with the discovery endpoints in 4e-4.

// SCIM schema URNs (RFC 7643 §3, §8; RFC 7644 messages).
const (
	SchemaUser                  = "urn:ietf:params:scim:schemas:core:2.0:User"
	SchemaGroup                 = "urn:ietf:params:scim:schemas:core:2.0:Group"
	SchemaListResponse          = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SchemaError                 = "urn:ietf:params:scim:api:messages:2.0:Error"
	SchemaServiceProviderConfig = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	SchemaResourceType          = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
)

// ContentTypeSCIM is the media type RFC 7644 mandates for SCIM responses.
const ContentTypeSCIM = "application/scim+json"

// UserResource is the RFC 7643 §4.1 core:User wire shape.
type UserResource struct {
	Schemas    []string     `json:"schemas"`
	ID         string       `json:"id"`
	ExternalID string       `json:"externalId,omitempty"`
	UserName   string       `json:"userName"`
	Name       *UserName    `json:"name,omitempty"`
	Emails     []UserEmail  `json:"emails,omitempty"`
	Active     bool         `json:"active"`
	Meta       ResourceMeta `json:"meta"`
}

// UserName mirrors RFC 7643 §4.1.2 complex `name`.
type UserName struct {
	Formatted  string `json:"formatted,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
}

// UserEmail mirrors RFC 7643 §4.1.2 multi-valued `emails`.
type UserEmail struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary,omitempty"`
	Type    string `json:"type,omitempty"`
}

// UserCreateOrReplace is the inbound POST /Users + PUT /Users/{id} shape.
// Active is *bool so the handler can distinguish absent (default true on
// POST, false on PUT) from explicit false.
type UserCreateOrReplace struct {
	Schemas    []string    `json:"schemas"`
	ExternalID string      `json:"externalId"`
	UserName   string      `json:"userName"`
	Name       *UserName   `json:"name"`
	Emails     []UserEmail `json:"emails"`
	Active     *bool       `json:"active"`
}

// GroupResource is the RFC 7643 §4.2 core:Group wire shape.
type GroupResource struct {
	Schemas     []string      `json:"schemas"`
	ID          string        `json:"id"`
	ExternalID  string        `json:"externalId,omitempty"`
	DisplayName string        `json:"displayName"`
	Members     []GroupMember `json:"members,omitempty"`
	Meta        ResourceMeta  `json:"meta"`
}

// GroupMember mirrors RFC 7643 §4.2.1 multi-valued `members`. $ref is the
// absolute URL to the member (User or nested Group) resource.
type GroupMember struct {
	Value   string `json:"value"`
	Ref     string `json:"$ref,omitempty"`
	Type    string `json:"type,omitempty"`
	Display string `json:"display,omitempty"`
}

// GroupCreateOrReplace is the inbound POST /Groups + PUT /Groups/{id} shape.
type GroupCreateOrReplace struct {
	Schemas     []string      `json:"schemas"`
	ExternalID  string        `json:"externalId"`
	DisplayName string        `json:"displayName"`
	Members     []GroupMember `json:"members"`
}

// ResourceMeta mirrors RFC 7643 §3.1 `meta`. Version is a weak ETag
// derived from the resource's lastModified.
type ResourceMeta struct {
	ResourceType string `json:"resourceType"`
	Created      string `json:"created,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
	Location     string `json:"location"`
	Version      string `json:"version,omitempty"`
}

// ListResponse is the RFC 7644 §3.4.2 ListResponse envelope. Resources is
// left as a raw-message slice so Users + Groups share the envelope.
type ListResponse struct {
	Schemas      []string          `json:"schemas"`
	TotalResults int               `json:"totalResults"`
	StartIndex   int               `json:"startIndex"`
	ItemsPerPage int               `json:"itemsPerPage"`
	Resources    []json.RawMessage `json:"Resources"`
}

// --- Discovery-endpoint shapes (RFC 7644 §5 / §6), lifted in 4e-5a. ---

// ServiceProviderConfig is the GET /ServiceProviderConfig payload (RFC 7644 §5).
type ServiceProviderConfig struct {
	Schemas               []string        `json:"schemas"`
	DocumentationURI      string          `json:"documentationUri"`
	Patch                 SPCSupported    `json:"patch"`
	Bulk                  SPCBulk         `json:"bulk"`
	Filter                SPCFilter       `json:"filter"`
	ChangePassword        SPCSupported    `json:"changePassword"`
	Sort                  SPCSupported    `json:"sort"`
	ETag                  SPCSupported    `json:"etag"`
	AuthenticationSchemes []SPCAuthScheme `json:"authenticationSchemes"`
	Meta                  ResourceMeta    `json:"meta"`
}

type SPCSupported struct {
	Supported bool `json:"supported"`
}

type SPCBulk struct {
	Supported      bool `json:"supported"`
	MaxOperations  int  `json:"maxOperations"`
	MaxPayloadSize int  `json:"maxPayloadSize"`
}

type SPCFilter struct {
	Supported  bool `json:"supported"`
	MaxResults int  `json:"maxResults"`
}

type SPCAuthScheme struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Primary     bool   `json:"primary"`
}

// ResourceTypeEntry is one entry under GET /ResourceTypes.
type ResourceTypeEntry struct {
	Schemas  []string `json:"schemas"`
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Endpoint string   `json:"endpoint"`
	Schema   string   `json:"schema"`
}
