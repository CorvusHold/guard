package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// SCIMUser represents a SCIM 2.0 User resource.
type SCIMUser struct {
	Schemas    []string       `json:"schemas"`
	ID         string         `json:"id"`
	ExternalID string         `json:"externalId,omitempty"`
	UserName   string         `json:"userName"`
	Name       SCIMName       `json:"name,omitempty"`
	Emails     []SCIMEmail    `json:"emails,omitempty"`
	Active     bool           `json:"active"`
	Groups     []SCIMGroupRef `json:"groups,omitempty"`
	Meta       SCIMMeta       `json:"meta"`
}

// SCIMName represents a SCIM name sub-attribute.
type SCIMName struct {
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
}

// SCIMEmail represents a SCIM email sub-attribute.
type SCIMEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// SCIMGroupRef is a reference to a group in a SCIM user response.
type SCIMGroupRef struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Ref     string `json:"$ref,omitempty"`
}

// SCIMMeta contains resource metadata.
type SCIMMeta struct {
	ResourceType string    `json:"resourceType"`
	Created      time.Time `json:"created"`
	LastModified time.Time `json:"lastModified"`
	Location     string    `json:"location,omitempty"`
}

// SCIMListResponse is the standard SCIM list response.
type SCIMListResponse struct {
	Schemas      []string    `json:"schemas"`
	TotalResults int         `json:"totalResults"`
	StartIndex   int         `json:"startIndex"`
	ItemsPerPage int         `json:"itemsPerPage"`
	Resources    interface{} `json:"Resources"`
}

// SCIMGroup represents a SCIM 2.0 Group resource.
type SCIMGroup struct {
	Schemas     []string        `json:"schemas"`
	ID          string          `json:"id"`
	DisplayName string          `json:"displayName"`
	Members     []SCIMMemberRef `json:"members,omitempty"`
	Meta        SCIMMeta        `json:"meta"`
}

// SCIMMemberRef is a reference to a member in a SCIM group.
type SCIMMemberRef struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Ref     string `json:"$ref,omitempty"`
}

// SCIMError represents a SCIM error response.
type SCIMError struct {
	Schemas []string `json:"schemas"`
	Detail  string   `json:"detail"`
	Status  int      `json:"status"`
}

// SCIMPatchOp represents a single SCIM PATCH operation (RFC 7644 §3.5.2).
type SCIMPatchOp struct {
	Op    string      `json:"op"`    // add, remove, replace
	Path  string      `json:"path"`  // attribute path, e.g. "name.givenName"
	Value interface{} `json:"value"` // new value
}

// SCIMPatchRequest represents a SCIM PATCH request body.
type SCIMPatchRequest struct {
	Schemas    []string      `json:"schemas"`
	Operations []SCIMPatchOp `json:"Operations"`
}

// Service defines the SCIM provisioning service interface.
type Service interface {
	// Users
	GetUser(ctx context.Context, tenantID uuid.UUID, userID string) (SCIMUser, error)
	ListUsers(ctx context.Context, tenantID uuid.UUID, filter string, startIndex, count int) (SCIMListResponse, error)
	CreateUser(ctx context.Context, tenantID uuid.UUID, user SCIMUser) (SCIMUser, error)
	UpdateUser(ctx context.Context, tenantID uuid.UUID, userID string, user SCIMUser) (SCIMUser, error)
	PatchUser(ctx context.Context, tenantID uuid.UUID, userID string, ops []SCIMPatchOp) (SCIMUser, error)
	DeleteUser(ctx context.Context, tenantID uuid.UUID, userID string) error

	// Groups
	GetGroup(ctx context.Context, tenantID uuid.UUID, groupID string) (SCIMGroup, error)
	ListGroups(ctx context.Context, tenantID uuid.UUID, filter string, startIndex, count int) (SCIMListResponse, error)
	CreateGroup(ctx context.Context, tenantID uuid.UUID, group SCIMGroup) (SCIMGroup, error)
	UpdateGroup(ctx context.Context, tenantID uuid.UUID, groupID string, group SCIMGroup) (SCIMGroup, error)
	PatchGroup(ctx context.Context, tenantID uuid.UUID, groupID string, ops []SCIMPatchOp) (SCIMGroup, error)
	DeleteGroup(ctx context.Context, tenantID uuid.UUID, groupID string) error
}
