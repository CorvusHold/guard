package guard

import (
	"context"
	"errors"
)

// FGAGroup represents a Fine-Grained Authorization group.
type FGAGroup struct {
	ID          string
	TenantID    string
	Name        string
	Description string
	CreatedAt   string
	UpdatedAt   string
}

// CreateFGAGroupRequest contains the parameters for creating a new FGA group.
type CreateFGAGroupRequest struct {
	TenantID    string
	Name        string
	Description string
}

// UpdateFGAGroupRequest contains the fields that can be updated for an FGA group.
type UpdateFGAGroupRequest struct {
	Name        *string
	Description *string
}

// FGAGroupMember represents a member of an FGA group.
type FGAGroupMember struct {
	UserID  string
	GroupID string
	AddedAt string
	AddedBy string
}

// AddFGAGroupMemberRequest contains the user ID to add to a group.
type AddFGAGroupMemberRequest struct {
	UserID string
}

// FGAACLTuple represents an Access Control List tuple for fine-grained authorization.
type FGAACLTuple struct {
	ID            string
	TenantID      string
	SubjectType   string
	SubjectID     string
	PermissionKey string
	ObjectType    string
	ObjectID      *string
	CreatedBy     *string
	CreatedAt     string
}

// CreateFGAACLTupleRequest contains the parameters for creating a new ACL tuple.
type CreateFGAACLTupleRequest struct {
	TenantID      string
	SubjectType   string
	SubjectID     string
	PermissionKey string
	ObjectType    string
	ObjectID      *string
}

// FGAAuthorizeRequest contains the parameters for an authorization check.
type FGAAuthorizeRequest struct {
	TenantID      string
	SubjectType   string
	SubjectID     *string
	PermissionKey string
	ObjectType    string
	ObjectID      *string
}

// FGAAuthorizeResponse contains the result of an authorization check.
type FGAAuthorizeResponse struct {
	Allowed bool
}

// ListFGAGroups retrieves all FGA groups for a tenant. Requires admin role.
func (c *GuardClient) ListFGAGroups(ctx context.Context, tenantID string) ([]FGAGroup, error) {
	if tenantID == "" {
		tenantID = c.tenantID
	}
	if tenantID == "" {
		return nil, errors.New("tenant ID required")
	}

	params := &GetApiV1AuthAdminFgaGroupsParams{TenantId: tenantID}
	resp, err := c.inner.GetApiV1AuthAdminFgaGroupsWithResponse(ctx, params)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}

	var groups []FGAGroup
	if resp.JSON200.Groups != nil {
		for _, g := range *resp.JSON200.Groups {
			group := FGAGroup{}
			if g.Id != nil {
				group.ID = *g.Id
			}
			if g.TenantId != nil {
				group.TenantID = *g.TenantId
			}
			if g.Name != nil {
				group.Name = *g.Name
			}
			if g.Description != nil {
				group.Description = *g.Description
			}
			groups = append(groups, group)
		}
	}

	return groups, nil
}

// CreateFGAGroup creates a new FGA group. Requires admin role.
func (c *GuardClient) CreateFGAGroup(ctx context.Context, req CreateFGAGroupRequest) (*FGAGroup, error) {
	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = c.tenantID
	}
	if tenantID == "" {
		return nil, errors.New("tenant ID required")
	}

	body := ControllerFgaCreateGroupReq{
		TenantId:    tenantID,
		Name:        req.Name,
		Description: &req.Description,
	}
	resp, err := c.inner.PostApiV1AuthAdminFgaGroupsWithResponse(ctx, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON201 == nil {
		return nil, errors.New(resp.Status())
	}

	result := resp.JSON201
	group := &FGAGroup{}
	if result.Id != nil {
		group.ID = *result.Id
	}
	if result.TenantId != nil {
		group.TenantID = *result.TenantId
	}
	if result.Name != nil {
		group.Name = *result.Name
	}
	if result.Description != nil {
		group.Description = *result.Description
	}

	return group, nil
}

// UpdateFGAGroup is not yet implemented.
// See ADR 0008 for status on additional FGA management endpoints.
// func (c *GuardClient) UpdateFGAGroup(ctx context.Context, groupID string, req UpdateFGAGroupRequest) error

// DeleteFGAGroup is not yet implemented.
// See ADR 0008 for status on additional FGA management endpoints.
// func (c *GuardClient) DeleteFGAGroup(ctx context.Context, groupID string) error

// ListFGAGroupMembers is not yet implemented.
// See ADR 0008 for status on additional FGA management endpoints.
// func (c *GuardClient) ListFGAGroupMembers(ctx context.Context, groupID string) ([]FGAGroupMember, error)

// AddFGAGroupMember is not yet implemented.
// See ADR 0008 for status on additional FGA management endpoints.
// func (c *GuardClient) AddFGAGroupMember(ctx context.Context, groupID string, req AddFGAGroupMemberRequest) error

// RemoveFGAGroupMember is not yet implemented.
// See ADR 0008 for status on additional FGA management endpoints.
// func (c *GuardClient) RemoveFGAGroupMember(ctx context.Context, groupID, userID string) error

// ListFGAACLTuples is not yet implemented.
// See ADR 0008 for status on additional FGA management endpoints.
// func (c *GuardClient) ListFGAACLTuples(ctx context.Context, tenantID string) ([]FGAACLTuple, error)

// CreateFGAACLTuple is not yet implemented.
// See ADR 0008 for status on additional FGA management endpoints.
// func (c *GuardClient) CreateFGAACLTuple(ctx context.Context, req CreateFGAACLTupleRequest) (*FGAACLTuple, error)

// DeleteFGAACLTuple is not yet implemented.
// See ADR 0008 for status on additional FGA management endpoints.
// func (c *GuardClient) DeleteFGAACLTuple(ctx context.Context, tupleID string) error

// FGAAuthorize is not yet implemented.
// See ADR 0008 for status on additional FGA management endpoints.
// func (c *GuardClient) FGAAuthorize(ctx context.Context, req FGAAuthorizeRequest) (*FGAAuthorizeResponse, error)
