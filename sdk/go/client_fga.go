package guard

import (
	"context"
	"errors"
	"net/http"
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

	params := &GetV1AuthAdminFgaGroupsParams{TenantId: tenantID}
	resp, err := c.inner.GetV1AuthAdminFgaGroupsWithResponse(ctx, params)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}

	var groups []FGAGroup
	if resp.JSON200.Groups != nil {
		for _, g := range *resp.JSON200.Groups {
			group := FGAGroup{
				ID:       g.Id,
				TenantID: g.TenantId,
				Name:     g.Name,
			}
			if g.Description != nil {
				group.Description = *g.Description
			}
			if g.CreatedAt != nil {
				group.CreatedAt = *g.CreatedAt
			}
			if g.UpdatedAt != nil {
				group.UpdatedAt = *g.UpdatedAt
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
	resp, err := c.inner.PostV1AuthAdminFgaGroupsWithResponse(ctx, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON201 == nil && resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}

	// Handle both 201 Created and 200 OK responses
	var result *ControllerFgaGroupItem
	if resp.JSON201 != nil {
		result = resp.JSON201
	} else {
		result = resp.JSON200
	}

	group := &FGAGroup{
		ID:       result.Id,
		TenantID: result.TenantId,
		Name:     result.Name,
	}
	if result.Description != nil {
		group.Description = *result.Description
	}
	if result.CreatedAt != nil {
		group.CreatedAt = *result.CreatedAt
	}
	if result.UpdatedAt != nil {
		group.UpdatedAt = *result.UpdatedAt
	}

	return group, nil
}

// UpdateFGAGroup updates an existing FGA group. Requires admin role.
func (c *GuardClient) UpdateFGAGroup(ctx context.Context, groupID string, req UpdateFGAGroupRequest) error {
	tenantID := c.tenantID
	if tenantID == "" {
		return errors.New("tenant ID required")
	}

	body := ControllerFgaUpdateGroupReq{
		TenantId:    tenantID,
		Name:        req.Name,
		Description: req.Description,
	}
	resp, err := c.inner.PatchV1AuthAdminFgaGroupsIdWithResponse(ctx, groupID, body)
	if err != nil {
		return err
	}
	if resp.HTTPResponse == nil || (resp.StatusCode() != http.StatusOK && resp.StatusCode() != http.StatusNoContent) {
		return errors.New(resp.Status())
	}
	return nil
}

// DeleteFGAGroup deletes an FGA group. Requires admin role.
func (c *GuardClient) DeleteFGAGroup(ctx context.Context, groupID string) error {
	tenantID := c.tenantID
	if tenantID == "" {
		return errors.New("tenant ID required")
	}

	params := &DeleteV1AuthAdminFgaGroupsIdParams{TenantId: tenantID}
	resp, err := c.inner.DeleteV1AuthAdminFgaGroupsIdWithResponse(ctx, groupID, params)
	if err != nil {
		return err
	}
	if resp.HTTPResponse == nil || (resp.StatusCode() != http.StatusOK && resp.StatusCode() != http.StatusNoContent) {
		return errors.New(resp.Status())
	}
	return nil
}

// ListFGAGroupMembers retrieves all members of an FGA group. Requires admin role.
func (c *GuardClient) ListFGAGroupMembers(ctx context.Context, groupID string) ([]FGAGroupMember, error) {
	resp, err := c.inner.GetV1AuthAdminFgaGroupsIdMembersWithResponse(ctx, groupID)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}

	var members []FGAGroupMember
	if resp.JSON200.Members != nil {
		for _, m := range *resp.JSON200.Members {
			member := FGAGroupMember{
				UserID:  m.UserId,
				GroupID: m.GroupId,
			}
			if m.AddedAt != nil {
				member.AddedAt = *m.AddedAt
			}
			if m.AddedBy != nil {
				member.AddedBy = *m.AddedBy
			}
			members = append(members, member)
		}
	}

	return members, nil
}

// AddFGAGroupMember adds a user to an FGA group. Requires admin role.
func (c *GuardClient) AddFGAGroupMember(ctx context.Context, groupID string, req AddFGAGroupMemberRequest) error {
	body := ControllerFgaAddGroupMemberReq{
		UserId: req.UserID,
	}
	resp, err := c.inner.PostV1AuthAdminFgaGroupsIdMembersWithResponse(ctx, groupID, body)
	if err != nil {
		return err
	}
	if resp.HTTPResponse == nil || (resp.StatusCode() != http.StatusOK && resp.StatusCode() != http.StatusNoContent && resp.StatusCode() != http.StatusCreated) {
		return errors.New(resp.Status())
	}
	return nil
}

// RemoveFGAGroupMember removes a user from an FGA group. Requires admin role.
func (c *GuardClient) RemoveFGAGroupMember(ctx context.Context, groupID, userID string) error {
	resp, err := c.inner.DeleteV1AuthAdminFgaGroupsIdMembersUserIdWithResponse(ctx, groupID, userID)
	if err != nil {
		return err
	}
	if resp.HTTPResponse == nil || (resp.StatusCode() != http.StatusOK && resp.StatusCode() != http.StatusNoContent) {
		return errors.New(resp.Status())
	}
	return nil
}

// ListFGAACLTuples retrieves all ACL tuples for a tenant. Requires admin role.
func (c *GuardClient) ListFGAACLTuples(ctx context.Context, tenantID string) ([]FGAACLTuple, error) {
	if tenantID == "" {
		tenantID = c.tenantID
	}
	if tenantID == "" {
		return nil, errors.New("tenant ID required")
	}

	params := &GetV1AuthAdminFgaAclTuplesParams{TenantId: tenantID}
	resp, err := c.inner.GetV1AuthAdminFgaAclTuplesWithResponse(ctx, params)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}

	var tuples []FGAACLTuple
	if resp.JSON200.Tuples != nil {
		for _, t := range *resp.JSON200.Tuples {
			tuple := FGAACLTuple{
				ID:            t.Id,
				TenantID:      t.TenantId,
				SubjectType:   t.SubjectType,
				SubjectID:     t.SubjectId,
				PermissionKey: t.PermissionKey,
				ObjectType:    t.ObjectType,
			}
			if t.ObjectId != nil {
				tuple.ObjectID = t.ObjectId
			}
			if t.CreatedBy != nil {
				tuple.CreatedBy = t.CreatedBy
			}
			if t.CreatedAt != nil {
				tuple.CreatedAt = *t.CreatedAt
			}
			tuples = append(tuples, tuple)
		}
	}

	return tuples, nil
}

// CreateFGAACLTuple creates a new ACL tuple. Requires admin role.
func (c *GuardClient) CreateFGAACLTuple(ctx context.Context, req CreateFGAACLTupleRequest) (*FGAACLTuple, error) {
	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = c.tenantID
	}
	if tenantID == "" {
		return nil, errors.New("tenant ID required")
	}

	body := ControllerFgaCreateAclTupleReq{
		TenantId:      tenantID,
		SubjectType:   req.SubjectType,
		SubjectId:     req.SubjectID,
		PermissionKey: req.PermissionKey,
		ObjectType:    req.ObjectType,
		ObjectId:      req.ObjectID,
	}
	resp, err := c.inner.PostV1AuthAdminFgaAclTuplesWithResponse(ctx, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON201 == nil && resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}

	// Handle both 201 Created and 200 OK responses
	var result *ControllerFgaAclTupleItem
	if resp.JSON201 != nil {
		result = resp.JSON201
	} else {
		result = resp.JSON200
	}

	tuple := &FGAACLTuple{
		ID:            result.Id,
		TenantID:      result.TenantId,
		SubjectType:   result.SubjectType,
		SubjectID:     result.SubjectId,
		PermissionKey: result.PermissionKey,
		ObjectType:    result.ObjectType,
	}
	if result.ObjectId != nil {
		tuple.ObjectID = result.ObjectId
	}
	if result.CreatedBy != nil {
		tuple.CreatedBy = result.CreatedBy
	}
	if result.CreatedAt != nil {
		tuple.CreatedAt = *result.CreatedAt
	}

	return tuple, nil
}

// DeleteFGAACLTuple deletes an ACL tuple by ID. Requires admin role.
func (c *GuardClient) DeleteFGAACLTuple(ctx context.Context, tupleID string) error {
	resp, err := c.inner.DeleteV1AuthAdminFgaAclTuplesIdWithResponse(ctx, tupleID)
	if err != nil {
		return err
	}
	if resp.HTTPResponse == nil || (resp.StatusCode() != http.StatusOK && resp.StatusCode() != http.StatusNoContent) {
		return errors.New(resp.Status())
	}
	return nil
}

// FGAAuthorize checks if a subject has a specific permission on an object. Requires admin role.
func (c *GuardClient) FGAAuthorize(ctx context.Context, req FGAAuthorizeRequest) (*FGAAuthorizeResponse, error) {
	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = c.tenantID
	}
	if tenantID == "" {
		return nil, errors.New("tenant ID required")
	}

	body := ControllerFgaAuthorizeReq{
		TenantId:      tenantID,
		SubjectType:   req.SubjectType,
		SubjectId:     req.SubjectID,
		PermissionKey: req.PermissionKey,
		ObjectType:    req.ObjectType,
		ObjectId:      req.ObjectID,
	}
	resp, err := c.inner.PostV1AuthAdminFgaAuthorizeWithResponse(ctx, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}

	allowed := false
	if resp.JSON200.Allowed != nil {
		allowed = *resp.JSON200.Allowed
	}

	return &FGAAuthorizeResponse{
		Allowed: allowed,
	}, nil
}
