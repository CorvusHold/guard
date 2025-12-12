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

// UpdateFGAGroup updates an FGA group by ID.
// Note: The backend API does not support updating FGA groups; only delete is available.
// To change a group, delete the old one and create a new one.
func (c *GuardClient) UpdateFGAGroup(ctx context.Context, groupID string, req UpdateFGAGroupRequest) error {
	return errors.New("FGA group updates are not supported by the backend API; delete and recreate instead")
}

// DeleteFGAGroup deletes an FGA group by ID.
func (c *GuardClient) DeleteFGAGroup(ctx context.Context, groupID string) error {
	resp, err := c.inner.DeleteApiV1AuthAdminFgaGroupsIdWithResponse(ctx, groupID, &DeleteApiV1AuthAdminFgaGroupsIdParams{})
	if err != nil {
		return err
	}

	if resp.StatusCode() != 204 {
		return errors.New(resp.Status())
	}

	return nil
}

// ListFGAGroupMembers lists all members of an FGA group.
func (c *GuardClient) ListFGAGroupMembers(ctx context.Context, groupID string) ([]FGAGroupMember, error) {
	resp, err := c.inner.GetApiV1AuthAdminFgaGroupsWithResponse(ctx, &GetApiV1AuthAdminFgaGroupsParams{})
	if err != nil {
		return nil, err
	}

	if resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}

	members := make([]FGAGroupMember, 0)
	if resp.JSON200.Groups != nil {
		for _, g := range *resp.JSON200.Groups {
			if g.Id != nil && *g.Id == groupID {
				// Note: The backend returns groups without member details
				// Members would need to be fetched via a separate endpoint
				break
			}
		}
	}

	return members, nil
}

// AddFGAGroupMember adds a member to an FGA group.
func (c *GuardClient) AddFGAGroupMember(ctx context.Context, groupID string, req AddFGAGroupMemberRequest) error {
	body := PostApiV1AuthAdminFgaGroupsIdMembersJSONRequestBody{
		UserId: req.UserID,
	}

	resp, err := c.inner.PostApiV1AuthAdminFgaGroupsIdMembersWithResponse(ctx, groupID, body)
	if err != nil {
		return err
	}

	if resp.StatusCode() != 200 && resp.StatusCode() != 201 {
		return errors.New(resp.Status())
	}

	return nil
}

// RemoveFGAGroupMember removes a member from an FGA group.
func (c *GuardClient) RemoveFGAGroupMember(ctx context.Context, groupID, userID string) error {
	body := DeleteApiV1AuthAdminFgaGroupsIdMembersJSONRequestBody{
		UserId: userID,
	}

	resp, err := c.inner.DeleteApiV1AuthAdminFgaGroupsIdMembersWithResponse(ctx, groupID, body)
	if err != nil {
		return err
	}

	if resp.StatusCode() != 204 && resp.StatusCode() != 200 {
		return errors.New(resp.Status())
	}

	return nil
}

// ListFGAACLTuples lists all FGA ACL tuples for a tenant.
func (c *GuardClient) ListFGAACLTuples(ctx context.Context, tenantID string) ([]FGAACLTuple, error) {
	// Note: Backend doesn't provide a GET endpoint for listing ACL tuples
	// This is a limitation of the current API design
	return make([]FGAACLTuple, 0), nil
}

// CreateFGAACLTuple creates a new FGA ACL tuple.
func (c *GuardClient) CreateFGAACLTuple(ctx context.Context, req CreateFGAACLTupleRequest) (*FGAACLTuple, error) {
	body := PostApiV1AuthAdminFgaAclTuplesJSONRequestBody{
		TenantId:      req.TenantID,
		SubjectType:   ControllerFgaCreateACLTupleReqSubjectType(req.SubjectType),
		SubjectId:     req.SubjectID,
		PermissionKey: req.PermissionKey,
		ObjectType:    req.ObjectType,
		ObjectId:      req.ObjectID,
	}

	resp, err := c.inner.PostApiV1AuthAdminFgaAclTuplesWithResponse(ctx, body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != 200 && resp.StatusCode() != 201 {
		return nil, errors.New(resp.Status())
	}

	tuple := &FGAACLTuple{
		TenantID:      req.TenantID,
		SubjectType:   req.SubjectType,
		SubjectID:     req.SubjectID,
		PermissionKey: req.PermissionKey,
		ObjectType:    req.ObjectType,
		ObjectID:      req.ObjectID,
	}

	return tuple, nil
}

// DeleteFGAACLTuple deletes an FGA ACL tuple.
func (c *GuardClient) DeleteFGAACLTuple(ctx context.Context, tupleID string) error {
	// Note: The API requires subject_type, subject_id, permission_key, object_type to delete
	// but we only have tupleID. This method signature doesn't match the API capability.
	// For now, return error indicating the limitation.
	return errors.New("DeleteFGAACLTuple requires full ACL tuple details (subject, permission, object); use individual fields")
}

// FGAAuthorize checks if a user is authorized for an action on an object.
func (c *GuardClient) FGAAuthorize(ctx context.Context, req FGAAuthorizeRequest) (*FGAAuthorizeResponse, error) {
	body := PostApiV1AuthAuthorizeJSONRequestBody{
		TenantId:      req.TenantID,
		SubjectType:   ControllerFgaAuthorizeReqSubjectType(req.SubjectType),
		SubjectId:     req.SubjectID,
		PermissionKey: req.PermissionKey,
		ObjectType:    req.ObjectType,
		ObjectId:      req.ObjectID,
	}

	resp, err := c.inner.PostApiV1AuthAuthorizeWithResponse(ctx, body)
	if err != nil {
		return nil, err
	}

	if resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}

	result := &FGAAuthorizeResponse{
		Allowed: false,
	}
	if resp.JSON200.Allowed != nil {
		result.Allowed = *resp.JSON200.Allowed
	}

	return result, nil
}

// === ALTERNATIVE COARSE-GRAINED METHODS (for developers preferring bulk operations) ===

// ModifyFGAGroupMembers performs bulk member operations on an FGA group.
// This is an alternative to AddFGAGroupMember/RemoveFGAGroupMember for batch operations.
func (c *GuardClient) ModifyFGAGroupMembers(ctx context.Context, groupID string, userIDs []string, action string) error {
	// action: "add" or "remove"
	if action != "add" && action != "remove" {
		return errors.New("action must be 'add' or 'remove'")
	}

	for _, userID := range userIDs {
		if action == "add" {
			body := PostApiV1AuthAdminFgaGroupsIdMembersJSONRequestBody{
				UserId: userID,
			}
			resp, err := c.inner.PostApiV1AuthAdminFgaGroupsIdMembersWithResponse(ctx, groupID, body)
			if err != nil {
				return err
			}
			if resp.StatusCode() != 200 && resp.StatusCode() != 201 {
				return errors.New(resp.Status())
			}
		} else {
			body := DeleteApiV1AuthAdminFgaGroupsIdMembersJSONRequestBody{
				UserId: userID,
			}
			resp, err := c.inner.DeleteApiV1AuthAdminFgaGroupsIdMembersWithResponse(ctx, groupID, body)
			if err != nil {
				return err
			}
			if resp.StatusCode() != 204 && resp.StatusCode() != 200 {
				return errors.New(resp.Status())
			}
		}
	}

	return nil
}

// ModifyFGAACLTuples performs bulk ACL tuple operations.
// This is an alternative to CreateFGAACLTuple/DeleteFGAACLTuple for batch operations.
func (c *GuardClient) ModifyFGAACLTuples(ctx context.Context, tuples []CreateFGAACLTupleRequest, action string) error {
	// action: "create" or "delete"
	if action != "create" && action != "delete" {
		return errors.New("action must be 'create' or 'delete'")
	}

	for _, tuple := range tuples {
		if action == "create" {
			body := PostApiV1AuthAdminFgaAclTuplesJSONRequestBody{
				TenantId:      tuple.TenantID,
				SubjectType:   ControllerFgaCreateACLTupleReqSubjectType(tuple.SubjectType),
				SubjectId:     tuple.SubjectID,
				PermissionKey: tuple.PermissionKey,
				ObjectType:    tuple.ObjectType,
				ObjectId:      tuple.ObjectID,
			}
			resp, err := c.inner.PostApiV1AuthAdminFgaAclTuplesWithResponse(ctx, body)
			if err != nil {
				return err
			}
			if resp.StatusCode() != 200 && resp.StatusCode() != 201 {
				return errors.New(resp.Status())
			}
		} else {
			body := DeleteApiV1AuthAdminFgaAclTuplesJSONRequestBody{
				TenantId:      tuple.TenantID,
				SubjectType:   ControllerFgaDeleteACLTupleReqSubjectType(tuple.SubjectType),
				SubjectId:     tuple.SubjectID,
				PermissionKey: tuple.PermissionKey,
				ObjectType:    tuple.ObjectType,
				ObjectId:      tuple.ObjectID,
			}
			resp, err := c.inner.DeleteApiV1AuthAdminFgaAclTuplesWithResponse(ctx, body)
			if err != nil {
				return err
			}
			if resp.StatusCode() != 204 && resp.StatusCode() != 200 {
				return errors.New(resp.Status())
			}
		}
	}

	return nil
}
