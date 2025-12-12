package guard

import (
	"context"
	"errors"
	"net/http"
)

// Permission represents an RBAC permission.
type Permission struct {
	Key         string
	Name        string
	Description string
}

// Role represents an RBAC role.
type Role struct {
	ID          string
	TenantID    string
	Name        string
	Description string
	IsSystem    bool
	CreatedAt   string
	UpdatedAt   string
}

// CreateRoleRequest contains the parameters for creating a new role.
type CreateRoleRequest struct {
	TenantID    string
	Name        string
	Description string
}

// UpdateRoleRequest contains the fields that can be updated for a role.
type UpdateRoleRequest struct {
	Name        *string
	Description *string
}

// RolePermissionRequest contains the permission key for role permission operations.
type RolePermissionRequest struct {
	PermissionKey string
}

// UserRoleRequest contains the tenant and role ID for user role operations.
type UserRoleRequest struct {
	TenantID string
	RoleID   string
}

// ListPermissions retrieves all available permissions. Requires admin role.
func (c *GuardClient) ListPermissions(ctx context.Context) ([]Permission, error) {
	resp, err := c.inner.GetApiV1AuthAdminRbacPermissionsWithResponse(ctx, nil)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}

	var permissions []Permission
	if resp.JSON200.Permissions != nil {
		for _, p := range *resp.JSON200.Permissions {
			perm := Permission{}
			if p.Key != nil {
				perm.Key = *p.Key
			}
			if p.Description != nil {
				perm.Description = *p.Description
			}
			permissions = append(permissions, perm)
		}
	}

	return permissions, nil
}

// ListRoles retrieves all roles for a tenant. Requires admin role.
func (c *GuardClient) ListRoles(ctx context.Context, tenantID string) ([]Role, error) {
	if tenantID == "" {
		tenantID = c.tenantID
	}
	if tenantID == "" {
		return nil, errors.New("tenant ID required")
	}

	params := &GetApiV1AuthAdminRbacRolesParams{TenantId: tenantID}
	resp, err := c.inner.GetApiV1AuthAdminRbacRolesWithResponse(ctx, params)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}

	var roles []Role
	if resp.JSON200.Roles != nil {
		for _, r := range *resp.JSON200.Roles {
			role := Role{}
			if r.Id != nil {
				role.ID = *r.Id
			}
			if r.TenantId != nil {
				role.TenantID = *r.TenantId
			}
			if r.Name != nil {
				role.Name = *r.Name
			}
			if r.Description != nil {
				role.Description = *r.Description
			}
			if r.CreatedAt != nil {
				role.CreatedAt = *r.CreatedAt
			}
			if r.UpdatedAt != nil {
				role.UpdatedAt = *r.UpdatedAt
			}
			roles = append(roles, role)
		}
	}

	return roles, nil
}

// CreateRole creates a new role. Requires admin role.
func (c *GuardClient) CreateRole(ctx context.Context, req CreateRoleRequest) (*Role, error) {
	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = c.tenantID
	}
	if tenantID == "" {
		return nil, errors.New("tenant ID required")
	}

	body := ControllerRbacCreateRoleReq{
		TenantId:    tenantID,
		Name:        req.Name,
		Description: &req.Description,
	}
	resp, err := c.inner.PostApiV1AuthAdminRbacRolesWithResponse(ctx, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON201 == nil {
		return nil, errors.New(resp.Status())
	}

	result := resp.JSON201
	role := &Role{}
	if result.Id != nil {
		role.ID = *result.Id
	}
	if result.TenantId != nil {
		role.TenantID = *result.TenantId
	}
	if result.Name != nil {
		role.Name = *result.Name
	}
	if result.Description != nil {
		role.Description = *result.Description
	}
	if result.CreatedAt != nil {
		role.CreatedAt = *result.CreatedAt
	}
	if result.UpdatedAt != nil {
		role.UpdatedAt = *result.UpdatedAt
	}

	return role, nil
}

// UpdateRole updates an existing role. Requires admin role.
func (c *GuardClient) UpdateRole(ctx context.Context, roleID string, req UpdateRoleRequest) error {
	tenantID := c.tenantID
	if tenantID == "" {
		return errors.New("tenant ID required")
	}

	body := ControllerRbacUpdateRoleReq{
		TenantId: tenantID,
	}
	if req.Name != nil {
		body.Name = *req.Name
	}
	body.Description = req.Description
	resp, err := c.inner.PatchApiV1AuthAdminRbacRolesIdWithResponse(ctx, roleID, body)
	if err != nil {
		return err
	}
	if resp.HTTPResponse == nil || (resp.StatusCode() != http.StatusOK && resp.StatusCode() != http.StatusNoContent) {
		return errors.New(resp.Status())
	}
	return nil
}

// DeleteRole deletes a role. Requires admin role.
func (c *GuardClient) DeleteRole(ctx context.Context, roleID string) error {
	tenantID := c.tenantID
	if tenantID == "" {
		return errors.New("tenant ID required")
	}

	params := &DeleteApiV1AuthAdminRbacRolesIdParams{TenantId: tenantID}
	resp, err := c.inner.DeleteApiV1AuthAdminRbacRolesIdWithResponse(ctx, roleID, params)
	if err != nil {
		return err
	}
	if resp.HTTPResponse == nil || (resp.StatusCode() != http.StatusOK && resp.StatusCode() != http.StatusNoContent) {
		return errors.New(resp.Status())
	}
	return nil
}

// UpsertRolePermission adds or updates a permission for a role. Requires admin role.
func (c *GuardClient) UpsertRolePermission(ctx context.Context, roleID string, req RolePermissionRequest) error {
	body := ControllerRbacRolePermissionReq{
		PermissionKey: req.PermissionKey,
	}
	resp, err := c.inner.PostApiV1AuthAdminRbacRolesIdPermissionsWithResponse(ctx, roleID, body)
	if err != nil {
		return err
	}
	if resp.HTTPResponse == nil || (resp.StatusCode() != http.StatusOK && resp.StatusCode() != http.StatusNoContent && resp.StatusCode() != http.StatusCreated) {
		return errors.New(resp.Status())
	}
	return nil
}

// DeleteRolePermission removes a permission from a role. Requires admin role.
func (c *GuardClient) DeleteRolePermission(ctx context.Context, roleID string, permissionKey string) error {
	body := ControllerRbacRolePermissionReq{
		PermissionKey: permissionKey,
	}
	resp, err := c.inner.DeleteApiV1AuthAdminRbacRolesIdPermissionsWithResponse(ctx, roleID, body)
	if err != nil {
		return err
	}
	if resp.HTTPResponse == nil || (resp.StatusCode() != http.StatusOK && resp.StatusCode() != http.StatusNoContent) {
		return errors.New(resp.Status())
	}
	return nil
}

// ListUserRoles lists all role IDs assigned to a user.
func (c *GuardClient) ListUserRoles(ctx context.Context, userID, tenantID string) ([]Role, error) {
	params := &GetApiV1AuthAdminRbacUsersIdRolesParams{
		TenantId: tenantID,
	}

	resp, err := c.inner.GetApiV1AuthAdminRbacUsersIdRolesWithResponse(ctx, userID, params)
	if err != nil {
		return nil, err
	}

	if resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}

	roles := make([]Role, 0)
	if resp.JSON200.RoleIds != nil {
		// Backend returns only role IDs; create role stubs with ID populated
		// Clients can fetch full role details via ListRoles if needed
		for _, roleID := range *resp.JSON200.RoleIds {
			roles = append(roles, Role{ID: roleID})
		}
	}

	return roles, nil
}

// AddUserRole adds a role assignment to a user.
func (c *GuardClient) AddUserRole(ctx context.Context, userID string, req UserRoleRequest) error {
	body := PostApiV1AuthAdminRbacUsersIdRolesJSONRequestBody{
		RoleId:   req.RoleID,
		TenantId: req.TenantID,
	}

	resp, err := c.inner.PostApiV1AuthAdminRbacUsersIdRolesWithResponse(ctx, userID, body)
	if err != nil {
		return err
	}

	if resp.StatusCode() != 200 && resp.StatusCode() != 201 {
		return errors.New(resp.Status())
	}

	return nil
}

// RemoveUserRole removes a role assignment from a user.
func (c *GuardClient) RemoveUserRole(ctx context.Context, userID string, req UserRoleRequest) error {
	body := DeleteApiV1AuthAdminRbacUsersIdRolesJSONRequestBody{
		RoleId:   req.RoleID,
		TenantId: req.TenantID,
	}

	resp, err := c.inner.DeleteApiV1AuthAdminRbacUsersIdRolesWithResponse(ctx, userID, body)
	if err != nil {
		return err
	}

	if resp.StatusCode() != 200 && resp.StatusCode() != 204 {
		return errors.New(resp.Status())
	}

	return nil
}

// ResolveUserPermissions resolves all permissions granted to a user through their roles.
func (c *GuardClient) ResolveUserPermissions(ctx context.Context, userID, tenantID string) ([]Permission, error) {
	params := &GetApiV1AuthAdminRbacUsersIdPermissionsResolveParams{
		TenantId: tenantID,
	}

	resp, err := c.inner.GetApiV1AuthAdminRbacUsersIdPermissionsResolveWithResponse(ctx, userID, params)
	if err != nil {
		return nil, err
	}

	if resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}

	permissions := make([]Permission, 0)
	if resp.JSON200.Grants != nil {
		for _, grant := range *resp.JSON200.Grants {
			permission := Permission{}
			if grant.Key != nil {
				permission.Key = *grant.Key
			}
			permissions = append(permissions, permission)
		}
	}

	return permissions, nil
}

// === ALTERNATIVE BULK OPERATION METHODS (for developers preferring batch operations) ===

// ModifyUserRoles performs bulk role assignment operations on a user.
// This is an alternative to AddUserRole/RemoveUserRole for batch operations.
func (c *GuardClient) ModifyUserRoles(ctx context.Context, userID, tenantID string, roleIDs []string, action string) error {
	// action: "add" or "remove"
	if action != "add" && action != "remove" {
		return errors.New("action must be 'add' or 'remove'")
	}

	for _, roleID := range roleIDs {
		body := PostApiV1AuthAdminRbacUsersIdRolesJSONRequestBody{
			RoleId:   roleID,
			TenantId: tenantID,
		}

		if action == "add" {
			resp, err := c.inner.PostApiV1AuthAdminRbacUsersIdRolesWithResponse(ctx, userID, body)
			if err != nil {
				return err
			}
			if resp.StatusCode() != 200 && resp.StatusCode() != 201 {
				return errors.New(resp.Status())
			}
		} else {
			resp, err := c.inner.DeleteApiV1AuthAdminRbacUsersIdRolesWithResponse(ctx, userID, body)
			if err != nil {
				return err
			}
			if resp.StatusCode() != 200 && resp.StatusCode() != 204 {
				return errors.New(resp.Status())
			}
		}
	}

	return nil
}

// GetUserRoleObjects retrieves full role objects assigned to a user.
// This is an enhanced version of ListUserRoles that returns complete role details.
// Note: This fetches full role details by making additional GetRole calls.
func (c *GuardClient) GetUserRoleObjects(ctx context.Context, userID, tenantID string) ([]Role, error) {
	// First get the role IDs
	params := &GetApiV1AuthAdminRbacUsersIdRolesParams{
		TenantId: tenantID,
	}

	resp, err := c.inner.GetApiV1AuthAdminRbacUsersIdRolesWithResponse(ctx, userID, params)
	if err != nil {
		return nil, err
	}

	if resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}

	// Get all roles in the tenant
	roles, err := c.ListRoles(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	// Filter to only the roles assigned to this user
	roleMap := make(map[string]Role)
	for _, role := range roles {
		roleMap[role.ID] = role
	}

	result := make([]Role, 0)
	if resp.JSON200.RoleIds != nil {
		for _, roleID := range *resp.JSON200.RoleIds {
			if role, exists := roleMap[roleID]; exists {
				result = append(result, role)
			}
		}
	}

	return result, nil
}
