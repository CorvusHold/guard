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
	resp, err := c.inner.GetV1AuthAdminRbacPermissionsWithResponse(ctx)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}

	var permissions []Permission
	if resp.JSON200.Permissions != nil {
		for _, p := range *resp.JSON200.Permissions {
			perm := Permission{
				Key:  p.Key,
				Name: p.Name,
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

	params := &GetV1AuthAdminRbacRolesParams{TenantId: tenantID}
	resp, err := c.inner.GetV1AuthAdminRbacRolesWithResponse(ctx, params)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}

	var roles []Role
	if resp.JSON200.Roles != nil {
		for _, r := range *resp.JSON200.Roles {
			role := Role{
				ID:       r.Id,
				TenantID: r.TenantId,
				Name:     r.Name,
			}
			if r.Description != nil {
				role.Description = *r.Description
			}
			if r.IsSystem != nil {
				role.IsSystem = *r.IsSystem
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
	resp, err := c.inner.PostV1AuthAdminRbacRolesWithResponse(ctx, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON201 == nil && resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}

	// Handle both 201 Created and 200 OK responses
	var result *ControllerRbacRoleItem
	if resp.JSON201 != nil {
		result = resp.JSON201
	} else {
		result = resp.JSON200
	}

	role := &Role{
		ID:       result.Id,
		TenantID: result.TenantId,
		Name:     result.Name,
	}
	if result.Description != nil {
		role.Description = *result.Description
	}
	if result.IsSystem != nil {
		role.IsSystem = *result.IsSystem
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
		TenantId:    tenantID,
		Name:        req.Name,
		Description: req.Description,
	}
	resp, err := c.inner.PatchV1AuthAdminRbacRolesIdWithResponse(ctx, roleID, body)
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

	params := &DeleteV1AuthAdminRbacRolesIdParams{TenantId: tenantID}
	resp, err := c.inner.DeleteV1AuthAdminRbacRolesIdWithResponse(ctx, roleID, params)
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
	resp, err := c.inner.PostV1AuthAdminRbacRolesIdPermissionsWithResponse(ctx, roleID, body)
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
	resp, err := c.inner.DeleteV1AuthAdminRbacRolesIdPermissionsWithResponse(ctx, roleID, body)
	if err != nil {
		return err
	}
	if resp.HTTPResponse == nil || (resp.StatusCode() != http.StatusOK && resp.StatusCode() != http.StatusNoContent) {
		return errors.New(resp.Status())
	}
	return nil
}

// ListUserRoles retrieves all roles for a user in a tenant. Requires admin role.
func (c *GuardClient) ListUserRoles(ctx context.Context, userID, tenantID string) ([]Role, error) {
	if tenantID == "" {
		tenantID = c.tenantID
	}
	if tenantID == "" {
		return nil, errors.New("tenant ID required")
	}

	params := &GetV1AuthAdminRbacUsersUserIdRolesParams{TenantId: tenantID}
	resp, err := c.inner.GetV1AuthAdminRbacUsersUserIdRolesWithResponse(ctx, userID, params)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}

	var roles []Role
	if resp.JSON200.Roles != nil {
		for _, r := range *resp.JSON200.Roles {
			role := Role{
				ID:       r.Id,
				TenantID: r.TenantId,
				Name:     r.Name,
			}
			if r.Description != nil {
				role.Description = *r.Description
			}
			if r.IsSystem != nil {
				role.IsSystem = *r.IsSystem
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

// AddUserRole assigns a role to a user. Requires admin role.
func (c *GuardClient) AddUserRole(ctx context.Context, userID string, req UserRoleRequest) error {
	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = c.tenantID
	}
	if tenantID == "" {
		return errors.New("tenant ID required")
	}

	body := ControllerRbacModifyUserRoleReq{
		TenantId: tenantID,
		RoleId:   req.RoleID,
	}
	resp, err := c.inner.PostV1AuthAdminRbacUsersUserIdRolesWithResponse(ctx, userID, body)
	if err != nil {
		return err
	}
	if resp.HTTPResponse == nil || (resp.StatusCode() != http.StatusOK && resp.StatusCode() != http.StatusNoContent && resp.StatusCode() != http.StatusCreated) {
		return errors.New(resp.Status())
	}
	return nil
}

// RemoveUserRole removes a role from a user. Requires admin role.
func (c *GuardClient) RemoveUserRole(ctx context.Context, userID string, req UserRoleRequest) error {
	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = c.tenantID
	}
	if tenantID == "" {
		return errors.New("tenant ID required")
	}

	body := ControllerRbacModifyUserRoleReq{
		TenantId: tenantID,
		RoleId:   req.RoleID,
	}
	resp, err := c.inner.DeleteV1AuthAdminRbacUsersUserIdRolesWithResponse(ctx, userID, body)
	if err != nil {
		return err
	}
	if resp.HTTPResponse == nil || (resp.StatusCode() != http.StatusOK && resp.StatusCode() != http.StatusNoContent) {
		return errors.New(resp.Status())
	}
	return nil
}

// ResolveUserPermissions retrieves all resolved permissions for a user in a tenant.
// This includes permissions from all assigned roles. Requires admin role.
func (c *GuardClient) ResolveUserPermissions(ctx context.Context, userID, tenantID string) ([]Permission, error) {
	if tenantID == "" {
		tenantID = c.tenantID
	}
	if tenantID == "" {
		return nil, errors.New("tenant ID required")
	}

	params := &GetV1AuthAdminRbacUsersUserIdPermissionsResolveParams{TenantId: tenantID}
	resp, err := c.inner.GetV1AuthAdminRbacUsersUserIdPermissionsResolveWithResponse(ctx, userID, params)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}

	var permissions []Permission
	if resp.JSON200.Permissions != nil {
		for _, p := range *resp.JSON200.Permissions {
			perm := Permission{
				Key:  p.Key,
				Name: p.Name,
			}
			if p.Description != nil {
				perm.Description = *p.Description
			}
			permissions = append(permissions, perm)
		}
	}

	return permissions, nil
}
