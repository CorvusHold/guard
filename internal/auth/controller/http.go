package controller

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	domain "github.com/corvusHold/guard/internal/auth/domain"
	"github.com/corvusHold/guard/internal/config"
	evdomain "github.com/corvusHold/guard/internal/events/domain"
	"github.com/corvusHold/guard/internal/platform/ratelimit"
	"github.com/corvusHold/guard/internal/platform/validation"
	sdomain "github.com/corvusHold/guard/internal/settings/domain"
)

type Controller struct {
	svc   domain.Service
	magic domain.MagicLinkService
	sso   domain.SSOService
	// optional rate limit dependencies
	settings sdomain.Service
	rl       ratelimit.Store
	cfg      config.Config
	pub      evdomain.Publisher
}

// ---- Admin: RBAC v2 ----

// RBAC List Permissions godoc
// @Summary      List all permissions (admin-only)
// @Description  Returns all known permissions.
// @Tags         auth.admin
// @Security     BearerAuth
// @Produce      json
// @Success      200  {object}  rbacPermissionsResp
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Router       /v1/auth/admin/rbac/permissions [get]
func (h *Controller) rbacListPermissions(c echo.Context) error {
	tok := bearerToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}
	// require admin
	isAdmin := false
	for _, r := range in.Roles {
		if strings.EqualFold(r, "admin") {
			isAdmin = true
			break
		}
	}
	if !isAdmin {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
	}

	perms, err := h.svc.ListPermissions(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	out := make([]rbacPermissionItem, 0, len(perms))
	for _, p := range perms {
		out = append(out, rbacPermissionItem{ID: p.ID, Key: p.Key, Description: p.Description, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt})
	}
	return c.JSON(http.StatusOK, rbacPermissionsResp{Permissions: out})
}

// RBAC List Roles godoc
// @Summary      List roles for a tenant (admin-only)
// @Description  Returns all roles for the specified tenant.
// @Tags         auth.admin
// @Security     BearerAuth
// @Produce      json
// @Param        tenant_id  query  string  true  "Tenant ID (UUID)"
// @Success      200  {object}  rbacRolesResp
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Router       /v1/auth/admin/rbac/roles [get]
func (h *Controller) rbacListRoles(c echo.Context) error {
	tok := bearerToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}
	isAdmin := false
	for _, r := range in.Roles {
		if strings.EqualFold(r, "admin") {
			isAdmin = true
			break
		}
	}
	if !isAdmin {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
	}

	tenStr := c.QueryParam("tenant_id")
	if tenStr == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "tenant_id required"})
	}
	tenantID, err := uuid.Parse(tenStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
	}

	roles, err := h.svc.ListRoles(c.Request().Context(), tenantID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	out := make([]rbacRoleItem, 0, len(roles))
	for _, r := range roles {
		out = append(out, rbacRoleItem{ID: r.ID, TenantID: r.TenantID, Name: r.Name, Description: r.Description, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt})
	}
	return c.JSON(http.StatusOK, rbacRolesResp{Roles: out})
}

// RBAC Create Role godoc
// @Summary      Create role (admin-only)
// @Description  Creates a new role for the specified tenant.
// @Tags         auth.admin
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        body  body  rbacCreateRoleReq  true  "tenant_id, name, optional description"
// @Success      201   {object}  rbacRoleItem
// @Failure      400   {object}  map[string]string
// @Failure      401   {object}  map[string]string
// @Failure      403   {object}  map[string]string
// @Router       /v1/auth/admin/rbac/roles [post]
func (h *Controller) rbacCreateRole(c echo.Context) error {
	tok := bearerToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}
	isAdmin := false
	for _, r := range in.Roles {
		if strings.EqualFold(r, "admin") {
			isAdmin = true
			break
		}
	}
	if !isAdmin {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
	}

	var req rbacCreateRoleReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err))
	}
	tenantID, err := uuid.Parse(req.TenantID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
	}

	r, err := h.svc.CreateRole(c.Request().Context(), tenantID, req.Name, req.Description)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusCreated, rbacRoleItem{ID: r.ID, TenantID: r.TenantID, Name: r.Name, Description: r.Description, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt})
}

// RBAC Update Role godoc
// @Summary      Update role (admin-only)
// @Description  Updates a role's name/description in the specified tenant.
// @Tags         auth.admin
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        id    path   string            true  "Role ID (UUID)"
// @Param        body  body   rbacUpdateRoleReq true  "tenant_id, name, optional description"
// @Success      200   {object}  rbacRoleItem
// @Failure      400   {object}  map[string]string
// @Failure      401   {object}  map[string]string
// @Failure      403   {object}  map[string]string
// @Router       /v1/auth/admin/rbac/roles/{id} [patch]
func (h *Controller) rbacUpdateRole(c echo.Context) error {
	tok := bearerToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}
	isAdmin := false
	for _, r := range in.Roles {
		if strings.EqualFold(r, "admin") {
			isAdmin = true
			break
		}
	}
	if !isAdmin {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
	}

	roleIDStr := c.Param("id")
	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid role id"})
	}

	var req rbacUpdateRoleReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err))
	}
	tenantID, err := uuid.Parse(req.TenantID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
	}

	r, err := h.svc.UpdateRole(c.Request().Context(), roleID, tenantID, req.Name, req.Description)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, rbacRoleItem{ID: r.ID, TenantID: r.TenantID, Name: r.Name, Description: r.Description, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt})
}

// RBAC Delete Role godoc
// @Summary      Delete role (admin-only)
// @Description  Deletes a role for the specified tenant.
// @Tags         auth.admin
// @Security     BearerAuth
// @Param        id         path   string  true  "Role ID (UUID)"
// @Param        tenant_id  query  string  true  "Tenant ID (UUID)"
// @Success      204
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Router       /v1/auth/admin/rbac/roles/{id} [delete]
func (h *Controller) rbacDeleteRole(c echo.Context) error {
	tok := bearerToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}
	isAdmin := false
	for _, r := range in.Roles {
		if strings.EqualFold(r, "admin") {
			isAdmin = true
			break
		}
	}
	if !isAdmin {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
	}

	roleIDStr := c.Param("id")
	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid role id"})
	}
	tenStr := c.QueryParam("tenant_id")
	if tenStr == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "tenant_id required"})
	}
	tenantID, err := uuid.Parse(tenStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
	}

	if err := h.svc.DeleteRole(c.Request().Context(), roleID, tenantID); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.NoContent(http.StatusNoContent)
}

// RBAC List User Roles godoc
// @Summary      List role IDs assigned to a user (admin-only)
// @Description  Lists role assignments for a user within a tenant.
// @Tags         auth.admin
// @Security     BearerAuth
// @Produce      json
// @Param        id         path   string  true  "User ID (UUID)"
// @Param        tenant_id  query  string  true  "Tenant ID (UUID)"
// @Success      200  {object}  rbacUserRolesResp
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Router       /v1/auth/admin/rbac/users/{id}/roles [get]
func (h *Controller) rbacListUserRoles(c echo.Context) error {
	tok := bearerToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}
	isAdmin := false
	for _, r := range in.Roles {
		if strings.EqualFold(r, "admin") {
			isAdmin = true
			break
		}
	}
	if !isAdmin {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
	}

	userIDStr := c.Param("id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid user id"})
	}
	tenStr := c.QueryParam("tenant_id")
	if tenStr == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "tenant_id required"})
	}
	tenantID, err := uuid.Parse(tenStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
	}

	ids, err := h.svc.ListUserRoleIDs(c.Request().Context(), userID, tenantID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, rbacUserRolesResp{RoleIDs: ids})
}

// RBAC Add User Role godoc
// @Summary      Add a role to a user (admin-only)
// @Description  Adds a role assignment for a user within a tenant.
// @Tags         auth.admin
// @Security     BearerAuth
// @Accept       json
// @Param        id    path   string               true  "User ID (UUID)"
// @Param        body  body   rbacModifyUserRoleReq true  "tenant_id, role_id"
// @Success      204
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Router       /v1/auth/admin/rbac/users/{id}/roles [post]
func (h *Controller) rbacAddUserRole(c echo.Context) error {
	tok := bearerToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}
	isAdmin := false
	for _, r := range in.Roles {
		if strings.EqualFold(r, "admin") {
			isAdmin = true
			break
		}
	}
	if !isAdmin {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
	}

	userIDStr := c.Param("id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid user id"})
	}

	var req rbacModifyUserRoleReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err))
	}
	tenantID, err := uuid.Parse(req.TenantID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
	}
	roleID, err := uuid.Parse(req.RoleID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid role_id"})
	}

	if err := h.svc.AddUserRole(c.Request().Context(), userID, tenantID, roleID); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.NoContent(http.StatusNoContent)
}

// RBAC Remove User Role godoc
// @Summary      Remove a role from a user (admin-only)
// @Description  Removes a role assignment for a user within a tenant.
// @Tags         auth.admin
// @Security     BearerAuth
// @Accept       json
// @Param        id    path   string               true  "User ID (UUID)"
// @Param        body  body   rbacModifyUserRoleReq true  "tenant_id, role_id"
// @Success      204
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Router       /v1/auth/admin/rbac/users/{id}/roles [delete]
func (h *Controller) rbacRemoveUserRole(c echo.Context) error {
	tok := bearerToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}
	isAdmin := false
	for _, r := range in.Roles {
		if strings.EqualFold(r, "admin") {
			isAdmin = true
			break
		}
	}
	if !isAdmin {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
	}

	userIDStr := c.Param("id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid user id"})
	}

	var req rbacModifyUserRoleReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err))
	}
	tenantID, err := uuid.Parse(req.TenantID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
	}
	roleID, err := uuid.Parse(req.RoleID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid role_id"})
	}

	if err := h.svc.RemoveUserRole(c.Request().Context(), userID, tenantID, roleID); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.NoContent(http.StatusNoContent)
}

// RBAC Upsert Role Permission godoc
// @Summary      Grant/Update a permission to a role (admin-only)
// @Description  Upserts a permission grant for a role, optionally scoped to a resource.
// @Tags         auth.admin
// @Security     BearerAuth
// @Accept       json
// @Param        id    path   string                 true  "Role ID (UUID)"
// @Param        body  body   rbacRolePermissionReq  true  "permission_key, scope_type, optional resource_type/resource_id"
// @Success      204
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Router       /v1/auth/admin/rbac/roles/{id}/permissions [post]
func (h *Controller) rbacUpsertRolePermission(c echo.Context) error {
	tok := bearerToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}
	isAdmin := false
	for _, r := range in.Roles {
		if strings.EqualFold(r, "admin") {
			isAdmin = true
			break
		}
	}
	if !isAdmin {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
	}

	roleIDStr := c.Param("id")
	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid role id"})
	}

	var req rbacRolePermissionReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err))
	}
	var rt, rid *string
	if req.ResourceType != "" {
		rt = &req.ResourceType
	}
	if req.ResourceID != "" {
		rid = &req.ResourceID
	}

	if err := h.svc.UpsertRolePermission(c.Request().Context(), roleID, req.PermissionKey, req.ScopeType, rt, rid); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.NoContent(http.StatusNoContent)
}

// RBAC Delete Role Permission godoc
// @Summary      Delete a permission grant from a role (admin-only)
// @Description  Deletes a permission grant for a role, optionally scoped to a resource.
// @Tags         auth.admin
// @Security     BearerAuth
// @Accept       json
// @Param        id    path   string                 true  "Role ID (UUID)"
// @Param        body  body   rbacRolePermissionReq  true  "permission_key, scope_type, optional resource_type/resource_id"
// @Success      204
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Router       /v1/auth/admin/rbac/roles/{id}/permissions [delete]
func (h *Controller) rbacDeleteRolePermission(c echo.Context) error {
	tok := bearerToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}
	isAdmin := false
	for _, r := range in.Roles {
		if strings.EqualFold(r, "admin") {
			isAdmin = true
			break
		}
	}
	if !isAdmin {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
	}

	roleIDStr := c.Param("id")
	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid role id"})
	}

	var req rbacRolePermissionReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err))
	}
	var rt, rid *string
	if req.ResourceType != "" {
		rt = &req.ResourceType
	}
	if req.ResourceID != "" {
		rid = &req.ResourceID
	}

	if err := h.svc.DeleteRolePermission(c.Request().Context(), roleID, req.PermissionKey, req.ScopeType, rt, rid); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.NoContent(http.StatusNoContent)
}

// RBAC Resolve User Permissions godoc
// @Summary      Resolve user permissions (admin-only)
// @Description  Aggregates user permissions from roles and ACL for a tenant.
// @Tags         auth.admin
// @Security     BearerAuth
// @Produce      json
// @Param        id         path   string  true  "User ID (UUID)"
// @Param        tenant_id  query  string  true  "Tenant ID (UUID)"
// @Success      200  {object}  rbacResolvedPermissionsResp
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Router       /v1/auth/admin/rbac/users/{id}/permissions/resolve [get]
func (h *Controller) rbacResolveUserPermissions(c echo.Context) error {
	tok := bearerToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}
	isAdmin := false
	for _, r := range in.Roles {
		if strings.EqualFold(r, "admin") {
			isAdmin = true
			break
		}
	}
	if !isAdmin {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
	}

	userIDStr := c.Param("id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid user id"})
	}
	tenStr := c.QueryParam("tenant_id")
	if tenStr == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "tenant_id required"})
	}
	tenantID, err := uuid.Parse(tenStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
	}

	rp, err := h.svc.ResolveUserPermissions(c.Request().Context(), userID, tenantID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	out := make([]permissionGrantItem, 0, len(rp.Grants))
	for _, g := range rp.Grants {
		out = append(out, permissionGrantItem{Key: g.Key, ObjectType: g.ObjectType, ObjectID: g.ObjectID})
	}
	return c.JSON(http.StatusOK, rbacResolvedPermissionsResp{Grants: out})
}

// magicTokenForTest issues a magic link token without sending email. Test/CI only.
func (h *Controller) magicTokenForTest(c echo.Context) error {
	// Only allow in non-production environments
	if strings.EqualFold(h.cfg.AppEnv, "production") {
		return c.NoContent(http.StatusNotFound)
	}
	var req magicSendReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err))
	}
	tenID, err := uuid.Parse(req.TenantID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
	}
	tok, err := h.magic.CreateForTest(c.Request().Context(), domain.MagicSendInput{
		TenantID:    tenID,
		Email:       req.Email,
		RedirectURL: req.RedirectURL,
	})
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, magicTokenResp{Token: tok})
}

// New constructs controller with loaded config (backward compatible for tests).
func New(svc domain.Service, magic domain.MagicLinkService, sso domain.SSOService) *Controller {
	cfg, _ := config.Load()
	return NewWithConfig(svc, magic, sso, cfg)
}

// NewWithConfig allows passing explicit config.
func NewWithConfig(svc domain.Service, magic domain.MagicLinkService, sso domain.SSOService, cfg config.Config) *Controller {
	return &Controller{svc: svc, magic: magic, sso: sso, cfg: cfg}
}

// WithRateLimit enables tenant-aware, store-backed rate limiting when provided.
func (h *Controller) WithRateLimit(settings sdomain.Service, store ratelimit.Store) *Controller {
	h.settings = settings
	h.rl = store
	return h
}

// WithPublisher injects an audit event publisher for controller-level event emission.
func (h *Controller) WithPublisher(p evdomain.Publisher) *Controller { h.pub = p; return h }

// detectAuthMode checks the X-Auth-Mode header to determine if cookie mode is requested.
// Defaults to bearer if header is not present or invalid.
func detectAuthMode(c echo.Context) string {
	mode := strings.ToLower(strings.TrimSpace(c.Request().Header.Get("X-Auth-Mode")))
	if mode == "cookie" {
		return "cookie"
	}
	return "bearer"
}

// setTokenCookies sets HTTP-only secure cookies for access and refresh tokens.
func setTokenCookies(c echo.Context, accessToken, refreshToken string, cfg config.Config) {
	// Access token cookie (15 minutes default)
	accessMaxAge := int(cfg.AccessTokenTTL.Seconds())
	accessCookie := &http.Cookie{
		Name:     "guard_access_token",
		Value:    accessToken,
		Path:     "/",
		MaxAge:   accessMaxAge,
		HttpOnly: true,
		Secure:   c.Request().TLS != nil, // Only set Secure flag if using HTTPS
		SameSite: http.SameSiteStrictMode,
	}
	c.SetCookie(accessCookie)

	// Refresh token cookie (30 days default)
	refreshMaxAge := int(cfg.RefreshTokenTTL.Seconds())
	refreshCookie := &http.Cookie{
		Name:     "guard_refresh_token",
		Value:    refreshToken,
		Path:     "/",
		MaxAge:   refreshMaxAge,
		HttpOnly: true,
		Secure:   c.Request().TLS != nil,
		SameSite: http.SameSiteStrictMode,
	}
	c.SetCookie(refreshCookie)
}

// OAuth2Metadata godoc
// @Summary      OAuth 2.0 Authorization Server Metadata
// @Description  RFC 8414 compliant discovery endpoint that returns server metadata including supported authentication modes
// @Tags         auth
// @Produce      json
// @Success      200  {object}  oauth2MetadataResp
// @Router       /.well-known/oauth-authorization-server [get]
func (h *Controller) OAuth2Metadata(c echo.Context) error {
	baseURL := h.cfg.PublicBaseURL
	if baseURL == "" {
		// Fallback to constructing from request
		scheme := "https"
		if c.Request().TLS == nil {
			scheme = "http"
		}
		baseURL = scheme + "://" + c.Request().Host
	}

	resp := oauth2MetadataResp{
		Issuer:                baseURL,
		TokenEndpoint:         baseURL + "/v1/auth/refresh",
		IntrospectionEndpoint: baseURL + "/v1/auth/introspect",
		RevocationEndpoint:    baseURL + "/v1/auth/revoke",
		UserinfoEndpoint:      baseURL + "/v1/auth/me",
		ResponseTypesSupported: []string{
			"token", // Direct token response (password, magic link, SSO)
		},
		GrantTypesSupported: []string{
			"password",      // /v1/auth/password/login, /v1/auth/password/signup
			"refresh_token", // /v1/auth/refresh
			// Custom grant types
			"urn:guard:params:oauth:grant-type:magic-link", // /v1/auth/magic/verify
			"urn:guard:params:oauth:grant-type:sso",        // /v1/auth/sso/:provider/callback
		},
		TokenEndpointAuthMethodsSupported: []string{
			"none", // Public client, no client authentication required
		},
		IntrospectionEndpointAuthMethodsSupported: []string{
			"bearer", // Requires Bearer token in Authorization header
		},
		RevocationEndpointAuthMethodsSupported: []string{
			"bearer", // Requires Bearer token in Authorization header
		},
		ScopesSupported: []string{
			"openid",  // OpenID Connect compatible
			"profile", // User profile information
			"email",   // User email
		},
		// Guard-specific extensions
		GuardAuthModesSupported: []string{"bearer", "cookie"},
		GuardAuthModeDefault:    h.cfg.DefaultAuthMode,
		GuardVersion:            "1.0.0",
	}

	return c.JSON(http.StatusOK, resp)
}

// Register mounts all auth routes under /v1/auth with multi-method structure.
func (h *Controller) Register(e *echo.Echo) {
	// RFC 8414 OAuth 2.0 Authorization Server Metadata (well-known endpoint)
	e.GET("/.well-known/oauth-authorization-server", h.OAuth2Metadata)

	g := e.Group("/v1/auth")

	// Rate limits (fixed-window, per-tenant-or-IP)
	mkPolicy := func(prefix string, limKey, winKey string, defLim int, defWin time.Duration) ratelimit.Policy {
		p := ratelimit.Policy{Window: defWin, Limit: defLim, Key: ratelimit.KeyTenantOrIP(prefix)}
		p.Name = prefix
		if h.settings != nil {
			p.WindowFunc = func(c echo.Context) time.Duration {
				// extract tenant_id from query
				var tid *uuid.UUID
				if v := c.QueryParam("tenant_id"); v != "" {
					v = strings.TrimPrefix(v, "rl-")
					if id, err := uuid.Parse(v); err == nil {
						tid = &id
					}
				}
				d, _ := h.settings.GetDuration(c.Request().Context(), winKey, tid, defWin)
				return d
			}
			p.LimitFunc = func(c echo.Context) int {
				var tid *uuid.UUID
				if v := c.QueryParam("tenant_id"); v != "" {
					v = strings.TrimPrefix(v, "rl-")
					if id, err := uuid.Parse(v); err == nil {
						tid = &id
					}
				}
				n, _ := h.settings.GetInt(c.Request().Context(), limKey, tid, defLim)
				return n
			}
		}
		return p
	}
	mkMW := func(p ratelimit.Policy) echo.MiddlewareFunc {
		if h.rl != nil {
			return ratelimit.MiddlewareWithStore(p, h.rl)
		}
		return ratelimit.Middleware(p)
	}

	rlSignup := mkMW(mkPolicy("auth:signup", sdomain.KeyRLSignupLimit, sdomain.KeyRLSignupWindow, 2, time.Minute))
	rlLogin := mkMW(mkPolicy("auth:login", sdomain.KeyRLLoginLimit, sdomain.KeyRLLoginWindow, 2, time.Minute))
	rlMagic := mkMW(mkPolicy("auth:magic", sdomain.KeyRLMagicLimit, sdomain.KeyRLMagicWindow, 5, time.Minute))
	rlToken := mkMW(mkPolicy("auth:token", sdomain.KeyRLTokenLimit, sdomain.KeyRLTokenWindow, 10, time.Minute))
	rlMFA := mkMW(mkPolicy("auth:mfa", sdomain.KeyRLMFALimit, sdomain.KeyRLMFAWindow, 10, time.Minute))
	rlSSO := mkMW(mkPolicy("auth:sso", sdomain.KeyRLSsoLimit, sdomain.KeyRLSsoWindow, 10, time.Minute))

	// Password-based auth
	g.POST("/password/signup", h.signup, rlSignup)
	g.POST("/password/login", h.login, rlLogin)
	g.POST("/password/reset/request", h.resetPasswordRequest)
	g.POST("/password/reset/confirm", h.resetPasswordConfirm)

	// Magic-link auth
	g.POST("/magic/send", h.sendMagic, rlMagic)
	g.POST("/magic/verify", h.verifyMagic, rlMagic)
	g.GET("/magic/verify", h.verifyMagic, rlMagic)
	// Test-only: fetch raw magic token (only in non-production envs)
	g.POST("/magic/token", h.magicTokenForTest, rlMagic)

	// SSO / Social providers
	g.GET("/sso/:provider/start", h.ssoStart, rlSSO)
	g.GET("/sso/:provider/callback", h.ssoCallback, rlSSO)
	g.GET("/sso/:provider/portal-link", h.ssoOrganizationPortalLinkGenerator, rlSSO)

	// Email discovery for progressive login
	g.POST("/email/discover", h.emailDiscovery)

	// Token lifecycle
	g.POST("/refresh", h.refresh, rlToken)
	g.POST("/logout", h.logout, rlToken)
	g.GET("/me", h.me, rlToken)
	g.POST("/introspect", h.introspect, rlToken)
	g.POST("/revoke", h.revoke, rlToken)

	// Admin: user management
	g.POST("/admin/users/:id/roles", h.adminUpdateRoles, rlToken)
	g.GET("/admin/users", h.adminListUsers, rlToken)
	g.PATCH("/admin/users/:id", h.adminUpdateNames, rlToken)
	g.POST("/admin/users/:id/block", h.adminBlockUser, rlToken)
	g.POST("/admin/users/:id/unblock", h.adminUnblockUser, rlToken)
	// Admin: RBAC v2
	g.GET("/admin/rbac/permissions", h.rbacListPermissions, rlToken)
	g.GET("/admin/rbac/roles", h.rbacListRoles, rlToken)
	g.POST("/admin/rbac/roles", h.rbacCreateRole, rlToken)
	g.PATCH("/admin/rbac/roles/:id", h.rbacUpdateRole, rlToken)
	g.DELETE("/admin/rbac/roles/:id", h.rbacDeleteRole, rlToken)
	g.GET("/admin/rbac/users/:id/roles", h.rbacListUserRoles, rlToken)
	g.POST("/admin/rbac/users/:id/roles", h.rbacAddUserRole, rlToken)
	g.DELETE("/admin/rbac/users/:id/roles", h.rbacRemoveUserRole, rlToken)
	g.POST("/admin/rbac/roles/:id/permissions", h.rbacUpsertRolePermission, rlToken)
	g.DELETE("/admin/rbac/roles/:id/permissions", h.rbacDeleteRolePermission, rlToken)
	g.GET("/admin/rbac/users/:id/permissions/resolve", h.rbacResolveUserPermissions, rlToken)

	// Admin: FGA (groups, memberships, ACL tuples)
	g.POST("/admin/fga/groups", h.fgaCreateGroup, rlToken)
	g.GET("/admin/fga/groups", h.fgaListGroups, rlToken)
	g.DELETE("/admin/fga/groups/:id", h.fgaDeleteGroup, rlToken)
	g.POST("/admin/fga/groups/:id/members", h.fgaAddGroupMember, rlToken)
	g.DELETE("/admin/fga/groups/:id/members", h.fgaRemoveGroupMember, rlToken)
	g.POST("/admin/fga/acl/tuples", h.fgaCreateACLTuple, rlToken)
	g.DELETE("/admin/fga/acl/tuples", h.fgaDeleteACLTuple, rlToken)

	// Authorization decision
	g.POST("/authorize", h.fgaAuthorize, rlToken)

	// Sessions (self)
	g.GET("/sessions", h.sessionsList, rlToken)
	g.POST("/sessions/:id/revoke", h.sessionRevoke, rlToken)

	// MFA: TOTP + Backup codes
	g.POST("/mfa/totp/start", h.totpStart, rlMFA)
	g.POST("/mfa/totp/activate", h.totpActivate, rlMFA)
	g.POST("/mfa/totp/disable", h.totpDisable, rlMFA)
	g.POST("/mfa/backup/generate", h.backupGenerate, rlMFA)
	g.POST("/mfa/backup/consume", h.backupConsume, rlMFA)
	g.GET("/mfa/backup/count", h.backupCount, rlMFA)
	g.POST("/mfa/verify", h.verifyMFA, rlMFA)
}

type signupReq struct {
	TenantID  string `json:"tenant_id" validate:"required,uuid4"`
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required,min=8"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

type loginReq struct {
	TenantID string `json:"tenant_id" validate:"required,uuid4"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type refreshReq struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

type tokensResp struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// oauth2MetadataResp follows RFC 8414 OAuth 2.0 Authorization Server Metadata
type oauth2MetadataResp struct {
	Issuer                                    string   `json:"issuer"`
	TokenEndpoint                             string   `json:"token_endpoint,omitempty"`
	IntrospectionEndpoint                     string   `json:"introspection_endpoint,omitempty"`
	RevocationEndpoint                        string   `json:"revocation_endpoint,omitempty"`
	UserinfoEndpoint                          string   `json:"userinfo_endpoint,omitempty"`
	ResponseTypesSupported                    []string `json:"response_types_supported,omitempty"`
	GrantTypesSupported                       []string `json:"grant_types_supported,omitempty"`
	TokenEndpointAuthMethodsSupported         []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	RevocationEndpointAuthMethodsSupported    []string `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	ScopesSupported                           []string `json:"scopes_supported,omitempty"`
	// Guard-specific extensions
	GuardAuthModesSupported []string `json:"guard_auth_modes_supported,omitempty"`
	GuardAuthModeDefault    string   `json:"guard_auth_mode_default,omitempty"`
	GuardVersion            string   `json:"guard_version,omitempty"`
}

type introspectReq struct {
	Token string `json:"token" validate:"omitempty"`
}

type revokeReq struct {
	Token     string `json:"token" validate:"required"`
	TokenType string `json:"token_type" validate:"required"`
}

type magicSendReq struct {
	TenantID    string `json:"tenant_id" validate:"required,uuid4"`
	Email       string `json:"email" validate:"required,email"`
	RedirectURL string `json:"redirect_url" validate:"omitempty,url"`
}

type magicVerifyReq struct {
	Token string `json:"token" validate:"required"`
}

type magicTokenResp struct {
	Token string `json:"token"`
}

type mfaTOTPStartResp struct {
	Secret     string `json:"secret"`
	OtpauthURL string `json:"otpauth_url"`
}

type mfaTOTPActivateReq struct {
	Code string `json:"code" validate:"required"`
}

type mfaBackupGenerateReq struct {
	Count int `json:"count" validate:"omitempty,min=1,max=20"`
}

type mfaBackupGenerateResp struct {
	Codes []string `json:"codes"`
}

type mfaBackupConsumeReq struct {
	Code string `json:"code" validate:"required"`
}

type mfaBackupConsumeResp struct {
	Consumed bool `json:"consumed"`
}

type mfaBackupCountResp struct {
	Count int64 `json:"count"`
}

type mfaChallengeResp struct {
	ChallengeToken string   `json:"challenge_token"`
	Methods        []string `json:"methods"`
}

type mfaVerifyReq struct {
	ChallengeToken string `json:"challenge_token" validate:"required"`
	Code           string `json:"code" validate:"required"`
	Method         string `json:"method" validate:"required,oneof=totp backup_code"`
}

type resetPasswordRequestReq struct {
	TenantID string `json:"tenant_id" validate:"required,uuid4"`
	Email    string `json:"email" validate:"required,email"`
}

type resetPasswordConfirmReq struct {
	TenantID    string `json:"tenant_id" validate:"required,uuid4"`
	Token       string `json:"token" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=8"`
}

type adminUpdateRolesReq struct {
	Roles []string `json:"roles" validate:"required,dive,required"`
}

// Admin Users DTOs
type adminUser struct {
	ID            uuid.UUID  `json:"id"`
	EmailVerified bool       `json:"email_verified"`
	IsActive      bool       `json:"is_active"`
	FirstName     string     `json:"first_name"`
	LastName      string     `json:"last_name"`
	Roles         []string   `json:"roles"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	LastLoginAt   *time.Time `json:"last_login_at,omitempty"`
}

type adminUsersResp struct {
	Users []adminUser `json:"users"`
}

type adminUpdateNamesReq struct {
	FirstName string `json:"first_name" validate:"omitempty"`
	LastName  string `json:"last_name" validate:"omitempty"`
}

// --- RBAC v2 DTOs ---
type rbacPermissionItem struct {
	ID          uuid.UUID `json:"id"`
	Key         string    `json:"key"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type rbacPermissionsResp struct {
	Permissions []rbacPermissionItem `json:"permissions"`
}

type rbacRoleItem struct {
	ID          uuid.UUID `json:"id"`
	TenantID    uuid.UUID `json:"tenant_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type rbacRolesResp struct {
	Roles []rbacRoleItem `json:"roles"`
}

type rbacCreateRoleReq struct {
	TenantID    string `json:"tenant_id" validate:"required,uuid4"`
	Name        string `json:"name" validate:"required"`
	Description string `json:"description" validate:"omitempty"`
}

type rbacUpdateRoleReq struct {
	TenantID    string `json:"tenant_id" validate:"required,uuid4"`
	Name        string `json:"name" validate:"required"`
	Description string `json:"description" validate:"omitempty"`
}

type rbacUserRolesResp struct {
	RoleIDs []uuid.UUID `json:"role_ids"`
}

type rbacModifyUserRoleReq struct {
	TenantID string `json:"tenant_id" validate:"required,uuid4"`
	RoleID   string `json:"role_id" validate:"required,uuid4"`
}

type rbacRolePermissionReq struct {
	PermissionKey string `json:"permission_key" validate:"required"`
	ScopeType     string `json:"scope_type" validate:"required"`
	ResourceType  string `json:"resource_type" validate:"omitempty"`
	ResourceID    string `json:"resource_id" validate:"omitempty"`
}

type permissionGrantItem struct {
	Key        string  `json:"key"`
	ObjectType string  `json:"object_type"`
	ObjectID   *string `json:"object_id,omitempty"`
}

type rbacResolvedPermissionsResp struct {
	Grants []permissionGrantItem `json:"grants"`
}

// Sessions DTOs
type sessionItem struct {
	ID        uuid.UUID `json:"id"`
	Revoked   bool      `json:"revoked"`
	UserAgent string    `json:"user_agent"`
	IP        string    `json:"ip"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type sessionsListResp struct {
	Sessions []sessionItem `json:"sessions"`
}

func bearerToken(c echo.Context) string {
	h := c.Request().Header.Get("Authorization")
	if h == "" {
		return ""
	}
	parts := strings.SplitN(h, " ", 2)
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return parts[1]
	}
	return ""
}

// Signup godoc
// @Summary      Password signup
// @Description  Creates a new user for a tenant with email and password and returns access/refresh tokens
// @Tags         auth.password
// @Accept       json
// @Produce      json
// @Param        body  body  signupReq  true  "tenant_id, email, password, optional first/last name"
// @Success      201   {object}  tokensResp
// @Failure      400   {object}  map[string]string
// @Failure      429   {object}  map[string]string
// @Router       /v1/auth/password/signup [post]
func (h *Controller) signup(c echo.Context) error {
	var req signupReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err))
	}
	tenID, err := uuid.Parse(req.TenantID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
	}
	tok, err := h.svc.Signup(c.Request().Context(), domain.SignupInput{
		TenantID:  tenID,
		Email:     req.Email,
		Password:  req.Password,
		FirstName: req.FirstName,
		LastName:  req.LastName,
	})
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusCreated, tokensResp{AccessToken: tok.AccessToken, RefreshToken: tok.RefreshToken})
}

// Password Login godoc
// @Summary      Password login
// @Description  Logs in with email/password. If MFA is enabled for the user, responds 202 with a challenge to complete via /v1/auth/mfa/verify.
// @Tags         auth.password
// @Accept       json
// @Produce      json
// @Param        body  body  loginReq  true  "email/password"
// @Success      200   {object}  tokensResp
// @Success      202   {object}  mfaChallengeResp
// @Failure      400   {object}  map[string]string
// @Failure      401   {object}  map[string]string
// @Failure      429   {object}  map[string]string
// @Router       /v1/auth/password/login [post]
func (h *Controller) login(c echo.Context) error {
	var req loginReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err))
	}
	tenID, err := uuid.Parse(req.TenantID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
	}
	ua := c.Request().UserAgent()
	ip := c.RealIP()
	// Normalize email to lowercase and trim spaces to match DB lookup semantics
	email := strings.ToLower(strings.TrimSpace(req.Email))
	tok, err := h.svc.Login(c.Request().Context(), domain.LoginInput{
		TenantID:  tenID,
		Email:     email,
		Password:  req.Password,
		UserAgent: ua,
		IP:        ip,
	})
	if err != nil {
		var mfaErr domain.ErrMFARequired
		if errors.As(err, &mfaErr) {
			return c.JSON(http.StatusAccepted, mfaChallengeResp{ChallengeToken: mfaErr.ChallengeToken, Methods: mfaErr.Methods})
		}
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": err.Error()})
	}
	// Check auth mode and set cookies if requested
	authMode := detectAuthMode(c)
	if authMode == "cookie" {
		setTokenCookies(c, tok.AccessToken, tok.RefreshToken, h.cfg)
		// In cookie mode, return success without tokens in body
		return c.JSON(http.StatusOK, map[string]bool{"success": true})
	}
	return c.JSON(http.StatusOK, tokensResp{AccessToken: tok.AccessToken, RefreshToken: tok.RefreshToken})
}

// Refresh godoc
// @Summary      Refresh access token
// @Description  Exchanges a refresh token for new access and refresh tokens. When using cookie mode (`X-Auth-Mode: cookie`), the server will read `guard_refresh_token` from cookies if the body omits `refresh_token` and returns `{"success":true}` while setting new cookies.
// @Tags         auth.tokens
// @Accept       json
// @Produce      json
// @Param        body  body  refreshReq  true  "refresh_token"
// @Success      200   {object}  tokensResp
// @Failure      400   {object}  map[string]string
// @Failure      401   {object}  map[string]string
// @Failure      429   {object}  map[string]string
// @Router       /v1/auth/refresh [post]
func (h *Controller) refresh(c echo.Context) error {
	// Peek and restore body for debug logging
	var raw []byte
	if c.Request().Body != nil {
		if buf, err := io.ReadAll(c.Request().Body); err == nil {
			raw = buf
			c.Request().Body = io.NopCloser(bytes.NewReader(buf))
		}
	}
	if os.Getenv("AUTH_DEBUG") != "" || os.Getenv("RATELIMIT_DEBUG") != "" {
		if len(raw) > 0 {
			c.Logger().Debugf("refresh: raw body=%s", string(raw))
		} else {
			c.Logger().Debug("refresh: raw body=<empty>")
		}
		c.Logger().Debugf("refresh: tenant_id=%s", c.QueryParam("tenant_id"))
	}
	var req refreshReq
	if err := c.Bind(&req); err != nil {
		if os.Getenv("AUTH_DEBUG") != "" || os.Getenv("RATELIMIT_DEBUG") != "" {
			c.Logger().Warnf("refresh: bind error=%v body=%s", err, string(raw))
		}
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	ua := c.Request().UserAgent()
	ip := c.RealIP()
	authMode := detectAuthMode(c)
	if authMode != "cookie" || req.RefreshToken != "" {
		if err := c.Validate(&req); err != nil {
			if os.Getenv("AUTH_DEBUG") != "" || os.Getenv("RATELIMIT_DEBUG") != "" {
				c.Logger().Warnf("refresh: validation error=%v body=%s", err, string(raw))
			}
			return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err))
		}
	}
	// In cookie mode, try to get refresh token from cookie if not in body
	refreshToken := req.RefreshToken
	if authMode == "cookie" && refreshToken == "" {
		if cookie, err := c.Cookie("guard_refresh_token"); err == nil {
			refreshToken = cookie.Value
		}
	}
	tok, err := h.svc.Refresh(c.Request().Context(), domain.RefreshInput{RefreshToken: refreshToken, UserAgent: ua, IP: ip})
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": err.Error()})
	}
	// Check auth mode and set cookies if requested
	if authMode == "cookie" {
		setTokenCookies(c, tok.AccessToken, tok.RefreshToken, h.cfg)
		// In cookie mode, return success without tokens in body
		return c.JSON(http.StatusOK, map[string]bool{"success": true})
	}
	return c.JSON(http.StatusOK, tokensResp{AccessToken: tok.AccessToken, RefreshToken: tok.RefreshToken})
}

// Logout godoc
// @Summary      Logout (revoke refresh token)
// @Description  Revokes the provided refresh token if present; idempotent
// @Tags         auth.tokens
// @Accept       json
// @Param        body  body  refreshReq  false  "refresh_token (optional)"
// @Success      204
// @Failure      400  {object}  map[string]string
// @Failure      429  {object}  map[string]string
// @Router       /v1/auth/logout [post]
func (h *Controller) logout(c echo.Context) error {
	// Peek and restore body for debug logging
	var raw []byte
	if c.Request().Body != nil {
		if buf, err := io.ReadAll(c.Request().Body); err == nil {
			raw = buf
			c.Request().Body = io.NopCloser(bytes.NewReader(buf))
		}
	}
	if os.Getenv("AUTH_DEBUG") != "" || os.Getenv("RATELIMIT_DEBUG") != "" {
		if len(raw) > 0 {
			c.Logger().Debugf("logout: raw body=%s", string(raw))
		} else {
			c.Logger().Debug("logout: raw body=<empty>")
		}
		c.Logger().Debugf("logout: tenant_id=%s", c.QueryParam("tenant_id"))
	}
	var req refreshReq
	if err := c.Bind(&req); err != nil {
		if os.Getenv("AUTH_DEBUG") != "" || os.Getenv("RATELIMIT_DEBUG") != "" {
			c.Logger().Warnf("logout: bind error=%v body=%s", err, string(raw))
		}
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	// In cookie mode, try to get refresh token from cookie if not in body
	authMode := detectAuthMode(c)
	refreshToken := req.RefreshToken
	if authMode == "cookie" && refreshToken == "" {
		if cookie, err := c.Cookie("guard_refresh_token"); err == nil {
			refreshToken = cookie.Value
		}
	}
	if refreshToken == "" {
		// Clear cookies if in cookie mode
		if authMode == "cookie" {
			c.SetCookie(&http.Cookie{Name: "guard_access_token", Path: "/", MaxAge: -1})
			c.SetCookie(&http.Cookie{Name: "guard_refresh_token", Path: "/", MaxAge: -1})
		}
		return c.NoContent(http.StatusNoContent)
	}
	if err := h.svc.Logout(c.Request().Context(), refreshToken); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	// Clear cookies if in cookie mode
	if authMode == "cookie" {
		c.SetCookie(&http.Cookie{Name: "guard_access_token", Path: "/", MaxAge: -1})
		c.SetCookie(&http.Cookie{Name: "guard_refresh_token", Path: "/", MaxAge: -1})
	}
	return c.NoContent(http.StatusNoContent)
}

// Me godoc
// @Summary      Get current user's profile
// @Description  Returns the authenticated user's profile derived from the access token
// @Tags         auth.profile
// @Security     BearerAuth
// @Produce      json
// @Success      200  {object}  domain.UserProfile
// @Failure      401  {object}  map[string]string
// @Failure      429  {object}  map[string]string
// @Router       /v1/auth/me [get]
func (h *Controller) me(c echo.Context) error {
	// Try bearer token first, then cookie
	tok := bearerToken(c)
	if tok == "" {
		// Try to get from cookie
		if cookie, err := c.Cookie("guard_access_token"); err == nil {
			tok = cookie.Value
		}
	}
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing access token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}
	prof, err := h.svc.Me(c.Request().Context(), in.UserID, in.TenantID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, prof)
}

// // EmailDiscovery godoc
// // @Summary      Discover user/tenant by email
// // @Description  Check if an email exists in any tenant and provide guidance
// // @Tags         auth
// // @Accept       json
// // @Produce      json
// // @Param        request body EmailDiscoveryRequest true "Email to discover"
// // @Success      200  {object}  EmailDiscoveryResponse
// // @Failure      400  {object}  map[string]string
// // @Failure      500  {object}  map[string]string
// // @Router       /v1/auth/email/discover [post]
// func (h *Controller) emailDiscovery(c echo.Context) error {
// 	var req EmailDiscoveryRequest
// 	if err := c.Bind(&req); err != nil {
// 		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request"})
// 	}

// 	// Get tenant ID from header if provided
// 	tenantID := c.Request().Header.Get("X-Tenant-ID")

// 	var response EmailDiscoveryResponse

// 	if tenantID != "" {
// 		// Tenant is specified, check if user exists in this tenant
// 		_, err := h.svc.GetUserByEmail(c.Request().Context(), req.Email, tenantID)
// 		if err != nil {
// 			if strings.Contains(err.Error(), "not found") {
// 				// User doesn't exist in this tenant
// 				response = EmailDiscoveryResponse{
// 					Found:      false,
// 					HasTenant:  true,
// 					TenantID:   tenantID,
// 					UserExists: false,
// 				}
// 			} else {
// 				return c.JSON(http.StatusInternalServerError, map[string]string{"error": "internal server error"})
// 			}
// 		} else {
// 			// User exists in this tenant
// 			response = EmailDiscoveryResponse{
// 				Found:      true,
// 				HasTenant:  true,
// 				TenantID:   tenantID,
// 				UserExists: true,
// 			}
// 		}
// 	} else {
// 		// No tenant specified, discover which tenant(s) the user belongs to
// 		tenants, err := h.svc.FindTenantsByUserEmail(c.Request().Context(), req.Email)
// 		if err != nil {
// 			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "internal server error"})
// 		}

// 		if len(tenants) == 0 {
// 			// Email not found in any tenant
// 			response = EmailDiscoveryResponse{
// 				Found:       false,
// 				HasTenant:   false,
// 				UserExists:  false,
// 				Suggestions: generateEmailSuggestions(req.Email),
// 			}
// 		} else if len(tenants) == 1 {
// 			// Email found in exactly one tenant
// 			tenant := tenants[0]
// 			response = EmailDiscoveryResponse{
// 				Found:      true,
// 				HasTenant:  true,
// 				TenantID:   tenant.ID,
// 				TenantName: tenant.Name,
// 				UserExists: true,
// 			}
// 		} else {
// 			// Email found in multiple tenants - return first one with suggestions
// 			tenant := tenants[0]
// 			var suggestions []string
// 			for _, t := range tenants {
// 				suggestions = append(suggestions, t.Name)
// 			}

// 			response = EmailDiscoveryResponse{
// 				Found:       true,
// 				HasTenant:   true,
// 				TenantID:    tenant.ID,
// 				TenantName:  tenant.Name,
// 				UserExists:  true,
// 				Suggestions: suggestions,
// 			}
// 		}
// 	}

// 	return c.JSON(http.StatusOK, response)
// }

// generateEmailSuggestions generates helpful suggestions for email typos
func generateEmailSuggestions(email string) []string {
	// Common email domain typos and suggestions
	commonDomains := []string{
		"gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
		"icloud.com", "protonmail.com",
	}

	// Extract domain from email
	atIndex := strings.LastIndex(email, "@")
	if atIndex == -1 {
		return nil // No @ found
	}

	localPart := email[:atIndex]
	domain := email[atIndex+1:]

	var suggestions []string

	// Suggest common domains if current domain is uncommon or potentially misspelled
	for _, commonDomain := range commonDomains {
		if domain != commonDomain {
			suggestions = append(suggestions, localPart+"@"+commonDomain)
		}
	}

	// Limit suggestions
	if len(suggestions) > 3 {
		suggestions = suggestions[:3]
	}

	return suggestions
}

// Introspect godoc
// @Summary      Introspect access token
// @Description  Validate and parse JWT token either from Authorization header or request body
// @Tags         auth.introspect
// @Accept       json
// @Produce      json
// @Param        token  body      introspectReq  false  "Token in body; otherwise uses Authorization Bearer"
// @Success      200    {object}  domain.Introspection
// @Failure      400    {object}  map[string]string
// @Failure      401    {object}  map[string]string
// @Failure      429    {object}  map[string]string
// @Router       /v1/auth/introspect [post]
func (h *Controller) introspect(c echo.Context) error {
	var req introspectReq
	_ = c.Bind(&req) // optional body
	tok := req.Token
	if tok == "" {
		tok = bearerToken(c)
	}
	if tok == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "token required"})
	}
	out, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil {
		// return inactive with error message for clarity
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, out)
}

// Revoke godoc
// @Summary      Revoke token
// @Description  Revoke a token; currently supports token_type="refresh"
// @Tags         auth.tokens
// @Accept       json
// @Param        body  body  revokeReq  true  "token and token_type=refresh"
// @Success      204
// @Failure      400  {object}  map[string]string
// @Failure      429  {object}  map[string]string
// @Router       /v1/auth/revoke [post]
func (h *Controller) revoke(c echo.Context) error {
	var req revokeReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err))
	}
	if err := h.svc.Revoke(c.Request().Context(), req.Token, req.TokenType); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.NoContent(http.StatusNoContent)
}

// Admin Update Roles godoc
// @Summary      Update a user's roles (admin-only)
// @Description  Updates the roles array for a user. Requires caller to have the admin role.
// @Tags         auth.admin
// @Security     BearerAuth
// @Accept       json
// @Param        id    path   string                 true  "User ID (UUID)"
// @Param        body  body   adminUpdateRolesReq    true  "roles"
// @Success      204
// @Failure      400   {object}  map[string]string
// @Failure      401   {object}  map[string]string
// @Failure      403   {object}  map[string]string
// @Failure      429   {object}  map[string]string
// @Router       /v1/auth/admin/users/{id}/roles [post]
func (h *Controller) adminUpdateRoles(c echo.Context) error {
	tok := bearerToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}
	// RBAC: require admin role
	isAdmin := false
	for _, r := range in.Roles {
		if strings.EqualFold(r, "admin") {
			isAdmin = true
			break
		}
	}
	if !isAdmin {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
	}

	userIDStr := c.Param("id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid user id"})
	}

	var req adminUpdateRolesReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err))
	}
	// Explicitly reject empty roles array (tests use a noop validator, so enforce here)
	if len(req.Roles) == 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "roles must not be empty"})
	}

	if err := h.svc.UpdateUserRoles(c.Request().Context(), userID, req.Roles); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.NoContent(http.StatusNoContent)
}

// Admin List Users godoc
// @Summary      List users for a tenant (admin-only)
// @Description  Lists all users that belong to the specified tenant. Requires caller to have the admin role.
// @Tags         auth.admin
// @Security     BearerAuth
// @Produce      json
// @Param        tenant_id  query  string  true  "Tenant ID (UUID)"
// @Success      200  {object}  adminUsersResp
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Failure      429  {object}  map[string]string
// @Router       /v1/auth/admin/users [get]
func (h *Controller) adminListUsers(c echo.Context) error {
	tok := bearerToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}
	// RBAC: require admin role
	isAdmin := false
	for _, r := range in.Roles {
		if strings.EqualFold(r, "admin") {
			isAdmin = true
			break
		}
	}
	if !isAdmin {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
	}

	tenStr := c.QueryParam("tenant_id")
	if tenStr == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "tenant_id required"})
	}
	tenantID, err := uuid.Parse(tenStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
	}

	users, err := h.svc.ListTenantUsers(c.Request().Context(), tenantID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	out := make([]adminUser, 0, len(users))
	for _, u := range users {
		out = append(out, adminUser{
			ID:            u.ID,
			EmailVerified: u.EmailVerified,
			IsActive:      u.IsActive,
			FirstName:     u.FirstName,
			LastName:      u.LastName,
			Roles:         u.Roles,
			CreatedAt:     u.CreatedAt,
			UpdatedAt:     u.UpdatedAt,
			LastLoginAt:   u.LastLoginAt,
		})
	}
	return c.JSON(http.StatusOK, adminUsersResp{Users: out})
}

// Admin Update Names godoc
// @Summary      Update a user's names (admin-only)
// @Description  Updates first and/or last name for a user. Requires caller to have the admin role.
// @Tags         auth.admin
// @Security     BearerAuth
// @Accept       json
// @Param        id    path   string               true  "User ID (UUID)"
// @Param        body  body   adminUpdateNamesReq  true  "first_name, last_name"
// @Success      204
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Failure      429  {object}  map[string]string
// @Router       /v1/auth/admin/users/{id} [patch]
func (h *Controller) adminUpdateNames(c echo.Context) error {
	tok := bearerToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}
	// RBAC: require admin role
	isAdmin := false
	for _, r := range in.Roles {
		if strings.EqualFold(r, "admin") {
			isAdmin = true
			break
		}
	}
	if !isAdmin {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
	}

	userIDStr := c.Param("id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid user id"})
	}

	var req adminUpdateNamesReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err))
	}

	if err := h.svc.UpdateUserNames(c.Request().Context(), userID, req.FirstName, req.LastName); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.NoContent(http.StatusNoContent)
}

// Admin Block User godoc
// @Summary      Block a user (admin-only)
// @Description  Sets a user's active status to false. Requires caller to have the admin role.
// @Tags         auth.admin
// @Security     BearerAuth
// @Param        id   path   string  true  "User ID (UUID)"
// @Success      204
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Failure      429  {object}  map[string]string
// @Router       /v1/auth/admin/users/{id}/block [post]
func (h *Controller) adminBlockUser(c echo.Context) error {
	tok := bearerToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}
	// RBAC: require admin role
	isAdmin := false
	for _, r := range in.Roles {
		if strings.EqualFold(r, "admin") {
			isAdmin = true
			break
		}
	}
	if !isAdmin {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
	}

	userIDStr := c.Param("id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid user id"})
	}

	if err := h.svc.SetUserActive(c.Request().Context(), userID, false); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.NoContent(http.StatusNoContent)
}

// Admin Unblock User godoc
// @Summary      Unblock a user (admin-only)
// @Description  Sets a user's active status to true. Requires caller to have the admin role.
// @Tags         auth.admin
// @Security     BearerAuth
// @Param        id   path   string  true  "User ID (UUID)"
// @Success      204
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Failure      429  {object}  map[string]string
// @Router       /v1/auth/admin/users/{id}/unblock [post]
func (h *Controller) adminUnblockUser(c echo.Context) error {
	tok := bearerToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}
	// RBAC: require admin role
	isAdmin := false
	for _, r := range in.Roles {
		if strings.EqualFold(r, "admin") {
			isAdmin = true
			break
		}
	}
	if !isAdmin {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
	}

	userIDStr := c.Param("id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid user id"})
	}

	if err := h.svc.SetUserActive(c.Request().Context(), userID, true); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.NoContent(http.StatusNoContent)
}

// Sessions List godoc
// @Summary      List my active sessions
// @Description  Lists the authenticated user's sessions (refresh tokens) for the current tenant.
// @Tags         auth.sessions
// @Security     BearerAuth
// @Produce      json
// @Success      200  {object}  sessionsListResp
// @Failure      401  {object}  map[string]string
// @Failure      429  {object}  map[string]string
// @Router       /v1/auth/sessions [get]
func (h *Controller) sessionsList(c echo.Context) error {
	tok := bearerToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}

	sessions, err := h.svc.ListUserSessions(c.Request().Context(), in.UserID, in.TenantID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	out := make([]sessionItem, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, sessionItem{
			ID:        s.ID,
			Revoked:   s.Revoked,
			UserAgent: s.UserAgent,
			IP:        s.IP,
			CreatedAt: s.CreatedAt,
			ExpiresAt: s.ExpiresAt,
		})
	}
	return c.JSON(http.StatusOK, sessionsListResp{Sessions: out})
}

// Session Revoke godoc
// @Summary      Revoke a specific session
// @Description  Revokes a specific session by ID for the authenticated user within the current tenant.
// @Tags         auth.sessions
// @Security     BearerAuth
// @Param        id   path   string  true  "Session ID (UUID)"
// @Success      204
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      429  {object}  map[string]string
// @Router       /v1/auth/sessions/{id}/revoke [post]
func (h *Controller) sessionRevoke(c echo.Context) error {
	tok := bearerToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}

	sidStr := c.Param("id")
	sid, err := uuid.Parse(sidStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid session id"})
	}

	if err := h.svc.RevokeSession(c.Request().Context(), in.UserID, in.TenantID, sid); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.NoContent(http.StatusNoContent)
}

// ---- Password reset (stubs) ----
// Password Reset Request godoc
// @Summary      Request password reset
// @Description  Requests a password reset for the given email address
// @Tags         auth.password
// @Accept       json
// @Produce      json
// @Param        body  body  resetPasswordRequestReq  true  "tenant_id, email"
// @Success      202
// @Failure      400  {object}  map[string]string
// @Failure      429  {object}  map[string]string
// @Router       /v1/auth/password/reset/request [post]
func (h *Controller) resetPasswordRequest(c echo.Context) error {
	var req resetPasswordRequestReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err))
	}
	// Stub: endpoint contract established; implementation pending
	return c.NoContent(http.StatusAccepted)
}

// Password Reset Confirm godoc
// @Summary      Confirm password reset
// @Description  Resets the password for the given email address
// @Tags         auth.password
// @Accept       json
// @Produce      json
// @Param        body  body  resetPasswordConfirmReq  true  "tenant_id, token, new_password"
// @Success      200
// @Failure      400  {object}  map[string]string
// @Failure      429  {object}  map[string]string
// @Router       /v1/auth/password/reset/confirm [post]
func (h *Controller) resetPasswordConfirm(c echo.Context) error {
	var req resetPasswordConfirmReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err))
	}
	// Stub: endpoint contract established; implementation pending
	return c.NoContent(http.StatusOK)
}

// ---- Magic link ----
// Magic Send godoc
// @Summary      Send magic login link
// @Description  Sends a single-use magic login link to the user's email
// @Tags         auth.magic
// @Accept       json
// @Param        body  body  magicSendReq  true  "tenant_id, email, optional redirect_url"
// @Success      202
// @Failure      400  {object}  map[string]string
// @Failure      429  {object}  map[string]string
// @Router       /v1/auth/magic/send [post]
func (h *Controller) sendMagic(c echo.Context) error {
	var req magicSendReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err))
	}
	tenID, err := uuid.Parse(req.TenantID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
	}
	if err := h.magic.Send(c.Request().Context(), domain.MagicSendInput{
		TenantID:    tenID,
		Email:       req.Email,
		RedirectURL: req.RedirectURL,
	}); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.NoContent(http.StatusAccepted)
}

// Magic Verify godoc
// @Summary      Verify magic link token
// @Description  Verifies magic link token from query parameter or request body and returns tokens
// @Tags         auth.magic
// @Accept       json
// @Produce      json
// @Param        token  query  string        false  "Magic token (alternative to body)"
// @Param        body   body   magicVerifyReq  false  "Magic token in JSON body"
// @Success      200    {object}  tokensResp
// @Failure      400    {object}  map[string]string
// @Failure      401    {object}  map[string]string
// @Failure      429    {object}  map[string]string
// @Router       /v1/auth/magic/verify [get]
// @Router       /v1/auth/magic/verify [post]
func (h *Controller) verifyMagic(c echo.Context) error {
	// accept ?token=... or JSON body
	token := c.QueryParam("token")
	if token == "" {
		var req magicVerifyReq
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
		}
		if err := c.Validate(&req); err != nil {
			return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err))
		}
		token = req.Token
	}
	ua := c.Request().UserAgent()
	ip := c.RealIP()
	toks, err := h.magic.Verify(c.Request().Context(), domain.MagicVerifyInput{Token: token, UserAgent: ua, IP: ip})
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, tokensResp{AccessToken: toks.AccessToken, RefreshToken: toks.RefreshToken})
}

// ---- SSO/Social (stubs) ----
var allowedProviders = map[string]struct{}{
	"google":  {},
	"github":  {},
	"azuread": {},
	"workos":  {},
}

var allowedSSOOrganizationPortalIntents = map[string]struct{}{
	// FROM WorkOS requirement
	"sso":                 {},
	"dsync":               {},
	"audit_logs":          {},
	"log_streams":         {},
	"domain_verification": {},
	"certificate_renewal": {},

	//Corvus custom intents
	"user_management": {},
}

// SSO Start godoc
// @Summary      Start SSO/OAuth flow
// @Description  Initiates an SSO flow for the given provider and redirects to the provider authorization URL
// @Tags         auth.sso
// @Param        provider         path      string  true   "SSO provider (google, github, azuread, workos)"
// @Param        tenant_id        query     string  true   "Tenant ID (UUID)"
// @Param        redirect_url     query     string  false  "Absolute redirect URL after callback"
// @Param        state            query     string  false  "Opaque state to round-trip"
// @Param        connection_id    query     string  false  "Provider connection identifier"
// @Param        organization_id  query     string  false  "Organization identifier"
// @Success      302
// @Failure      400  {object}  map[string]string
// @Router       /v1/auth/sso/{provider}/start [get]
func (h *Controller) ssoStart(c echo.Context) error {
	p := c.Param("provider")
	if _, ok := allowedProviders[p]; !ok {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "unsupported provider"})
	}
	// Query: tenant_id, redirect_url, state(optional), connection_id(optional), organization_id(optional)
	tenIDStr := c.QueryParam("tenant_id")
	redir := c.QueryParam("redirect_url")
	state := c.QueryParam("state")
	connID := c.QueryParam("connection_id")
	orgID := c.QueryParam("organization_id")
	// Ensure redirect is absolute if provided
	if redir != "" {
		if _, err := url.ParseRequestURI(redir); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid redirect_url"})
		}
	}
	tenID, err := uuid.Parse(tenIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
	}
	authURL, err := h.sso.Start(c.Request().Context(), domain.SSOStartInput{Provider: p, TenantID: tenID, RedirectURL: redir, State: state, ConnectionID: connID, OrganizationID: orgID})
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.Redirect(http.StatusFound, authURL)
}

// SSO Callback godoc
// @Summary      Handle SSO/OAuth callback
// @Description  Completes SSO flow and returns access/refresh tokens
// @Tags         auth.sso
// @Param        provider  path   string  true  "SSO provider (google, github, azuread)"
// @Produce      json
// @Success      200  {object}  tokensResp
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Router       /v1/auth/sso/{provider}/callback [get]
func (h *Controller) ssoCallback(c echo.Context) error {
	p := c.Param("provider")
	if _, ok := allowedProviders[p]; !ok {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "unsupported provider"})
	}
	toks, err := h.sso.Callback(c.Request().Context(), domain.SSOCallbackInput{Provider: p, Query: c.QueryParams(), UserAgent: c.Request().UserAgent(), IP: c.RealIP()})
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, tokensResp{AccessToken: toks.AccessToken, RefreshToken: toks.RefreshToken})
}

// SSO Organization Portal Link Generator godoc
// @Summary      Generate organization portal link
// @Description  Generates a link to the organization portal for the given provider and organization ID (admin-only)
// @Tags         auth.sso
// @Security     BearerAuth
// @Param        provider  path   string  true  "SSO provider (workos)"
// @Param        organization_id  query   string  true  "Organization identifier"
// @Param        tenant_id  query   string  true  "Tenant ID (UUID)"
// @Param        intent  query   string  false  "Intent (sso, dsync, audit_logs, log_streams, domain_verification, certificate_renewal, user_management)"
// @Success      200  {object}  domain.PortalLink
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Failure      429  {object}  map[string]string
// @Router       /v1/auth/sso/{provider}/portal-link [get]
func (h *Controller) ssoOrganizationPortalLinkGenerator(c echo.Context) error {
	p := c.Param("provider")
	if _, ok := allowedProviders[p]; !ok {
		c.Logger().Errorf("sso.portal_link: unsupported provider p=%s ip=%s ua=%s", p, c.RealIP(), c.Request().UserAgent())
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "unsupported provider"})
	}
	// TEMPORARY: only workos supported
	if p != "workos" {
		c.Logger().Errorf("sso.portal_link: only workos supported p=%s ip=%s ua=%s", p, c.RealIP(), c.Request().UserAgent())
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "only workos supported"})
	}
	ua := c.Request().UserAgent()
	ip := c.RealIP()
	// RBAC: admin only
	tok := bearerToken(c)
	if tok == "" {
		c.Logger().Errorf("sso.portal_link: missing bearer token ip=%s ua=%s", ip, ua)
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	inTok, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !inTok.Active {
		c.Logger().Errorf("sso.portal_link: invalid token ip=%s ua=%s err=%v", ip, ua, err)
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}
	isAdmin := false
	for _, r := range inTok.Roles {
		if strings.EqualFold(r, "admin") {
			isAdmin = true
			break
		}
	}
	if !isAdmin {
		c.Logger().Errorf("sso.portal_link: forbidden (non-admin) tenant_id=%s user_id=%s ip=%s ua=%s", inTok.TenantID.String(), inTok.UserID.String(), ip, ua)
		return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
	}

	// Validate inputs
	tenIDStr := c.QueryParam("tenant_id")
	tenID, err := uuid.Parse(tenIDStr)
	if err != nil {
		c.Logger().Errorf("sso.portal_link: invalid tenant_id tenant_id_q=%s user_id=%s ip=%s ua=%s", tenIDStr, inTok.UserID.String(), ip, ua)
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
	}
	// Optional: ensure admin acts within same tenant
	if inTok.TenantID != tenID {
		c.Logger().Errorf("sso.portal_link: forbidden (tenant mismatch) token_tenant=%s tenant_id_q=%s user_id=%s ip=%s ua=%s", inTok.TenantID.String(), tenIDStr, inTok.UserID.String(), ip, ua)
		return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
	}
	orgID := c.QueryParam("organization_id")
	if orgID == "" {
		c.Logger().Errorf("sso.portal_link: organization_id required tenant_id=%s user_id=%s ip=%s ua=%s", tenID.String(), inTok.UserID.String(), ip, ua)
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "organization_id required"})
	}
	intentStr := strings.TrimSpace(c.QueryParam("intent"))
	if intentStr != "" {
		if _, ok := allowedSSOOrganizationPortalIntents[intentStr]; !ok {
			c.Logger().Errorf("sso.portal_link: unsupported intent tenant_id=%s org_id=%s intent=%s user_id=%s ip=%s ua=%s", tenID.String(), orgID, intentStr, inTok.UserID.String(), ip, ua)
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "unsupported intent"})
		}
	}
	c.Logger().Infof("sso.portal_link: generating tenant_id=%s org_id=%s intent=%s user_id=%s ip=%s ua=%s", tenID.String(), orgID, intentStr, inTok.UserID.String(), ip, ua)
	link, err := h.sso.OrganizationPortalLinkGenerator(c.Request().Context(), domain.SSOOrganizationPortalLinkGeneratorInput{Provider: p, OrganizationID: orgID, TenantID: tenID, Intent: intentStr})
	if err != nil {
		c.Logger().Errorf("sso.portal_link: generation failed tenant_id=%s org_id=%s intent=%s user_id=%s ip=%s ua=%s err=%v", tenID.String(), orgID, intentStr, inTok.UserID.String(), ip, ua, err)
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	c.Logger().Infof("sso.portal_link: success tenant_id=%s org_id=%s intent=%s user_id=%s ip=%s ua=%s", tenID.String(), orgID, intentStr, inTok.UserID.String(), ip, ua)
	return c.JSON(http.StatusOK, link)
}

// ---- MFA: TOTP ----

// TOTP Start godoc
// @Summary      Start TOTP enrollment
// @Description  Generates and stores a TOTP secret (disabled) and returns the secret and otpauth URL
// @Tags         auth.mfa.totp
// @Security     BearerAuth
// @Produce      json
// @Success      200  {object}  mfaTOTPStartResp
// @Failure      401  {object}  map[string]string
// @Router       /v1/auth/mfa/totp/start [post]
func (h *Controller) totpStart(c echo.Context) error {
	tok := bearerToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}
	secret, url, err := h.svc.StartTOTPEnrollment(c.Request().Context(), in.UserID, in.TenantID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, mfaTOTPStartResp{Secret: secret, OtpauthURL: url})
}

// TOTP Activate godoc
// @Summary      Activate TOTP
// @Description  Verifies a TOTP code for the stored secret and enables MFA
// @Tags         auth.mfa.totp
// @Security     BearerAuth
// @Accept       json
// @Param        body  body  mfaTOTPActivateReq  true  "TOTP code"
// @Success      204
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      429  {object}  map[string]string
// @Router       /v1/auth/mfa/totp/activate [post]
func (h *Controller) totpActivate(c echo.Context) error {
	var req mfaTOTPActivateReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err))
	}
	tok := bearerToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}
	if err := h.svc.ActivateTOTP(c.Request().Context(), in.UserID, req.Code); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.NoContent(http.StatusNoContent)
}

// TOTP Disable godoc
// @Summary      Disable TOTP
// @Description  Disables TOTP for the user
// @Tags         auth.mfa.totp
// @Security     BearerAuth
// @Success      204
// @Failure      401  {object}  map[string]string
// @Failure      429  {object}  map[string]string
// @Router       /v1/auth/mfa/totp/disable [post]
func (h *Controller) totpDisable(c echo.Context) error {
	tok := bearerToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}
	if err := h.svc.DisableTOTP(c.Request().Context(), in.UserID); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.NoContent(http.StatusNoContent)
}

// ---- MFA: Backup Codes ----

// Backup Generate godoc
// @Summary      Generate MFA backup codes
// @Description  Generates backup codes, stores their hashes, and returns the codes
// @Tags         auth.mfa.backup
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        body  body  mfaBackupGenerateReq  false  "count (default 10, max 20)"
// @Success      200  {object}  mfaBackupGenerateResp
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      429  {object}  map[string]string
// @Router       /v1/auth/mfa/backup/generate [post]
func (h *Controller) backupGenerate(c echo.Context) error {
	var req mfaBackupGenerateReq
	_ = c.Bind(&req) // optional body
	if req.Count == 0 {
		req.Count = 10
	}
	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err))
	}
	tok := bearerToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}
	codes, err := h.svc.GenerateBackupCodes(c.Request().Context(), in.UserID, req.Count)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, mfaBackupGenerateResp{Codes: codes})
}

// Backup Consume godoc
// @Summary      Consume an MFA backup code
// @Description  Consumes a single-use backup code
// @Tags         auth.mfa.backup
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        body  body  mfaBackupConsumeReq  true  "backup code"
// @Success      200  {object}  mfaBackupConsumeResp
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      429  {object}  map[string]string
// @Router       /v1/auth/mfa/backup/consume [post]
func (h *Controller) backupConsume(c echo.Context) error {
	var req mfaBackupConsumeReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err))
	}
	tok := bearerToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}
	ok, err := h.svc.ConsumeBackupCode(c.Request().Context(), in.UserID, req.Code)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, mfaBackupConsumeResp{Consumed: ok})
}

// Backup Count godoc
// @Summary      Count remaining MFA backup codes
// @Description  Returns number of unused backup codes
// @Tags         auth.mfa.backup
// @Security     BearerAuth
// @Produce      json
// @Success      200  {object}  mfaBackupCountResp
// @Failure      401  {object}  map[string]string
// @Failure      429  {object}  map[string]string
// @Router       /v1/auth/mfa/backup/count [get]
func (h *Controller) backupCount(c echo.Context) error {
	tok := bearerToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}
	n, err := h.svc.CountRemainingBackupCodes(c.Request().Context(), in.UserID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, mfaBackupCountResp{Count: n})
}

// ---- MFA: Challenge Verify ----

// Verify MFA godoc
// @Summary      Verify MFA challenge
// @Description  Verifies a TOTP or backup code against a challenge token and returns access/refresh tokens.
// @Tags         auth.mfa
// @Accept       json
// @Produce      json
// @Param        body  body  mfaVerifyReq  true  "challenge_token, method, and code"
// @Success      200   {object}  tokensResp
// @Failure      400   {object}  map[string]string
// @Failure      401   {object}  map[string]string
// @Failure      429   {object}  map[string]string
// @Router       /v1/auth/mfa/verify [post]
func (h *Controller) verifyMFA(c echo.Context) error {
	var req mfaVerifyReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err))
	}
	ua := c.Request().UserAgent()
	ip := c.RealIP()
	// Optional debug log to confirm handler execution and tenant key context
	if os.Getenv("RATELIMIT_DEBUG") != "" {
		c.Logger().Infof("verifyMFA entered: tenant_id_q=%s ua=%s ip=%s", c.QueryParam("tenant_id"), ua, ip)
	}
	toks, err := h.svc.VerifyMFA(c.Request().Context(), domain.MFAVerifyInput{
		ChallengeToken: req.ChallengeToken,
		Method:         req.Method,
		Code:           req.Code,
		UserAgent:      ua,
		IP:             ip,
	})
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": err.Error()})
	}
	// Check auth mode and set cookies if requested
	authMode := detectAuthMode(c)
	if authMode == "cookie" {
		setTokenCookies(c, toks.AccessToken, toks.RefreshToken, h.cfg)
		// In cookie mode, return success without tokens in body
		return c.JSON(http.StatusOK, map[string]bool{"success": true})
	}
	return c.JSON(http.StatusOK, tokensResp{AccessToken: toks.AccessToken, RefreshToken: toks.RefreshToken})
}
