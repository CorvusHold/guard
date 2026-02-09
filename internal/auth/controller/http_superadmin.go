package controller

import (
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

// registerSuperAdminRoutes registers platform-level admin endpoints.
func (h *Controller) registerSuperAdminRoutes(g *echo.Group) {
	platform := g.Group("/platform")
	platform.GET("/tenants", h.platformListTenants)
	platform.GET("/users/search", h.platformSearchUsers)
	platform.GET("/audit-logs", h.platformAuditLogs)
	platform.GET("/stats", h.platformStats)
}

// @Summary      List all tenants with stats
// @Description  Platform-level endpoint to list all tenants with user counts
// @Tags         Platform Admin
// @Produce      json
// @Param        limit   query  int  false  "Limit"
// @Param        offset  query  int  false  "Offset"
// @Success      200  {object}  map[string]interface{}
// @Router       /api/v1/auth/admin/platform/tenants [get]
func (h *Controller) platformListTenants(c echo.Context) error {
	in, err := h.requireAuth(c)
	if err != nil {
		return nil
	}
	// Check platform:admin permission
	ok, err := h.svc.HasPermission(c.Request().Context(), in.UserID, in.TenantID, "platform:admin", "*", nil)
	if err != nil || !ok {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "platform admin required"})
	}

	limit, _ := strconv.Atoi(c.QueryParam("limit"))
	offset, _ := strconv.Atoi(c.QueryParam("offset"))
	if limit <= 0 {
		limit = 50
	}

	rows, err := h.svc.ListAllTenantsWithStats(c.Request().Context(), limit, offset)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, map[string]interface{}{"tenants": rows})
}

// @Summary      Search users across tenants
// @Description  Platform-level endpoint to search users globally
// @Tags         Platform Admin
// @Produce      json
// @Param        q  query  string  true  "Search query (email)"
// @Success      200  {object}  map[string]interface{}
// @Router       /api/v1/auth/admin/platform/users/search [get]
func (h *Controller) platformSearchUsers(c echo.Context) error {
	in, err := h.requireAuth(c)
	if err != nil {
		return nil
	}
	ok, err := h.svc.HasPermission(c.Request().Context(), in.UserID, in.TenantID, "platform:admin", "*", nil)
	if err != nil || !ok {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "platform admin required"})
	}

	query := c.QueryParam("q")
	if query == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "q parameter required"})
	}

	users, err := h.svc.SearchUsersGlobal(c.Request().Context(), query)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, map[string]interface{}{"users": users})
}

// @Summary      Query audit logs
// @Description  Platform-level endpoint to query audit logs across tenants
// @Tags         Platform Admin
// @Produce      json
// @Param        tenant_id  query  string  false  "Filter by tenant"
// @Param        user_id    query  string  false  "Filter by user"
// @Param        action     query  string  false  "Filter by action"
// @Param        limit      query  int     false  "Limit"
// @Param        offset     query  int     false  "Offset"
// @Success      200  {object}  map[string]interface{}
// @Router       /api/v1/auth/admin/platform/audit-logs [get]
func (h *Controller) platformAuditLogs(c echo.Context) error {
	in, err := h.requireAuth(c)
	if err != nil {
		return nil
	}
	ok, err := h.svc.HasPermission(c.Request().Context(), in.UserID, in.TenantID, "platform:admin", "*", nil)
	if err != nil || !ok {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "platform admin required"})
	}

	limit, _ := strconv.Atoi(c.QueryParam("limit"))
	offset, _ := strconv.Atoi(c.QueryParam("offset"))
	if limit <= 0 {
		limit = 50
	}

	var tenantID *uuid.UUID
	if tid := c.QueryParam("tenant_id"); tid != "" {
		if id, err := uuid.Parse(tid); err == nil {
			tenantID = &id
		}
	}
	var userID *uuid.UUID
	if uid := c.QueryParam("user_id"); uid != "" {
		if id, err := uuid.Parse(uid); err == nil {
			userID = &id
		}
	}
	action := c.QueryParam("action")

	logs, total, err := h.svc.QueryAuditLogs(c.Request().Context(), tenantID, userID, action, limit, offset)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, map[string]interface{}{"audit_logs": logs, "total": total})
}

// @Summary      Platform stats
// @Description  Returns aggregate platform statistics
// @Tags         Platform Admin
// @Produce      json
// @Success      200  {object}  map[string]interface{}
// @Router       /api/v1/auth/admin/platform/stats [get]
func (h *Controller) platformStats(c echo.Context) error {
	in, err := h.requireAuth(c)
	if err != nil {
		return nil
	}
	ok, err := h.svc.HasPermission(c.Request().Context(), in.UserID, in.TenantID, "platform:admin", "*", nil)
	if err != nil || !ok {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "platform admin required"})
	}

	stats, err := h.svc.PlatformStats(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, stats)
}
