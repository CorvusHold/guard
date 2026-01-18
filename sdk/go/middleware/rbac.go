package middleware

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

// RequireRole returns an Echo middleware that enforces role-based access control.
//
// The middleware checks if the authenticated user has at least one of the specified roles.
// Returns 403 Forbidden if the user does not have any of the required roles.
// Returns 401 Unauthorized if the user is not authenticated (RequireAuth not applied).
//
// Role comparison is case-insensitive.
//
// Example usage:
//
//	// Require admin role
//	admin := e.Group("/api/admin")
//	admin.Use(middleware.RequireAuth(guardClient))
//	admin.Use(middleware.RequireRole(guardClient, "admin"))
//	admin.GET("/users", listUsersHandler)
//
//	// Require any of multiple roles
//	api := e.Group("/api")
//	api.Use(middleware.RequireAuth(guardClient))
//	api.Use(middleware.RequireRole(guardClient, "admin", "moderator", "editor"))
//	api.DELETE("/:id", deleteHandler)
func RequireRole(client Client, roles ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Get introspection from context (set by RequireAuth)
			introspection, err := GetIntrospection(c)
			if err != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "not authenticated")
			}

			// Extract user roles
			var userRoles []string
			if introspection.Roles != nil {
				userRoles = *introspection.Roles
			}

			// Build case-insensitive role lookup
			userRoleMap := make(map[string]bool)
			for _, r := range userRoles {
				userRoleMap[strings.ToLower(r)] = true
			}

			// Check if user has any of the required roles
			for _, required := range roles {
				if userRoleMap[strings.ToLower(required)] {
					return next(c)
				}
			}

			return echo.NewHTTPError(http.StatusForbidden, "insufficient permissions")
		}
	}
}

// RequireAdmin is a convenience middleware that requires the "admin" role.
//
// Example usage:
//
//	admin := e.Group("/api/admin")
//	admin.Use(middleware.RequireAuth(guardClient))
//	admin.Use(middleware.RequireAdmin(guardClient))
//	admin.GET("/stats", statsHandler)
func RequireAdmin(client Client) echo.MiddlewareFunc {
	return RequireRole(client, "admin")
}

// RequirePermission returns an Echo middleware that enforces fine-grained permission checks.
//
// The middleware calls Guard's ResolveUserPermissions API to check if the authenticated user
// has the specified permission key. Returns 403 Forbidden if the user lacks the permission.
// Returns 401 Unauthorized if the user is not authenticated.
//
// This is useful for permission-based access control beyond simple role checks.
//
// Example usage:
//
//	documents := e.Group("/api/documents")
//	documents.Use(middleware.RequireAuth(guardClient))
//	documents.POST("", middleware.RequirePermission(guardClient, "documents:create"), createDocumentHandler)
//	documents.DELETE("/:id", middleware.RequirePermission(guardClient, "documents:delete"), deleteDocumentHandler)
func RequirePermission(client Client, permissionKey string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Get user and tenant from context (set by RequireAuth)
			userID, err := GetUserID(c)
			if err != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "not authenticated")
			}

			tenantID, err := GetTenantID(c)
			if err != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "not authenticated")
			}

			// Check if user has the required permission
			// Note: This is a convenience wrapper that checks if permission key exists in resolved permissions
			// For advanced object-level authorization, use Guard's Authorize API directly
			hasPermission, err := hasPermissionKey(c, client, userID, tenantID, permissionKey)
			if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, "permission check failed")
			}

			if !hasPermission {
				return echo.NewHTTPError(http.StatusForbidden, "insufficient permissions")
			}

			return next(c)
		}
	}
}

// hasPermissionKey is a helper that checks if a user has a specific permission key.
// It uses Guard's ResolveUserPermissions API.
func hasPermissionKey(ctx echo.Context, client Client, userID, tenantID, permissionKey string) (bool, error) {
	permissions, err := client.ResolveUserPermissions(ctx.Request().Context(), userID, tenantID)
	if err != nil {
		return false, err
	}

	for _, perm := range permissions {
		if perm.Key == permissionKey {
			return true, nil
		}
	}

	return false, nil
}
