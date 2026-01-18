package middleware

import (
	"context"
	"net/http"
	"strings"

	guard "github.com/corvusHold/guard/sdk/go"
	"github.com/labstack/echo/v4"
)

// Client is the minimal interface for Guard client methods used by middleware.
// This allows for dependency injection and testing with mock clients.
type Client interface {
	Introspect(ctx context.Context, token *string) (*guard.DomainIntrospection, error)
	ResolveUserPermissions(ctx context.Context, userID, tenantID string) ([]guard.Permission, error)
}

// Context key constants for storing authentication data in Echo context
const (
	ContextKeyUserID           = "guard:user_id"
	ContextKeyTenantID         = "guard:tenant_id"
	ContextKeyEmail            = "guard:email"
	ContextKeyRoles            = "guard:roles"
	ContextKeyIntrospection    = "guard:introspection"
)

// RequireAuth is an Echo middleware that validates Guard tokens via Introspect.
//
// The middleware:
// 1. Extracts the Bearer token from Authorization header (or guard_access_token cookie as fallback)
// 2. Validates the token by calling Guard's Introspect API
// 3. Optionally validates tenant from X-Tenant-ID header matches the token
// 4. Injects user context into Echo context for downstream handlers
// 5. Returns 401 for missing/invalid tokens
// 6. Returns 403 for tenant mismatches
//
// Example usage:
//
//	e := echo.New()
//	guardClient, _ := guard.NewClient("https://guard.example.com")
//
//	// Protect all routes under /api
//	api := e.Group("/api")
//	api.Use(middleware.RequireAuth(guardClient))
//	api.GET("/profile", profileHandler)
func RequireAuth(client Client) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Extract token from Authorization header or cookie
			token := extractToken(c)
			if token == "" {
				return echo.NewHTTPError(http.StatusUnauthorized, "missing or invalid token")
			}

			// Introspect token with Guard API
			introspection, err := client.Introspect(c.Request().Context(), &token)
			if err != nil || introspection == nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "invalid token")
			}

			// Check if token is active
			if introspection.Active == nil || !*introspection.Active {
				return echo.NewHTTPError(http.StatusUnauthorized, "token not active")
			}

			// Validate tenant if X-Tenant-ID header is provided
			tenantHeader := c.Request().Header.Get("X-Tenant-ID")
			if tenantHeader != "" && introspection.TenantId != nil {
				if tenantHeader != *introspection.TenantId {
					return echo.NewHTTPError(http.StatusForbidden, "tenant mismatch")
				}
			}

			// Store introspection and extracted fields in context
			c.Set(ContextKeyIntrospection, introspection)
			if introspection.UserId != nil {
				c.Set(ContextKeyUserID, *introspection.UserId)
			}
			if introspection.TenantId != nil {
				c.Set(ContextKeyTenantID, *introspection.TenantId)
			}
			if introspection.Email != nil {
				c.Set(ContextKeyEmail, *introspection.Email)
			}
			if introspection.Roles != nil {
				c.Set(ContextKeyRoles, *introspection.Roles)
			}

			return next(c)
		}
	}
}

// extractToken extracts the Bearer token from the Authorization header or guard_access_token cookie.
// Returns empty string if token is not found.
func extractToken(c echo.Context) string {
	// Try Authorization header first
	auth := c.Request().Header.Get("Authorization")
	if auth != "" {
		const prefix = "Bearer "
		if strings.HasPrefix(auth, prefix) {
			return strings.TrimPrefix(auth, prefix)
		}
	}

	// Fallback to cookie-based authentication
	cookie, err := c.Cookie("guard_access_token")
	if err == nil && cookie.Value != "" {
		return cookie.Value
	}

	return ""
}
