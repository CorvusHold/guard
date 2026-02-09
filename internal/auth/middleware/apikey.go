package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/corvusHold/guard/internal/auth/domain"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type contextKey string

const (
	// ContextKeyAPIKey is the context key for the validated API key.
	ContextKeyAPIKey contextKey = "guard_api_key"
	// HeaderAPIKey is the HTTP header for API key authentication.
	HeaderAPIKey = "X-Guard-API-Key"
)

// APIKeyValidator validates API keys.
type APIKeyValidator interface {
	ValidateAPIKey(ctx context.Context, rawKey string) (domain.APIKey, error)
}

// RequireAPIKey is an Echo middleware that validates API keys via the X-Guard-API-Key header
// or Authorization: Bearer gk_* header.
// If the header is present and valid, the request context is enriched with the API key metadata.
// If the header is absent, the middleware passes through (allowing bearer token auth to handle it).
// If the header is present but invalid, the request is rejected with 401.
func RequireAPIKey(validator APIKeyValidator) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Clear any client-supplied X-Tenant-ID to prevent spoofing
			c.Request().Header.Del("X-Tenant-ID")

			rawKey := strings.TrimSpace(c.Request().Header.Get(HeaderAPIKey))

			// Also check Authorization: Bearer gk_* for API key auth
			if rawKey == "" {
				auth := strings.TrimSpace(c.Request().Header.Get("Authorization"))
				if strings.HasPrefix(auth, "Bearer gk_") {
					rawKey = strings.TrimPrefix(auth, "Bearer ")
				}
			}

			if rawKey == "" {
				return next(c)
			}

			key, err := validator.ValidateAPIKey(c.Request().Context(), rawKey)
			if err != nil {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid api key"})
			}

			// Store API key in context and propagate tenant via Echo context
			ctx := context.WithValue(c.Request().Context(), ContextKeyAPIKey, key)
			c.SetRequest(c.Request().WithContext(ctx))
			c.Set("tenantID", key.TenantID.String())

			return next(c)
		}
	}
}

// APIKeyFromContext retrieves the validated API key from the request context.
func APIKeyFromContext(ctx context.Context) (domain.APIKey, bool) {
	key, ok := ctx.Value(ContextKeyAPIKey).(domain.APIKey)
	return key, ok
}

// APIKeyTenantID retrieves the tenant ID from a validated API key in the context.
func APIKeyTenantID(ctx context.Context) (uuid.UUID, bool) {
	key, ok := APIKeyFromContext(ctx)
	if !ok {
		return uuid.Nil, false
	}
	return key.TenantID, true
}

// APIKeyHasScope checks if the API key in context has the required scope.
func APIKeyHasScope(ctx context.Context, scope string) bool {
	key, ok := APIKeyFromContext(ctx)
	if !ok {
		return false
	}
	for _, s := range key.Scopes {
		if s == scope || s == "*" {
			return true
		}
	}
	return false
}

// RequireScopes returns an Echo middleware that enforces the given scopes on API key-authenticated requests.
// If the request is not API key-authenticated (e.g., bearer token), it passes through.
// If the request is API key-authenticated but lacks the required scope, it returns 403.
func RequireScopes(scopes ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			_, isAPIKey := APIKeyFromContext(c.Request().Context())
			if !isAPIKey {
				return next(c)
			}
			for _, scope := range scopes {
				if !APIKeyHasScope(c.Request().Context(), scope) {
					return c.JSON(http.StatusForbidden, map[string]string{
						"error":          "insufficient scope",
						"required_scope": scope,
					})
				}
			}
			return next(c)
		}
	}
}
