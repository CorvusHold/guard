package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/corvusHold/guard/internal/config"
)

const (
	ctxUserIDKey   = "auth_user_id"
	ctxTenantIDKey = "auth_tenant_id"
)

// NewJWT returns an Echo middleware that validates access JWTs and
// stores user and tenant IDs in the context.
func NewJWT(cfg config.Config) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			auth := c.Request().Header.Get("Authorization")

			// If no Authorization header, fall back to cookie-based session token
			if auth == "" {
				if cookie, err := c.Cookie("guard_access_token"); err == nil && cookie != nil && cookie.Value != "" {
					auth = "Bearer " + cookie.Value
				}
			}

			if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
			}
			tokStr := strings.TrimPrefix(auth, "Bearer ")

			tok, err := jwt.Parse(tokStr, func(token *jwt.Token) (any, error) {
				return []byte(cfg.JWTSigningKey), nil
			}, jwt.WithLeeway(30*time.Second), jwt.WithIssuedAt(), jwt.WithValidMethods([]string{"HS256"}))
			if err != nil || !tok.Valid {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
			}

			claims, ok := tok.Claims.(jwt.MapClaims)
			if !ok {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid claims"})
			}
			sub, _ := claims["sub"].(string)
			ten, _ := claims["ten"].(string)
			uid, err1 := uuid.Parse(sub)
			tid, err2 := uuid.Parse(ten)
			if err1 != nil || err2 != nil {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid subject or tenant"})
			}

			c.Set(ctxUserIDKey, uid)
			c.Set(ctxTenantIDKey, tid)
			return next(c)
		}
	}
}

// UserID returns the authenticated user's ID from context.
func UserID(c echo.Context) (uuid.UUID, bool) {
	v := c.Get(ctxUserIDKey)
	if v == nil {
		return uuid.UUID{}, false
	}
	id, ok := v.(uuid.UUID)
	return id, ok
}

// TenantID returns the authenticated tenant's ID from context.
func TenantID(c echo.Context) (uuid.UUID, bool) {
	v := c.Get(ctxTenantIDKey)
	if v == nil {
		return uuid.UUID{}, false
	}
	id, ok := v.(uuid.UUID)
	return id, ok
}
