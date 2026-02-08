package controller

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

// --- API Key DTOs ---

type createAPIKeyReq struct {
	Name      string   `json:"name" validate:"required"`
	Scopes    []string `json:"scopes"`
	ExpiresAt *string  `json:"expires_at,omitempty"` // RFC3339 timestamp
}

type createAPIKeyResp struct {
	ID        uuid.UUID  `json:"id"`
	TenantID  uuid.UUID  `json:"tenant_id"`
	Name      string     `json:"name"`
	KeyPrefix string     `json:"key_prefix"`
	Scopes    []string   `json:"scopes"`
	RawKey    string     `json:"raw_key"` // Only returned on creation
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

type apiKeyItem struct {
	ID         uuid.UUID  `json:"id"`
	TenantID   uuid.UUID  `json:"tenant_id"`
	Name       string     `json:"name"`
	KeyPrefix  string     `json:"key_prefix"`
	Scopes     []string   `json:"scopes"`
	CreatedBy  *uuid.UUID `json:"created_by,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

type apiKeysListResp struct {
	APIKeys []apiKeyItem `json:"api_keys"`
}

// CreateAPIKey godoc
// @Summary      Create an API key (admin-only)
// @Description  Creates a new API key for service-to-service authentication. The raw key is returned only once.
// @Tags         auth.admin
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        body  body  createAPIKeyReq  true  "API key details"
// @Success      201   {object}  createAPIKeyResp
// @Failure      400   {object}  map[string]string
// @Failure      401   {object}  map[string]string
// @Failure      403   {object}  map[string]string
// @Router       /api/v1/auth/admin/api-keys [post]
func (h *Controller) createAPIKey(c echo.Context) error {
	tok := h.resolveAccessToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}

	// Require admin role
	if !hasRole(in.Roles, "admin") {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
	}

	var req createAPIKeyReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	var expiresAt *time.Time
	if req.ExpiresAt != nil && *req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid expires_at format, use RFC3339"})
		}
		expiresAt = &t
	}

	key, rawKey, err := h.svc.CreateAPIKey(c.Request().Context(), in.TenantID, req.Name, req.Scopes, in.UserID, expiresAt)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusCreated, createAPIKeyResp{
		ID:        key.ID,
		TenantID:  key.TenantID,
		Name:      key.Name,
		KeyPrefix: key.KeyPrefix,
		Scopes:    key.Scopes,
		RawKey:    rawKey,
		ExpiresAt: key.ExpiresAt,
		CreatedAt: key.CreatedAt,
	})
}

// ListAPIKeys godoc
// @Summary      List API keys for a tenant (admin-only)
// @Description  Returns all API keys for the caller's tenant. Raw keys are never returned.
// @Tags         auth.admin
// @Security     BearerAuth
// @Produce      json
// @Success      200  {object}  apiKeysListResp
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Router       /api/v1/auth/admin/api-keys [get]
func (h *Controller) listAPIKeys(c echo.Context) error {
	tok := h.resolveAccessToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}

	if !hasRole(in.Roles, "admin") {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
	}

	keys, err := h.svc.ListAPIKeys(c.Request().Context(), in.TenantID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	out := make([]apiKeyItem, 0, len(keys))
	for _, k := range keys {
		out = append(out, apiKeyItem{
			ID:         k.ID,
			TenantID:   k.TenantID,
			Name:       k.Name,
			KeyPrefix:  k.KeyPrefix,
			Scopes:     k.Scopes,
			CreatedBy:  k.CreatedBy,
			ExpiresAt:  k.ExpiresAt,
			RevokedAt:  k.RevokedAt,
			LastUsedAt: k.LastUsedAt,
			CreatedAt:  k.CreatedAt,
			UpdatedAt:  k.UpdatedAt,
		})
	}

	return c.JSON(http.StatusOK, apiKeysListResp{APIKeys: out})
}

// RevokeAPIKey godoc
// @Summary      Revoke an API key (admin-only)
// @Description  Revokes an API key. The key will no longer be accepted for authentication.
// @Tags         auth.admin
// @Security     BearerAuth
// @Param        id  path  string  true  "API Key ID (UUID)"
// @Success      204
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Router       /api/v1/auth/admin/api-keys/{id}/revoke [post]
func (h *Controller) revokeAPIKey(c echo.Context) error {
	tok := h.resolveAccessToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}

	if !hasRole(in.Roles, "admin") {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
	}

	keyID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid api key id"})
	}

	if err := h.svc.RevokeAPIKey(c.Request().Context(), keyID, in.TenantID); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	return c.NoContent(http.StatusNoContent)
}

// hasRole checks if a role exists in a list of roles (case-insensitive).
func hasRole(roles []string, target string) bool {
	for _, r := range roles {
		if r == target {
			return true
		}
	}
	return false
}
