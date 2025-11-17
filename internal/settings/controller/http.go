package controller

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	amw "github.com/corvusHold/guard/internal/auth/middleware"
	evdomain "github.com/corvusHold/guard/internal/events/domain"
	rl "github.com/corvusHold/guard/internal/platform/ratelimit"
	sdomain "github.com/corvusHold/guard/internal/settings/domain"
)

// Controller exposes minimal tenant-scoped settings management endpoints.
// It intentionally supports a whitelist of keys required for SSO setup.
type Controller struct {
	repo    sdomain.Repository
	service sdomain.Service
	// Injected concerns
	jwtMW       echo.MiddlewareFunc
	rlStore     rl.Store
	pub         evdomain.Publisher
	roleFetcher func(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) ([]string, error)
}

func New(repo sdomain.Repository, service sdomain.Service) *Controller {
	return &Controller{repo: repo, service: service}
}

// Register mounts settings endpoints under /v1.
func (h *Controller) Register(e *echo.Echo) {
	// Build rate limit middlewares (tenant-scoped) with dynamic overrides from settings service.
	// Defaults: GET 60/min, PUT 10/min
	getDefaultWin := time.Minute
	getDefaultLim := 60
	putDefaultWin := time.Minute
	putDefaultLim := 10

	mkKey := func(prefix string) func(echo.Context) string {
		return func(c echo.Context) string { return prefix + ":ten:" + c.Param("id") }
	}
	getWinF := func(c echo.Context) time.Duration {
		if tid, err := uuid.Parse(c.Param("id")); err == nil {
			if d, err := h.service.GetDuration(c.Request().Context(), sdomain.KeyRLSettingsGetWindow, &tid, getDefaultWin); err == nil {
				return d
			}
		}
		return getDefaultWin
	}
	getLimF := func(c echo.Context) int {
		if tid, err := uuid.Parse(c.Param("id")); err == nil {
			if v, err := h.service.GetInt(c.Request().Context(), sdomain.KeyRLSettingsGetLimit, &tid, getDefaultLim); err == nil {
				return v
			}
		}
		return getDefaultLim
	}
	putWinF := func(c echo.Context) time.Duration {
		if tid, err := uuid.Parse(c.Param("id")); err == nil {
			if d, err := h.service.GetDuration(c.Request().Context(), sdomain.KeyRLSettingsPutWindow, &tid, putDefaultWin); err == nil {
				return d
			}
		}
		return putDefaultWin
	}
	putLimF := func(c echo.Context) int {
		if tid, err := uuid.Parse(c.Param("id")); err == nil {
			if v, err := h.service.GetInt(c.Request().Context(), sdomain.KeyRLSettingsPutLimit, &tid, putDefaultLim); err == nil {
				return v
			}
		}
		return putDefaultLim
	}

	getPolicy := rl.Policy{Name: "settings:get", Window: getDefaultWin, Limit: getDefaultLim, Key: mkKey("settings:get"), WindowFunc: getWinF, LimitFunc: getLimF}
	putPolicy := rl.Policy{Name: "settings:put", Window: putDefaultWin, Limit: putDefaultLim, Key: mkKey("settings:put"), WindowFunc: putWinF, LimitFunc: putLimF}

	var getRL echo.MiddlewareFunc
	var putRL echo.MiddlewareFunc
	if h.rlStore != nil {
		getRL = rl.MiddlewareWithStore(getPolicy, h.rlStore)
		putRL = rl.MiddlewareWithStore(putPolicy, h.rlStore)
	} else {
		getRL = rl.Middleware(getPolicy)
		putRL = rl.Middleware(putPolicy)
	}

	// Compose middleware per route
	getMW := []echo.MiddlewareFunc{}
	putMW := []echo.MiddlewareFunc{}
	if h.jwtMW != nil {
		getMW = append(getMW, h.jwtMW)
		putMW = append(putMW, h.jwtMW)
	}
	getMW = append(getMW, getRL)
	putMW = append(putMW, putRL)

	e.GET("/v1/tenants/:id/settings", h.getTenantSettings, getMW...)
	e.PUT("/v1/tenants/:id/settings", h.putTenantSettings, putMW...)
}

// WithJWT injects a JWT middleware for these endpoints.
func (h *Controller) WithJWT(mw echo.MiddlewareFunc) *Controller { h.jwtMW = mw; return h }

// WithRateLimit injects a shared Store for distributed rate limiting.
func (h *Controller) WithRateLimit(store rl.Store) *Controller { h.rlStore = store; return h }

// WithPublisher injects an audit event publisher.
func (h *Controller) WithPublisher(p evdomain.Publisher) *Controller { h.pub = p; return h }

// WithRoleFetcher injects a function to fetch roles for RBAC.
func (h *Controller) WithRoleFetcher(fn func(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) ([]string, error)) *Controller {
	h.roleFetcher = fn
	return h
}

type settingsResponse struct {
	// SSO
	SSOProvider                 string `json:"sso_provider"`
	WorkOSClientID              string `json:"workos_client_id"`
	WorkOSClientSecret          string `json:"workos_client_secret,omitempty"` // masked
	WorkOSAPIKey                string `json:"workos_api_key,omitempty"`       // masked
	WorkOSDefaultConnectionID   string `json:"workos_default_connection_id,omitempty"`
	WorkOSDefaultOrganizationID string `json:"workos_default_organization_id,omitempty"`
	SSOStateTTL                 string `json:"sso_state_ttl"`
	SSORedirectAllowlist        string `json:"sso_redirect_allowlist"`
	// App
	AppCORSAllowedOrigins string `json:"app_cors_allowed_origins"`
}

type putSettingsRequest struct {
	SSOProvider                 *string `json:"sso_provider"`
	WorkOSClientID              *string `json:"workos_client_id"`
	WorkOSClientSecret          *string `json:"workos_client_secret"`
	WorkOSAPIKey                *string `json:"workos_api_key"`
	WorkOSDefaultConnectionID   *string `json:"workos_default_connection_id"`
	WorkOSDefaultOrganizationID *string `json:"workos_default_organization_id"`
	SSOStateTTL                 *string `json:"sso_state_ttl"`
	SSORedirectAllowlist        *string `json:"sso_redirect_allowlist"`
	// App
	AppCORSAllowedOrigins *string `json:"app_cors_allowed_origins"`
	// Auth
	JWTSigningKey *string `json:"jwt_signing_key"`
}

// Get Tenant Settings godoc
// @Summary      Get tenant settings (subset)
// @Description  Returns tenant-scoped settings required for SSO setup (WorkOS)
// @Tags         tenants
// @Produce      json
// @Param        id   path   string  true  "Tenant ID (UUID)"
// @Success      200  {object}  settingsResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Failure      429  {object}  map[string]string
// @Security     BearerAuth
// @Router       /v1/tenants/{id}/settings [get]
func (h *Controller) getTenantSettings(c echo.Context) error {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	// Enforce tenant match from JWT
	if tid, ok := amw.TenantID(c); !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	} else if tid != id {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
	}
	// Use typed getters with empty defaults
	prov, _ := h.service.GetString(c.Request().Context(), sdomain.KeySSOProvider, &id, "")
	cid, _ := h.service.GetString(c.Request().Context(), sdomain.KeyWorkOSClientID, &id, "")
	csec, _ := h.service.GetString(c.Request().Context(), sdomain.KeyWorkOSClientSecret, &id, "")
	apikey, _ := h.service.GetString(c.Request().Context(), sdomain.KeyWorkOSAPIKey, &id, "")
	defConn, _ := h.service.GetString(c.Request().Context(), sdomain.KeyWorkOSDefaultConnectionID, &id, "")
	defOrg, _ := h.service.GetString(c.Request().Context(), sdomain.KeyWorkOSDefaultOrganizationID, &id, "")
	stateTTL, _ := h.service.GetString(c.Request().Context(), sdomain.KeySSOStateTTL, &id, "")
	allow, _ := h.service.GetString(c.Request().Context(), sdomain.KeySSORedirectAllowlist, &id, "")
	corsAllow, _ := h.service.GetString(c.Request().Context(), sdomain.KeyAppCORSAllowedOrigins, &id, "")
	// Mask secrets if present
	mask := func(s string) string {
		if s == "" {
			return ""
		}
		if len(s) <= 4 {
			return "****"
		}
		return "****" + s[len(s)-4:]
	}
	resp := settingsResponse{
		SSOProvider:                 prov,
		WorkOSClientID:              cid,
		WorkOSClientSecret:          mask(csec),
		WorkOSAPIKey:                mask(apikey),
		WorkOSDefaultConnectionID:   defConn,
		WorkOSDefaultOrganizationID: defOrg,
		SSOStateTTL:                 stateTTL,
		SSORedirectAllowlist:        allow,
		AppCORSAllowedOrigins:       corsAllow,
	}
	return c.JSON(http.StatusOK, resp)
}

// Put Tenant Settings godoc
// @Summary      Upsert tenant settings (subset)
// @Description  Upserts tenant settings for SSO setup (WorkOS). Only whitelisted keys are accepted.
// @Tags         tenants
// @Accept       json
// @Param        id    path   string              true  "Tenant ID (UUID)"
// @Param        body  body   putSettingsRequest  true  "settings"
// @Success      204
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Failure      429  {object}  map[string]string
// @Security     BearerAuth
// @Router       /v1/tenants/{id}/settings [put]
func (h *Controller) putTenantSettings(c echo.Context) error {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	// Enforce tenant match and RBAC (admin|owner)
	uid, okU := amw.UserID(c)
	tid, okT := amw.TenantID(c)
	if !okU || !okT {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	if tid != id {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
	}
	if h.roleFetcher != nil {
		roles, err := h.roleFetcher(c.Request().Context(), uid, tid)
		if err != nil {
			return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
		}
		allowed := false
		for _, r := range roles {
			if r == "admin" || r == "owner" {
				allowed = true
				break
			}
		}
		if !allowed {
			return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
		}
	}
	var req putSettingsRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	ctx := c.Request().Context()
	// Validate inputs
	if req.JWTSigningKey != nil {
		v := strings.TrimSpace(*req.JWTSigningKey)
		// Require sufficiently long secrets when provided
		if v != "" && len(v) < 16 {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid jwt_signing_key"})
		}
	}
	if req.SSOProvider != nil {
		v := strings.ToLower(strings.TrimSpace(*req.SSOProvider))
		if v != "" && v != "dev" && v != "workos" {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid sso_provider"})
		}
	}
	if req.SSOStateTTL != nil {
		if _, err := time.ParseDuration(strings.TrimSpace(*req.SSOStateTTL)); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid sso_state_ttl"})
		}
	}
	if req.SSORedirectAllowlist != nil {
		list := strings.Split(*req.SSORedirectAllowlist, ",")
		for _, raw := range list {
			s := strings.TrimSpace(raw)
			if s == "" {
				continue
			}
			u, err := url.Parse(s)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid sso_redirect_allowlist"})
			}
		}
	}
	if req.AppCORSAllowedOrigins != nil {
		list := strings.Split(*req.AppCORSAllowedOrigins, ",")
		for _, raw := range list {
			s := strings.TrimSpace(raw)
			if s == "" {
				continue
			}
			u, err := url.Parse(s)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid app_cors_allowed_origins"})
			}
		}
	}

	// Upsert allowed keys and track changes
	changed := make([]string, 0, 8)
	if req.SSOProvider != nil {
		if err := h.repo.Upsert(ctx, sdomain.KeySSOProvider, &id, *req.SSOProvider, false); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		changed = append(changed, sdomain.KeySSOProvider)
	}
	if req.WorkOSClientID != nil {
		if err := h.repo.Upsert(ctx, sdomain.KeyWorkOSClientID, &id, *req.WorkOSClientID, false); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		changed = append(changed, sdomain.KeyWorkOSClientID)
	}
	if req.WorkOSClientSecret != nil {
		if err := h.repo.Upsert(ctx, sdomain.KeyWorkOSClientSecret, &id, *req.WorkOSClientSecret, true); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		changed = append(changed, sdomain.KeyWorkOSClientSecret)
	}
	if req.WorkOSAPIKey != nil {
		if err := h.repo.Upsert(ctx, sdomain.KeyWorkOSAPIKey, &id, *req.WorkOSAPIKey, true); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		changed = append(changed, sdomain.KeyWorkOSAPIKey)
	}
	if req.WorkOSDefaultConnectionID != nil {
		v := strings.TrimSpace(*req.WorkOSDefaultConnectionID)
		if err := h.repo.Upsert(ctx, sdomain.KeyWorkOSDefaultConnectionID, &id, v, false); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		changed = append(changed, sdomain.KeyWorkOSDefaultConnectionID)
	}
	if req.WorkOSDefaultOrganizationID != nil {
		v := strings.TrimSpace(*req.WorkOSDefaultOrganizationID)
		if err := h.repo.Upsert(ctx, sdomain.KeyWorkOSDefaultOrganizationID, &id, v, false); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		changed = append(changed, sdomain.KeyWorkOSDefaultOrganizationID)
	}
	if req.SSOStateTTL != nil {
		if err := h.repo.Upsert(ctx, sdomain.KeySSOStateTTL, &id, *req.SSOStateTTL, false); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		changed = append(changed, sdomain.KeySSOStateTTL)
	}
	if req.SSORedirectAllowlist != nil {
		if err := h.repo.Upsert(ctx, sdomain.KeySSORedirectAllowlist, &id, *req.SSORedirectAllowlist, false); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		changed = append(changed, sdomain.KeySSORedirectAllowlist)
	}
	if req.AppCORSAllowedOrigins != nil {
		if err := h.repo.Upsert(ctx, sdomain.KeyAppCORSAllowedOrigins, &id, *req.AppCORSAllowedOrigins, false); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		changed = append(changed, sdomain.KeyAppCORSAllowedOrigins)
	}
	if req.JWTSigningKey != nil {
		v := strings.TrimSpace(*req.JWTSigningKey)
		if err := h.repo.Upsert(ctx, sdomain.KeyJWTSigning, &id, v, true); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		changed = append(changed, sdomain.KeyJWTSigning)
	}
	// Publish audit event (redact secrets)
	if h.pub != nil && len(changed) > 0 {
		meta := map[string]string{
			"changed": strings.Join(changed, ","),
		}
		// Provide hints without secrets
		if req.WorkOSClientSecret != nil {
			meta["sso.workos.client_secret"] = "redacted"
		}
		if req.WorkOSAPIKey != nil {
			meta["sso.workos.api_key"] = "redacted"
		}
		if req.JWTSigningKey != nil {
			meta["auth.jwt_signing_key"] = "redacted"
		}
		_ = h.pub.Publish(ctx, evdomain.Event{Type: "settings.update.success", TenantID: id, UserID: uid, Meta: meta, Time: time.Now()})
	}
	return c.NoContent(http.StatusNoContent)
}
