package controller

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	authdomain "github.com/corvusHold/guard/internal/auth/domain"
	"github.com/corvusHold/guard/internal/auth/sso/domain"
	"github.com/corvusHold/guard/internal/auth/sso/service"
	"github.com/corvusHold/guard/internal/platform/ratelimit"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"
)

const guardAccessTokenCookieName = "guard_access_token"

// SSOController handles HTTP requests for SSO endpoints.
type SSOController struct {
	ssoService  *service.SSOService
	authService authdomain.Service // For introspection and admin checks
	log         zerolog.Logger
	rl          ratelimit.Store
}

// New creates a new SSO controller.
func New(ssoService *service.SSOService, authService authdomain.Service) *SSOController {
	return &SSOController{
		ssoService:  ssoService,
		authService: authService,
		log:         zerolog.Nop(),
	}
}

// SetLogger sets the logger for the controller.
func (h *SSOController) SetLogger(log zerolog.Logger) {
	h.log = log
}

// WithRateLimitStore sets the rate limit store for the controller.
func (h *SSOController) WithRateLimitStore(store ratelimit.Store) *SSOController {
	h.rl = store
	return h
}

// Register registers SSO routes with the Echo router.
func (h *SSOController) Register(e *echo.Echo) {
	// Rate limiting middleware for public SSO endpoints
	var rlInitiate, rlCallback echo.MiddlewareFunc
	if h.rl != nil {
		rlInitiate = ratelimit.MiddlewareWithStore(ratelimit.Policy{
			Name:   "sso:initiate",
			Limit:  10,
			Window: time.Minute,
			Key:    func(c echo.Context) string { return c.RealIP() },
		}, h.rl)

		rlCallback = ratelimit.MiddlewareWithStore(ratelimit.Policy{
			Name:   "sso:callback",
			Limit:  20,
			Window: time.Minute,
			Key:    func(c echo.Context) string { return c.RealIP() },
		}, h.rl)
	}

	// Public SSO endpoints (no authentication required)
	// New tenant-scoped URLs: /api/v1/auth/sso/t/:tenant_id/:slug/*
	if rlInitiate != nil {
		e.GET("/api/v1/auth/sso/t/:tenant_id/:slug/login", h.handleSSOInitiateV2, rlInitiate)
		e.GET("/api/v1/auth/sso/:slug/login", h.handleSSOInitiateLegacy, rlInitiate) // Legacy redirect
	} else {
		e.GET("/api/v1/auth/sso/t/:tenant_id/:slug/login", h.handleSSOInitiateV2)
		e.GET("/api/v1/auth/sso/:slug/login", h.handleSSOInitiateLegacy)
	}

	if rlCallback != nil {
		e.GET("/api/v1/auth/sso/t/:tenant_id/:slug/callback", h.handleSSOCallbackV2, rlCallback)
		e.POST("/api/v1/auth/sso/t/:tenant_id/:slug/callback", h.handleSSOCallbackV2, rlCallback) // SAML POST binding
		e.GET("/api/v1/auth/sso/:slug/callback", h.handleSSOCallbackLegacy, rlCallback)           // Legacy redirect
		e.POST("/api/v1/auth/sso/:slug/callback", h.handleSSOCallbackLegacy, rlCallback)
	} else {
		e.GET("/api/v1/auth/sso/t/:tenant_id/:slug/callback", h.handleSSOCallbackV2)
		e.POST("/api/v1/auth/sso/t/:tenant_id/:slug/callback", h.handleSSOCallbackV2)
		e.GET("/api/v1/auth/sso/:slug/callback", h.handleSSOCallbackLegacy)
		e.POST("/api/v1/auth/sso/:slug/callback", h.handleSSOCallbackLegacy)
	}

	e.GET("/api/v1/auth/sso/t/:tenant_id/:slug/metadata", h.handleSAMLMetadataV2)
	e.GET("/api/v1/auth/sso/t/:tenant_id/:slug/logout", h.handleSSOLogout)
	e.POST("/api/v1/auth/sso/t/:tenant_id/:slug/logout", h.handleSSOLogout) // SAML SLO POST binding
	e.GET("/api/v1/auth/sso/:slug/metadata", h.handleSAMLMetadataLegacy)    // Legacy redirect
}

// RegisterV1 registers SSO JSON APIs under /api/v1/sso.
// Browser flows are registered separately via Register on the root echo.
func (h *SSOController) RegisterV1(apiV1 *echo.Group) {
	// Rate limiting middleware for JSON API endpoints
	var rlPortalSession, rlPortalProvider echo.MiddlewareFunc
	if h.rl != nil {
		rlPortalSession = ratelimit.MiddlewareWithStore(ratelimit.Policy{
			Name:   "sso:portal_session",
			Limit:  10,
			Window: time.Minute,
			Key:    func(c echo.Context) string { return "sso:portal_session:" + c.RealIP() },
		}, h.rl)

		rlPortalProvider = ratelimit.MiddlewareWithStore(ratelimit.Policy{
			Name:   "sso:portal_provider",
			Limit:  20,
			Window: time.Minute,
			Key:    func(c echo.Context) string { return "sso:portal_provider:" + c.RealIP() },
		}, h.rl)
	}

	// Admin API endpoints (authentication required)
	admin := apiV1.Group("/sso")
	admin.POST("/providers", h.handleCreateProvider)
	admin.GET("/providers", h.handleListProviders)
	admin.GET("/providers/:id", h.handleGetProvider)
	admin.PUT("/providers/:id", h.handleUpdateProvider)
	admin.DELETE("/providers/:id", h.handleDeleteProvider)
	admin.POST("/providers/:id/test", h.handleTestProvider)
	admin.GET("/sp-info", h.handleGetSPInfo)

	// Portal token endpoints (no Guard auth, portal-token gated)
	if rlPortalSession != nil {
		apiV1.POST("/sso/portal/session", h.handlePortalSession, rlPortalSession)
	} else {
		apiV1.POST("/sso/portal/session", h.handlePortalSession)
	}
	if rlPortalProvider != nil {
		apiV1.GET("/sso/portal/provider", h.handlePortalProvider, rlPortalProvider)
	} else {
		apiV1.GET("/sso/portal/provider", h.handlePortalProvider)
	}
}

// ============================================================================
// V2 Tenant-Scoped SSO Endpoints
// URL format: /api/v1/auth/sso/t/:tenant_id/:slug/*
// These endpoints use tenant_id in the URL path instead of query params,
// making them compatible with SAML POST binding and more reliable.
// ============================================================================

// handleSSOInitiateV2 initiates an SSO login flow using tenant-scoped URLs.
// GET /api/v1/auth/sso/t/:tenant_id/:slug/login?redirect_url=xxx
func (h *SSOController) handleSSOInitiateV2(c echo.Context) error {
	tenantIDStr := c.Param("tenant_id")
	slug := c.Param("slug")

	if tenantIDStr == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "tenant_id is required"})
	}
	if slug == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "provider slug is required"})
	}

	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
	}

	redirectURL := c.QueryParam("redirect_url")
	loginHint := c.QueryParam("login_hint")
	forceAuthn := c.QueryParam("force_authn") == "true"

	ipAddress := c.RealIP()
	userAgent := c.Request().UserAgent()

	resp, err := h.ssoService.InitiateSSO(c.Request().Context(), service.InitiateSSORequest{
		TenantID:     tenantID,
		ProviderSlug: slug,
		RedirectURL:  redirectURL,
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		LoginHint:    loginHint,
		ForceAuthn:   forceAuthn,
	})
	if err != nil {
		h.log.Error().Err(err).Str("slug", slug).Str("tenant_id", tenantIDStr).Msg("failed to initiate SSO")
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	return c.Redirect(http.StatusFound, resp.AuthorizationURL)
}

// ============================================================================
// Shared Callback Processing
// ============================================================================

// callbackRequest contains the parsed parameters for SSO callback processing.
type callbackRequest struct {
	TenantID     uuid.UUID
	Slug         string
	Code         string // OIDC authorization code
	State        string // OIDC state parameter
	SAMLResponse string // SAML response (POST binding)
	RelayState   string // SAML relay state
	IPAddress    string
	UserAgent    string
}

// callbackResult contains the result of SSO callback processing.
type callbackResult struct {
	Tokens      *authdomain.AccessTokens
	RedirectURL string
	UserID      uuid.UUID
	Email       string
	IsNewUser   bool
	Error       error
}

// processCallback handles the common SSO callback logic:
// 1. Calls the SSO service to validate the callback and get user info
// 2. Issues access and refresh tokens for the authenticated user
// 3. Returns a structured result with tokens or error
func (h *SSOController) processCallback(ctx context.Context, req callbackRequest) callbackResult {
	resp, err := h.ssoService.HandleCallback(ctx, service.CallbackRequest{
		TenantID:     req.TenantID,
		ProviderSlug: req.Slug,
		Code:         req.Code,
		State:        req.State,
		SAMLResponse: req.SAMLResponse,
		RelayState:   req.RelayState,
		IPAddress:    req.IPAddress,
		UserAgent:    req.UserAgent,
	})
	if err != nil {
		h.log.Error().Err(err).Str("slug", req.Slug).Str("tenant_id", req.TenantID.String()).Msg("SSO callback failed")
		return callbackResult{Error: err}
	}

	tokens, err := h.authService.IssueTokensForSSO(ctx, authdomain.SSOTokenInput{
		UserID:        resp.User.ID,
		TenantID:      req.TenantID,
		SSOProviderID: &resp.SSOProviderID,
		UserAgent:     req.UserAgent,
		IP:            req.IPAddress,
	})
	if err != nil {
		h.log.Error().Err(err).Msg("failed to issue tokens for SSO user")
		return callbackResult{Error: fmt.Errorf("failed to create session: %w", err)}
	}

	h.log.Info().
		Str("user_id", resp.User.ID.String()).
		Str("email", resp.Profile.Email).
		Bool("is_new_user", resp.IsNewUser).
		Str("redirect_url", resp.RedirectURL).
		Msg("SSO login successful")

	return callbackResult{
		Tokens:      &tokens,
		RedirectURL: resp.RedirectURL,
		UserID:      resp.User.ID,
		Email:       resp.Profile.Email,
		IsNewUser:   resp.IsNewUser,
	}
}

// handleSSOCallbackV2 handles the SSO callback using tenant-scoped URLs.
// GET/POST /api/v1/auth/sso/t/:tenant_id/:slug/callback
func (h *SSOController) handleSSOCallbackV2(c echo.Context) error {
	tenantIDStr := c.Param("tenant_id")
	slug := c.Param("slug")

	if tenantIDStr == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "tenant_id is required"})
	}
	if slug == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "provider slug is required"})
	}

	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
	}

	// Use shared callback processing
	result := h.processCallback(c.Request().Context(), callbackRequest{
		TenantID:     tenantID,
		Slug:         slug,
		Code:         c.QueryParam("code"),
		State:        c.QueryParam("state"),
		SAMLResponse: c.FormValue("SAMLResponse"),
		RelayState:   c.FormValue("RelayState"),
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
	})

	if result.Error != nil {
		// Check if it's a session creation error (internal) vs callback validation error (bad request)
		if strings.Contains(result.Error.Error(), "failed to create session") {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create session"})
		}
		return c.JSON(http.StatusBadRequest, map[string]string{"error": result.Error.Error()})
	}

	// If a redirect URL was provided during initiation, redirect with tokens
	if result.RedirectURL != "" {
		redirectURL, err := url.Parse(result.RedirectURL)
		if err != nil {
			h.log.Error().Err(err).Str("redirect_url", result.RedirectURL).Msg("invalid redirect URL")
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid redirect URL"})
		}

		// Check if redirect URL prefers query params (has ?use_query=true)
		// Otherwise use fragment (more secure - not sent to server logs)
		useQuery := redirectURL.Query().Get("use_query") == "true"

		if useQuery {
			// Use query parameters (less secure but works with server-side routes)
			q := redirectURL.Query()
			q.Del("use_query") // Remove the flag from final URL
			q.Set("access_token", result.Tokens.AccessToken)
			q.Set("refresh_token", result.Tokens.RefreshToken)
			redirectURL.RawQuery = q.Encode()
		} else {
			// Use fragment to avoid token leakage in server logs/referrer headers
			redirectURL.Fragment = fmt.Sprintf("access_token=%s&refresh_token=%s",
				url.QueryEscape(result.Tokens.AccessToken),
				url.QueryEscape(result.Tokens.RefreshToken))
		}
		return c.Redirect(http.StatusFound, redirectURL.String())
	}

	// Fallback to JSON response if no redirect URL
	return c.JSON(http.StatusOK, map[string]interface{}{
		"access_token":  result.Tokens.AccessToken,
		"refresh_token": result.Tokens.RefreshToken,
	})
}

// handleSAMLMetadataV2 returns SAML SP metadata using tenant-scoped URLs.
// GET /api/v1/auth/sso/t/:tenant_id/:slug/metadata
func (h *SSOController) handleSAMLMetadataV2(c echo.Context) error {
	tenantIDStr := c.Param("tenant_id")
	slug := c.Param("slug")

	if tenantIDStr == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "tenant_id is required"})
	}
	if slug == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "provider slug is required"})
	}

	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
	}

	metadata, err := h.ssoService.GetProviderMetadata(c.Request().Context(), tenantID, slug)
	if err != nil {
		h.log.Error().Err(err).Str("slug", slug).Str("tenant_id", tenantIDStr).Msg("failed to get provider metadata")
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	if metadata.MetadataXML != "" {
		return c.XMLBlob(http.StatusOK, []byte(metadata.MetadataXML))
	}

	return c.JSON(http.StatusOK, metadata)
}

// handleSSOLogout handles SSO logout (Single Logout).
// GET/POST /api/v1/auth/sso/t/:tenant_id/:slug/logout
func (h *SSOController) handleSSOLogout(c echo.Context) error {
	tenantIDStr := c.Param("tenant_id")
	slug := c.Param("slug")

	if tenantIDStr == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "tenant_id is required"})
	}
	if slug == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "provider slug is required"})
	}

	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
	}

	// Get SAML logout request/response if present
	samlRequest := c.FormValue("SAMLRequest")
	samlResponse := c.FormValue("SAMLResponse")
	relayState := c.FormValue("RelayState")

	// Try to extract user context from bearer token or cookie for session revocation
	var userID uuid.UUID
	var hasUserContext bool
	token := bearerToken(c)
	if token == "" {
		// Try cookie mode
		if cookie, cerr := c.Cookie(guardAccessTokenCookieName); cerr == nil && cookie.Value != "" {
			token = cookie.Value
		}
	}
	if token != "" {
		if introspection, introErr := h.authService.Introspect(c.Request().Context(), token); introErr == nil && introspection.Active {
			userID = introspection.UserID
			hasUserContext = true
		}
	}

	// Revoke user sessions before acknowledging logout (Phase 1: Local Session Revocation)
	if hasUserContext {
		count, revokeErr := h.authService.RevokeUserSessions(c.Request().Context(), userID, tenantID)
		if revokeErr != nil {
			h.log.Error().Err(revokeErr).
				Str("user_id", userID.String()).
				Str("tenant_id", tenantIDStr).
				Msg("failed to revoke sessions during SSO logout")
			// Continue with logout flow even if revocation fails
		} else {
			h.log.Info().
				Str("user_id", userID.String()).
				Str("tenant_id", tenantIDStr).
				Int64("sessions_revoked", count).
				Msg("revoked user sessions during SSO logout")
		}
	}

	// If this is an IdP-initiated logout (SAMLRequest present)
	if samlRequest != "" {
		h.log.Info().Str("tenant_id", tenantIDStr).Str("slug", slug).Msg("processing IdP-initiated logout")
		// TODO: Implement IdP-initiated SLO (Phase 2)
		return c.JSON(http.StatusOK, map[string]string{"status": "logged_out"})
	}

	// If this is a logout response from IdP
	if samlResponse != "" {
		h.log.Info().Str("tenant_id", tenantIDStr).Str("slug", slug).Msg("processing logout response")
		_ = relayState // Will be used to redirect user
		return c.JSON(http.StatusOK, map[string]string{"status": "logged_out"})
	}

	// SP-initiated logout
	h.log.Info().Str("tenant_id", tenantIDStr).Str("slug", slug).Msg("initiating SP logout")

	// Get the provider to check if SLO is configured
	config, err := h.ssoService.GetProviderBySlug(c.Request().Context(), tenantID, slug)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "provider not found"})
	}

	// If IdP has SLO URL configured, redirect there
	if config.IdPSLOUrl != "" {
		// TODO: Generate proper SAML LogoutRequest (Phase 2)
		return c.Redirect(http.StatusFound, config.IdPSLOUrl)
	}

	// No SLO configured, just acknowledge logout
	return c.JSON(http.StatusOK, map[string]string{"status": "logged_out"})
}

// ============================================================================
// Legacy Redirect Handlers (Backward Compatibility)
// These redirect old URLs to the new tenant-scoped format
// ============================================================================

// handleSSOInitiateLegacy redirects legacy SSO initiate to V2 format.
// GET /api/v1/auth/sso/:slug/login?tenant_id=xxx -> /api/v1/auth/sso/t/:tenant_id/:slug/login
func (h *SSOController) handleSSOInitiateLegacy(c echo.Context) error {
	slug := c.Param("slug")
	tenantIDStr := c.QueryParam("tenant_id")

	if tenantIDStr == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":   "tenant_id is required",
			"message": "Please use the new URL format: /api/v1/auth/sso/t/{tenant_id}/{slug}/login",
		})
	}

	// Validate tenant_id format
	if _, err := uuid.Parse(tenantIDStr); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
	}

	h.log.Warn().
		Str("slug", slug).
		Str("tenant_id", tenantIDStr).
		Msg("legacy SSO URL used, redirecting to V2 format")

	// Build new URL with all query params except tenant_id
	newURL := fmt.Sprintf("/api/v1/auth/sso/t/%s/%s/login", tenantIDStr, slug)
	query := c.QueryParams()
	query.Del("tenant_id")
	if len(query) > 0 {
		newURL += "?" + query.Encode()
	}

	return c.Redirect(http.StatusPermanentRedirect, newURL)
}

// handleSSOCallbackLegacy redirects legacy SSO callback to V2 format.
// GET/POST /api/v1/auth/sso/:slug/callback?tenant_id=xxx -> /api/v1/auth/sso/t/:tenant_id/:slug/callback
func (h *SSOController) handleSSOCallbackLegacy(c echo.Context) error {
	slug := c.Param("slug")
	tenantIDStr := c.QueryParam("tenant_id")
	if tenantIDStr == "" {
		tenantIDStr = c.FormValue("tenant_id")
	}

	if tenantIDStr == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":   "tenant_id is required",
			"message": "Please use the new URL format: /api/v1/auth/sso/t/{tenant_id}/{slug}/callback",
		})
	}

	if _, err := uuid.Parse(tenantIDStr); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
	}

	h.log.Warn().
		Str("slug", slug).
		Str("tenant_id", tenantIDStr).
		Msg("legacy SSO callback URL used, redirecting to V2 format")

	// For POST requests (SAML), we can't redirect, so handle directly using shared callback processing
	if c.Request().Method == http.MethodPost {
		tenantID, _ := uuid.Parse(tenantIDStr)

		result := h.processCallback(c.Request().Context(), callbackRequest{
			TenantID:     tenantID,
			Slug:         slug,
			SAMLResponse: c.FormValue("SAMLResponse"),
			RelayState:   c.FormValue("RelayState"),
			IPAddress:    c.RealIP(),
			UserAgent:    c.Request().UserAgent(),
		})

		if result.Error != nil {
			if strings.Contains(result.Error.Error(), "failed to create session") {
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create session"})
			}
			return c.JSON(http.StatusBadRequest, map[string]string{"error": result.Error.Error()})
		}

		return c.JSON(http.StatusOK, map[string]interface{}{
			"access_token":  result.Tokens.AccessToken,
			"refresh_token": result.Tokens.RefreshToken,
		})
	}

	// For GET requests, redirect
	newURL := fmt.Sprintf("/api/v1/auth/sso/t/%s/%s/callback", tenantIDStr, slug)
	query := c.QueryParams()
	query.Del("tenant_id")
	if len(query) > 0 {
		newURL += "?" + query.Encode()
	}

	return c.Redirect(http.StatusPermanentRedirect, newURL)
}

// handleSAMLMetadataLegacy redirects legacy metadata URL to V2 format.
// GET /api/v1/auth/sso/:slug/metadata?tenant_id=xxx -> /api/v1/auth/sso/t/:tenant_id/:slug/metadata
func (h *SSOController) handleSAMLMetadataLegacy(c echo.Context) error {
	slug := c.Param("slug")
	tenantIDStr := c.QueryParam("tenant_id")

	if tenantIDStr == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":   "tenant_id is required",
			"message": "Please use the new URL format: /api/v1/auth/sso/t/{tenant_id}/{slug}/metadata",
		})
	}

	if _, err := uuid.Parse(tenantIDStr); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
	}

	h.log.Warn().
		Str("slug", slug).
		Str("tenant_id", tenantIDStr).
		Msg("legacy SAML metadata URL used, redirecting to V2 format")

	newURL := fmt.Sprintf("/api/v1/auth/sso/t/%s/%s/metadata", tenantIDStr, slug)
	return c.Redirect(http.StatusPermanentRedirect, newURL)
}

type portalSessionRequest struct {
	Token string `json:"token"`
}

type portalSessionResponse struct {
	TenantID      uuid.UUID `json:"tenant_id"`
	ProviderSlug  string    `json:"provider_slug"`
	PortalTokenID uuid.UUID `json:"portal_token_id"`
	Intent        string    `json:"intent"`
}

// POST /api/v1/sso/portal/session
// @Summary Exchange portal token for session
// @Description Exchanges a one-time portal token for validated portal session context
// @Tags SSO
// @Accept json
// @Produce json
// @Param body body portalSessionRequest true "Portal token exchange request"
// @Success 200 {object} portalSessionResponse
// @Failure 400 {object} map[string]string
// @Router /api/v1/sso/portal/session [post]
func (h *SSOController) handlePortalSession(c echo.Context) error {
	var req portalSessionRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if strings.TrimSpace(req.Token) == "" {
		// allow ?token= as fallback
		req.Token = c.QueryParam("token")
	}
	if strings.TrimSpace(req.Token) == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "token required"})
	}

	sess, err := h.ssoService.ExchangePortalToken(c.Request().Context(), req.Token)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid or expired portal token"})
	}

	return c.JSON(http.StatusOK, portalSessionResponse{
		TenantID:      sess.TenantID,
		ProviderSlug:  sess.ProviderSlug,
		PortalTokenID: sess.PortalTokenID,
		Intent:        sess.Intent,
	})
}

// GET /api/v1/sso/portal/provider
// @Summary Get masked SSO provider via portal token
// @Description Fetches the masked SSO provider configuration using a portal token
// @Tags SSO
// @Produce json
// @Param X-Portal-Token header string false "Portal token"
// @Param token query string false "Portal token (fallback)"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/v1/sso/portal/provider [get]
func (h *SSOController) handlePortalProvider(c echo.Context) error {
	token := strings.TrimSpace(c.Request().Header.Get("X-Portal-Token"))
	if token == "" {
		token = strings.TrimSpace(c.QueryParam("token"))
	}
	if token == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "portal token required"})
	}

	// Use ValidatePortalToken instead of ExchangePortalToken to avoid consuming
	// an additional use. The token was already consumed by /session endpoint.
	sess, err := h.ssoService.ValidatePortalToken(c.Request().Context(), token)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid or expired portal token"})
	}

	config, err := h.ssoService.GetProviderBySlug(c.Request().Context(), sess.TenantID, sess.ProviderSlug)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "provider not found"})
	}

	return c.JSON(http.StatusOK, h.maskSecrets(config))
}

// Admin API Endpoints

// @Summary      Create SSO Provider
// @Description  Creates a new SSO provider configuration
// @Tags         auth.admin
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        body  body  createProviderRequest  true  "Provider configuration"
// @Success      201   {object}  map[string]interface{}
// @Failure      400   {object}  map[string]string
// @Failure      401   {object}  map[string]string
// @Failure      403   {object}  map[string]string
// @Router       /api/v1/sso/providers [post]
func (h *SSOController) handleCreateProvider(c echo.Context) error {
	// Check authentication
	userID, tenantID, isAdmin, err := h.requireAdmin(c)
	if err != nil {
		return err
	}

	var req createProviderRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	// Use authenticated tenant if not specified
	if req.TenantID == uuid.Nil {
		req.TenantID = tenantID
	}

	// Validate request
	if req.Name == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "name is required"})
	}
	if req.Slug == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "slug is required"})
	}
	if req.ProviderType == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "provider_type is required"})
	}

	// Create provider
	config, err := h.ssoService.CreateProvider(c.Request().Context(), service.CreateProviderRequest{
		TenantID:               req.TenantID,
		Name:                   req.Name,
		Slug:                   req.Slug,
		ProviderType:           req.ProviderType,
		Enabled:                req.Enabled,
		AllowSignup:            req.AllowSignup,
		TrustEmailVerified:     req.TrustEmailVerified,
		Domains:                req.Domains,
		AttributeMapping:       req.AttributeMapping,
		Issuer:                 req.Issuer,
		AuthorizationEndpoint:  req.AuthorizationEndpoint,
		TokenEndpoint:          req.TokenEndpoint,
		UserinfoEndpoint:       req.UserinfoEndpoint,
		JWKSUri:                req.JWKSUri,
		ClientID:               req.ClientID,
		ClientSecret:           req.ClientSecret,
		Scopes:                 req.Scopes,
		ResponseType:           req.ResponseType,
		ResponseMode:           req.ResponseMode,
		EntityID:               req.EntityID,
		ACSUrl:                 req.ACSUrl,
		SLOUrl:                 req.SLOUrl,
		IdPMetadataURL:         req.IdPMetadataURL,
		IdPMetadataXML:         req.IdPMetadataXML,
		IdPEntityID:            req.IdPEntityID,
		IdPSSOUrl:              req.IdPSSOUrl,
		IdPSLOUrl:              req.IdPSLOUrl,
		IdPCertificate:         req.IdPCertificate,
		SPCertificate:          req.SPCertificate,
		SPPrivateKey:           req.SPPrivateKey,
		SPCertificateExpiresAt: req.SPCertificateExpiresAt,
		WantAssertionsSigned:   req.WantAssertionsSigned,
		WantResponseSigned:     req.WantResponseSigned,
		SignRequests:           req.SignRequests,
		ForceAuthn:             req.ForceAuthn,
		CreatedBy:              userID,
	})
	if err != nil {
		h.log.Error().Err(err).Msg("failed to create SSO provider")
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	h.log.Info().
		Str("provider_id", config.ID.String()).
		Str("name", config.Name).
		Bool("is_admin", isAdmin).
		Msg("SSO provider created")

	return c.JSON(http.StatusCreated, h.maskSecrets(config))
}

// @Summary      List SSO Providers
// @Description  Lists all SSO providers for a tenant
// @Tags         auth.admin
// @Security     BearerAuth
// @Produce      json
// @Param        tenant_id  query   string  false  "Tenant ID (UUID)"
// @Success      200        {object}  map[string]interface{}
// @Failure      400        {object}  map[string]string
// @Failure      401        {object}  map[string]string
// @Failure      403        {object}  map[string]string
// @Router       /api/v1/sso/providers [get]
func (h *SSOController) handleListProviders(c echo.Context) error {
	// Check authentication
	_, tenantID, _, err := h.requireAdmin(c)
	if err != nil {
		return err
	}

	// Allow override via query param for admin users
	tenantIDParam := c.QueryParam("tenant_id")
	if tenantIDParam != "" {
		if tid, err := uuid.Parse(tenantIDParam); err == nil {
			tenantID = tid
		}
	}

	// Parse pagination params
	limit := int32(100)
	offset := int32(0)

	configs, err := h.ssoService.ListProviders(c.Request().Context(), tenantID, limit, offset)
	if err != nil {
		h.log.Error().Err(err).Msg("failed to list SSO providers")
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	// Mask secrets in response
	masked := make([]interface{}, len(configs))
	for i, config := range configs {
		masked[i] = h.maskSecrets(config)
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"providers": masked,
		"total":     len(configs),
	})
}

// @Summary      Get SSO Provider
// @Description  Retrieves a single SSO provider by ID
// @Tags         auth.admin
// @Security     BearerAuth
// @Produce      json
// @Param        id  path   string  true  "Provider ID (UUID)"
// @Success      200  {object}  map[string]interface{}
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /api/v1/sso/providers/{id} [get]
func (h *SSOController) handleGetProvider(c echo.Context) error {
	// Check authentication
	_, tenantID, _, err := h.requireAdmin(c)
	if err != nil {
		return err
	}

	providerIDStr := c.Param("id")
	providerID, err := uuid.Parse(providerIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid provider ID"})
	}

	config, err := h.ssoService.GetProvider(c.Request().Context(), tenantID, providerID)
	if err != nil {
		h.log.Error().Err(err).Str("provider_id", providerIDStr).Msg("failed to get SSO provider")
		return c.JSON(http.StatusNotFound, map[string]string{"error": "provider not found"})
	}

	return c.JSON(http.StatusOK, h.maskSecrets(config))
}

// @Summary      Update SSO Provider
// @Description  Updates an existing SSO provider configuration
// @Tags         auth.admin
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        id    path   string                  true  "Provider ID (UUID)"
// @Param        body  body   updateProviderRequest  true  "Updated provider configuration"
// @Success      200   {object}  map[string]interface{}
// @Failure      400   {object}  map[string]string
// @Failure      401   {object}  map[string]string
// @Failure      403   {object}  map[string]string
// @Failure      404   {object}  map[string]string
// @Router       /api/v1/sso/providers/{id} [put]
func (h *SSOController) handleUpdateProvider(c echo.Context) error {
	// Check authentication
	userID, tenantID, _, err := h.requireAdmin(c)
	if err != nil {
		return err
	}

	providerIDStr := c.Param("id")
	providerID, err := uuid.Parse(providerIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid provider ID"})
	}

	var req updateProviderRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	// Parse linking policy if provided
	var linkingPolicy *domain.LinkingPolicy
	if req.LinkingPolicy != nil {
		lp := domain.LinkingPolicy(strings.TrimSpace(*req.LinkingPolicy))
		if !lp.IsValid() {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid linking_policy"})
		}
		linkingPolicy = &lp
	}

	// Build update request
	updateReq := service.UpdateProviderRequest{
		UpdatedBy:              userID,
		Name:                   req.Name,
		Enabled:                req.Enabled,
		AllowSignup:            req.AllowSignup,
		TrustEmailVerified:     req.TrustEmailVerified,
		LinkingPolicy:          linkingPolicy,
		Domains:                req.Domains,
		AttributeMapping:       req.AttributeMapping,
		Issuer:                 req.Issuer,
		AuthorizationEndpoint:  req.AuthorizationEndpoint,
		TokenEndpoint:          req.TokenEndpoint,
		UserinfoEndpoint:       req.UserinfoEndpoint,
		JWKSUri:                req.JWKSUri,
		ClientID:               req.ClientID,
		ClientSecret:           req.ClientSecret,
		Scopes:                 req.Scopes,
		ResponseType:           req.ResponseType,
		ResponseMode:           req.ResponseMode,
		EntityID:               req.EntityID,
		ACSUrl:                 req.ACSUrl,
		SLOUrl:                 req.SLOUrl,
		IdPMetadataURL:         req.IdPMetadataURL,
		IdPMetadataXML:         req.IdPMetadataXML,
		IdPEntityID:            req.IdPEntityID,
		IdPSSOUrl:              req.IdPSSOUrl,
		IdPSLOUrl:              req.IdPSLOUrl,
		IdPCertificate:         req.IdPCertificate,
		SPCertificate:          req.SPCertificate,
		SPPrivateKey:           req.SPPrivateKey,
		SPCertificateExpiresAt: req.SPCertificateExpiresAt,
		WantAssertionsSigned:   req.WantAssertionsSigned,
		WantResponseSigned:     req.WantResponseSigned,
		SignRequests:           req.SignRequests,
		ForceAuthn:             req.ForceAuthn,
	}

	// Update provider
	config, err := h.ssoService.UpdateProvider(c.Request().Context(), tenantID, providerID, updateReq)
	if err != nil {
		h.log.Error().Err(err).Str("provider_id", providerIDStr).Msg("failed to update SSO provider")
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	h.log.Info().
		Str("provider_id", config.ID.String()).
		Str("name", config.Name).
		Msg("SSO provider updated")

	return c.JSON(http.StatusOK, h.maskSecrets(config))
}

// @Summary      Delete SSO Provider
// @Description  Deletes an SSO provider configuration
// @Tags         auth.admin
// @Security     BearerAuth
// @Param        id  path   string  true  "Provider ID (UUID)"
// @Success      204
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /api/v1/sso/providers/{id} [delete]
func (h *SSOController) handleDeleteProvider(c echo.Context) error {
	// Check authentication
	_, tenantID, _, err := h.requireAdmin(c)
	if err != nil {
		return err
	}

	providerIDStr := c.Param("id")
	providerID, err := uuid.Parse(providerIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid provider ID"})
	}

	if err := h.ssoService.DeleteProvider(c.Request().Context(), tenantID, providerID); err != nil {
		h.log.Error().Err(err).Str("provider_id", providerIDStr).Msg("failed to delete SSO provider")
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	return c.NoContent(http.StatusNoContent)
}

// @Summary      Test SSO Provider
// @Description  Tests an SSO provider configuration for connectivity
// @Tags         auth.admin
// @Security     BearerAuth
// @Produce      json
// @Param        id  path   string  true  "Provider ID (UUID)"
// @Success      200  {object}  map[string]interface{}
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /api/v1/sso/providers/{id}/test [post]
func (h *SSOController) handleTestProvider(c echo.Context) error {
	// Check authentication
	_, tenantID, _, err := h.requireAdmin(c)
	if err != nil {
		return err
	}

	providerIDStr := c.Param("id")
	providerID, err := uuid.Parse(providerIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid provider ID"})
	}

	// Load provider
	config, err := h.ssoService.GetProvider(c.Request().Context(), tenantID, providerID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "provider not found"})
	}

	// Get metadata to test connectivity
	metadata, err := h.ssoService.GetProviderMetadata(c.Request().Context(), tenantID, config.Slug)
	if err != nil {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"success":  true,
		"metadata": metadata,
	})
}

// spInfoResponse is the response DTO for GET /api/v1/sso/sp-info.
type spInfoResponse struct {
	EntityID    string `json:"entity_id"`
	ACSURL      string `json:"acs_url"`
	SLOURL      string `json:"slo_url,omitempty"`
	MetadataURL string `json:"metadata_url"`
	LoginURL    string `json:"login_url"`
	BaseURL     string `json:"base_url"`
	TenantID    string `json:"tenant_id"`
}

// handleGetSPInfo returns computed Service Provider URLs for SAML configuration.
// GET /api/v1/sso/sp-info?slug=xxx
// @Summary Get SP Info for SAML configuration
// @Description Returns the computed Service Provider URLs (Entity ID, ACS URL, SLO URL) needed to configure an Identity Provider
// @Tags SSO
// @Accept json
// @Produce json
// @Param slug query string true "Provider slug (e.g. 'okta', 'azure-ad')"
// @Success 200 {object} spInfoResponse
// @Failure 400 {object} map[string]string "Invalid request"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 403 {object} map[string]string "Forbidden"
// @Failure 500 {object} map[string]string "Internal server error"
// @Security BearerAuth
// @Router /api/v1/sso/sp-info [get]
func (h *SSOController) handleGetSPInfo(c echo.Context) error {
	// Check authentication (admin required)
	_, tenantID, _, err := h.requireAdmin(c)
	if err != nil {
		return err
	}

	slug := c.QueryParam("slug")
	if slug == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "slug query parameter is required"})
	}

	// Allow tenant_id override for super-admin use cases
	tenantIDStr := c.QueryParam("tenant_id")
	if tenantIDStr != "" {
		parsedTenantID, parseErr := uuid.Parse(tenantIDStr)
		if parseErr != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
		}
		tenantID = parsedTenantID
	}

	// Get SP info from service using V2 tenant-scoped URLs
	spInfo, err := h.ssoService.GetSPInfo(tenantID, slug)
	if err != nil {
		h.log.Error().Err(err).Str("slug", slug).Str("tenant_id", tenantID.String()).Msg("failed to compute SP info")
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, spInfoResponse{
		EntityID:    spInfo.EntityID,
		ACSURL:      spInfo.ACSURL,
		SLOURL:      spInfo.SLOURL,
		MetadataURL: spInfo.MetadataURL,
		LoginURL:    spInfo.LoginURL,
		BaseURL:     spInfo.BaseURL,
		TenantID:    spInfo.TenantID,
	})
}

// Helper methods

// requireAdmin checks if the request has a valid bearer token with admin role.
func (h *SSOController) requireAdmin(c echo.Context) (userID, tenantID uuid.UUID, isAdmin bool, err error) {
	token := bearerToken(c)
	if token == "" {
		mode := strings.ToLower(strings.TrimSpace(c.Request().Header.Get("X-Auth-Mode")))
		if mode == "cookie" {
			if cookie, cerr := c.Cookie(guardAccessTokenCookieName); cerr == nil && cookie.Value != "" {
				token = cookie.Value
			}
		}
	}
	if token == "" {
		err = c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
		return
	}

	introspection, introErr := h.authService.Introspect(c.Request().Context(), token)
	if introErr != nil || !introspection.Active {
		err = c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
		return
	}

	userID = introspection.UserID
	tenantID = introspection.TenantID

	// Check if user has admin role
	for _, role := range introspection.Roles {
		if strings.EqualFold(role, "admin") {
			isAdmin = true
			break
		}
	}

	if !isAdmin {
		err = c.JSON(http.StatusForbidden, map[string]string{"error": "admin role required"})
		return
	}

	return
}

// bearerToken extracts the bearer token from the Authorization header.
func bearerToken(c echo.Context) string {
	auth := c.Request().Header.Get("Authorization")
	if auth == "" {
		return ""
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}

// maskSecrets masks sensitive fields in the config for API responses.
func (h *SSOController) maskSecrets(config *domain.Config) map[string]interface{} {
	result := map[string]interface{}{
		"id":                   config.ID,
		"tenant_id":            config.TenantID,
		"name":                 config.Name,
		"slug":                 config.Slug,
		"provider_type":        config.ProviderType,
		"enabled":              config.Enabled,
		"allow_signup":         config.AllowSignup,
		"trust_email_verified": config.TrustEmailVerified,
		"domains":              config.Domains,
		"attribute_mapping":    config.AttributeMapping,
		"created_at":           config.CreatedAt,
		"updated_at":           config.UpdatedAt,
	}

	// Include non-secret OIDC fields
	if config.Issuer != "" {
		result["issuer"] = config.Issuer
		result["authorization_endpoint"] = config.AuthorizationEndpoint
		result["token_endpoint"] = config.TokenEndpoint
		result["userinfo_endpoint"] = config.UserinfoEndpoint
		result["jwks_uri"] = config.JWKSUri
		result["client_id"] = config.ClientID
		result["client_secret"] = maskString(config.ClientSecret)
		result["scopes"] = config.Scopes
		result["response_type"] = config.ResponseType
		result["response_mode"] = config.ResponseMode
	}

	// Include non-secret SAML fields
	if config.EntityID != "" {
		result["entity_id"] = config.EntityID
		result["acs_url"] = config.ACSUrl
		result["slo_url"] = config.SLOUrl
		result["idp_metadata_url"] = config.IdPMetadataURL
		result["idp_entity_id"] = config.IdPEntityID
		result["idp_sso_url"] = config.IdPSSOUrl
		result["idp_slo_url"] = config.IdPSLOUrl
		result["want_assertions_signed"] = config.WantAssertionsSigned
		result["want_response_signed"] = config.WantResponseSigned
		result["sign_requests"] = config.SignRequests
		result["force_authn"] = config.ForceAuthn
		// Mask private key
		if config.SPPrivateKey != "" {
			result["sp_private_key"] = "***MASKED***"
		}
		if config.SPCertificate != "" {
			result["sp_certificate"] = config.SPCertificate
		}
		if config.SPCertificateExpiresAt != nil {
			result["sp_certificate_expires_at"] = config.SPCertificateExpiresAt
		}
	}

	return result
}

// maskString partially masks a string for display.
func maskString(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= 8 {
		return "***"
	}
	return fmt.Sprintf("%s...%s", s[:4], s[len(s)-4:])
}
