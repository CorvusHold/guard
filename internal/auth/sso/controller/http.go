package controller

import (
	"fmt"
	"net/http"
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
	if rlInitiate != nil {
		e.GET("/auth/sso/:slug/login", h.handleSSOInitiate, rlInitiate)
	} else {
		e.GET("/auth/sso/:slug/login", h.handleSSOInitiate)
	}

	if rlCallback != nil {
		e.GET("/auth/sso/:slug/callback", h.handleSSOCallback, rlCallback)
		e.POST("/auth/sso/:slug/callback", h.handleSSOCallback, rlCallback) // SAML POST binding
	} else {
		e.GET("/auth/sso/:slug/callback", h.handleSSOCallback)
		e.POST("/auth/sso/:slug/callback", h.handleSSOCallback)
	}

	e.GET("/auth/sso/:slug/metadata", h.handleSAMLMetadata)

	// Admin API endpoints (authentication required)
	admin := e.Group("/v1/sso")
	admin.POST("/providers", h.handleCreateProvider)
	admin.GET("/providers", h.handleListProviders)
	admin.GET("/providers/:id", h.handleGetProvider)
	admin.PUT("/providers/:id", h.handleUpdateProvider)
	admin.DELETE("/providers/:id", h.handleDeleteProvider)
	admin.POST("/providers/:id/test", h.handleTestProvider)
}

// Public SSO Endpoints

// handleSSOInitiate initiates an SSO login flow.
// GET /auth/sso/:slug/login?tenant_id=xxx&redirect_url=xxx
func (h *SSOController) handleSSOInitiate(c echo.Context) error {
	slug := c.Param("slug")
	if slug == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "provider slug is required"})
	}

	tenantIDStr := c.QueryParam("tenant_id")
	if tenantIDStr == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "tenant_id is required"})
	}

	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
	}

	redirectURL := c.QueryParam("redirect_url")
	loginHint := c.QueryParam("login_hint")
	forceAuthn := c.QueryParam("force_authn") == "true"

	// Get client IP and user agent
	ipAddress := c.RealIP()
	userAgent := c.Request().UserAgent()

	// Initiate SSO
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
		h.log.Error().Err(err).Str("slug", slug).Msg("failed to initiate SSO")
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	// Redirect to authorization URL
	return c.Redirect(http.StatusFound, resp.AuthorizationURL)
}

// handleSSOCallback handles the SSO callback from the identity provider.
// GET/POST /auth/sso/:slug/callback
func (h *SSOController) handleSSOCallback(c echo.Context) error {
	slug := c.Param("slug")
	if slug == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "provider slug is required"})
	}

	tenantIDStr := c.QueryParam("tenant_id")
	if tenantIDStr == "" {
		// Try to get from form for SAML POST binding
		tenantIDStr = c.FormValue("tenant_id")
	}
	if tenantIDStr == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "tenant_id is required"})
	}

	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
	}

	// Extract callback parameters
	code := c.QueryParam("code")
	state := c.QueryParam("state")
	samlResponse := c.FormValue("SAMLResponse")
	relayState := c.FormValue("RelayState")

	// Get client IP and user agent
	ipAddress := c.RealIP()
	userAgent := c.Request().UserAgent()

	// Handle callback
	resp, err := h.ssoService.HandleCallback(c.Request().Context(), service.CallbackRequest{
		TenantID:     tenantID,
		ProviderSlug: slug,
		Code:         code,
		State:        state,
		SAMLResponse: samlResponse,
		RelayState:   relayState,
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
	})
	if err != nil {
		h.log.Error().Err(err).Str("slug", slug).Msg("SSO callback failed")
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	// Issue access and refresh tokens for the SSO user
	// We use IssueTokensForSSO which is a new method we'll add to the auth service
	tokens, err := h.authService.IssueTokensForSSO(c.Request().Context(), authdomain.SSOTokenInput{
		UserID:    resp.User.ID,
		TenantID:  tenantID,
		UserAgent: userAgent,
		IP:        ipAddress,
	})
	if err != nil {
		h.log.Error().Err(err).Msg("failed to issue tokens for SSO user")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create session"})
	}

	h.log.Info().
		Str("user_id", resp.User.ID.String()).
		Str("email", resp.Profile.Email).
		Bool("is_new_user", resp.IsNewUser).
		Msg("SSO login successful")

	// Store OIDC refresh token if provided (for token refresh)
	if resp.Profile.RefreshToken != "" {
		h.log.Debug().Msg("storing OIDC refresh token for future use")
		// TODO: Store this in the database for later use
	}

	// Return response in the same format as other auth endpoints
	return c.JSON(http.StatusOK, map[string]interface{}{
		"access_token":  tokens.AccessToken,
		"refresh_token": tokens.RefreshToken,
	})
}

// handleSAMLMetadata returns SAML SP metadata.
// GET /auth/sso/:slug/metadata
func (h *SSOController) handleSAMLMetadata(c echo.Context) error {
	slug := c.Param("slug")
	if slug == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "provider slug is required"})
	}

	tenantIDStr := c.QueryParam("tenant_id")
	if tenantIDStr == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "tenant_id is required"})
	}

	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
	}

	// Get provider metadata
	metadata, err := h.ssoService.GetProviderMetadata(c.Request().Context(), tenantID, slug)
	if err != nil {
		h.log.Error().Err(err).Str("slug", slug).Msg("failed to get provider metadata")
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	// Return XML for SAML, JSON for OIDC
	if metadata.MetadataXML != "" {
		return c.XMLBlob(http.StatusOK, []byte(metadata.MetadataXML))
	}

	return c.JSON(http.StatusOK, metadata)
}

// Admin API Endpoints

// handleCreateProvider creates a new SSO provider.
// POST /v1/sso/providers
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

// handleListProviders lists all SSO providers for a tenant.
// GET /v1/sso/providers?tenant_id=xxx
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

// handleGetProvider retrieves a single SSO provider.
// GET /v1/sso/providers/:id
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

// handleUpdateProvider updates an existing SSO provider.
// PUT /v1/sso/providers/:id
func (h *SSOController) handleUpdateProvider(c echo.Context) error {
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

	var req updateProviderRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	// Build update request
	updateReq := service.UpdateProviderRequest{
		Name:                   req.Name,
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

// handleDeleteProvider deletes an SSO provider.
// DELETE /v1/sso/providers/:id
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

// handleTestProvider tests an SSO provider configuration.
// POST /v1/sso/providers/:id/test
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

// Helper methods

// requireAdmin checks if the request has a valid bearer token with admin role.
func (h *SSOController) requireAdmin(c echo.Context) (userID, tenantID uuid.UUID, isAdmin bool, err error) {
	token := bearerToken(c)
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
