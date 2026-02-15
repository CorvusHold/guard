package controller

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	authdomain "github.com/corvusHold/guard/internal/auth/domain"
	"github.com/corvusHold/guard/internal/auth/keys"
	authmw "github.com/corvusHold/guard/internal/auth/middleware"
	"github.com/corvusHold/guard/internal/config"
	"github.com/corvusHold/guard/internal/oauth/domain"
	"github.com/corvusHold/guard/internal/oauth/service"
	sdomain "github.com/corvusHold/guard/internal/settings/domain"

	"github.com/golang-jwt/jwt/v5"
)

// Controller handles OAuth 2.0 HTTP endpoints.
type Controller struct {
	svc      *service.Service
	authSvc  authdomain.Service
	settings sdomain.Service
	cfg      config.Config
	keyMgr   *keys.Manager
	rlToken  echo.MiddlewareFunc // rate limiter for /oauth/token
	rlAuth   echo.MiddlewareFunc // rate limiter for /oauth/authorize
}

// New creates a new OAuth controller.
func New(svc *service.Service, authSvc authdomain.Service, settings sdomain.Service, cfg config.Config, keyMgr *keys.Manager) *Controller {
	return &Controller{
		svc:      svc,
		authSvc:  authSvc,
		settings: settings,
		cfg:      cfg,
		keyMgr:   keyMgr,
	}
}

// WithRateLimits sets rate limit middleware for OAuth endpoints.
func (h *Controller) WithRateLimits(rlToken, rlAuth echo.MiddlewareFunc) *Controller {
	h.rlToken = rlToken
	h.rlAuth = rlAuth
	return h
}

// RegisterAdminRoutes registers OAuth client admin CRUD routes.
func (h *Controller) RegisterAdminRoutes(g *echo.Group) {
	g.POST("/oauth-clients", h.createClient)
	g.GET("/oauth-clients", h.listClients)
	g.GET("/oauth-clients/:id", h.getClient)
	g.PATCH("/oauth-clients/:id", h.updateClient)
	g.DELETE("/oauth-clients/:id", h.deleteClient)
}

// RegisterOAuthRoutes registers the public OAuth 2.0 endpoints.
func (h *Controller) RegisterOAuthRoutes(e *echo.Echo) {
	var authMW, tokenMW []echo.MiddlewareFunc
	if h.rlAuth != nil {
		authMW = append(authMW, h.rlAuth)
	}
	if h.rlToken != nil {
		tokenMW = append(tokenMW, h.rlToken)
	}
	e.GET("/oauth/authorize", h.authorize, authMW...)
	e.POST("/oauth/authorize/decision", h.authorizeDecision, authMW...)
	e.POST("/oauth/token", h.token, tokenMW...)
	e.POST("/oauth/revoke", h.revokeToken, tokenMW...)
}

// --- Admin CRUD ---

type createClientReq struct {
	Name         string   `json:"name" validate:"required"`
	ClientType   string   `json:"client_type" validate:"omitempty,oneof=confidential public"`
	RedirectURIs []string `json:"redirect_uris" validate:"required,min=1"`
	Scopes       []string `json:"scopes"`
	GrantTypes   []string `json:"grant_types"`
	LogoURI      string   `json:"logo_uri"`
}

type createClientResp struct {
	Client       domain.OAuthClient `json:"client"`
	ClientSecret string             `json:"client_secret,omitempty"`
}

// @Summary      Create OAuth client
// @Description  Registers a new OAuth 2.0 client application
// @Tags         auth.admin
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        body  body  createClientReq  true  "Client configuration"
// @Success      201  {object}  createClientResp
// @Failure      400  {object}  map[string]string
// @Router       /api/v1/auth/admin/oauth-clients [post]
func (h *Controller) createClient(c echo.Context) error {
	var req createClientReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	tenantID, err := extractTenantID(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	userID, _ := extractUserID(c)

	client, rawSecret, err := h.svc.CreateClient(c.Request().Context(), domain.CreateOAuthClientInput{
		TenantID:     tenantID,
		Name:         req.Name,
		ClientType:   req.ClientType,
		RedirectURIs: req.RedirectURIs,
		Scopes:       req.Scopes,
		GrantTypes:   req.GrantTypes,
		LogoURI:      req.LogoURI,
		CreatedBy:    userID,
	})
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusCreated, createClientResp{
		Client:       client,
		ClientSecret: rawSecret,
	})
}

// @Summary      List OAuth clients
// @Description  Returns all OAuth clients for the tenant
// @Tags         auth.admin
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Success      200  {object}  map[string]interface{}
// @Failure      401  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /api/v1/auth/admin/oauth-clients [get]
func (h *Controller) listClients(c echo.Context) error {
	tenantID, err := extractTenantID(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	clients, err := h.svc.ListClients(c.Request().Context(), tenantID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list clients"})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{"clients": clients})
}

// @Summary      Get OAuth client
// @Description  Returns a single OAuth client by ID
// @Tags         auth.admin
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        id  path  string  true  "Client UUID"
// @Success      200  {object}  domain.OAuthClient
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /api/v1/auth/admin/oauth-clients/{id} [get]
func (h *Controller) getClient(c echo.Context) error {
	tenantID, err := extractTenantID(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}

	client, err := h.svc.GetClient(c.Request().Context(), id, tenantID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "client not found"})
	}

	return c.JSON(http.StatusOK, client)
}

type updateClientReq struct {
	Name         *string  `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
	GrantTypes   []string `json:"grant_types"`
	LogoURI      *string  `json:"logo_uri"`
	IsActive     *bool    `json:"is_active"`
}

// @Summary      Update OAuth client
// @Description  Updates an existing OAuth client
// @Tags         auth.admin
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        id    path  string           true  "Client UUID"
// @Param        body  body  updateClientReq  true  "Fields to update"
// @Success      200  {object}  map[string]string
// @Failure      400  {object}  map[string]string
// @Router       /api/v1/auth/admin/oauth-clients/{id} [patch]
func (h *Controller) updateClient(c echo.Context) error {
	tenantID, err := extractTenantID(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}

	var req updateClientReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	if err := h.svc.UpdateClient(c.Request().Context(), id, tenantID, domain.UpdateOAuthClientInput{
		Name:         req.Name,
		RedirectURIs: req.RedirectURIs,
		Scopes:       req.Scopes,
		GrantTypes:   req.GrantTypes,
		LogoURI:      req.LogoURI,
		IsActive:     req.IsActive,
	}); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "updated"})
}

// @Summary      Delete OAuth client
// @Description  Deletes an OAuth client
// @Tags         auth.admin
// @Security     BearerAuth
// @Accept       json
// @Param        id  path  string  true  "Client UUID"
// @Success      204
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Router       /api/v1/auth/admin/oauth-clients/{id} [delete]
func (h *Controller) deleteClient(c echo.Context) error {
	tenantID, err := extractTenantID(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}

	if err := h.svc.DeleteClient(c.Request().Context(), id, tenantID); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	return c.NoContent(http.StatusNoContent)
}

// --- OAuth 2.0 Endpoints ---

// @Summary      OAuth 2.0 Authorization
// @Description  Initiates the OAuth 2.0 authorization code flow (RFC 6749 §4.1.1). Returns consent screen data or redirects if consent was previously granted.
// @Tags         OAuth
// @Accept       application/x-www-form-urlencoded
// @Produce      json
// @Param        client_id             query  string  true   "Client ID"
// @Param        redirect_uri          query  string  true   "Redirect URI"
// @Param        response_type         query  string  true   "Response type (must be 'code')"
// @Param        scope                 query  string  false  "Space-separated scopes"
// @Param        state                 query  string  false  "CSRF state parameter"
// @Param        nonce                 query  string  false  "Nonce for ID token replay protection"
// @Param        code_challenge        query  string  false  "PKCE code challenge"
// @Param        code_challenge_method query  string  false  "PKCE method (S256)"
// @Success      200  {object}  map[string]interface{}  "Consent screen data"
// @Success      302  "Redirect with authorization code"
// @Failure      400  {object}  map[string]string
// @Router       /oauth/authorize [get]
func (h *Controller) authorize(c echo.Context) error {
	in := domain.AuthorizeInput{
		ClientID:            c.QueryParam("client_id"),
		RedirectURI:         c.QueryParam("redirect_uri"),
		ResponseType:        c.QueryParam("response_type"),
		Scope:               c.QueryParam("scope"),
		State:               c.QueryParam("state"),
		Nonce:               c.QueryParam("nonce"),
		CodeChallenge:       c.QueryParam("code_challenge"),
		CodeChallengeMethod: c.QueryParam("code_challenge_method"),
	}

	client, err := h.svc.ValidateAuthorizeRequest(c.Request().Context(), in)
	if err != nil {
		// If redirect_uri is invalid or client_id is bad, we can't redirect — show error directly
		if in.RedirectURI == "" || strings.Contains(err.Error(), "redirect_uri") || strings.Contains(err.Error(), "client_id") {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		// Otherwise redirect with error
		return redirectWithError(c, in.RedirectURI, in.State, "invalid_request", err.Error())
	}

	// Check if user is authenticated (JWT in Authorization header or cookie)
	userID, tenantID, authenticated := h.extractAuthFromRequest(c)
	if !authenticated {
		// Redirect to login page with return_to
		loginURL := h.buildLoginURL(c)
		return c.Redirect(http.StatusFound, loginURL)
	}

	in.UserID = userID
	in.TenantID = tenantID

	scopes := strings.Fields(in.Scope)
	if len(scopes) == 0 {
		scopes = []string{domain.ScopeOpenID}
	}

	// Skip consent if user has previously approved these scopes for this client
	if h.svc.HasConsent(c.Request().Context(), userID, tenantID, in.ClientID, scopes) {
		result, err := h.svc.CreateAuthorizationCode(c.Request().Context(), in)
		if err != nil {
			return redirectWithError(c, in.RedirectURI, in.State, "server_error", "failed to create authorization code")
		}
		u, err := url.Parse(result.RedirectURI)
		if err != nil {
			return redirectWithError(c, in.RedirectURI, in.State, "server_error", "invalid redirect URI")
		}
		q := u.Query()
		q.Set("code", result.Code)
		if result.State != "" {
			q.Set("state", result.State)
		}
		u.RawQuery = q.Encode()
		return c.Redirect(http.StatusFound, u.String())
	}

	scopeDetails := make([]map[string]string, 0, len(scopes))
	for _, s := range scopes {
		desc, ok := domain.ScopeDescriptions[s]
		if !ok {
			desc = s
		}
		scopeDetails = append(scopeDetails, map[string]string{"scope": s, "description": desc})
	}

	// Generate CSRF consent challenge token
	consentChallenge := h.generateConsentChallenge(userID, in.ClientID)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"consent_required": true,
		"client": map[string]interface{}{
			"name":     client.Name,
			"logo_uri": client.LogoURI,
		},
		"scopes":                scopeDetails,
		"consent_challenge":     consentChallenge,
		"client_id":             in.ClientID,
		"redirect_uri":          in.RedirectURI,
		"response_type":         in.ResponseType,
		"scope":                 in.Scope,
		"state":                 in.State,
		"nonce":                 in.Nonce,
		"code_challenge":        in.CodeChallenge,
		"code_challenge_method": in.CodeChallengeMethod,
	})
}

type authorizeDecisionReq struct {
	Approved            bool   `json:"approved"`
	ConsentChallenge    string `json:"consent_challenge" validate:"required"`
	ClientID            string `json:"client_id" validate:"required"`
	RedirectURI         string `json:"redirect_uri" validate:"required"`
	ResponseType        string `json:"response_type" validate:"required"`
	Scope               string `json:"scope"`
	State               string `json:"state"`
	Nonce               string `json:"nonce"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

// @Summary      OAuth 2.0 Authorization Decision
// @Description  Processes the user's consent decision (approve or deny) for an OAuth authorization request.
// @Tags         OAuth
// @Accept       json
// @Produce      json
// @Param        body  body  authorizeDecisionReq  true  "Consent decision"
// @Success      302  "Redirect with authorization code or error"
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Router       /oauth/authorize/decision [post]
func (h *Controller) authorizeDecision(c echo.Context) error {
	var req authorizeDecisionReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	if !req.Approved {
		// Require a valid client_id to prevent open redirects
		if req.ClientID == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid client_id"})
		}
		// Validate redirect_uri against registered client before redirecting
		client, err := h.svc.GetClientByClientID(c.Request().Context(), req.ClientID)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid client_id"})
		}
		validURI := false
		for _, uri := range client.RedirectURIs {
			if uri == req.RedirectURI {
				validURI = true
				break
			}
		}
		if !validURI {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid redirect_uri"})
		}
		return redirectWithError(c, req.RedirectURI, req.State, "access_denied", "user denied the request")
	}

	userID, tenantID, authenticated := h.extractAuthFromRequest(c)
	if !authenticated {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "not authenticated"})
	}

	// Verify CSRF consent challenge
	if !h.verifyConsentChallenge(req.ConsentChallenge, userID, req.ClientID) {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "invalid or expired consent challenge"})
	}

	in := domain.AuthorizeInput{
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		ResponseType:        req.ResponseType,
		Scope:               req.Scope,
		State:               req.State,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		UserID:              userID,
		TenantID:            tenantID,
	}

	// Re-validate the request; if the error is about redirect_uri or client_id,
	// return a JSON error instead of redirecting to an unvalidated URI.
	if _, err := h.svc.ValidateAuthorizeRequest(c.Request().Context(), in); err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "redirect_uri") || strings.Contains(errMsg, "client_id") || strings.Contains(errMsg, "client is deactivated") {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": errMsg})
		}
		return redirectWithError(c, req.RedirectURI, req.State, "invalid_request", errMsg)
	}

	// Create authorization code
	result, err := h.svc.CreateAuthorizationCode(c.Request().Context(), in)
	if err != nil {
		return redirectWithError(c, req.RedirectURI, req.State, "server_error", "failed to create authorization code")
	}

	// Persist consent so future requests skip the consent screen
	scopes := strings.Fields(req.Scope)
	if len(scopes) == 0 {
		scopes = []string{domain.ScopeOpenID}
	}
	_ = h.svc.SaveConsent(c.Request().Context(), userID, tenantID, req.ClientID, scopes)

	// Redirect with code
	redirectURL, err := url.Parse(result.RedirectURI)
	if err != nil {
		return redirectWithError(c, req.RedirectURI, req.State, "server_error", "invalid redirect URI")
	}
	q := redirectURL.Query()
	q.Set("code", result.Code)
	if result.State != "" {
		q.Set("state", result.State)
	}
	redirectURL.RawQuery = q.Encode()

	return c.Redirect(http.StatusFound, redirectURL.String())
}

// @Summary      Revoke Token
// @Description  Revokes an OAuth 2.0 token (RFC 7009). Accepts refresh_token or access_token.
// @Tags         OAuth
// @Accept       application/x-www-form-urlencoded
// @Produce      json
// @Param        token            formData  string  true   "The token to revoke"
// @Param        token_type_hint  formData  string  false  "Token type hint (refresh_token or access_token)"
// @Success      200  {object}  map[string]string
// @Failure      400  {object}  map[string]string
// @Router       /oauth/revoke [post]
func (h *Controller) revokeToken(c echo.Context) error {
	token := c.FormValue("token")
	if token == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "token is required",
		})
	}

	tokenTypeHint := c.FormValue("token_type_hint")
	if tokenTypeHint == "" {
		tokenTypeHint = "refresh_token"
	}

	// Delegate to the existing auth service revocation
	if err := h.authSvc.Revoke(c.Request().Context(), token, tokenTypeHint); err != nil {
		// Per RFC 7009 §2.2, the server responds with 200 even if the token is invalid
		// Only return error for truly unexpected failures
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

// @Summary      OAuth 2.0 Token Exchange
// @Description  Exchanges an authorization code, client credentials, or refresh token for access tokens (RFC 6749 §3.2).
// @Tags         OAuth
// @Accept       application/x-www-form-urlencoded
// @Produce      json
// @Param        grant_type     formData  string  true   "Grant type (authorization_code, client_credentials, refresh_token)"
// @Param        code           formData  string  false  "Authorization code (for authorization_code grant)"
// @Param        redirect_uri   formData  string  false  "Redirect URI (for authorization_code grant)"
// @Param        client_id      formData  string  false  "Client ID"
// @Param        client_secret  formData  string  false  "Client secret"
// @Param        code_verifier  formData  string  false  "PKCE code verifier"
// @Param        refresh_token  formData  string  false  "Refresh token (for refresh_token grant)"
// @Param        scope          formData  string  false  "Requested scopes"
// @Success      200  {object}  domain.TokenResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Router       /oauth/token [post]
func (h *Controller) token(c echo.Context) error {
	grantType := c.FormValue("grant_type")

	// Also support client auth from Basic header
	clientID, clientSecret := extractClientAuth(c)

	switch grantType {
	case "authorization_code":
		return h.tokenAuthorizationCode(c, clientID, clientSecret)
	case "client_credentials":
		return h.tokenClientCredentials(c, clientID, clientSecret)
	case "refresh_token":
		return h.tokenRefreshToken(c, clientID, clientSecret)
	default:
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "unsupported_grant_type",
			"error_description": "grant_type must be authorization_code, client_credentials, or refresh_token",
		})
	}
}

func (h *Controller) tokenAuthorizationCode(c echo.Context, clientID, clientSecret string) error {
	// Allow client_id from form if not in Basic auth
	if clientID == "" {
		clientID = c.FormValue("client_id")
	}
	if clientSecret == "" {
		clientSecret = c.FormValue("client_secret")
	}

	req := domain.TokenRequest{
		GrantType:    "authorization_code",
		Code:         c.FormValue("code"),
		RedirectURI:  c.FormValue("redirect_uri"),
		ClientID:     clientID,
		ClientSecret: clientSecret,
		CodeVerifier: c.FormValue("code_verifier"),
	}

	code, client, err := h.svc.ExchangeAuthorizationCode(c.Request().Context(), req)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "invalid_grant",
			"error_description": "authorization code exchange failed",
		})
	}

	// Issue tokens using the auth service
	tokens, err := h.authSvc.IssueTokensForSSO(c.Request().Context(), authdomain.SSOTokenInput{
		UserID:    code.UserID,
		TenantID:  code.TenantID,
		UserAgent: c.Request().UserAgent(),
		IP:        c.RealIP(),
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": "failed to issue tokens",
		})
	}

	accessTTL, _ := h.settings.GetDuration(c.Request().Context(), sdomain.KeyAccessTTL, &code.TenantID, h.cfg.AccessTokenTTL)

	resp := domain.TokenResponse{
		AccessToken:  tokens.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(accessTTL.Seconds()),
		RefreshToken: tokens.RefreshToken,
		Scope:        strings.Join(code.Scopes, " "),
	}

	// Issue ID token if openid scope was requested
	if containsScope(code.Scopes, domain.ScopeOpenID) {
		idToken, err := h.issueIDToken(c, code.UserID, code.TenantID, client.ClientID, code.Nonce, code.Scopes)
		if err == nil {
			resp.IDToken = idToken
		}
	}

	return c.JSON(http.StatusOK, resp)
}

func (h *Controller) tokenClientCredentials(c echo.Context, clientID, clientSecret string) error {
	if clientID == "" {
		clientID = c.FormValue("client_id")
	}
	if clientSecret == "" {
		clientSecret = c.FormValue("client_secret")
	}

	client, err := h.svc.AuthenticateClient(c.Request().Context(), clientID, clientSecret)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error":             "invalid_client",
			"error_description": "client authentication failed",
		})
	}

	scope := c.FormValue("scope")
	scopes := strings.Fields(scope)
	if len(scopes) == 0 {
		scopes = client.Scopes
	} else {
		// Validate that every requested scope is allowed for this client
		for _, s := range scopes {
			if !containsScope(client.Scopes, s) {
				return c.JSON(http.StatusBadRequest, map[string]string{
					"error":             "invalid_scope",
					"error_description": "requested scope '" + s + "' not allowed for this client",
				})
			}
		}
	}

	// Issue a machine-to-machine access token
	accessTTL, _ := h.settings.GetDuration(c.Request().Context(), sdomain.KeyAccessTTL, &client.TenantID, h.cfg.AccessTokenTTL)
	signingKey, _ := h.settings.GetString(c.Request().Context(), sdomain.KeyJWTSigning, &client.TenantID, h.cfg.JWTSigningKey)
	issuer, _ := h.settings.GetString(c.Request().Context(), sdomain.KeyJWTIssuer, &client.TenantID, h.cfg.PublicBaseURL)

	claims := jwt.MapClaims{
		"sub":       client.ClientID,
		"ten":       client.TenantID.String(),
		"iss":       issuer,
		"aud":       client.ClientID,
		"exp":       time.Now().Add(accessTTL).Unix(),
		"iat":       time.Now().Unix(),
		"scope":     strings.Join(scopes, " "),
		"client_id": client.ClientID,
		"grant":     "client_credentials",
	}

	accessToken, err := h.signJWTClaims(claims, signingKey)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": "failed to sign token",
		})
	}

	return c.JSON(http.StatusOK, domain.TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(accessTTL.Seconds()),
		Scope:       strings.Join(scopes, " "),
	})
}

func (h *Controller) tokenRefreshToken(c echo.Context, clientID, clientSecret string) error {
	if clientID == "" {
		clientID = c.FormValue("client_id")
	}
	if clientSecret == "" {
		clientSecret = c.FormValue("client_secret")
	}

	refreshToken := c.FormValue("refresh_token")
	if refreshToken == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "refresh_token is required",
		})
	}

	// Authenticate the client if credentials are provided (confidential clients)
	if clientID != "" {
		_, err := h.svc.AuthenticateClient(c.Request().Context(), clientID, clientSecret)
		if err != nil {
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error":             "invalid_client",
				"error_description": "client authentication failed",
			})
		}
	}

	// Delegate to the existing auth service refresh flow
	tokens, err := h.authSvc.Refresh(c.Request().Context(), authdomain.RefreshInput{
		RefreshToken: refreshToken,
		UserAgent:    c.Request().UserAgent(),
		IP:           c.RealIP(),
	})
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "invalid_grant",
			"error_description": "invalid or expired refresh token",
		})
	}

	accessTTL, _ := h.settings.GetDuration(c.Request().Context(), sdomain.KeyAccessTTL, nil, h.cfg.AccessTokenTTL)

	return c.JSON(http.StatusOK, domain.TokenResponse{
		AccessToken:  tokens.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(accessTTL.Seconds()),
		RefreshToken: tokens.RefreshToken,
	})
}

// issueIDToken creates an OIDC ID Token.
func (h *Controller) issueIDToken(c echo.Context, userID, tenantID uuid.UUID, clientID, nonce string, scopes []string) (string, error) {
	signingKey, _ := h.settings.GetString(c.Request().Context(), sdomain.KeyJWTSigning, &tenantID, h.cfg.JWTSigningKey)
	issuer, _ := h.settings.GetString(c.Request().Context(), sdomain.KeyJWTIssuer, &tenantID, h.cfg.PublicBaseURL)

	claims := jwt.MapClaims{
		"iss":       issuer,
		"sub":       userID.String(),
		"aud":       clientID,
		"exp":       time.Now().Add(time.Hour).Unix(),
		"iat":       time.Now().Unix(),
		"auth_time": time.Now().Unix(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}

	// Fetch user profile for profile/email claims
	if containsScope(scopes, domain.ScopeProfile) || containsScope(scopes, domain.ScopeEmail) {
		profile, err := h.authSvc.Me(c.Request().Context(), userID, tenantID)
		if err == nil {
			if containsScope(scopes, domain.ScopeProfile) {
				claims["name"] = strings.TrimSpace(profile.FirstName + " " + profile.LastName)
				claims["given_name"] = profile.FirstName
				claims["family_name"] = profile.LastName
			}
			if containsScope(scopes, domain.ScopeEmail) {
				claims["email"] = profile.Email
				claims["email_verified"] = profile.EmailVerified
			}
		}
	}

	return h.signJWTClaims(claims, signingKey)
}

// signJWTClaims signs JWT claims using the configured key manager or HMAC fallback.
func (h *Controller) signJWTClaims(claims jwt.MapClaims, signingKey string) (string, error) {
	var signingMethod jwt.SigningMethod
	var signKey interface{}
	if h.keyMgr != nil && h.keyMgr.IsAsymmetric() {
		signingMethod = h.keyMgr.SigningMethod()
		signKey = h.keyMgr.SigningKey(signingKey)
	} else {
		signingMethod = jwt.SigningMethodHS256
		signKey = []byte(signingKey)
	}
	t := jwt.NewWithClaims(signingMethod, claims)
	if h.keyMgr != nil && h.keyMgr.IsAsymmetric() {
		t.Header["kid"] = h.keyMgr.KeyID()
	}
	return t.SignedString(signKey)
}

// --- Helpers ---

func (h *Controller) extractAuthFromRequest(c echo.Context) (uuid.UUID, uuid.UUID, bool) {
	// Try Authorization header
	auth := c.Request().Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		tokenStr := strings.TrimPrefix(auth, "Bearer ")
		userID, tenantID, ok := h.parseAccessToken(c.Request().Context(), tokenStr)
		if ok {
			return userID, tenantID, true
		}
	}

	// Try cookie
	cookie, err := c.Cookie("guard_access_token")
	if err == nil && cookie.Value != "" {
		userID, tenantID, ok := h.parseAccessToken(c.Request().Context(), cookie.Value)
		if ok {
			return userID, tenantID, true
		}
	}

	return uuid.Nil, uuid.Nil, false
}

func (h *Controller) parseAccessToken(ctx context.Context, tokenStr string) (uuid.UUID, uuid.UUID, bool) {
	// Verify the JWT signature via the auth service — these routes are NOT behind auth middleware.
	introspection, err := h.authSvc.Introspect(ctx, tokenStr)
	if err != nil || !introspection.Active {
		return uuid.Nil, uuid.Nil, false
	}
	if introspection.UserID == uuid.Nil || introspection.TenantID == uuid.Nil {
		return uuid.Nil, uuid.Nil, false
	}
	return introspection.UserID, introspection.TenantID, true
}

func (h *Controller) buildLoginURL(c echo.Context) string {
	baseURL := strings.TrimRight(h.cfg.PublicBaseURL, "/")
	reqScheme := "https"
	if c.Request().TLS == nil {
		reqScheme = "http"
	}
	guardBaseURL := reqScheme + "://" + c.Request().Host
	if baseURL == "" {
		baseURL = guardBaseURL
	}
	returnTo := c.Request().URL.String()
	q := url.Values{}
	q.Set("return_to", returnTo)
	q.Set("guard-base-url", guardBaseURL)
	q.Set("auth-mode", h.cfg.DefaultAuthMode)
	return baseURL + "/login?" + q.Encode()
}

func extractTenantID(c echo.Context) (uuid.UUID, error) {
	if id, ok := authmw.TenantID(c); ok {
		return id, nil
	}
	return uuid.Nil, fmt.Errorf("tenant_id not found")
}

func extractUserID(c echo.Context) (uuid.UUID, error) {
	if id, ok := authmw.UserID(c); ok {
		return id, nil
	}
	return uuid.Nil, fmt.Errorf("user_id not found")
}

func extractClientAuth(c echo.Context) (string, string) {
	// Try Basic auth header first
	auth := c.Request().Header.Get("Authorization")
	if strings.HasPrefix(auth, "Basic ") {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
		if err == nil {
			parts := strings.SplitN(string(decoded), ":", 2)
			if len(parts) == 2 {
				// RFC 6749 §2.3.1: URL-decode client_id and client_secret
				cid, err1 := url.QueryUnescape(parts[0])
				csec, err2 := url.QueryUnescape(parts[1])
				if err1 != nil || err2 != nil {
					return "", ""
				}
				return cid, csec
			}
		}
	}
	return "", ""
}

func redirectWithError(c echo.Context, redirectURI, state, errorCode, description string) error {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": errorCode, "error_description": description})
	}
	q := u.Query()
	q.Set("error", errorCode)
	q.Set("error_description", description)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return c.Redirect(http.StatusFound, u.String())
}

const consentChallengeTTL = 10 * time.Minute

// generateConsentChallenge creates an HMAC-based CSRF token binding user + client + time.
// Format: base64(timestamp + "." + hmac)
func (h *Controller) generateConsentChallenge(userID uuid.UUID, clientID string) string {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(h.cfg.JWTSigningKey))
	mac.Write([]byte(userID.String() + ":" + clientID + ":" + ts))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return base64.RawURLEncoding.EncodeToString([]byte(ts + "." + sig))
}

// verifyConsentChallenge validates the CSRF consent challenge token.
func (h *Controller) verifyConsentChallenge(challenge string, userID uuid.UUID, clientID string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(challenge)
	if err != nil {
		return false
	}
	parts := strings.SplitN(string(raw), ".", 2)
	if len(parts) != 2 {
		return false
	}
	ts, sig := parts[0], parts[1]

	// Check expiry
	tsInt, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return false
	}
	if time.Since(time.Unix(tsInt, 0)) > consentChallengeTTL {
		return false
	}

	// Recompute HMAC
	mac := hmac.New(sha256.New, []byte(h.cfg.JWTSigningKey))
	mac.Write([]byte(userID.String() + ":" + clientID + ":" + ts))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(sig), []byte(expectedSig))
}

func containsScope(scopes []string, scope string) bool {
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}
