package controller

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	domain "github.com/corvusHold/guard/internal/auth/domain"
	sdomain "github.com/corvusHold/guard/internal/settings/domain"
	"github.com/corvusHold/guard/internal/platform/ratelimit"
	"github.com/corvusHold/guard/internal/platform/validation"
	"github.com/corvusHold/guard/internal/config"
)

type Controller struct {
	svc   domain.Service
	magic domain.MagicLinkService
	sso   domain.SSOService
	// optional rate limit dependencies
	settings sdomain.Service
	rl       ratelimit.Store
	cfg      config.Config
}

// magicTokenForTest issues a magic link token without sending email. Test/CI only.
func (h *Controller) magicTokenForTest(c echo.Context) error {
    // Only allow in non-production environments
    if strings.EqualFold(h.cfg.AppEnv, "production") {
        return c.NoContent(http.StatusNotFound)
    }
    var req magicSendReq
    if err := c.Bind(&req); err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
    }
    if err := c.Validate(&req); err != nil {
        return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err))
    }
    tenID, err := uuid.Parse(req.TenantID)
    if err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
    }
    tok, err := h.magic.CreateForTest(c.Request().Context(), domain.MagicSendInput{
        TenantID:    tenID,
        Email:       req.Email,
        RedirectURL: req.RedirectURL,
    })
    if err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
    }
    return c.JSON(http.StatusOK, magicTokenResp{Token: tok})
}

// New constructs controller with loaded config (backward compatible for tests).
func New(svc domain.Service, magic domain.MagicLinkService, sso domain.SSOService) *Controller {
    cfg, _ := config.Load()
    return NewWithConfig(svc, magic, sso, cfg)
}

// NewWithConfig allows passing explicit config.
func NewWithConfig(svc domain.Service, magic domain.MagicLinkService, sso domain.SSOService, cfg config.Config) *Controller {
    return &Controller{svc: svc, magic: magic, sso: sso, cfg: cfg}
}

// WithRateLimit enables tenant-aware, store-backed rate limiting when provided.
func (h *Controller) WithRateLimit(settings sdomain.Service, store ratelimit.Store) *Controller {
	h.settings = settings
	h.rl = store
	return h
}

// Register mounts all auth routes under /v1/auth with multi-method structure.
func (h *Controller) Register(e *echo.Echo) {
	g := e.Group("/v1/auth")

	// Rate limits (fixed-window, per-tenant-or-IP)
	mkPolicy := func(prefix string, limKey, winKey string, defLim int, defWin time.Duration) ratelimit.Policy {
		p := ratelimit.Policy{Window: defWin, Limit: defLim, Key: ratelimit.KeyTenantOrIP(prefix)}
		p.Name = prefix
		if h.settings != nil {
			p.WindowFunc = func(c echo.Context) time.Duration {
				// extract tenant_id from query
				var tid *uuid.UUID
				if v := c.QueryParam("tenant_id"); v != "" {
					v = strings.TrimPrefix(v, "rl-")
					if id, err := uuid.Parse(v); err == nil { tid = &id }
				}
				d, _ := h.settings.GetDuration(c.Request().Context(), winKey, tid, defWin)
				return d
			}
			p.LimitFunc = func(c echo.Context) int {
				var tid *uuid.UUID
				if v := c.QueryParam("tenant_id"); v != "" {
					v = strings.TrimPrefix(v, "rl-")
					if id, err := uuid.Parse(v); err == nil { tid = &id }
				}
				n, _ := h.settings.GetInt(c.Request().Context(), limKey, tid, defLim)
				return n
			}
		}
		return p
	}
	mkMW := func(p ratelimit.Policy) echo.MiddlewareFunc {
		if h.rl != nil { return ratelimit.MiddlewareWithStore(p, h.rl) }
		return ratelimit.Middleware(p)
	}

	rlSignup := mkMW(mkPolicy("auth:signup", sdomain.KeyRLSignupLimit, sdomain.KeyRLSignupWindow, 2, time.Minute))
	rlLogin := mkMW(mkPolicy("auth:login", sdomain.KeyRLLoginLimit, sdomain.KeyRLLoginWindow, 2, time.Minute))
	rlMagic := mkMW(mkPolicy("auth:magic", sdomain.KeyRLMagicLimit, sdomain.KeyRLMagicWindow, 5, time.Minute))
	rlToken := mkMW(mkPolicy("auth:token", sdomain.KeyRLTokenLimit, sdomain.KeyRLTokenWindow, 10, time.Minute))
	rlMFA := mkMW(mkPolicy("auth:mfa", sdomain.KeyRLMFALimit, sdomain.KeyRLMFAWindow, 10, time.Minute))
	rlSSO := mkMW(mkPolicy("auth:sso", sdomain.KeyRLSsoLimit, sdomain.KeyRLSsoWindow, 10, time.Minute))

	// Password-based auth
	g.POST("/password/signup", h.signup, rlSignup)
	g.POST("/password/login", h.login, rlLogin)
	g.POST("/password/reset/request", h.resetPasswordRequest)
	g.POST("/password/reset/confirm", h.resetPasswordConfirm)

	// Magic-link auth
	g.POST("/magic/send", h.sendMagic, rlMagic)
	g.POST("/magic/verify", h.verifyMagic, rlMagic)
	g.GET("/magic/verify", h.verifyMagic, rlMagic)
	// Test-only: fetch raw magic token (only in non-production envs)
	g.POST("/magic/token", h.magicTokenForTest, rlMagic)

	// SSO / Social providers
	g.GET("/sso/:provider/start", h.ssoStart, rlSSO)
	g.GET("/sso/:provider/callback", h.ssoCallback, rlSSO)

	// Token lifecycle
	g.POST("/refresh", h.refresh, rlToken)
	g.POST("/logout", h.logout, rlToken)
	g.GET("/me", h.me, rlToken)
	g.POST("/introspect", h.introspect, rlToken)
	g.POST("/revoke", h.revoke, rlToken)

	// MFA: TOTP + Backup codes
	g.POST("/mfa/totp/start", h.totpStart, rlMFA)
	g.POST("/mfa/totp/activate", h.totpActivate, rlMFA)
	g.POST("/mfa/totp/disable", h.totpDisable, rlMFA)
	g.POST("/mfa/backup/generate", h.backupGenerate, rlMFA)
	g.POST("/mfa/backup/consume", h.backupConsume, rlMFA)
	g.GET("/mfa/backup/count", h.backupCount, rlMFA)
	g.POST("/mfa/verify", h.verifyMFA, rlMFA)
}

type signupReq struct {
	TenantID  string `json:"tenant_id" validate:"required,uuid4"`
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required,min=8"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

type loginReq struct {
	TenantID string `json:"tenant_id" validate:"required,uuid4"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type refreshReq struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

type tokensResp struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type introspectReq struct {
	Token string `json:"token" validate:"omitempty"`
}

type revokeReq struct {
	Token     string `json:"token" validate:"required"`
	TokenType string `json:"token_type" validate:"required"`
}

type magicSendReq struct {
	TenantID    string `json:"tenant_id" validate:"required,uuid4"`
	Email       string `json:"email" validate:"required,email"`
	RedirectURL string `json:"redirect_url" validate:"omitempty,url"`
}

type magicVerifyReq struct {
	Token string `json:"token" validate:"required"`
}

type magicTokenResp struct {
	Token string `json:"token"`
}

type mfaTOTPStartResp struct {
	Secret     string `json:"secret"`
	OtpauthURL string `json:"otpauth_url"`
}

type mfaTOTPActivateReq struct {
	Code string `json:"code" validate:"required"`
}

type mfaBackupGenerateReq struct {
	Count int `json:"count" validate:"omitempty,min=1,max=20"`
}

type mfaBackupGenerateResp struct {
	Codes []string `json:"codes"`
}

type mfaBackupConsumeReq struct {
	Code string `json:"code" validate:"required"`
}

type mfaBackupConsumeResp struct {
	Consumed bool `json:"consumed"`
}

type mfaBackupCountResp struct {
	Count int64 `json:"count"`
}

type mfaChallengeResp struct {
	ChallengeToken string   `json:"challenge_token"`
	Methods        []string `json:"methods"`
}

type mfaVerifyReq struct {
	ChallengeToken string `json:"challenge_token" validate:"required"`
	Code           string `json:"code" validate:"required"`
	Method         string `json:"method" validate:"required,oneof=totp backup_code"`
}

type resetPasswordRequestReq struct {
	TenantID string `json:"tenant_id" validate:"required,uuid4"`
	Email    string `json:"email" validate:"required,email"`
}

type resetPasswordConfirmReq struct {
	TenantID    string `json:"tenant_id" validate:"required,uuid4"`
	Token       string `json:"token" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=8"`
}

func bearerToken(c echo.Context) string {
	h := c.Request().Header.Get("Authorization")
	if h == "" { return "" }
	parts := strings.SplitN(h, " ", 2)
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return parts[1]
	}
	return ""
}

// Signup godoc
// @Summary      Password signup
// @Description  Creates a new user for a tenant with email and password and returns access/refresh tokens
// @Tags         auth.password
// @Accept       json
// @Produce      json
// @Param        body  body  signupReq  true  "tenant_id, email, password, optional first/last name"
// @Success      201   {object}  tokensResp
// @Failure      400   {object}  map[string]string
// @Failure      429   {object}  map[string]string
// @Router       /v1/auth/password/signup [post]
func (h *Controller) signup(c echo.Context) error {
	var req signupReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err))
	}
	tenID, err := uuid.Parse(req.TenantID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
	}
	tok, err := h.svc.Signup(c.Request().Context(), domain.SignupInput{
		TenantID:  tenID,
		Email:     req.Email,
		Password:  req.Password,
		FirstName: req.FirstName,
		LastName:  req.LastName,
	})
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusCreated, tokensResp{AccessToken: tok.AccessToken, RefreshToken: tok.RefreshToken})
}

// Password Login godoc
// @Summary      Password login
// @Description  Logs in with email/password. If MFA is enabled for the user, responds 202 with a challenge to complete via /v1/auth/mfa/verify.
// @Tags         auth.password
// @Accept       json
// @Produce      json
// @Param        body  body  loginReq  true  "email/password"
// @Success      200   {object}  tokensResp
// @Success      202   {object}  mfaChallengeResp
// @Failure      400   {object}  map[string]string
// @Failure      401   {object}  map[string]string
// @Failure      429   {object}  map[string]string
// @Router       /v1/auth/password/login [post]
func (h *Controller) login(c echo.Context) error {
	var req loginReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err))
	}
	tenID, err := uuid.Parse(req.TenantID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
	}
	ua := c.Request().UserAgent()
	ip := c.RealIP()
	tok, err := h.svc.Login(c.Request().Context(), domain.LoginInput{
		TenantID:  tenID,
		Email:     req.Email,
		Password:  req.Password,
		UserAgent: ua,
		IP:        ip,
	})
	if err != nil {
		var mfaErr domain.ErrMFARequired
		if errors.As(err, &mfaErr) {
			return c.JSON(http.StatusAccepted, mfaChallengeResp{ChallengeToken: mfaErr.ChallengeToken, Methods: mfaErr.Methods})
		}
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, tokensResp{AccessToken: tok.AccessToken, RefreshToken: tok.RefreshToken})
}

// Refresh godoc
// @Summary      Refresh access token
// @Description  Exchanges a refresh token for new access and refresh tokens
// @Tags         auth.tokens
// @Accept       json
// @Produce      json
// @Param        body  body  refreshReq  true  "refresh_token"
// @Success      200   {object}  tokensResp
// @Failure      400   {object}  map[string]string
// @Failure      401   {object}  map[string]string
// @Failure      429   {object}  map[string]string
// @Router       /v1/auth/refresh [post]
func (h *Controller) refresh(c echo.Context) error {
	var req refreshReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err))
	}
	ua := c.Request().UserAgent()
	ip := c.RealIP()
	tok, err := h.svc.Refresh(c.Request().Context(), domain.RefreshInput{RefreshToken: req.RefreshToken, UserAgent: ua, IP: ip})
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, tokensResp{AccessToken: tok.AccessToken, RefreshToken: tok.RefreshToken})
}

// Logout godoc
// @Summary      Logout (revoke refresh token)
// @Description  Revokes the provided refresh token if present; idempotent
// @Tags         auth.tokens
// @Accept       json
// @Param        body  body  refreshReq  false  "refresh_token (optional)"
// @Success      204
// @Failure      400  {object}  map[string]string
// @Failure      429  {object}  map[string]string
// @Router       /v1/auth/logout [post]
func (h *Controller) logout(c echo.Context) error {
	var req refreshReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if req.RefreshToken == "" {
		return c.NoContent(http.StatusNoContent)
	}
	if err := h.svc.Logout(c.Request().Context(), req.RefreshToken); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.NoContent(http.StatusNoContent)
}

// Me godoc
// @Summary      Get current user's profile
// @Description  Returns the authenticated user's profile derived from the access token
// @Tags         auth.profile
// @Security     BearerAuth
// @Produce      json
// @Success      200  {object}  domain.UserProfile
// @Failure      401  {object}  map[string]string
// @Failure      429  {object}  map[string]string
// @Router       /v1/auth/me [get]
func (h *Controller) me(c echo.Context) error {
	tok := bearerToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}
	prof, err := h.svc.Me(c.Request().Context(), in.UserID, in.TenantID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, prof)
}

// Introspect godoc
// @Summary      Introspect access token
// @Description  Validate and parse JWT token either from Authorization header or request body
// @Tags         auth.introspect
// @Accept       json
// @Produce      json
// @Param        token  body      introspectReq  false  "Token in body; otherwise uses Authorization Bearer"
// @Success      200    {object}  domain.Introspection
// @Failure      400    {object}  map[string]string
// @Failure      401    {object}  map[string]string
// @Failure      429    {object}  map[string]string
// @Router       /v1/auth/introspect [post]
func (h *Controller) introspect(c echo.Context) error {
	var req introspectReq
	_ = c.Bind(&req) // optional body
	tok := req.Token
	if tok == "" {
		tok = bearerToken(c)
	}
	if tok == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "token required"})
	}
	out, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil {
		// return inactive with error message for clarity
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, out)
}

// Revoke godoc
// @Summary      Revoke token
// @Description  Revoke a token; currently supports token_type="refresh"
// @Tags         auth.tokens
// @Accept       json
// @Param        body  body  revokeReq  true  "token and token_type=refresh"
// @Success      204
// @Failure      400  {object}  map[string]string
// @Failure      429  {object}  map[string]string
// @Router       /v1/auth/revoke [post]
func (h *Controller) revoke(c echo.Context) error {
	var req revokeReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err))
	}
	if err := h.svc.Revoke(c.Request().Context(), req.Token, req.TokenType); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.NoContent(http.StatusNoContent)
}

// ---- Password reset (stubs) ----
// Password Reset Request godoc
// @Summary      Request password reset
// @Description  Requests a password reset for the given email address
// @Tags         auth.password
// @Accept       json
// @Produce      json
// @Param        body  body  resetPasswordRequestReq  true  "tenant_id, email"
// @Success      202
// @Failure      400  {object}  map[string]string
// @Failure      429  {object}  map[string]string
// @Router       /v1/auth/password/reset/request [post]
func (h *Controller) resetPasswordRequest(c echo.Context) error {
	var req resetPasswordRequestReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err))
	}
	// Stub: endpoint contract established; implementation pending
	return c.NoContent(http.StatusAccepted)
}

// Password Reset Confirm godoc
// @Summary      Confirm password reset
// @Description  Resets the password for the given email address
// @Tags         auth.password
// @Accept       json
// @Produce      json
// @Param        body  body  resetPasswordConfirmReq  true  "tenant_id, token, new_password"
// @Success      200
// @Failure      400  {object}  map[string]string
// @Failure      429  {object}  map[string]string
// @Router       /v1/auth/password/reset/confirm [post]
func (h *Controller) resetPasswordConfirm(c echo.Context) error {
	var req resetPasswordConfirmReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err))
	}
	// Stub: endpoint contract established; implementation pending
	return c.NoContent(http.StatusOK)
}

// ---- Magic link ----
// Magic Send godoc
// @Summary      Send magic login link
// @Description  Sends a single-use magic login link to the user's email
// @Tags         auth.magic
// @Accept       json
// @Param        body  body  magicSendReq  true  "tenant_id, email, optional redirect_url"
// @Success      202
// @Failure      400  {object}  map[string]string
// @Failure      429  {object}  map[string]string
// @Router       /v1/auth/magic/send [post]
func (h *Controller) sendMagic(c echo.Context) error {
	var req magicSendReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err))
	}
	tenID, err := uuid.Parse(req.TenantID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
	}
	if err := h.magic.Send(c.Request().Context(), domain.MagicSendInput{
		TenantID: tenID,
		Email:    req.Email,
		RedirectURL: req.RedirectURL,
	}); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.NoContent(http.StatusAccepted)
}

// Magic Verify godoc
// @Summary      Verify magic link token
// @Description  Verifies magic link token from query parameter or request body and returns tokens
// @Tags         auth.magic
// @Accept       json
// @Produce      json
// @Param        token  query  string        false  "Magic token (alternative to body)"
// @Param        body   body   magicVerifyReq  false  "Magic token in JSON body"
// @Success      200    {object}  tokensResp
// @Failure      400    {object}  map[string]string
// @Failure      401    {object}  map[string]string
// @Failure      429    {object}  map[string]string
// @Router       /v1/auth/magic/verify [get]
// @Router       /v1/auth/magic/verify [post]
func (h *Controller) verifyMagic(c echo.Context) error {
	// accept ?token=... or JSON body
	token := c.QueryParam("token")
	if token == "" {
		var req magicVerifyReq
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
		}
		if err := c.Validate(&req); err != nil {
			return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err))
		}
		token = req.Token
	}
	ua := c.Request().UserAgent()
	ip := c.RealIP()
	toks, err := h.magic.Verify(c.Request().Context(), domain.MagicVerifyInput{Token: token, UserAgent: ua, IP: ip})
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, tokensResp{AccessToken: toks.AccessToken, RefreshToken: toks.RefreshToken})
}

// ---- SSO/Social (stubs) ----
var allowedProviders = map[string]struct{}{
	"google":   {},
	"github":   {},
	"azuread":  {},
}

// SSO Start godoc
// @Summary      Start SSO/OAuth flow
// @Description  Initiates an SSO flow for the given provider and redirects to the provider authorization URL
// @Tags         auth.sso
// @Param        provider         path      string  true   "SSO provider (google, github, azuread)"
// @Param        tenant_id        query     string  true   "Tenant ID (UUID)"
// @Param        redirect_url     query     string  false  "Absolute redirect URL after callback"
// @Param        state            query     string  false  "Opaque state to round-trip"
// @Param        connection_id    query     string  false  "Provider connection identifier"
// @Param        organization_id  query     string  false  "Organization identifier"
// @Success      302
// @Failure      400  {object}  map[string]string
// @Router       /v1/auth/sso/{provider}/start [get]
func (h *Controller) ssoStart(c echo.Context) error {
	p := c.Param("provider")
	if _, ok := allowedProviders[p]; !ok {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "unsupported provider"})
	}
	// Query: tenant_id, redirect_url, state(optional), connection_id(optional), organization_id(optional)
	tenIDStr := c.QueryParam("tenant_id")
	redir := c.QueryParam("redirect_url")
	state := c.QueryParam("state")
	connID := c.QueryParam("connection_id")
	orgID := c.QueryParam("organization_id")
	// Ensure redirect is absolute if provided
	if redir != "" {
		if _, err := url.ParseRequestURI(redir); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid redirect_url"})
		}
	}
	tenID, err := uuid.Parse(tenIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
	}
	authURL, err := h.sso.Start(c.Request().Context(), domain.SSOStartInput{Provider: p, TenantID: tenID, RedirectURL: redir, State: state, ConnectionID: connID, OrganizationID: orgID})
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.Redirect(http.StatusFound, authURL)
}

// SSO Callback godoc
// @Summary      Handle SSO/OAuth callback
// @Description  Completes SSO flow and returns access/refresh tokens
// @Tags         auth.sso
// @Param        provider  path   string  true  "SSO provider (google, github, azuread)"
// @Produce      json
// @Success      200  {object}  tokensResp
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Router       /v1/auth/sso/{provider}/callback [get]
func (h *Controller) ssoCallback(c echo.Context) error {
	p := c.Param("provider")
	if _, ok := allowedProviders[p]; !ok {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "unsupported provider"})
	}
	toks, err := h.sso.Callback(c.Request().Context(), domain.SSOCallbackInput{Provider: p, Query: c.QueryParams(), UserAgent: c.Request().UserAgent(), IP: c.RealIP()})
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, tokensResp{AccessToken: toks.AccessToken, RefreshToken: toks.RefreshToken})
}

// ---- MFA: TOTP ----

// TOTP Start godoc
// @Summary      Start TOTP enrollment
// @Description  Generates and stores a TOTP secret (disabled) and returns the secret and otpauth URL
// @Tags         auth.mfa.totp
// @Security     BearerAuth
// @Produce      json
// @Success      200  {object}  mfaTOTPStartResp
// @Failure      401  {object}  map[string]string
// @Router       /v1/auth/mfa/totp/start [post]
func (h *Controller) totpStart(c echo.Context) error {
	tok := bearerToken(c)
	if tok == "" { return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"}) }
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active { return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"}) }
	secret, url, err := h.svc.StartTOTPEnrollment(c.Request().Context(), in.UserID, in.TenantID)
	if err != nil { return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()}) }
	return c.JSON(http.StatusOK, mfaTOTPStartResp{Secret: secret, OtpauthURL: url})
}

// TOTP Activate godoc
// @Summary      Activate TOTP
// @Description  Verifies a TOTP code for the stored secret and enables MFA
// @Tags         auth.mfa.totp
// @Security     BearerAuth
// @Accept       json
// @Param        body  body  mfaTOTPActivateReq  true  "TOTP code"
// @Success      204
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      429  {object}  map[string]string
// @Router       /v1/auth/mfa/totp/activate [post]
func (h *Controller) totpActivate(c echo.Context) error {
	var req mfaTOTPActivateReq
	if err := c.Bind(&req); err != nil { return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"}) }
	if err := c.Validate(&req); err != nil { return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err)) }
	tok := bearerToken(c)
	if tok == "" { return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"}) }
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active { return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"}) }
	if err := h.svc.ActivateTOTP(c.Request().Context(), in.UserID, req.Code); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.NoContent(http.StatusNoContent)
}

// TOTP Disable godoc
// @Summary      Disable TOTP
// @Description  Disables TOTP for the user
// @Tags         auth.mfa.totp
// @Security     BearerAuth
// @Success      204
// @Failure      401  {object}  map[string]string
// @Failure      429  {object}  map[string]string
// @Router       /v1/auth/mfa/totp/disable [post]
func (h *Controller) totpDisable(c echo.Context) error {
	tok := bearerToken(c)
	if tok == "" { return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"}) }
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active { return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"}) }
	if err := h.svc.DisableTOTP(c.Request().Context(), in.UserID); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.NoContent(http.StatusNoContent)
}

// ---- MFA: Backup Codes ----

// Backup Generate godoc
// @Summary      Generate MFA backup codes
// @Description  Generates backup codes, stores their hashes, and returns the codes
// @Tags         auth.mfa.backup
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        body  body  mfaBackupGenerateReq  false  "count (default 10, max 20)"
// @Success      200  {object}  mfaBackupGenerateResp
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      429  {object}  map[string]string
// @Router       /v1/auth/mfa/backup/generate [post]
func (h *Controller) backupGenerate(c echo.Context) error {
	var req mfaBackupGenerateReq
	_ = c.Bind(&req) // optional body
	if req.Count == 0 { req.Count = 10 }
	if err := c.Validate(&req); err != nil { return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err)) }
	tok := bearerToken(c)
	if tok == "" { return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"}) }
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active { return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"}) }
	codes, err := h.svc.GenerateBackupCodes(c.Request().Context(), in.UserID, req.Count)
	if err != nil { return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()}) }
	return c.JSON(http.StatusOK, mfaBackupGenerateResp{Codes: codes})
}

// Backup Consume godoc
// @Summary      Consume an MFA backup code
// @Description  Consumes a single-use backup code
// @Tags         auth.mfa.backup
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        body  body  mfaBackupConsumeReq  true  "backup code"
// @Success      200  {object}  mfaBackupConsumeResp
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      429  {object}  map[string]string
// @Router       /v1/auth/mfa/backup/consume [post]
func (h *Controller) backupConsume(c echo.Context) error {
	var req mfaBackupConsumeReq
	if err := c.Bind(&req); err != nil { return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"}) }
	if err := c.Validate(&req); err != nil { return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err)) }
	tok := bearerToken(c)
	if tok == "" { return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"}) }
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active { return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"}) }
	ok, err := h.svc.ConsumeBackupCode(c.Request().Context(), in.UserID, req.Code)
	if err != nil { return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()}) }
	return c.JSON(http.StatusOK, mfaBackupConsumeResp{Consumed: ok})
}

// Backup Count godoc
// @Summary      Count remaining MFA backup codes
// @Description  Returns number of unused backup codes
// @Tags         auth.mfa.backup
// @Security     BearerAuth
// @Produce      json
// @Success      200  {object}  mfaBackupCountResp
// @Failure      401  {object}  map[string]string
// @Failure      429  {object}  map[string]string
// @Router       /v1/auth/mfa/backup/count [get]
func (h *Controller) backupCount(c echo.Context) error {
	tok := bearerToken(c)
	if tok == "" { return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"}) }
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active { return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"}) }
	n, err := h.svc.CountRemainingBackupCodes(c.Request().Context(), in.UserID)
	if err != nil { return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()}) }
	return c.JSON(http.StatusOK, mfaBackupCountResp{Count: n})
}

// ---- MFA: Challenge Verify ----

// Verify MFA godoc
// @Summary      Verify MFA challenge
// @Description  Verifies a TOTP or backup code against a challenge token and returns access/refresh tokens.
// @Tags         auth.mfa
// @Accept       json
// @Produce      json
// @Param        body  body  mfaVerifyReq  true  "challenge_token, method, and code"
// @Success      200   {object}  tokensResp
// @Failure      400   {object}  map[string]string
// @Failure      401   {object}  map[string]string
// @Failure      429   {object}  map[string]string
// @Router       /v1/auth/mfa/verify [post]
func (h *Controller) verifyMFA(c echo.Context) error {
	var req mfaVerifyReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err))
	}
	ua := c.Request().UserAgent()
	ip := c.RealIP()
	// Optional debug log to confirm handler execution and tenant key context
	if os.Getenv("RATELIMIT_DEBUG") != "" {
		c.Logger().Infof("verifyMFA entered: tenant_id_q=%s ua=%s ip=%s", c.QueryParam("tenant_id"), ua, ip)
	}
	toks, err := h.svc.VerifyMFA(c.Request().Context(), domain.MFAVerifyInput{
		ChallengeToken: req.ChallengeToken,
		Method:         req.Method,
		Code:           req.Code,
		UserAgent:      ua,
		IP:             ip,
	})
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, tokensResp{AccessToken: toks.AccessToken, RefreshToken: toks.RefreshToken})
}
