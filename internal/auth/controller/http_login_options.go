package controller

import (
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	sdomain "github.com/corvusHold/guard/internal/settings/domain"
)

// SSOProviderOption represents an SSO provider available for login
type SSOProviderOption struct {
	Slug         string `json:"slug"`
	Name         string `json:"name"`
	ProviderType string `json:"provider_type"` // "oidc", "saml"
	LogoURL      string `json:"logo_url,omitempty"`
	LoginURL     string `json:"login_url"`
}

// SocialProviderOption represents a social login provider
type SocialProviderOption struct {
	Provider string `json:"provider"` // "google", "github", "microsoft", etc.
	Name     string `json:"name"`
	LogoURL  string `json:"logo_url,omitempty"`
	LoginURL string `json:"login_url"`
}

// LoginOptionsResponse represents the available login options for a user/tenant
type LoginOptionsResponse struct {
	// Authentication methods available
	PasswordEnabled  bool `json:"password_enabled"`
	MagicLinkEnabled bool `json:"magic_link_enabled"`

	// SSO providers configured for this tenant
	SSOProviders []SSOProviderOption `json:"sso_providers"`

	// Social login providers (tenant-wide or global)
	SocialProviders []SocialProviderOption `json:"social_providers"`

	// Recommended/preferred login method based on context
	// Values: "sso", "password", "magic_link"
	PreferredMethod string `json:"preferred_method"`

	// Ordered recommendation list for clients that support adaptive UI.
	// Values: "sso", "password", "magic_link"
	RecommendedMethods []string `json:"recommended_methods,omitempty"`

	// Reason for the top recommendation.
	// Values: "sso_required", "last_successful_method", "domain_matched_sso", "preferred_method", "default_order"
	RecommendedMethodReason string `json:"recommended_method_reason,omitempty"`

	// Last successful login method for this email in this tenant (if known).
	// Values: "sso", "password", "magic_link"
	LastSuccessfulMethod string `json:"last_successful_method,omitempty"`

	// If true, SSO is required for this domain/tenant (password disabled)
	SSORequired bool `json:"sso_required"`

	// Explicit policy flag for SSO-only login UX.
	SSOOnly bool `json:"sso_only,omitempty"`

	// If true, user exists and can use password login
	UserExists bool `json:"user_exists"`

	// Tenant information (if discovered)
	TenantID   string `json:"tenant_id,omitempty"`
	TenantName string `json:"tenant_name,omitempty"`

	// If email is present in multiple tenants, list them so the UI can prompt the user.
	// When multiple tenants are present, tenant_id/tenant_name will only be set when
	// exactly one tenant is resolved; otherwise clients must let the user choose.
	Tenants []TenantInfo `json:"tenants,omitempty"`

	// If email domain matches an SSO provider's configured domains
	DomainMatchedSSO *SSOProviderOption `json:"domain_matched_sso,omitempty"`

	// Whether new user signup is enabled for this tenant
	SignupEnabled bool `json:"signup_enabled"`

	// Tenant logo URL for branding on the login page
	TenantLogoURL string `json:"tenant_logo_url,omitempty"`
}

// GetLoginOptions godoc
// @Summary      Get available login options
// @Description  Returns available authentication methods based on email/tenant context.
//
//	This enables dynamic login UIs that show only relevant options.
//
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        email     query  string  false  "User email for context-aware options"
// @Param        tenant_id query  string  false  "Tenant ID to scope options"
// @Success      200  {object}  LoginOptionsResponse
// @Failure      400  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /api/v1/auth/login-options [get]
func (h *Controller) getLoginOptions(c echo.Context) error {
	email := c.QueryParam("email")
	tenantIDStr := c.QueryParam("tenant_id")

	response := LoginOptionsResponse{
		PasswordEnabled:  true, // Default: password login enabled
		MagicLinkEnabled: true, // Default: magic link enabled
		SignupEnabled:    true, // Default: signup enabled
		SSOProviders:     []SSOProviderOption{},
		SocialProviders:  []SocialProviderOption{},
		PreferredMethod:  "password",
	}

	var tenantID uuid.UUID
	var err error
	var resolvedUserID uuid.UUID
	var hasResolvedUser bool

	// If tenant_id provided, use it directly
	if tenantIDStr != "" {
		tenantID, err = uuid.Parse(tenantIDStr)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
		}
		response.TenantID = tenantIDStr
	}

	// If email provided, try to discover tenant and user
	if email != "" {
		email = strings.TrimSpace(strings.ToLower(email))

		// If no tenant specified, try to discover from email
		if tenantIDStr == "" {
			tenants, discoverErr := h.svc.FindTenantsByUserEmail(c.Request().Context(), email)
			if discoverErr == nil && len(tenants) > 0 {
				response.Tenants = toTenantInfos(tenants)
				response.UserExists = true

				// Only auto-select when exactly one tenant exists to avoid random choice.
				if len(tenants) == 1 {
					tenant := tenants[0]
					var parseErr error
					tenantID, parseErr = uuid.Parse(tenant.ID)
					if parseErr != nil {
						c.Logger().Warnf("invalid tenant ID %s: %v", tenant.ID, parseErr)
					} else {
						response.TenantID = tenant.ID
						response.TenantName = tenant.Name
						user, userErr := h.svc.GetUserByEmail(c.Request().Context(), email, tenant.ID)
						if userErr == nil && user != nil {
							resolvedUserID = user.ID
							hasResolvedUser = true
						}
					}
				}
			}
		} else {
			// Check if user exists in specified tenant
			user, userErr := h.svc.GetUserByEmail(c.Request().Context(), email, tenantIDStr)
			if userErr == nil && user != nil {
				response.UserExists = true
				resolvedUserID = user.ID
				hasResolvedUser = true
			}
		}
	}

	// If we have a tenant, fetch tenant-scoped settings
	if tenantID != uuid.Nil && h.settings != nil {
		if signupStr, sErr := h.settings.GetString(c.Request().Context(), sdomain.KeySignupEnabled, &tenantID, "true"); sErr == nil {
			response.SignupEnabled = signupStr != "false"
		}
		if ssoRequiredStr, sErr := h.settings.GetString(c.Request().Context(), sdomain.KeySSORequired, &tenantID, "false"); sErr == nil {
			response.SSORequired = strings.EqualFold(strings.TrimSpace(ssoRequiredStr), "true")
		}
		if logoURL, lErr := h.settings.GetString(c.Request().Context(), sdomain.KeyTenantLogoURL, &tenantID, ""); lErr == nil {
			response.TenantLogoURL = logoURL
		}
	}

	// If we have a tenant, get SSO providers
	if tenantID != uuid.Nil {
		providers, listErr := h.svc.ListSSOProvidersPublic(c.Request().Context(), tenantID)
		if listErr != nil {
			c.Logger().Warnf("failed to list SSO providers for tenant %s: %v", tenantID, listErr)
		}
		if listErr == nil {
			// Extract domain from email for SSO matching
			emailDomain := ""
			if email != "" {
				if atIdx := strings.LastIndex(email, "@"); atIdx > 0 {
					emailDomain = email[atIdx+1:]
				}
			}

			for _, p := range providers {
				opt := SSOProviderOption{
					Slug:         p.Slug,
					Name:         p.Name,
					ProviderType: p.ProviderType,
					LoginURL:     buildSSOLoginURL(h.cfg.PublicBaseURL, tenantID.String(), p.Slug),
					LogoURL:      getSSOProviderLogo(p.Name, p.ProviderType),
				}

				response.SSOProviders = append(response.SSOProviders, opt)

				// Check if email domain matches this provider's configured domains
				if emailDomain != "" && len(p.Domains) > 0 {
					for _, domain := range p.Domains {
						if strings.EqualFold(domain, emailDomain) {
							matchedOpt := opt
							response.DomainMatchedSSO = &matchedOpt
							response.PreferredMethod = "sso"
							break
						}
					}
				}
			}
		}
	}

	hasSSO := response.DomainMatchedSSO != nil || len(response.SSOProviders) > 0
	if response.SSORequired {
		response.PasswordEnabled = false
		response.MagicLinkEnabled = false
		response.SSOOnly = hasSSO
		if !hasSSO {
			response.PreferredMethod = ""
		}
	}

	if tenantID != uuid.Nil && hasResolvedUser {
		sessions, sessErr := h.svc.ListUserSessions(c.Request().Context(), resolvedUserID, tenantID)
		if sessErr == nil {
			var latestAt time.Time
			for _, sess := range sessions {
				method := normalizeLoginMethod(sess.AuthMethod)
				if method == "" {
					continue
				}

				sessionAt := sess.CreatedAt
				if sess.LastUsedAt != nil && sess.LastUsedAt.After(sessionAt) {
					sessionAt = *sess.LastUsedAt
				}

				if response.LastSuccessfulMethod == "" || sessionAt.After(latestAt) {
					latestAt = sessionAt
					response.LastSuccessfulMethod = method
				}
			}
		}
	}

	available := map[string]bool{
		"sso":        hasSSO,
		"password":   response.PasswordEnabled,
		"magic_link": response.MagicLinkEnabled,
	}

	recommended := make([]string, 0, 3)
	addRecommended := func(method string) {
		m := normalizeLoginMethod(method)
		if m == "" || !available[m] {
			return
		}
		for _, existing := range recommended {
			if existing == m {
				return
			}
		}
		recommended = append(recommended, m)
	}

	if response.SSORequired && hasSSO {
		addRecommended("sso")
		response.RecommendedMethodReason = "sso_required"
	}
	if response.LastSuccessfulMethod != "" {
		addRecommended(response.LastSuccessfulMethod)
		if response.RecommendedMethodReason == "" {
			response.RecommendedMethodReason = "last_successful_method"
		}
	}
	if response.DomainMatchedSSO != nil {
		addRecommended("sso")
		if response.RecommendedMethodReason == "" {
			response.RecommendedMethodReason = "domain_matched_sso"
		}
	}
	if response.PreferredMethod != "" {
		addRecommended(response.PreferredMethod)
		if response.RecommendedMethodReason == "" {
			response.RecommendedMethodReason = "preferred_method"
		}
	}

	addRecommended("sso")
	addRecommended("password")
	addRecommended("magic_link")

	if len(recommended) > 0 {
		response.RecommendedMethods = recommended
		response.PreferredMethod = recommended[0]
		if response.RecommendedMethodReason == "" {
			response.RecommendedMethodReason = "default_order"
		}
	} else {
		response.PreferredMethod = ""
		response.RecommendedMethodReason = ""
	}

	return c.JSON(http.StatusOK, response)
}

func normalizeLoginMethod(method string) string {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "sso":
		return "sso"
	case "password":
		return "password"
	case "magic_link", "magic", "magic-link":
		return "magic_link"
	default:
		return ""
	}
}

// buildSSOLoginURL constructs the V2 tenant-scoped SSO login URL
func buildSSOLoginURL(baseURL, tenantID, slug string) string {
	if baseURL == "" {
		return ""
	}
	return strings.TrimRight(baseURL, "/") + "/api/v1/auth/sso/t/" + tenantID + "/" + slug + "/login"
}

// getSSOProviderLogo returns a local asset path based on provider name.
// Uses curated local/static assets to avoid leaking client metadata and external dependencies.
func getSSOProviderLogo(name, providerType string) string {
	nameLower := strings.ToLower(name)

	// Map provider keys to local asset paths (served from our domain)
	logoMap := map[string]string{
		"okta":      "/assets/sso/okta.svg",
		"azure":     "/assets/sso/azure.svg",
		"microsoft": "/assets/sso/microsoft.svg",
		"google":    "/assets/sso/google.svg",
		"onelogin":  "/assets/sso/onelogin.svg",
		"ping":      "/assets/sso/ping.svg",
		"auth0":     "/assets/sso/auth0.svg",
		"jumpcloud": "/assets/sso/jumpcloud.svg",
		"duo":       "/assets/sso/duo.svg",
	}

	for key, path := range logoMap {
		if strings.Contains(nameLower, key) {
			return path
		}
	}

	// Generic fallback icon for unknown providers (SAML, OIDC, or other)
	if providerType == "saml" {
		return "/assets/sso/saml-generic.svg"
	}

	// Default SSO/OIDC fallback
	return "/assets/sso/sso-generic.svg"
}
