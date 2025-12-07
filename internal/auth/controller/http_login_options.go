package controller

import (
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
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
	// Values: "sso", "password", "magic_link", "social"
	PreferredMethod string `json:"preferred_method"`

	// If true, SSO is required for this domain/tenant (password disabled)
	SSORequired bool `json:"sso_required"`

	// If true, user exists and can use password login
	UserExists bool `json:"user_exists"`

	// Tenant information (if discovered)
	TenantID   string `json:"tenant_id,omitempty"`
	TenantName string `json:"tenant_name,omitempty"`

	// If email domain matches an SSO provider's configured domains
	DomainMatchedSSO *SSOProviderOption `json:"domain_matched_sso,omitempty"`
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
// @Router       /v1/auth/login-options [get]
func (h *Controller) getLoginOptions(c echo.Context) error {
	email := c.QueryParam("email")
	tenantIDStr := c.QueryParam("tenant_id")

	response := LoginOptionsResponse{
		PasswordEnabled:  true, // Default: password login enabled
		MagicLinkEnabled: true, // Default: magic link enabled
		SSOProviders:     []SSOProviderOption{},
		SocialProviders:  []SocialProviderOption{},
		PreferredMethod:  "password",
	}

	var tenantID uuid.UUID
	var err error

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
				// Use first tenant found
				tenant := tenants[0]
				tenantID, _ = uuid.Parse(tenant.ID)
				response.TenantID = tenant.ID
				response.TenantName = tenant.Name
				response.UserExists = true
			}
		} else {
			// Check if user exists in specified tenant
			_, userErr := h.svc.GetUserByEmail(c.Request().Context(), email, tenantIDStr)
			if userErr == nil {
				response.UserExists = true
			}
		}
	}

	// If we have a tenant, get SSO providers
	if tenantID != uuid.Nil {
		providers, listErr := h.svc.ListSSOProvidersPublic(c.Request().Context(), tenantID)
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

	// Determine preferred method based on context
	if response.DomainMatchedSSO != nil {
		response.PreferredMethod = "sso"
		// Check if SSO is enforced for this domain (could be a tenant setting)
		// For now, we don't enforce - just recommend
	} else if len(response.SSOProviders) > 0 && !response.UserExists {
		// New user with SSO available - suggest SSO
		response.PreferredMethod = "sso"
	} else if response.UserExists {
		// Existing user - password is fine
		response.PreferredMethod = "password"
	}

	return c.JSON(http.StatusOK, response)
}

// buildSSOLoginURL constructs the V2 tenant-scoped SSO login URL
func buildSSOLoginURL(baseURL, tenantID, slug string) string {
	if baseURL == "" {
		return ""
	}
	return baseURL + "/auth/sso/t/" + tenantID + "/" + slug + "/login"
}

// getSSOProviderLogo returns a logo URL based on provider name
func getSSOProviderLogo(name, providerType string) string {
	nameLower := strings.ToLower(name)

	// Common identity providers
	logoMap := map[string]string{
		"okta":      "https://www.okta.com/sites/default/files/Okta_Logo_BrightBlue_Medium.png",
		"azure":     "https://upload.wikimedia.org/wikipedia/commons/a/a8/Microsoft_Azure_Logo.svg",
		"microsoft": "https://upload.wikimedia.org/wikipedia/commons/4/44/Microsoft_logo.svg",
		"google":    "https://upload.wikimedia.org/wikipedia/commons/5/53/Google_%22G%22_Logo.svg",
		"onelogin":  "https://www.onelogin.com/assets/img/press/presskit/downloads/onelogin-mark.png",
		"ping":      "https://www.pingidentity.com/content/dam/ping-6-2-assets/logos/ping-logo.svg",
		"auth0":     "https://cdn.auth0.com/styleguide/latest/lib/logos/img/logo-blue.svg",
		"jumpcloud": "https://jumpcloud.com/wp-content/uploads/2022/03/JumpCloud-Logo-Stacked.svg",
		"duo":       "https://duo.com/assets/img/duo-logo.svg",
	}

	for key, url := range logoMap {
		if strings.Contains(nameLower, key) {
			return url
		}
	}

	// Default based on type
	if providerType == "saml" {
		return "" // Could return a generic SAML icon
	}

	return ""
}
