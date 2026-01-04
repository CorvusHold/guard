package controller

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

// EmailDiscoveryRequest represents the request to discover user/tenant by email
type EmailDiscoveryRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// EmailDiscoveryResponse represents the response for email discovery
type EmailDiscoveryResponse struct {
	Found       bool         `json:"found"`
	HasTenant   bool         `json:"has_tenant"`
	TenantID    string       `json:"tenant_id,omitempty"`
	TenantName  string       `json:"tenant_name,omitempty"`
	UserExists  bool         `json:"user_exists"`
	Suggestions []string     `json:"suggestions,omitempty"`
	Tenants     []TenantInfo `json:"tenants,omitempty"`
}

// EmailDiscovery godoc
// @Summary      Discover user/tenant by email
// @Description  Check if an email exists in any tenant and provide guidance
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body EmailDiscoveryRequest true "Email to discover"
// @Success      200  {object}  EmailDiscoveryResponse
// @Failure      400  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /api/v1/auth/email/discover [post]
func (h *Controller) emailDiscovery(c echo.Context) error {
	var req EmailDiscoveryRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request"})
	}

	// Get tenant ID from header if provided
	tenantID := c.Request().Header.Get("X-Tenant-ID")

	var response EmailDiscoveryResponse

	if tenantID != "" {
		// Tenant is specified, check if user exists in this tenant
		_, err := h.svc.GetUserByEmail(c.Request().Context(), req.Email, tenantID)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				// User doesn't exist in this tenant
				response = EmailDiscoveryResponse{
					Found:      false,
					HasTenant:  true,
					TenantID:   tenantID,
					UserExists: false,
				}
			} else {
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": "internal server error"})
			}
		} else {
			// User exists in this tenant
			response = EmailDiscoveryResponse{
				Found:      true,
				HasTenant:  true,
				TenantID:   tenantID,
				UserExists: true,
			}
		}
	} else {
		// No tenant specified, discover which tenant(s) the user belongs to
		tenants, err := h.svc.FindTenantsByUserEmail(c.Request().Context(), req.Email)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		}

		if len(tenants) == 0 {
			// Email not found in any tenant
			response = EmailDiscoveryResponse{
				Found:       false,
				HasTenant:   false,
				UserExists:  false,
				Suggestions: generateEmailSuggestions(req.Email),
			}
		} else if len(tenants) == 1 {
			// Email found in exactly one tenant
			tenant := tenants[0]
			response = EmailDiscoveryResponse{
				Found:      true,
				HasTenant:  true,
				TenantID:   tenant.ID,
				TenantName: tenant.Name,
				UserExists: true,
				Tenants:    toTenantInfos(tenants),
			}
		} else {
			// Email found in multiple tenants - return the list and avoid forcing a default
			var suggestions []string
			for _, t := range tenants {
				suggestions = append(suggestions, t.Name)
			}

			response = EmailDiscoveryResponse{
				Found:       true,
				HasTenant:   true,
				UserExists:  true,
				Suggestions: suggestions,
				Tenants:     toTenantInfos(tenants),
			}
		}
	}

	return c.JSON(http.StatusOK, response)
}

// // generateEmailSuggestions generates helpful suggestions for email typos
// func generateEmailSuggestions(email string) []string {
// 	// Common email domain typos and suggestions
// 	commonDomains := []string{
// 		"gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
// 		"icloud.com", "protonmail.com",
// 	}

// 	// Extract domain from email
// 	atIndex := strings.LastIndex(email, "@")
// 	if atIndex == -1 {
// 		return nil // No @ found
// 	}

// 	localPart := email[:atIndex]
// 	domain := email[atIndex+1:]

// 	var suggestions []string

// 	// Suggest common domains if current domain is uncommon or potentially misspelled
// 	for _, commonDomain := range commonDomains {
// 		if domain != commonDomain {
// 			suggestions = append(suggestions, localPart+"@"+commonDomain)
// 		}
// 	}

// 	// Limit suggestions
// 	if len(suggestions) > 3 {
// 		suggestions = suggestions[:3]
// 	}

// 	return suggestions
// }
