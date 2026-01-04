package controller

import (
	authdomain "github.com/corvusHold/guard/internal/auth/domain"
)

// TenantInfo represents basic tenant information for discovery/login options.
type TenantInfo struct {
	// Tenant ID (UUID)
	ID string `json:"id" example:"3efda476-f0b9-47a8-b96b-5a543b88da3e" validate:"required"`
	// Tenant display name
	Name string `json:"name" example:"Acme Corp" validate:"required"`
}

// toTenantInfos converts domain tenant info into response DTOs.
func toTenantInfos(tenants []authdomain.TenantInfo) []TenantInfo {
	out := make([]TenantInfo, 0, len(tenants))
	for _, t := range tenants {
		out = append(out, TenantInfo{
			ID:   t.ID,
			Name: t.Name,
		})
	}
	return out
}
