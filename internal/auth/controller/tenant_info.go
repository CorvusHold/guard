package controller

import (
	authdomain "github.com/corvusHold/guard/internal/auth/domain"
)

// TenantInfo represents basic tenant information for discovery/login options.
type TenantInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
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
