package service

import (
	"context"
	"fmt"

	domain "github.com/corvusHold/guard/internal/auth/domain"
	"github.com/google/uuid"
)

// FindTenantsByUserEmail finds all tenants where a user with the given email exists
func (s *Service) FindTenantsByUserEmail(ctx context.Context, email string) ([]domain.TenantInfo, error) {
	// Query all auth identities where this email exists
	identities, err := s.repo.FindAuthIdentitiesByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("failed to find identities by email: %w", err)
	}

	// Group by tenant and get tenant info
	tenantMap := make(map[string]domain.TenantInfo)
	for _, identity := range identities {
		tenantIDStr := identity.TenantID.String()
		if _, exists := tenantMap[tenantIDStr]; !exists {
			name := fmt.Sprintf("Tenant %s", tenantIDStr[:8])
			if ten, getErr := s.repo.GetTenantByID(ctx, identity.TenantID); getErr == nil && ten.Name != "" {
				name = ten.Name
			}
			tenantMap[tenantIDStr] = domain.TenantInfo{
				ID:   tenantIDStr,
				Name: name,
			}
		}
	}

	// Convert map to slice
	var tenants []domain.TenantInfo
	for _, tenant := range tenantMap {
		tenants = append(tenants, tenant)
	}

	return tenants, nil
}

// GetUserByEmail gets a user by email in a specific tenant
func (s *Service) GetUserByEmail(ctx context.Context, email, tenantID string) (*domain.User, error) {
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return nil, fmt.Errorf("invalid tenant ID: %w", err)
	}

	identity, err := s.repo.GetAuthIdentityByEmailTenant(ctx, tenantUUID, email)
	if err != nil {
		return nil, err
	}

	user, err := s.repo.GetUserByID(ctx, identity.UserID)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// ListSSOProvidersPublic returns public info about enabled SSO providers for a tenant.
// This is used for login options discovery - only returns non-sensitive info.
func (s *Service) ListSSOProvidersPublic(ctx context.Context, tenantID uuid.UUID) ([]domain.PublicSSOProvider, error) {
	return s.repo.ListEnabledSSOProviders(ctx, tenantID)
}
