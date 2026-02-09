package service

import (
	"context"

	"github.com/corvusHold/guard/internal/auth/domain"
	"github.com/google/uuid"
)

// ListAllTenantsWithStats returns all tenants with user counts.
func (s *Service) ListAllTenantsWithStats(ctx context.Context, limit, offset int) ([]domain.TenantStats, error) {
	if limit <= 0 {
		limit = 50
	}
	return s.repo.ListAllTenantsWithStats(ctx, limit, offset)
}

// SearchUsersGlobal searches users across all tenants by email.
func (s *Service) SearchUsersGlobal(ctx context.Context, query string) ([]domain.UserSearchResult, error) {
	return s.repo.SearchUsersGlobal(ctx, query)
}

// QueryAuditLogs queries audit logs with optional filters.
func (s *Service) QueryAuditLogs(ctx context.Context, tenantID *uuid.UUID, userID *uuid.UUID, action string, limit, offset int) ([]domain.AuditLogEntry, int, error) {
	if limit <= 0 {
		limit = 50
	}
	return s.repo.QueryAuditLogs(ctx, tenantID, userID, action, limit, offset)
}

// PlatformStats returns aggregate platform statistics.
func (s *Service) PlatformStats(ctx context.Context) (domain.PlatformStatsResult, error) {
	return s.repo.PlatformStats(ctx)
}

// ListUsersByTenant returns users in a tenant for bulk export.
func (s *Service) ListUsersByTenant(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]domain.UserExport, error) {
	if limit <= 0 {
		limit = 1000
	}
	return s.repo.ListUsersByTenant(ctx, tenantID, limit, offset)
}
