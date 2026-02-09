package service

import (
	"context"

	"github.com/google/uuid"
)

// RevokeTokenChain revokes a refresh token and its chain.
func (s *Service) RevokeTokenChain(ctx context.Context, tokenID uuid.UUID) error {
	return s.repo.RevokeTokenChain(ctx, tokenID)
}

// IsMFAEnrolled checks if a user has MFA enrolled in a tenant.
func (s *Service) IsMFAEnrolled(ctx context.Context, userID, tenantID uuid.UUID) (bool, error) {
	return s.repo.IsMFAEnrolled(ctx, userID, tenantID)
}
