package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/corvusHold/guard/internal/auth/domain"
	evdomain "github.com/corvusHold/guard/internal/events/domain"
	"github.com/google/uuid"
)

// CreateAPIKey creates a new API key for service-to-service authentication.
// Returns the APIKey metadata and the raw key (shown only once).
func (s *Service) CreateAPIKey(ctx context.Context, tenantID uuid.UUID, name string, scopes []string, createdBy uuid.UUID, expiresAt *time.Time) (domain.APIKey, string, error) {
	if name == "" {
		return domain.APIKey{}, "", errors.New("name is required")
	}
	if scopes == nil {
		scopes = []string{}
	}

	// Generate raw key: gk_<32 random bytes hex-encoded>
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return domain.APIKey{}, "", err
	}
	rawKey := "gk_" + hex.EncodeToString(raw)

	// Hash for storage
	h := sha256.Sum256([]byte(rawKey))
	keyHash := base64.RawURLEncoding.EncodeToString(h[:])

	// Prefix for identification (first 12 chars of raw key)
	keyPrefix := rawKey[:12]

	id := uuid.New()
	key, err := s.repo.CreateAPIKey(ctx, id, tenantID, name, keyHash, keyPrefix, scopes, createdBy, expiresAt)
	if err != nil {
		return domain.APIKey{}, "", err
	}

	// Publish audit event
	meta := map[string]string{
		"api_key_id":   id.String(),
		"api_key_name": name,
		"created_by":   createdBy.String(),
	}
	_ = s.pub.Publish(ctx, evdomain.Event{
		Type:     "auth.api_key.created",
		TenantID: tenantID,
		UserID:   createdBy,
		Meta:     meta,
		Time:     time.Now(),
	})

	return key, rawKey, nil
}

// ValidateAPIKey validates a raw API key and returns the associated metadata.
func (s *Service) ValidateAPIKey(ctx context.Context, rawKey string) (domain.APIKey, error) {
	if rawKey == "" {
		return domain.APIKey{}, errors.New("api key is required")
	}

	h := sha256.Sum256([]byte(rawKey))
	keyHash := base64.RawURLEncoding.EncodeToString(h[:])

	key, err := s.repo.GetAPIKeyByHash(ctx, keyHash)
	if err != nil {
		return domain.APIKey{}, errors.New("invalid api key")
	}

	// Check expiration
	if key.ExpiresAt != nil && time.Now().After(*key.ExpiresAt) {
		return domain.APIKey{}, errors.New("api key expired")
	}

	// Update last used (best-effort, don't fail validation)
	_ = s.repo.UpdateAPIKeyLastUsed(ctx, key.ID)

	return key, nil
}

// ListAPIKeys returns all API keys for a tenant.
func (s *Service) ListAPIKeys(ctx context.Context, tenantID uuid.UUID) ([]domain.APIKey, error) {
	return s.repo.ListAPIKeysByTenant(ctx, tenantID)
}

// RevokeAPIKey revokes an API key.
func (s *Service) RevokeAPIKey(ctx context.Context, keyID, tenantID uuid.UUID) error {
	if err := s.repo.RevokeAPIKey(ctx, keyID, tenantID); err != nil {
		return err
	}

	_ = s.pub.Publish(ctx, evdomain.Event{
		Type:     "auth.api_key.revoked",
		TenantID: tenantID,
		Meta: map[string]string{
			"api_key_id": keyID.String(),
		},
		Time: time.Now(),
	})

	return nil
}
