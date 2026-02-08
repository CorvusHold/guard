package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/corvusHold/guard/internal/webhooks/domain"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// Service implements webhook business logic.
type Service struct {
	repo domain.Repository
}

// New creates a new webhook service.
func New(repo domain.Repository) *Service {
	return &Service{repo: repo}
}

func (s *Service) Create(ctx context.Context, input domain.CreateWebhookInput) (domain.Webhook, error) {
	secretHash := HashSecret(input.Secret)
	wh := domain.Webhook{
		ID:         uuid.New(),
		TenantID:   input.TenantID,
		URL:        input.URL,
		SecretHash: secretHash,
		Events:     input.Events,
		IsActive:   true,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	return s.repo.CreateWebhook(ctx, wh)
}

func (s *Service) Get(ctx context.Context, id, tenantID uuid.UUID) (domain.Webhook, error) {
	return s.repo.GetWebhook(ctx, id, tenantID)
}

func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]domain.Webhook, error) {
	return s.repo.ListWebhooks(ctx, tenantID)
}

func (s *Service) Update(ctx context.Context, id, tenantID uuid.UUID, url *string, events []string, isActive *bool) (domain.Webhook, error) {
	return s.repo.UpdateWebhook(ctx, id, tenantID, url, events, isActive)
}

func (s *Service) Delete(ctx context.Context, id, tenantID uuid.UUID) error {
	return s.repo.DeleteWebhook(ctx, id, tenantID)
}

// EnqueueEvent creates delivery records for all webhooks subscribed to the event.
func (s *Service) EnqueueEvent(ctx context.Context, tenantID uuid.UUID, eventType string, payload interface{}) error {
	webhooks, err := s.repo.ListWebhooksByTenantAndEvent(ctx, tenantID, eventType)
	if err != nil {
		return err
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	var firstErr error
	for _, wh := range webhooks {
		d := domain.Delivery{
			ID:          uuid.New(),
			WebhookID:   wh.ID,
			EventType:   eventType,
			Payload:     payloadBytes,
			Status:      "pending",
			Attempts:    0,
			MaxAttempts: 5,
			CreatedAt:   time.Now(),
		}
		if err := s.repo.CreateDelivery(ctx, d); err != nil {
			log.Error().Err(err).Str("webhook_id", wh.ID.String()).Str("event_type", eventType).Msg("webhook: failed to enqueue delivery")
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// SignPayload creates an HMAC-SHA256 signature for a payload.
// The key parameter should be the SHA-256 hex digest of the original secret
// (i.e., the value returned by HashSecret). Consumers must derive the same
// HMAC key by computing SHA-256 of their stored secret before verification:
//
//	key = hex(sha256(raw_secret))
//	expected = HMAC-SHA256(key, payload)
func SignPayload(key string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// HashSecret returns the SHA-256 hex digest of a raw secret.
// This value is stored in the database and used as the HMAC signing key.
func HashSecret(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])
}
