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
	secretHash := hashSecret(input.Secret)
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

func (s *Service) Get(ctx context.Context, id uuid.UUID) (domain.Webhook, error) {
	return s.repo.GetWebhook(ctx, id)
}

func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]domain.Webhook, error) {
	return s.repo.ListWebhooks(ctx, tenantID)
}

func (s *Service) Update(ctx context.Context, id uuid.UUID, url *string, events []string, isActive *bool) (domain.Webhook, error) {
	return s.repo.UpdateWebhook(ctx, id, url, events, isActive)
}

func (s *Service) Delete(ctx context.Context, id uuid.UUID) error {
	return s.repo.DeleteWebhook(ctx, id)
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
			return err
		}
	}
	return nil
}

// SignPayload creates an HMAC-SHA256 signature for a payload using the webhook secret.
func SignPayload(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func hashSecret(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])
}
