package service

import (
	"context"
	"encoding/json"

	"github.com/corvusHold/guard/internal/events/domain"
	whrepo "github.com/corvusHold/guard/internal/webhooks/repository"
	whsvc "github.com/corvusHold/guard/internal/webhooks/service"
	"github.com/jackc/pgx/v5/pgxpool"
)

// WebhookPublisher is a Publisher that enqueues webhook deliveries for matching subscriptions.
type WebhookPublisher struct {
	svc *whsvc.Service
}

// NewWebhookPublisher creates a webhook-backed event publisher.
func NewWebhookPublisher(pg *pgxpool.Pool) *WebhookPublisher {
	repo := whrepo.New(pg)
	svc := whsvc.New(repo)
	return &WebhookPublisher{svc: svc}
}

func (w *WebhookPublisher) Publish(ctx context.Context, e domain.Event) error {
	payload := map[string]interface{}{
		"type":      e.Type,
		"tenant_id": e.TenantID.String(),
		"user_id":   e.UserID.String(),
		"meta":      e.Meta,
		"time":      e.Time,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_ = payloadBytes // payload is marshalled by EnqueueEvent internally
	return w.svc.EnqueueEvent(ctx, e.TenantID, e.Type, payload)
}
