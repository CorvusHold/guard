package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Webhook represents a webhook subscription.
type Webhook struct {
	ID         uuid.UUID `json:"id"`
	TenantID   uuid.UUID `json:"tenant_id"`
	URL        string    `json:"url"`
	SecretHash string    `json:"-"`
	Events     []string  `json:"events"`
	IsActive   bool      `json:"is_active"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Delivery represents a webhook delivery attempt.
type Delivery struct {
	ID          uuid.UUID  `json:"id"`
	WebhookID   uuid.UUID  `json:"webhook_id"`
	EventType   string     `json:"event_type"`
	Payload     []byte     `json:"payload"`
	Status      string     `json:"status"` // pending, retrying, delivered, failed
	Attempts    int        `json:"attempts"`
	MaxAttempts int        `json:"max_attempts"`
	NextRetryAt *time.Time `json:"next_retry_at,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// CreateWebhookInput is the input for creating a webhook.
type CreateWebhookInput struct {
	TenantID uuid.UUID
	URL      string
	Secret   string
	Events   []string
}

// Repository abstracts data access for webhooks.
type Repository interface {
	CreateWebhook(ctx context.Context, wh Webhook) (Webhook, error)
	GetWebhook(ctx context.Context, id uuid.UUID) (Webhook, error)
	ListWebhooks(ctx context.Context, tenantID uuid.UUID) ([]Webhook, error)
	UpdateWebhook(ctx context.Context, id uuid.UUID, url *string, events []string, isActive *bool) (Webhook, error)
	DeleteWebhook(ctx context.Context, id uuid.UUID) error

	CreateDelivery(ctx context.Context, d Delivery) error
	ListPendingDeliveries(ctx context.Context, limit int) ([]Delivery, error)
	UpdateDeliveryStatus(ctx context.Context, id uuid.UUID, status string, lastError string, nextRetryAt *time.Time, completedAt *time.Time) error

	// ListWebhooksByTenantAndEvent returns active webhooks for a tenant that subscribe to the given event.
	ListWebhooksByTenantAndEvent(ctx context.Context, tenantID uuid.UUID, eventType string) ([]Webhook, error)
}
