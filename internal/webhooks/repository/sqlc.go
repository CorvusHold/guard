package repository

import (
	"context"
	"time"

	"github.com/corvusHold/guard/internal/webhooks/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Repository implements domain.Repository using pgxpool.
type Repository struct {
	pool *pgxpool.Pool
}

// New creates a new webhook repository.
func New(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

func (r *Repository) CreateWebhook(ctx context.Context, wh domain.Webhook) (domain.Webhook, error) {
	err := r.pool.QueryRow(ctx,
		`INSERT INTO webhooks (id, tenant_id, url, secret_hash, events, is_active, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 RETURNING id, tenant_id, url, secret_hash, events, is_active, created_at, updated_at`,
		wh.ID, wh.TenantID, wh.URL, wh.SecretHash, wh.Events, wh.IsActive, wh.CreatedAt, wh.UpdatedAt,
	).Scan(&wh.ID, &wh.TenantID, &wh.URL, &wh.SecretHash, &wh.Events, &wh.IsActive, &wh.CreatedAt, &wh.UpdatedAt)
	return wh, err
}

func (r *Repository) GetWebhook(ctx context.Context, id, tenantID uuid.UUID) (domain.Webhook, error) {
	var wh domain.Webhook
	err := r.pool.QueryRow(ctx,
		`SELECT id, tenant_id, url, secret_hash, events, is_active, created_at, updated_at FROM webhooks WHERE id = $1 AND tenant_id = $2`, id, tenantID,
	).Scan(&wh.ID, &wh.TenantID, &wh.URL, &wh.SecretHash, &wh.Events, &wh.IsActive, &wh.CreatedAt, &wh.UpdatedAt)
	return wh, err
}

func (r *Repository) GetWebhookByID(ctx context.Context, id uuid.UUID) (domain.Webhook, error) {
	var wh domain.Webhook
	err := r.pool.QueryRow(ctx,
		`SELECT id, tenant_id, url, secret_hash, events, is_active, created_at, updated_at FROM webhooks WHERE id = $1`, id,
	).Scan(&wh.ID, &wh.TenantID, &wh.URL, &wh.SecretHash, &wh.Events, &wh.IsActive, &wh.CreatedAt, &wh.UpdatedAt)
	return wh, err
}

func (r *Repository) ListWebhooks(ctx context.Context, tenantID uuid.UUID) ([]domain.Webhook, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, tenant_id, url, secret_hash, events, is_active, created_at, updated_at FROM webhooks WHERE tenant_id = $1 ORDER BY created_at DESC`, tenantID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var webhooks []domain.Webhook
	for rows.Next() {
		var wh domain.Webhook
		if err := rows.Scan(&wh.ID, &wh.TenantID, &wh.URL, &wh.SecretHash, &wh.Events, &wh.IsActive, &wh.CreatedAt, &wh.UpdatedAt); err != nil {
			return nil, err
		}
		webhooks = append(webhooks, wh)
	}
	return webhooks, rows.Err()
}

func (r *Repository) UpdateWebhook(ctx context.Context, id, tenantID uuid.UUID, url *string, events []string, isActive *bool) (domain.Webhook, error) {
	// Single atomic UPDATE to eliminate TOCTOU race
	var wh domain.Webhook
	err := r.pool.QueryRow(ctx,
		`UPDATE webhooks SET
			url = COALESCE($3, url),
			events = COALESCE($4, events),
			is_active = COALESCE($5, is_active),
			updated_at = now()
		 WHERE id = $1 AND tenant_id = $2
		 RETURNING id, tenant_id, url, secret_hash, events, is_active, created_at, updated_at`,
		id, tenantID, url, events, isActive,
	).Scan(&wh.ID, &wh.TenantID, &wh.URL, &wh.SecretHash, &wh.Events, &wh.IsActive, &wh.CreatedAt, &wh.UpdatedAt)
	return wh, err
}

func (r *Repository) DeleteWebhook(ctx context.Context, id, tenantID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM webhooks WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	return err
}

func (r *Repository) CreateDelivery(ctx context.Context, d domain.Delivery) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO webhook_deliveries (id, webhook_id, event_type, payload, status, attempts, max_attempts, next_retry_at, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		d.ID, d.WebhookID, d.EventType, d.Payload, d.Status, d.Attempts, d.MaxAttempts, d.NextRetryAt, d.CreatedAt,
	)
	return err
}

func (r *Repository) ListPendingDeliveries(ctx context.Context, limit int) ([]domain.Delivery, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := r.pool.Query(ctx,
		`SELECT id, webhook_id, event_type, payload, status, attempts, max_attempts, next_retry_at, last_error, created_at, completed_at
		 FROM webhook_deliveries
		 WHERE status IN ('pending', 'retrying') AND (next_retry_at IS NULL OR next_retry_at <= now())
		 ORDER BY created_at ASC LIMIT $1
		 FOR UPDATE SKIP LOCKED`, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var deliveries []domain.Delivery
	for rows.Next() {
		var d domain.Delivery
		if err := rows.Scan(&d.ID, &d.WebhookID, &d.EventType, &d.Payload, &d.Status, &d.Attempts, &d.MaxAttempts, &d.NextRetryAt, &d.LastError, &d.CreatedAt, &d.CompletedAt); err != nil {
			return nil, err
		}
		deliveries = append(deliveries, d)
	}
	return deliveries, rows.Err()
}

func (r *Repository) UpdateDeliveryStatus(ctx context.Context, id uuid.UUID, status string, lastError string, nextRetryAt *time.Time, completedAt *time.Time) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE webhook_deliveries SET status=$1, last_error=$2, next_retry_at=$3, completed_at=$4, attempts=attempts+1 WHERE id=$5`,
		status, lastError, nextRetryAt, completedAt, id,
	)
	return err
}

func (r *Repository) ListWebhooksByTenantAndEvent(ctx context.Context, tenantID uuid.UUID, eventType string) ([]domain.Webhook, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, tenant_id, url, secret_hash, events, is_active, created_at, updated_at
		 FROM webhooks WHERE tenant_id = $1 AND is_active = TRUE AND ($2 = ANY(events) OR '*' = ANY(events))`, tenantID, eventType,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var webhooks []domain.Webhook
	for rows.Next() {
		var wh domain.Webhook
		if err := rows.Scan(&wh.ID, &wh.TenantID, &wh.URL, &wh.SecretHash, &wh.Events, &wh.IsActive, &wh.CreatedAt, &wh.UpdatedAt); err != nil {
			return nil, err
		}
		webhooks = append(webhooks, wh)
	}
	return webhooks, rows.Err()
}
