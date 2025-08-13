package domain

import (
	"context"

	"github.com/google/uuid"
)

// Sender is a pluggable email sending interface supporting per-tenant overrides.
// Implementations should use the settings service and config defaults internally.
// tenantID is required to allow per-tenant routing/config; use uuid.Nil for global.
// subject/body are plain text; HTML can be added later if needed.
type Sender interface {
	Send(ctx context.Context, tenantID uuid.UUID, to string, subject string, body string) error
}
