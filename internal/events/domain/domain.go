package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Event represents a security/audit event.
// Type examples: "auth.sso.login.success", "auth.login.failed"
// Meta may contain provider, ip, user_agent, etc.
type Event struct {
	Type     string
	TenantID uuid.UUID
	UserID   uuid.UUID
	Meta     map[string]string
	Time     time.Time
}

// Publisher publishes events to an external system (log, queue, etc.).
type Publisher interface {
	Publish(ctx context.Context, e Event) error
}
