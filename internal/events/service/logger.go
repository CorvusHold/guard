package service

import (
	"context"
	"github.com/corvusHold/guard/internal/events/domain"
	"github.com/rs/zerolog/log"
)

// Logger is a simple Publisher that logs events.
// In production, replace with a queue or external sink.

type Logger struct{}

func NewLogger() *Logger { return &Logger{} }

func (l *Logger) Publish(ctx context.Context, e domain.Event) error {
	log.Ctx(ctx).Info().
		Str("type", e.Type).
		Str("tenant_id", e.TenantID.String()).
		Str("user_id", e.UserID.String()).
		Fields(map[string]any{"meta": e.Meta}).
		Time("ts", e.Time).
		Msg("event")
	return nil
}
