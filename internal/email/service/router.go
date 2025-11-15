package service

import (
	"context"
	"strings"

	"github.com/corvusHold/guard/internal/config"
	edomain "github.com/corvusHold/guard/internal/email/domain"
	sdomain "github.com/corvusHold/guard/internal/settings/domain"
	"github.com/google/uuid"
)

// Ensure Router implements domain.Sender
var _ edomain.Sender = (*Router)(nil)

type Router struct {
	cfg      config.Config
	settings sdomain.Service
	smtp     edomain.Sender
	brevo    edomain.Sender
}

func NewRouter(settings sdomain.Service, cfg config.Config) *Router {
	return &Router{cfg: cfg, settings: settings, smtp: NewSMTP(settings, cfg), brevo: NewBrevo(settings, cfg)}
}

func (r *Router) Send(ctx context.Context, tenantID uuid.UUID, to, subject, body string) error {
	prov, _ := r.settings.GetString(ctx, sdomain.KeyEmailProvider, &tenantID, r.cfg.EmailProvider)
	switch strings.ToLower(prov) {
	case "brevo":
		return r.brevo.Send(ctx, tenantID, to, subject, body)
	default:
		return r.smtp.Send(ctx, tenantID, to, subject, body)
	}
}
