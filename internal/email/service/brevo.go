package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/corvusHold/guard/internal/config"
	edomain "github.com/corvusHold/guard/internal/email/domain"
	sdomain "github.com/corvusHold/guard/internal/settings/domain"
	"github.com/google/uuid"
)

// Ensure Brevo implements domain.Sender
var _ edomain.Sender = (*Brevo)(nil)

type Brevo struct {
	cfg      config.Config
	settings sdomain.Service
	http     *http.Client
}

func NewBrevo(settings sdomain.Service, cfg config.Config) *Brevo {
	return &Brevo{settings: settings, cfg: cfg, http: &http.Client{Timeout: 10 * time.Second}}
}

type brevoEmail struct {
	To          []map[string]string `json:"to"`
	Sender      map[string]string   `json:"sender"`
	Subject     string              `json:"subject"`
	TextContent string              `json:"textContent"`
}

func (b *Brevo) Send(ctx context.Context, tenantID uuid.UUID, to, subject, body string) error {
	apiKey, _ := b.settings.GetString(ctx, sdomain.KeyBrevoAPIKey, &tenantID, b.cfg.BrevoAPIKey)
	sender, _ := b.settings.GetString(ctx, sdomain.KeyBrevoSender, &tenantID, b.cfg.BrevoSender)
	if apiKey == "" || sender == "" {
		return fmt.Errorf("brevo not configured")
	}
	payload := brevoEmail{
		To:          []map[string]string{{"email": to}},
		Sender:      map[string]string{"email": sender},
		Subject:     subject,
		TextContent: body,
	}
	buf, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.brevo.com/v3/smtp/email", bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("api-key", apiKey)
	resp, err := b.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("brevo send failed: %s", resp.Status)
	}
	return nil
}
