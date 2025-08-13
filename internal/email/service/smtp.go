package service

import (
	"context"
	"fmt"
	"net/smtp"
	"strconv"

	edomain "github.com/corvusHold/guard/internal/email/domain"
	"github.com/corvusHold/guard/internal/config"
	sdomain "github.com/corvusHold/guard/internal/settings/domain"
	"github.com/google/uuid"
)

// Ensure SMTP implements domain.Sender
var _ edomain.Sender = (*SMTP)(nil)

type SMTP struct {
	cfg      config.Config
	settings sdomain.Service
}

func NewSMTP(settings sdomain.Service, cfg config.Config) *SMTP { return &SMTP{settings: settings, cfg: cfg} }

func (s *SMTP) Send(ctx context.Context, tenantID uuid.UUID, to, subject, body string) error {
	host, _ := s.settings.GetString(ctx, sdomain.KeySMTPHost, &tenantID, s.cfg.SMTPHost)
	from, _ := s.settings.GetString(ctx, sdomain.KeySMTPFrom, &tenantID, s.cfg.SMTPFrom)
	username, _ := s.settings.GetString(ctx, sdomain.KeySMTPUsername, &tenantID, s.cfg.SMTPUsername)
	password, _ := s.settings.GetString(ctx, sdomain.KeySMTPPassword, &tenantID, s.cfg.SMTPPassword)
	portStr, _ := s.settings.GetString(ctx, sdomain.KeySMTPPort, &tenantID, fmt.Sprintf("%d", s.cfg.SMTPPort))
	port, err := strconv.Atoi(portStr)
	if err != nil { port = s.cfg.SMTPPort }

	addr := fmt.Sprintf("%s:%d", host, port)
	msg := []byte(fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n", from, to, subject, body))
	var auth smtp.Auth
	if username != "" {
		auth = smtp.PlainAuth("", username, password, host)
	}
	return smtp.SendMail(addr, auth, from, []string{to}, msg)
}
