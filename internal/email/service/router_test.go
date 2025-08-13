package service

import (
	"context"
	"testing"
	"time"

	"github.com/corvusHold/guard/internal/config"
	sdomain "github.com/corvusHold/guard/internal/settings/domain"
	"github.com/google/uuid"
)

type mockSettings struct{ vals map[string]string }

func (m mockSettings) GetString(ctx context.Context, key string, tenantID *uuid.UUID, def string) (string, error) {
	if v, ok := m.vals[key]; ok {
		return v, nil
	}
	return def, nil
}
func (m mockSettings) GetDuration(ctx context.Context, key string, tenantID *uuid.UUID, def time.Duration) (time.Duration, error) {
	return def, nil
}
func (m mockSettings) GetInt(ctx context.Context, key string, tenantID *uuid.UUID, def int) (int, error) {
	return def, nil
}

var _ sdomain.Service = (*mockSettings)(nil)

type captureSender struct{ called bool; lastTo, lastSub, lastBody string; lastTenant uuid.UUID }

func (c *captureSender) Send(ctx context.Context, tenantID uuid.UUID, to, subject, body string) error {
	c.called = true
	c.lastTo, c.lastSub, c.lastBody = to, subject, body
	c.lastTenant = tenantID
	return nil
}

func TestRouter_SelectsSMTP(t *testing.T) {
	tenant := uuid.New()
	cfg, _ := config.Load()
	ms := mockSettings{vals: map[string]string{sdomain.KeyEmailProvider: "smtp"}}
	r := NewRouter(ms, cfg)
	// swap implementations with captures so we don't hit network
	smtpCap := &captureSender{}
	brevoCap := &captureSender{}
	r.smtp = smtpCap
	r.brevo = brevoCap

	if err := r.Send(context.Background(), tenant, "a@b.com", "sub", "body"); err != nil {
		t.Fatalf("send failed: %v", err)
	}
	if !smtpCap.called || brevoCap.called {
		t.Fatalf("expected smtp called, brevo not called")
	}
}

func TestRouter_SelectsBrevo(t *testing.T) {
	tenant := uuid.New()
	cfg, _ := config.Load()
	ms := mockSettings{vals: map[string]string{sdomain.KeyEmailProvider: "brevo"}}
	r := NewRouter(ms, cfg)
	smtpCap := &captureSender{}
	brevoCap := &captureSender{}
	r.smtp = smtpCap
	r.brevo = brevoCap

	if err := r.Send(context.Background(), tenant, "a@b.com", "sub", "body"); err != nil {
		t.Fatalf("send failed: %v", err)
	}
	if !brevoCap.called || smtpCap.called {
		t.Fatalf("expected brevo called, smtp not called")
	}
}
