package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/smtp"
	"strings"
	"testing"

	"github.com/corvusHold/guard/internal/config"
	sdomain "github.com/corvusHold/guard/internal/settings/domain"
	"github.com/google/uuid"
)

type emailRoundTripFunc func(*http.Request) (*http.Response, error)

func (f emailRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestSMTP_Send_UsesSettingsAndFallbackPort(t *testing.T) {
	tenantID := uuid.New()
	cfg := config.Config{SMTPPort: 2525}
	ms := mockSettings{vals: map[string]string{
		sdomain.KeySMTPHost:     "smtp.example.com",
		sdomain.KeySMTPFrom:     "noreply@example.com",
		sdomain.KeySMTPUsername: "smtp-user",
		sdomain.KeySMTPPassword: "smtp-pass",
		sdomain.KeySMTPPort:     "not-a-number",
	}}
	s := NewSMTP(ms, cfg)

	origSend := smtpSendMail
	defer func() { smtpSendMail = origSend }()

	called := false
	smtpSendMail = func(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
		called = true
		if addr != "smtp.example.com:2525" {
			t.Fatalf("expected addr smtp.example.com:2525, got %q", addr)
		}
		if from != "noreply@example.com" {
			t.Fatalf("expected from noreply@example.com, got %q", from)
		}
		if len(to) != 1 || to[0] != "to@example.com" {
			t.Fatalf("unexpected recipients: %#v", to)
		}
		if auth == nil {
			t.Fatal("expected SMTP auth when username is set")
		}
		if !strings.Contains(string(msg), "Subject: subject") || !strings.Contains(string(msg), "body") {
			t.Fatalf("unexpected smtp message: %s", string(msg))
		}
		return nil
	}

	if err := s.Send(context.Background(), tenantID, "to@example.com", "subject", "body"); err != nil {
		t.Fatalf("SMTP Send returned error: %v", err)
	}
	if !called {
		t.Fatal("expected smtpSendMail to be called")
	}
}

func TestSMTP_Send_NoAuthWhenUsernameEmpty(t *testing.T) {
	cfg := config.Config{SMTPPort: 2525}
	ms := mockSettings{vals: map[string]string{
		sdomain.KeySMTPHost: "smtp.example.com",
		sdomain.KeySMTPFrom: "noreply@example.com",
		sdomain.KeySMTPPort: "2526",
	}}
	s := NewSMTP(ms, cfg)

	origSend := smtpSendMail
	defer func() { smtpSendMail = origSend }()

	smtpSendMail = func(addr string, auth smtp.Auth, _ string, _ []string, _ []byte) error {
		if addr != "smtp.example.com:2526" {
			t.Fatalf("expected addr smtp.example.com:2526, got %q", addr)
		}
		if auth != nil {
			t.Fatalf("expected nil auth when username is empty, got %T", auth)
		}
		return nil
	}

	if err := s.Send(context.Background(), uuid.New(), "to@example.com", "subject", "body"); err != nil {
		t.Fatalf("SMTP Send returned error: %v", err)
	}
}

func TestBrevo_Send_ConfigAndHTTPPaths(t *testing.T) {
	tenantID := uuid.New()
	cfg := config.Config{}

	// Not configured
	b := NewBrevo(mockSettings{vals: map[string]string{}}, cfg)
	if err := b.Send(context.Background(), tenantID, "to@example.com", "sub", "body"); err == nil {
		t.Fatal("expected brevo not configured error")
	}

	// Success path + request assertions
	ms := mockSettings{vals: map[string]string{
		sdomain.KeyBrevoAPIKey: "brevo-key",
		sdomain.KeyBrevoSender: "sender@example.com",
	}}
	b = NewBrevo(ms, cfg)
	b.http = &http.Client{Transport: emailRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("api-key") != "brevo-key" {
			t.Fatalf("expected api-key header")
		}
		if req.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("expected json content-type, got %q", req.Header.Get("Content-Type"))
		}
		body, _ := io.ReadAll(req.Body)
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("invalid brevo payload json: %v", err)
		}
		return &http.Response{StatusCode: 201, Status: "201 Created", Body: io.NopCloser(strings.NewReader("ok"))}, nil
	})}
	if err := b.Send(context.Background(), tenantID, "to@example.com", "sub", "body"); err != nil {
		t.Fatalf("expected successful brevo send, got %v", err)
	}

	// HTTP client error path
	b.http = &http.Client{Transport: emailRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("network down")
	})}
	if err := b.Send(context.Background(), tenantID, "to@example.com", "sub", "body"); err == nil {
		t.Fatal("expected brevo http error")
	}

	// non-2xx path
	b.http = &http.Client{Transport: emailRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 500, Status: "500 Internal Server Error", Body: io.NopCloser(strings.NewReader("fail"))}, nil
	})}
	if err := b.Send(context.Background(), tenantID, "to@example.com", "sub", "body"); err == nil {
		t.Fatal("expected brevo status error")
	}
}
