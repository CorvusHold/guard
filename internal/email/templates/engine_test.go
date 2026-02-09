package templates

import (
	"context"
	"testing"
)

func TestRenderTemplate_DefaultMagicLink(t *testing.T) {
	e := NewEngine(nil) // nil pg = always use defaults
	data := TemplateData{
		AppName:        "Guard",
		RecipientEmail: "user@example.com",
		Link:           "https://guard.dev/magic?token=abc123",
		ExpiresIn:      "15 minutes",
	}
	subject, body, err := e.Render(context.Background(), nil, TemplateMagicLink, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if subject == "" {
		t.Error("expected non-empty subject")
	}
	if body == "" {
		t.Error("expected non-empty body")
	}
	// Subject should contain app name
	if !contains(subject, "Guard") {
		t.Errorf("subject should contain app name, got: %s", subject)
	}
	// Body should contain the link
	if !contains(body, "https://guard.dev/magic?token=abc123") {
		t.Errorf("body should contain link, got: %s", body)
	}
}

func TestRenderTemplate_DefaultPasswordReset(t *testing.T) {
	e := NewEngine(nil)
	data := TemplateData{
		AppName:        "TestApp",
		RecipientEmail: "reset@example.com",
		Link:           "https://guard.dev/reset?token=xyz",
		ExpiresIn:      "1 hour",
	}
	subject, body, err := e.Render(context.Background(), nil, TemplatePasswordReset, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if subject == "" {
		t.Error("expected non-empty subject")
	}
	if !contains(body, "https://guard.dev/reset?token=xyz") {
		t.Errorf("body should contain reset link, got: %s", body)
	}
}

func TestRenderTemplate_DefaultInvitation(t *testing.T) {
	e := NewEngine(nil)
	data := TemplateData{
		AppName:     "Guard",
		InviterName: "Alice",
		TenantName:  "Acme Corp",
		Link:        "https://guard.dev/invite?token=inv1",
	}
	subject, body, err := e.Render(context.Background(), nil, TemplateInvitation, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if subject == "" {
		t.Error("expected non-empty subject")
	}
	if !contains(body, "https://guard.dev/invite?token=inv1") {
		t.Errorf("body should contain invite link, got: %s", body)
	}
}

func TestRenderTemplate_AllDefaultTypes(t *testing.T) {
	e := NewEngine(nil)
	types := []TemplateType{
		TemplateMagicLink,
		TemplatePasswordReset,
		TemplateInvitation,
		TemplateWelcome,
		TemplateEmailVerification,
	}
	data := TemplateData{
		AppName:        "Guard",
		RecipientEmail: "test@example.com",
		Link:           "https://example.com",
		TenantName:     "Test",
		InviterName:    "Admin",
		ExpiresIn:      "30 minutes",
	}
	for _, tt := range types {
		t.Run(string(tt), func(t *testing.T) {
			subject, body, err := e.Render(context.Background(), nil, tt, data)
			if err != nil {
				t.Fatalf("render %s: %v", tt, err)
			}
			if subject == "" {
				t.Errorf("expected non-empty subject for %s", tt)
			}
			if body == "" {
				t.Errorf("expected non-empty body for %s", tt)
			}
		})
	}
}

func TestRenderTemplate_InvalidTemplate(t *testing.T) {
	// Render with a type that has no default should produce empty strings
	e := NewEngine(nil)
	data := TemplateData{AppName: "Guard"}
	subject, body, err := e.Render(context.Background(), nil, TemplateType("nonexistent"), data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if subject != "" {
		t.Errorf("expected empty subject for unknown type, got: %s", subject)
	}
	if body != "" {
		t.Errorf("expected empty body for unknown type, got: %s", body)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
