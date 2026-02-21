package templates

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRender_ParseErrorPaths(t *testing.T) {
	e := NewEngine(nil)
	data := TemplateData{AppName: "Guard"}

	origSubj := DefaultSubjects[TemplateMagicLink]
	origBody := DefaultBodies[TemplateMagicLink]
	defer func() {
		DefaultSubjects[TemplateMagicLink] = origSubj
		DefaultBodies[TemplateMagicLink] = origBody
	}()

	DefaultSubjects[TemplateMagicLink] = "{{"
	if _, _, err := e.Render(context.Background(), nil, TemplateMagicLink, data); err == nil {
		t.Fatal("expected subject template parse error")
	}

	DefaultSubjects[TemplateMagicLink] = origSubj
	DefaultBodies[TemplateMagicLink] = "{{"
	if _, _, err := e.Render(context.Background(), nil, TemplateMagicLink, data); err == nil {
		t.Fatal("expected body template parse error")
	}
}

func TestLoadTemplates_DBOverrideAttemptFallsBackOnQueryError(t *testing.T) {
	cfg, err := pgxpool.ParseConfig("postgres://127.0.0.1:1/postgres?sslmode=disable")
	if err != nil {
		t.Fatalf("parse pg config: %v", err)
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("new pg pool: %v", err)
	}
	defer pool.Close()

	e := NewEngine(pool)
	tenantID := uuid.New()
	subject, body := e.loadTemplates(context.Background(), &tenantID, TemplateWelcome)

	if subject != DefaultSubjects[TemplateWelcome] {
		t.Fatalf("expected fallback default subject, got %q", subject)
	}
	if body != DefaultBodies[TemplateWelcome] {
		t.Fatalf("expected fallback default body, got %q", body)
	}
}
