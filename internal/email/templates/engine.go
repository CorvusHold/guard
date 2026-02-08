package templates

import (
	"bytes"
	"context"
	"text/template"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Engine renders email templates with per-tenant overrides from the DB.
type Engine struct {
	pg *pgxpool.Pool
}

// NewEngine creates a new template engine.
func NewEngine(pg *pgxpool.Pool) *Engine {
	return &Engine{pg: pg}
}

// Render renders a template for the given type and tenant.
// It first checks for a per-tenant override in the DB, then falls back to defaults.
func (e *Engine) Render(ctx context.Context, tenantID *uuid.UUID, tmplType TemplateType, data TemplateData) (subject, body string, err error) {
	subjectTmpl, bodyTmpl := e.loadTemplates(ctx, tenantID, tmplType)

	subject, err = renderTemplate(subjectTmpl, data)
	if err != nil {
		return "", "", err
	}
	body, err = renderTemplate(bodyTmpl, data)
	if err != nil {
		return "", "", err
	}
	return subject, body, nil
}

func (e *Engine) loadTemplates(ctx context.Context, tenantID *uuid.UUID, tmplType TemplateType) (subjectTmpl, bodyTmpl string) {
	// Try per-tenant override from DB
	if tenantID != nil && e.pg != nil {
		var dbSubject, dbBody string
		err := e.pg.QueryRow(ctx,
			`SELECT subject_template, body_template FROM email_templates WHERE tenant_id = $1 AND template_type = $2`,
			*tenantID, string(tmplType),
		).Scan(&dbSubject, &dbBody)
		if err == nil && dbSubject != "" && dbBody != "" {
			return dbSubject, dbBody
		}
	}

	// Fall back to defaults
	subjectTmpl = DefaultSubjects[tmplType]
	bodyTmpl = DefaultBodies[tmplType]
	return subjectTmpl, bodyTmpl
}

func renderTemplate(tmplStr string, data TemplateData) (string, error) {
	t, err := template.New("email").Parse(tmplStr)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
