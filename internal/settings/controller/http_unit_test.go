package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	evdomain "github.com/corvusHold/guard/internal/events/domain"
	sdomain "github.com/corvusHold/guard/internal/settings/domain"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type settingsRepoStub struct {
	upserts []string
	err     error
}

func TestSettingsController_RegisterAndPutAdditionalBranches(t *testing.T) {
	e := echo.New()
	tenantID := uuid.New()
	userID := uuid.New()

	h := New(&settingsRepoStub{}, &settingsServiceStub{})
	if h.WithJWT(nil) == nil || h.WithRateLimit(nil) == nil || h.WithPublisher(nil) == nil || h.WithRoleFetcher(nil) == nil {
		t.Fatal("expected fluent With* methods to return controller")
	}
	h.Register(e)
	g := e.Group("/api/v1")
	h.RegisterV1(g)

	repoErr := &settingsRepoStub{err: errors.New("upsert failed")}
	h = &Controller{repo: repoErr, service: &settingsServiceStub{}, pub: &settingsPublisherStub{}}

	makeCtx := func(payload string) echo.Context {
		req := httptest.NewRequest(http.MethodPut, "/", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("auth_user_id", userID)
		c.Set("auth_tenant_id", tenantID)
		c.SetParamNames("id")
		c.SetParamValues(tenantID.String())
		return c
	}

	c := makeCtx("{")
	_ = h.putTenantSettings(c)
	if c.Response().Status != http.StatusBadRequest {
		t.Fatalf("expected invalid json 400, got %d", c.Response().Status)
	}

	h.roleFetcher = func(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) ([]string, error) {
		return nil, errors.New("rbac down")
	}
	c = makeCtx(`{"sso_provider":"workos"}`)
	_ = h.putTenantSettings(c)
	if c.Response().Status != http.StatusForbidden {
		t.Fatalf("expected role fetcher forbidden, got %d", c.Response().Status)
	}

	h.roleFetcher = nil
	c = makeCtx(`{"sso_provider":"workos"}`)
	_ = h.putTenantSettings(c)
	if c.Response().Status != http.StatusBadRequest {
		t.Fatalf("expected upsert failure 400, got %d", c.Response().Status)
	}

	repoOK := &settingsRepoStub{}
	pub := &settingsPublisherStub{}
	h = &Controller{repo: repoOK, service: &settingsServiceStub{}, pub: pub}
	payload := `{
		"sso_provider":"workos",
		"workos_client_id":"cid",
		"workos_client_secret":"sec",
		"workos_api_key":"key",
		"workos_default_connection_id":" conn ",
		"workos_default_organization_id":" org ",
		"sso_state_ttl":"10m",
		"sso_redirect_allowlist":"https://app.example.com, http://localhost:3000",
		"app_cors_allowed_origins":"https://app.example.com",
		"jwt_signing_key":"1234567890123456",
		"rl_login_limit":"10",
		"rl_login_window":"1m",
		"rl_signup_limit":"11",
		"rl_signup_window":"2m",
		"rl_magic_limit":"12",
		"rl_magic_window":"3m",
		"rl_sso_limit":"13",
		"rl_sso_window":"4m",
		"rl_token_limit":"14",
		"rl_token_window":"5m",
		"rl_mfa_limit":"15",
		"rl_mfa_window":"6m",
		"signup_enabled":"true",
		"tenant_logo_url":"https://img.example.com/logo.png"
	}`
	c = makeCtx(payload)
	_ = h.putTenantSettings(c)
	if c.Response().Status != http.StatusNoContent {
		t.Fatalf("expected 204 on full payload, got %d", c.Response().Status)
	}
	if len(repoOK.upserts) < 20 {
		t.Fatalf("expected many upserts for full payload, got %d", len(repoOK.upserts))
	}
	if len(pub.events) != 1 {
		t.Fatalf("expected one audit event on full payload, got %d", len(pub.events))
	}
}

func (s *settingsRepoStub) Get(ctx context.Context, key string, tenantID *uuid.UUID) (string, bool, error) {
	return "", false, nil
}

func (s *settingsRepoStub) Upsert(ctx context.Context, key string, tenantID *uuid.UUID, value string, secret bool) error {
	if s.err != nil {
		return s.err
	}
	s.upserts = append(s.upserts, key)
	return nil
}

type settingsServiceStub struct {
	vals map[string]string
}

func (s *settingsServiceStub) GetString(ctx context.Context, key string, tenantID *uuid.UUID, def string) (string, error) {
	if v, ok := s.vals[key]; ok {
		return v, nil
	}
	return def, nil
}
func (s *settingsServiceStub) GetDuration(ctx context.Context, key string, tenantID *uuid.UUID, def time.Duration) (time.Duration, error) {
	return def, nil
}
func (s *settingsServiceStub) GetInt(ctx context.Context, key string, tenantID *uuid.UUID, def int) (int, error) {
	return def, nil
}

type settingsPublisherStub struct{ events []evdomain.Event }

func (s *settingsPublisherStub) Publish(ctx context.Context, e evdomain.Event) error {
	s.events = append(s.events, e)
	return nil
}

func TestSettingsController_GetTenantSettings_ValidationAndMasking(t *testing.T) {
	e := echo.New()
	tenantID := uuid.New()

	h := &Controller{
		repo: &settingsRepoStub{},
		service: &settingsServiceStub{vals: map[string]string{
			sdomain.KeySSOProvider:        "workos",
			sdomain.KeyWorkOSClientSecret: "supersecret1234",
			sdomain.KeyWorkOSAPIKey:       "abcd",
		}},
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues("not-uuid")
	_ = h.getTenantSettings(c)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 invalid id, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(tenantID.String())
	_ = h.getTenantSettings(c)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 unauthorized, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	c.Set("auth_tenant_id", uuid.New())
	c.SetParamNames("id")
	c.SetParamValues(tenantID.String())
	_ = h.getTenantSettings(c)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 forbidden, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	c.Set("auth_tenant_id", tenantID)
	c.SetParamNames("id")
	c.SetParamValues(tenantID.String())
	_ = h.getTenantSettings(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var out settingsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.WorkOSClientSecret != "****1234" || out.WorkOSAPIKey != "****" {
		t.Fatalf("unexpected masking: %+v", out)
	}
}

func TestSettingsController_PutTenantSettings_ValidationAndAudit(t *testing.T) {
	e := echo.New()
	tenantID := uuid.New()
	userID := uuid.New()
	repo := &settingsRepoStub{}
	pub := &settingsPublisherStub{}
	h := &Controller{repo: repo, service: &settingsServiceStub{}, pub: pub}

	makeCtx := func(payload string) echo.Context {
		req := httptest.NewRequest(http.MethodPut, "/", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(tenantID.String())
		return c
	}

	c := makeCtx(`{}`)
	c.SetParamValues("bad-id")
	_ = h.putTenantSettings(c)
	if c.Response().Status != http.StatusBadRequest {
		t.Fatalf("expected 400 invalid id, got %d", c.Response().Status)
	}

	c = makeCtx(`{}`)
	_ = h.putTenantSettings(c)
	if c.Response().Status != http.StatusUnauthorized {
		t.Fatalf("expected 401 unauthorized, got %d", c.Response().Status)
	}

	c = makeCtx(`{}`)
	c.Set("auth_user_id", userID)
	c.Set("auth_tenant_id", uuid.New())
	_ = h.putTenantSettings(c)
	if c.Response().Status != http.StatusForbidden {
		t.Fatalf("expected 403 tenant mismatch, got %d", c.Response().Status)
	}

	h.roleFetcher = func(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) ([]string, error) {
		return []string{"member"}, nil
	}
	c = makeCtx(`{}`)
	c.Set("auth_user_id", userID)
	c.Set("auth_tenant_id", tenantID)
	_ = h.putTenantSettings(c)
	if c.Response().Status != http.StatusForbidden {
		t.Fatalf("expected 403 missing admin role, got %d", c.Response().Status)
	}

	h.roleFetcher = nil
	for name, payload := range map[string]string{
		"invalid_provider":    `{"sso_provider":"other"}`,
		"invalid_jwt":         `{"jwt_signing_key":"short"}`,
		"invalid_ttl":         `{"sso_state_ttl":"xx"}`,
		"invalid_allowlist":   `{"sso_redirect_allowlist":"not-a-url"}`,
		"invalid_cors":        `{"app_cors_allowed_origins":"notaurl"}`,
		"invalid_rl_limit":    `{"rl_login_limit":"abc"}`,
		"invalid_rl_window":   `{"rl_login_window":"abc"}`,
		"invalid_signup_flag": `{"signup_enabled":"maybe"}`,
	} {
		t.Run(name, func(t *testing.T) {
			c := makeCtx(payload)
			c.Set("auth_user_id", userID)
			c.Set("auth_tenant_id", tenantID)
			_ = h.putTenantSettings(c)
			if c.Response().Status != http.StatusBadRequest {
				t.Fatalf("expected 400 for %s, got %d", name, c.Response().Status)
			}
		})
	}

	c = makeCtx(`{"sso_provider":"workos","workos_client_secret":"secret","workos_api_key":"api","jwt_signing_key":"1234567890123456"}`)
	c.Set("auth_user_id", userID)
	c.Set("auth_tenant_id", tenantID)
	_ = h.putTenantSettings(c)
	if c.Response().Status != http.StatusNoContent {
		t.Fatalf("expected 204 success, got %d", c.Response().Status)
	}
	if len(repo.upserts) == 0 {
		t.Fatal("expected upserts on success")
	}
	if len(pub.events) != 1 {
		t.Fatalf("expected one audit event, got %d", len(pub.events))
	}
	ev := pub.events[0]
	if ev.Meta["sso.workos.client_secret"] != "redacted" || ev.Meta["sso.workos.api_key"] != "redacted" || ev.Meta["auth.jwt_signing_key"] != "redacted" {
		t.Fatalf("expected redaction metadata, got %+v", ev.Meta)
	}
}
