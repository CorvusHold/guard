package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	authrepo "github.com/corvusHold/guard/internal/auth/repository"
	svc "github.com/corvusHold/guard/internal/auth/service"
	"github.com/corvusHold/guard/internal/config"
	evdomain "github.com/corvusHold/guard/internal/events/domain"
	srepo "github.com/corvusHold/guard/internal/settings/repository"
	ssvc "github.com/corvusHold/guard/internal/settings/service"
	trepo "github.com/corvusHold/guard/internal/tenants/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// reuse noopValidator and tokensResponse types from http_integration_test.go if in same package

type noopValidatorSSO struct{}

func TestHTTP_SSO_Dev_RedirectAllowlist_Disallowed_400(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("skipping integration test: DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatalf("db connect: %v", err)
	}
	defer pool.Close()

	// tenant
	tr := trepo.New(pool)
	tenantID := uuid.New()
	name := "http-sso-dev-allowlist-disallowed-" + tenantID.String()
	if err := tr.Create(ctx, tenantID, name, nil); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	time.Sleep(25 * time.Millisecond)

	// services and settings
	repo := authrepo.New(pool)
	sr := srepo.New(pool)
	settings := ssvc.New(sr)
	cfg, _ := config.Load()
	// ensure dev provider and a strict allowlist that will NOT match
	_ = sr.Upsert(ctx, "sso.provider", &tenantID, "dev", false)
	_ = sr.Upsert(ctx, "sso.redirect_allowlist", &tenantID, "https://allowed.example/", false)
	magic := svc.NewMagic(repo, cfg, settings, nil)
	auth := svc.New(repo, cfg, settings)
	sso := svc.NewSSO(repo, cfg, settings)
	// capture audit events
	events := make([]evdomain.Event, 0, 2)
	sso.SetPublisher(publisherFunc(func(ctx context.Context, e evdomain.Event) error {
		events = append(events, e)
		return nil
	}))

	e := echo.New()
	e.Validator = noopValidatorSSO{}
	api := e.Group("/api")
	apiV1 := api.Group("/v1")
	c := New(auth, magic, sso)
	c.RegisterV1(apiV1)

	// Start with a redirect not on allowlist
	qs := url.Values{}
	qs.Set("tenant_id", tenantID.String())
	qs.Set("redirect_url", "http://localhost/cb")
	qs.Set("state", "x")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sso/google/start?"+qs.Encode(), nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	// assert audit failure event for disallowed redirect
	found := false
	for _, ev := range events {
		if ev.Type == "auth.sso.start.failure" && ev.TenantID == tenantID {
			if ev.Meta["provider"] == "google" && ev.Meta["reason"] == "redirect_disallowed" && ev.Meta["redirect_url"] == "http://localhost/cb" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("expected auth.sso.start.failure event with redirect_disallowed")
	}
}

func TestHTTP_SSO_Dev_RedirectAllowlist_AllowedPrefix_OK(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("skipping integration test: DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatalf("db connect: %v", err)
	}
	defer pool.Close()

	// tenant
	tr := trepo.New(pool)
	tenantID := uuid.New()
	name := "http-sso-dev-allowlist-ok-" + tenantID.String()
	if err := tr.Create(ctx, tenantID, name, nil); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	time.Sleep(25 * time.Millisecond)

	// services and settings
	repo := authrepo.New(pool)
	sr := srepo.New(pool)
	settings := ssvc.New(sr)
	cfg, _ := config.Load()
	// ensure dev provider and allowlist that matches http://localhost/*
	_ = sr.Upsert(ctx, "sso.provider", &tenantID, "dev", false)
	_ = sr.Upsert(ctx, "sso.redirect_allowlist", &tenantID, "http://localhost/", false)
	magic := svc.NewMagic(repo, cfg, settings, nil)
	auth := svc.New(repo, cfg, settings)
	sso := svc.NewSSO(repo, cfg, settings)
	// capture audit events
	events := make([]evdomain.Event, 0, 2)
	sso.SetPublisher(publisherFunc(func(ctx context.Context, e evdomain.Event) error {
		events = append(events, e)
		return nil
	}))

	e := echo.New()
	e.Validator = noopValidatorSSO{}
	api := e.Group("/api")
	apiV1 := api.Group("/v1")
	c := New(auth, magic, sso)
	c.RegisterV1(apiV1)

	// Start with an allowed redirect prefix
	qs := url.Values{}
	qs.Set("tenant_id", tenantID.String())
	qs.Set("redirect_url", "http://localhost/cb?ok=1")
	qs.Set("state", "abc")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sso/google/start?"+qs.Encode(), nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if loc == "" {
		t.Fatalf("expected redirect Location")
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	if u.Path == "" || u.Query().Get("code") == "" {
		t.Fatalf("invalid redirect: %s", loc)
	}

	// Follow callback
	req2 := httptest.NewRequest(http.MethodGet, u.RequestURI(), nil)
	req2.Header.Set("X-Auth-Mode", "bearer")
	rec2 := httptest.NewRecorder()
	e.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec2.Code, rec2.Body.String())
	}
	var trsp tokensResponseSSO
	if err := json.NewDecoder(rec2.Body).Decode(&trsp); err != nil {
		t.Fatalf("decode tokens: %v", err)
	}
	if trsp.AccessToken == "" || trsp.RefreshToken == "" {
		t.Fatalf("expected non-empty tokens: %+v", trsp)
	}
	// assert success audit event
	expectedEmail := "sso.dev.google." + tenantID.String() + "@example.test"
	okEvent := false
	for _, ev := range events {
		if ev.Type == "auth.sso.login.success" && ev.TenantID == tenantID {
			if ev.Meta["provider"] == "google" && ev.Meta["email"] == expectedEmail {
				okEvent = true
			}
		}
	}
	if !okEvent {
		t.Fatalf("expected auth.sso.login.success event for dev flow")
	}
}
func (noopValidatorSSO) Validate(i interface{}) error { return nil }

type tokensResponseSSO struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func TestHTTP_SSO_Dev_StartAndCallback(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("skipping integration test: DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatalf("db connect: %v", err)
	}
	defer pool.Close()

	// tenant
	tr := trepo.New(pool)
	tenantID := uuid.New()
	name := "http-sso-itest-" + tenantID.String()
	if err := tr.Create(ctx, tenantID, name, nil); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	time.Sleep(25 * time.Millisecond)

	// wire services
	repo := authrepo.New(pool)
	sr := srepo.New(pool)
	settings := ssvc.New(sr)
	cfg, _ := config.Load()
	// ensure dev provider for this tenant
	_ = sr.Upsert(ctx, "sso.provider", &tenantID, "dev", false)
	magic := svc.NewMagic(repo, cfg, settings, nil) // not used in this test
	auth := svc.New(repo, cfg, settings)
	sso := svc.NewSSO(repo, cfg, settings)

	e := echo.New()
	e.Validator = noopValidatorSSO{}
	api := e.Group("/api")
	apiV1 := api.Group("/v1")
	c := New(auth, magic, sso)
	c.RegisterV1(apiV1)

	// GET /api/v1/auth/sso/google/start
	qs := url.Values{}
	qs.Set("tenant_id", tenantID.String())
	qs.Set("redirect_url", "http://localhost/cb")
	qs.Set("state", "abc")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sso/google/start?"+qs.Encode(), nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if loc == "" {
		t.Fatalf("expected redirect Location")
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	if u.Path == "" || u.Query().Get("code") == "" {
		t.Fatalf("invalid redirect: %s", loc)
	}

	// Follow callback
	req2 := httptest.NewRequest(http.MethodGet, u.RequestURI(), nil)
	req2.Header.Set("X-Auth-Mode", "bearer")
	rec2 := httptest.NewRecorder()
	e.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec2.Code, rec2.Body.String())
	}
	var trsp tokensResponseSSO
	if err := json.NewDecoder(rec2.Body).Decode(&trsp); err != nil {
		t.Fatalf("decode tokens: %v", err)
	}
	if trsp.AccessToken == "" || trsp.RefreshToken == "" {
		t.Fatalf("expected non-empty tokens: %+v", trsp)
	}
}
