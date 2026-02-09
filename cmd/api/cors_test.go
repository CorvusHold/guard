package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"

	"github.com/corvusHold/guard/internal/config"
)

// stubSettingsService implements settdomain.Service for CORS tests.
type stubSettingsService struct {
	strings map[string]string
}

func (s *stubSettingsService) GetString(_ context.Context, key string, _ *uuid.UUID, def string) (string, error) {
	if v, ok := s.strings[key]; ok {
		return v, nil
	}
	return def, nil
}

func (s *stubSettingsService) GetDuration(_ context.Context, _ string, _ *uuid.UUID, def time.Duration) (time.Duration, error) {
	return def, nil
}

func (s *stubSettingsService) GetInt(_ context.Context, _ string, _ *uuid.UUID, def int) (int, error) {
	return def, nil
}

func TestResolveTenantID_Header(t *testing.T) {
	e := echo.New()
	tid := uuid.New()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/password/login", nil)
	req.Header.Set("X-Tenant-ID", tid.String())
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	got := resolveTenantID(c)
	if got == nil {
		t.Fatal("expected tenant ID from X-Tenant-ID header, got nil")
	}
	if *got != tid {
		t.Fatalf("expected %s, got %s", tid, *got)
	}
}

func TestResolveTenantID_HeaderPrecedence(t *testing.T) {
	e := echo.New()
	headerTID := uuid.New()
	queryTID := uuid.New()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/password/login?tenant_id="+queryTID.String(), nil)
	req.Header.Set("X-Tenant-ID", headerTID.String())
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	got := resolveTenantID(c)
	if got == nil {
		t.Fatal("expected tenant ID, got nil")
	}
	// Header takes precedence over query param
	if *got != headerTID {
		t.Fatalf("expected header tenant %s to take precedence, got %s", headerTID, *got)
	}
}

func TestDynamicTenantCORS_HeaderTenantOrigin(t *testing.T) {
	tid := uuid.New()
	tenantOrigin := "https://tenant-app.example.com"

	cfg := config.Config{CORSAllowedOrigins: []string{"https://global.example.com"}}
	svc := &stubSettingsService{strings: map[string]string{
		"app.cors_allowed_origins": tenantOrigin,
	}}
	log := zerolog.Nop()

	mw := dynamicTenantCORS(cfg, svc, log)

	e := echo.New()
	e.Use(mw)
	e.POST("/api/v1/auth/password/login", func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	// Preflight with tenant origin + X-Tenant-ID header should be allowed
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/auth/password/login", nil)
	req.Header.Set(echo.HeaderOrigin, tenantOrigin)
	req.Header.Set("X-Tenant-ID", tid.String())
	req.Header.Set(echo.HeaderAccessControlRequestMethod, http.MethodPost)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for preflight, got %d", rec.Code)
	}
	if got := rec.Header().Get(echo.HeaderAccessControlAllowOrigin); got != tenantOrigin {
		t.Fatalf("expected Access-Control-Allow-Origin=%s, got %s", tenantOrigin, got)
	}
}

func TestDynamicTenantCORS_NoHeaderNoTenantOrigin(t *testing.T) {
	cfg := config.Config{CORSAllowedOrigins: []string{"https://global.example.com"}}
	svc := &stubSettingsService{strings: map[string]string{
		"app.cors_allowed_origins": "https://tenant-app.example.com",
	}}
	log := zerolog.Nop()

	mw := dynamicTenantCORS(cfg, svc, log)

	e := echo.New()
	e.Use(mw)
	e.POST("/api/v1/auth/password/login", func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	// Request with tenant origin but NO X-Tenant-ID header should be rejected
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/login", nil)
	req.Header.Set(echo.HeaderOrigin, "https://tenant-app.example.com")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if got := rec.Header().Get(echo.HeaderAccessControlAllowOrigin); got != "" {
		t.Fatalf("expected no CORS header without X-Tenant-ID, got %s", got)
	}
}

func TestMatchCORSOrigin_Exact(t *testing.T) {
	patterns := []string{"https://app.example.com"}

	if !matchCORSOrigin("https://app.example.com", patterns) {
		t.Fatalf("expected exact origin match to be allowed")
	}

	if matchCORSOrigin("https://other.example.com", patterns) {
		t.Fatalf("did not expect different subdomain to be allowed for exact pattern")
	}
}

func TestMatchCORSOrigin_Star(t *testing.T) {
	patterns := []string{"*"}

	for _, origin := range []string{
		"https://app.example.com",
		"https://example.com",
		"http://localhost:3000",
	} {
		if !matchCORSOrigin(origin, patterns) {
			t.Fatalf("expected '*' pattern to allow origin %q", origin)
		}
	}
}

func TestMatchCORSOrigin_WildcardSubdomain(t *testing.T) {
	patterns := []string{"https://*.example.com"}

	for _, origin := range []string{
		"https://app.example.com",
		"https://foo.bar.example.com",
	} {
		if !matchCORSOrigin(origin, patterns) {
			t.Fatalf("expected wildcard pattern to allow origin %q", origin)
		}
	}

	if matchCORSOrigin("https://example.com", patterns) {
		t.Fatalf("did not expect bare domain to be allowed by wildcard pattern")
	}

	if matchCORSOrigin("https://example.com", patterns) {
		t.Fatalf("did not expect different domain to be allowed by wildcard pattern")
	}

	if matchCORSOrigin("http://app.example.com", patterns) {
		t.Fatalf("did not expect different scheme to be allowed by wildcard pattern")
	}
}

func TestMatchCORSOrigin_InvalidPatternDoesNotPanic(t *testing.T) {
	patterns := []string{"https://%gh&%ij"}

	if matchCORSOrigin("https://origin.example.com", patterns) {
		t.Fatalf("did not expect invalid URL pattern to match origin")
	}
}
