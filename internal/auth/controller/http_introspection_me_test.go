package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	svc "github.com/corvusHold/guard/internal/auth/service"
	authrepo "github.com/corvusHold/guard/internal/auth/repository"
	"github.com/corvusHold/guard/internal/config"
	srepo "github.com/corvusHold/guard/internal/settings/repository"
	ssvc "github.com/corvusHold/guard/internal/settings/service"
	trepo "github.com/corvusHold/guard/internal/tenants/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

func TestHTTP_Introspect_Me_Revoke(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("skipping integration test: DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil { t.Fatalf("db connect: %v", err) }
	defer pool.Close()

	// tenant
	tr := trepo.New(pool)
	tenantID := uuid.New()
	name := "http-introspect-me-itest-" + tenantID.String()
	if err := tr.Create(ctx, tenantID, name); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	time.Sleep(25 * time.Millisecond)

	// services
	repo := authrepo.New(pool)
	sr := srepo.New(pool)
	settings := ssvc.New(sr)
	cfg, _ := config.Load()
	auth := svc.New(repo, cfg, settings)
	magic := svc.NewMagic(repo, cfg, settings, &fakeEmail{})
	sso := svc.NewSSO(repo, cfg, settings)

	e := echo.New()
	e.Validator = noopValidator{}
	c := New(auth, magic, sso)
	c.Register(e)

	email := "user.me.itest@example.com"
	password := "Password!123"

	// signup
	sBody := map[string]string{
		"tenant_id": tenantID.String(),
		"email":     email,
		"password":  password,
	}
	sb, _ := json.Marshal(sBody)
	sreq := httptest.NewRequest(http.MethodPost, "/v1/auth/password/signup", bytes.NewReader(sb))
	sreq.Header.Set("Content-Type", "application/json")
	srec := httptest.NewRecorder()
	e.ServeHTTP(srec, sreq)
	if srec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", srec.Code, srec.Body.String())
	}
	var stoks tokensResponse
	if err := json.NewDecoder(bytes.NewReader(srec.Body.Bytes())).Decode(&stoks); err != nil {
		t.Fatalf("decode tokens: %v", err)
	}
	if stoks.AccessToken == "" || stoks.RefreshToken == "" {
		t.Fatalf("expected tokens")
	}

	// introspect using Authorization header
	ireq := httptest.NewRequest(http.MethodPost, "/v1/auth/introspect", nil)
	ireq.Header.Set("Authorization", "Bearer "+stoks.AccessToken)
	irec := httptest.NewRecorder()
	e.ServeHTTP(irec, ireq)
	if irec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", irec.Code, irec.Body.String())
	}
	var iout map[string]any
	if err := json.NewDecoder(bytes.NewReader(irec.Body.Bytes())).Decode(&iout); err != nil {
		t.Fatalf("decode introspect: %v", err)
	}
	if act, _ := iout["active"].(bool); !act {
		t.Fatalf("expected active=true in introspection")
	}

	// me endpoint
	mreq := httptest.NewRequest(http.MethodGet, "/v1/auth/me", nil)
	mreq.Header.Set("Authorization", "Bearer "+stoks.AccessToken)
	mrec := httptest.NewRecorder()
	e.ServeHTTP(mrec, mreq)
	if mrec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", mrec.Code, mrec.Body.String())
	}
	var profile map[string]any
	if err := json.NewDecoder(bytes.NewReader(mrec.Body.Bytes())).Decode(&profile); err != nil {
		t.Fatalf("decode profile: %v", err)
	}
	if profile["email"] != email { t.Fatalf("email mismatch: %v", profile["email"]) }

	// revoke refresh token and ensure refresh fails
	rb, _ := json.Marshal(map[string]string{"token": stoks.RefreshToken, "token_type": "refresh"})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/revoke", bytes.NewReader(rb))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	// now attempt refresh with revoked token
	rf, _ := json.Marshal(map[string]string{"refresh_token": stoks.RefreshToken})
	rreq := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", bytes.NewReader(rf))
	rreq.Header.Set("Content-Type", "application/json")
	rrec := httptest.NewRecorder()
	e.ServeHTTP(rrec, rreq)
	if rrec.Code == http.StatusOK {
		t.Fatalf("expected refresh to fail after revoke; got 200: %s", rrec.Body.String())
	}
}
