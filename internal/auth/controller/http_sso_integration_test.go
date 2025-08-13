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

// reuse noopValidator and tokensResponse types from http_integration_test.go if in same package

type noopValidatorSSO struct{}
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
	if err != nil { t.Fatalf("db connect: %v", err) }
	defer pool.Close()

	// tenant
	tr := trepo.New(pool)
	tenantID := uuid.New()
	name := "http-sso-itest-" + tenantID.String()
	if err := tr.Create(ctx, tenantID, name); err != nil {
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
	c := New(auth, magic, sso)
	c.Register(e)

	// GET /v1/auth/sso/google/start
	qs := url.Values{}
	qs.Set("tenant_id", tenantID.String())
	qs.Set("redirect_url", "http://localhost/cb")
	qs.Set("state", "abc")
	req := httptest.NewRequest(http.MethodGet, "/v1/auth/sso/google/start?"+qs.Encode(), nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if loc == "" { t.Fatalf("expected redirect Location") }
	u, err := url.Parse(loc)
	if err != nil { t.Fatalf("parse location: %v", err) }
	if u.Path == "" || u.Query().Get("code") == "" { t.Fatalf("invalid redirect: %s", loc) }

	// Follow callback
	req2 := httptest.NewRequest(http.MethodGet, u.RequestURI(), nil)
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
