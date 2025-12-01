package controller

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	authrepo "github.com/corvusHold/guard/internal/auth/repository"
	svc "github.com/corvusHold/guard/internal/auth/service"
	"github.com/corvusHold/guard/internal/config"
	srepo "github.com/corvusHold/guard/internal/settings/repository"
	ssvc "github.com/corvusHold/guard/internal/settings/service"
	trepo "github.com/corvusHold/guard/internal/tenants/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jarcoal/httpmock"
	"github.com/labstack/echo/v4"
)

type tokensResponseLogout struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func TestHTTP_SSO_WorkOS_LogoutRevokesRefreshToken(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" || os.Getenv("REDIS_ADDR") == "" {
		t.Skip("skipping integration test: DATABASE_URL or REDIS_ADDR not set")
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
	if err := tr.Create(ctx, tenantID, "http-sso-workos-logout-"+tenantID.String()); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	time.Sleep(25 * time.Millisecond)

	// settings
	sr := srepo.New(pool)
	settings := ssvc.New(sr)
	if err := sr.Upsert(ctx, "sso.provider", &tenantID, "workos", false); err != nil {
		t.Fatalf("upsert tenant sso.provider: %v", err)
	}
	if err := sr.Upsert(ctx, "sso.workos.client_id", &tenantID, "client_test_123", true); err != nil {
		t.Fatalf("upsert client_id: %v", err)
	}
	if err := sr.Upsert(ctx, "sso.workos.client_secret", &tenantID, "secret_test_456", true); err != nil {
		t.Fatalf("upsert client_secret: %v", err)
	}

	// services and echo
	repo := authrepo.New(pool)
	cfg, _ := config.Load()
	magic := svc.NewMagic(repo, cfg, settings, nil)
	auth := svc.New(repo, cfg, settings)
	sso := svc.NewSSO(repo, cfg, settings)

	e := echo.New()
	e.Validator = noopValidatorWorkOS{}
	c := New(auth, magic, sso)
	c.Register(e)

	// Start: expect redirect to WorkOS authorize
	qs := url.Values{}
	qs.Set("tenant_id", tenantID.String())
	req := httptest.NewRequest(http.MethodGet, "/v1/auth/sso/google/start?"+qs.Encode(), nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if loc == "" {
		t.Fatalf("expected redirect Location")
	}
	authURL, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	state := authURL.Query().Get("state")
	if state == "" {
		t.Fatalf("missing state")
	}

	// Mock WorkOS token exchange
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	httpmock.RegisterResponder("POST", "https://api.workos.com/sso/token",
		func(r *http.Request) (*http.Response, error) {
			// Assert form payload contains expected redirect_uri
			b, _ := io.ReadAll(r.Body)
			_ = r.Body.Close()
			formVals, _ := url.ParseQuery(string(b))
			expectedRedirect := cfg.PublicBaseURL + "/v1/auth/sso/google/callback"
			if formVals.Get("redirect_uri") != expectedRedirect {
				return httpmock.NewStringResponse(400, `{"error":"bad_redirect_uri"}`), nil
			}
			resp := httpmock.NewStringResponse(200, `{
				"access_token": "tok_workos_test",
				"profile": {
					"id": "prof_789",
					"email": "logout.workos.itest@example.com",
					"first_name": "Work",
					"last_name": "OS"
				}
			}`)
			return resp, nil
		},
	)

	// Callback with code + state
	cbQS := url.Values{}
	cbQS.Set("code", "code_logout_test")
	cbQS.Set("state", state)
	req2 := httptest.NewRequest(http.MethodGet, "/v1/auth/sso/google/callback?"+cbQS.Encode(), nil)
	rec2 := httptest.NewRecorder()
	e.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec2.Code, rec2.Body.String())
	}
	var trsp tokensResponseLogout
	if err := json.NewDecoder(rec2.Body).Decode(&trsp); err != nil {
		t.Fatalf("decode tokens: %v", err)
	}
	if trsp.RefreshToken == "" {
		t.Fatalf("expected refresh token")
	}

	// Verify token persisted and not revoked yet
	h := sha256.Sum256([]byte(trsp.RefreshToken))
	hashB64 := base64.RawURLEncoding.EncodeToString(h[:])
	if rt, err := repo.GetRefreshTokenByHash(ctx, hashB64); err != nil {
		t.Fatalf("refresh token not persisted: %v", err)
	} else if rt.Revoked {
		t.Fatalf("token unexpectedly revoked before logout")
	}

	// Call logout with the refresh token
	logoutBody := strings.NewReader(`{"refresh_token":"` + trsp.RefreshToken + `"}`)
	req3 := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", logoutBody)
	req3.Header.Set("Content-Type", "application/json")
	rec3 := httptest.NewRecorder()
	e.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec3.Code, rec3.Body.String())
	}

	// Verify token chain revoked
	if rt, err := repo.GetRefreshTokenByHash(ctx, hashB64); err != nil {
		t.Fatalf("lookup refresh token: %v", err)
	} else if !rt.Revoked {
		t.Fatalf("expected token revoked after logout")
	}

	// Attempt to refresh should now fail (401)
	refreshBody := strings.NewReader(`{"refresh_token":"` + trsp.RefreshToken + `"}`)
	req4 := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", refreshBody)
	req4.Header.Set("Content-Type", "application/json")
	rec4 := httptest.NewRecorder()
	e.ServeHTTP(rec4, req4)
	if rec4.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on refresh after logout, got %d: %s", rec4.Code, rec4.Body.String())
	}
}
