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

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"

	authrepo "github.com/corvusHold/guard/internal/auth/repository"
	svc "github.com/corvusHold/guard/internal/auth/service"
	"github.com/corvusHold/guard/internal/config"
	srepo "github.com/corvusHold/guard/internal/settings/repository"
	ssvc "github.com/corvusHold/guard/internal/settings/service"
	trepo "github.com/corvusHold/guard/internal/tenants/repository"
)

func TestHTTP_CookieMode_Login(t *testing.T) {
	e := echo.New()

	t.Run("login without X-Auth-Mode returns bearer tokens", func(t *testing.T) {
		body := map[string]string{
			"tenant_id": "test-tenant",
			"email":     "test@example.com",
			"password":  "password123",
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/v1/auth/password/login", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mode := detectAuthMode(ctx, "bearer")
		if mode != "bearer" {
			t.Errorf("expected bearer mode, got %s", mode)
		}
	})

	t.Run("login with X-Auth-Mode: cookie", func(t *testing.T) {
		body := map[string]string{
			"tenant_id": "test-tenant",
			"email":     "test@example.com",
			"password":  "password123",
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/v1/auth/password/login", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Auth-Mode", "cookie")
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mode := detectAuthMode(ctx, "bearer")
		if mode != "cookie" {
			t.Errorf("expected cookie mode, got %s", mode)
		}
	})

	t.Run("detectAuthMode handles case insensitivity", func(t *testing.T) {
		testCases := []struct {
			header   string
			expected string
		}{
			{"cookie", "cookie"},
			{"Cookie", "cookie"},
			{"COOKIE", "cookie"},
			{"  cookie  ", "cookie"},
			{"bearer", "bearer"},
			{"json", "bearer"},
			{"JSON", "bearer"},
			{"JsOn", "bearer"},
			{"invalid", "bearer"},
			{"", "bearer"},
		}

		for _, tc := range testCases {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.header != "" {
				req.Header.Set("X-Auth-Mode", tc.header)
			}
			rec := httptest.NewRecorder()
			ctx := e.NewContext(req, rec)

			mode := detectAuthMode(ctx, "bearer")
			if mode != tc.expected {
				t.Errorf("header %q: expected %s, got %s", tc.header, tc.expected, mode)
			}
		}
	})
}

func TestHTTP_CookieMode_SetCookies(t *testing.T) {
	cfg := config.Config{
		JWTSigningKey:   "test-key",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 30 * 24 * time.Hour,
		DefaultAuthMode: "cookie",
		CookieSameSite:  http.SameSiteStrictMode,
		ForceHTTPS:      true,
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	accessToken := "test-access-token"
	refreshToken := "test-refresh-token"

	setTokenCookies(ctx, accessToken, refreshToken, cfg)

	cookies := rec.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("expected 2 cookies, got %d", len(cookies))
	}

	var accessCookie *http.Cookie
	var refreshCookie *http.Cookie
	for _, cookie := range cookies {
		switch cookie.Name {
		case "guard_access_token":
			accessCookie = cookie
		case "guard_refresh_token":
			refreshCookie = cookie
		}
	}

	if accessCookie == nil {
		t.Fatal("access token cookie not found")
	}
	if accessCookie.Value != accessToken {
		t.Errorf("access token: expected %s, got %s", accessToken, accessCookie.Value)
	}
	if !accessCookie.HttpOnly {
		t.Error("access token cookie should be HttpOnly")
	}
	if accessCookie.Path != "/" {
		t.Errorf("access token path: expected /, got %s", accessCookie.Path)
	}
	if !accessCookie.Secure {
		t.Error("access token cookie should be secure when ForceHTTPS is enabled")
	}
	if accessCookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("expected SameSite=%v, got %v", http.SameSiteStrictMode, accessCookie.SameSite)
	}

	if refreshCookie == nil {
		t.Fatal("refresh token cookie not found")
	}
	if refreshCookie.Value != refreshToken {
		t.Errorf("refresh token: expected %s, got %s", refreshToken, refreshCookie.Value)
	}
	if !refreshCookie.HttpOnly {
		t.Error("refresh token cookie should be HttpOnly")
	}
	if refreshCookie.Path != "/" {
		t.Errorf("refresh token path: expected /, got %s", refreshCookie.Path)
	}
	if !refreshCookie.Secure {
		t.Error("refresh token cookie should be secure when ForceHTTPS is enabled")
	}
	if refreshCookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("expected SameSite=%v, got %v", http.SameSiteStrictMode, refreshCookie.SameSite)
	}
}

func TestHTTP_CookieMode_RefreshViaCookieMode(t *testing.T) {
	fix := newCookieModeTestFixture(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", bytes.NewBufferString("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Auth-Mode", "cookie")
	req.Header.Set("User-Agent", "cookie-itest")
	req.AddCookie(&http.Cookie{Name: "guard_refresh_token", Value: fix.refreshToken})
	rec := httptest.NewRecorder()
	fix.e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.NewDecoder(bytes.NewReader(rec.Body.Bytes())).Decode(&body); err != nil {
		t.Fatalf("decode refresh body: %v", err)
	}
	if success, ok := body["success"]; !ok || success != true {
		t.Fatalf("expected success response without tokens, got %+v", body)
	}
	if _, ok := body["access_token"]; ok {
		t.Fatalf("expected no access_token in cookie mode response, got %+v", body)
	}
	if _, ok := body["refresh_token"]; ok {
		t.Fatalf("expected no refresh_token in cookie mode response, got %+v", body)
	}
	accessCookie := requireCookie(t, rec.Result().Cookies(), "guard_access_token")
	if accessCookie.Value == "" {
		t.Fatalf("expected guard_access_token cookie to be set")
	}
	refreshCookie := requireCookie(t, rec.Result().Cookies(), "guard_refresh_token")
	if refreshCookie.Value == "" {
		t.Fatalf("expected guard_refresh_token cookie to be rotated")
	}
	fix.refreshToken = refreshCookie.Value
}

func TestHTTP_CookieMode_LogoutViaCookieMode(t *testing.T) {
	fix := newCookieModeTestFixture(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", bytes.NewBufferString("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Auth-Mode", "cookie")
	req.AddCookie(&http.Cookie{Name: "guard_refresh_token", Value: fix.refreshToken})
	rec := httptest.NewRecorder()
	fix.e.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("expected empty body on logout, got %q", rec.Body.String())
	}
	accessCookie := requireCookie(t, rec.Result().Cookies(), "guard_access_token")
	if accessCookie.MaxAge > 0 {
		t.Fatalf("expected guard_access_token cookie to be cleared, got MaxAge=%d", accessCookie.MaxAge)
	}
	refreshCookie := requireCookie(t, rec.Result().Cookies(), "guard_refresh_token")
	if refreshCookie.MaxAge > 0 {
		t.Fatalf("expected guard_refresh_token cookie to be cleared, got MaxAge=%d", refreshCookie.MaxAge)
	}
	// Refreshing with the revoked token (still using cookie mode) should now fail.
	again := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", bytes.NewBufferString("{}"))
	again.Header.Set("Content-Type", "application/json")
	again.Header.Set("X-Auth-Mode", "cookie")
	again.AddCookie(&http.Cookie{Name: "guard_refresh_token", Value: fix.refreshToken})
	againRec := httptest.NewRecorder()
	fix.e.ServeHTTP(againRec, again)
	if againRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected refresh to fail after logout, got %d: %s", againRec.Code, againRec.Body.String())
	}
}

type cookieModeTestFixture struct {
	e            *echo.Echo
	refreshToken string
}

type cookieTokensResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func newCookieModeTestFixture(t *testing.T) *cookieModeTestFixture {
	t.Helper()
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("skipping integration test: DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatalf("db connect: %v", err)
	}
	t.Cleanup(pool.Close)
	tr := trepo.New(pool)
	tenantID := uuid.New()
	name := "http-cookie-mode-itest-" + tenantID.String()
	if err := tr.Create(ctx, tenantID, name); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	// allow tenant replication to complete
	time.Sleep(25 * time.Millisecond)
	repo := authrepo.New(pool)
	sr := srepo.New(pool)
	settings := ssvc.New(sr)
	cfg, _ := config.Load()
	auth := svc.New(repo, cfg, settings)
	magic := svc.NewMagic(repo, cfg, settings, &fakeEmail{})
	sso := svc.NewSSO(repo, cfg, settings)
	e := echo.New()
	e.Validator = noopValidator{}
	controller := New(auth, magic, sso)
	controller.Register(e)
	email := "cookie-mode-user-" + tenantID.String() + "@example.com"
	password := "Password!123"
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
		t.Fatalf("signup expected 201, got %d: %s", srec.Code, srec.Body.String())
	}
	lBody := map[string]string{
		"tenant_id": tenantID.String(),
		"email":     email,
		"password":  password,
	}
	lb, _ := json.Marshal(lBody)
	lreq := httptest.NewRequest(http.MethodPost, "/v1/auth/password/login", bytes.NewReader(lb))
	lreq.Header.Set("Content-Type", "application/json")
	lreq.Header.Set("User-Agent", "cookie-itest")
	lrec := httptest.NewRecorder()
	e.ServeHTTP(lrec, lreq)
	if lrec.Code != http.StatusOK {
		t.Fatalf("login expected 200, got %d: %s", lrec.Code, lrec.Body.String())
	}
	var tokens cookieTokensResponse
	if err := json.NewDecoder(bytes.NewReader(lrec.Body.Bytes())).Decode(&tokens); err != nil {
		t.Fatalf("decode login tokens: %v", err)
	}
	if tokens.RefreshToken == "" {
		t.Fatalf("expected refresh token from login")
	}
	return &cookieModeTestFixture{e: e, refreshToken: tokens.RefreshToken}
}

func requireCookie(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("cookie %s not found", name)
	return nil
}
