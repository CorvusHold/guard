package controller

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/corvusHold/guard/internal/config"
	"github.com/labstack/echo/v4"
)

func TestHTTP_CookieMode_Login(t *testing.T) {
	e := echo.New()

	// Test login without X-Auth-Mode header (should return bearer tokens)
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

		// Mock service would be needed for full test
		// For now, just verify the detectAuthMode function works
		mode := detectAuthMode(ctx)
		if mode != "bearer" {
			t.Errorf("expected bearer mode, got %s", mode)
		}
	})

	// Test login with X-Auth-Mode: cookie header
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

		mode := detectAuthMode(ctx)
		if mode != "cookie" {
			t.Errorf("expected cookie mode, got %s", mode)
		}
	})

	// Test detectAuthMode with various header values
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

			mode := detectAuthMode(ctx)
			if mode != tc.expected {
				t.Errorf("header %q: expected %s, got %s", tc.header, tc.expected, mode)
			}
		}
	})
}

func TestHTTP_CookieMode_SetCookies(t *testing.T) {
	cfg := config.Config{
		JWTSigningKey:   "test-key",
		AccessTokenTTL:  900,
		RefreshTokenTTL: 2592000,
		DefaultAuthMode: "cookie",
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	// Test setTokenCookies
	accessToken := "test-access-token"
	refreshToken := "test-refresh-token"

	setTokenCookies(ctx, accessToken, refreshToken, cfg)

	// Check response headers for Set-Cookie
	cookies := rec.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("expected 2 cookies, got %d", len(cookies))
	}

	// Verify access token cookie
	var accessCookie *http.Cookie
	var refreshCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == "guard_access_token" {
			accessCookie = cookie
		} else if cookie.Name == "guard_refresh_token" {
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
}
