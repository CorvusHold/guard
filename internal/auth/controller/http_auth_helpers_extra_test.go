package controller

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/corvusHold/guard/internal/config"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

func TestBearerToken_ResolveAccessToken_AndRequireAuthMissingToken(t *testing.T) {
	e := echo.New()

	t.Run("bearer token parser", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer tok-1")
		c := e.NewContext(req, httptest.NewRecorder())
		if got := bearerToken(c); got != "tok-1" {
			t.Fatalf("expected tok-1, got %q", got)
		}

		req2 := httptest.NewRequest(http.MethodGet, "/", nil)
		req2.Header.Set("Authorization", "Basic abc")
		c2 := e.NewContext(req2, httptest.NewRecorder())
		if got := bearerToken(c2); got != "" {
			t.Fatalf("expected empty token for non-bearer auth, got %q", got)
		}
	})

	t.Run("resolve access token prefers bearer then cookie", func(t *testing.T) {
		h := &Controller{cfg: config.Config{DefaultAuthMode: "cookie"}}

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer header-token")
		req.AddCookie(&http.Cookie{Name: guardAccessTokenCookieName, Value: "cookie-token"})
		c := e.NewContext(req, httptest.NewRecorder())
		if got := h.resolveAccessToken(c); got != "header-token" {
			t.Fatalf("expected bearer token priority, got %q", got)
		}

		req2 := httptest.NewRequest(http.MethodGet, "/", nil)
		req2.Header.Set("X-Auth-Mode", "cookie")
		req2.AddCookie(&http.Cookie{Name: guardAccessTokenCookieName, Value: "cookie-token"})
		c2 := e.NewContext(req2, httptest.NewRecorder())
		if got := h.resolveAccessToken(c2); got != "cookie-token" {
			t.Fatalf("expected cookie fallback token, got %q", got)
		}
	})

	t.Run("requireAuth and admin helpers return auth errors when missing token", func(t *testing.T) {
		h := &Controller{cfg: config.Config{DefaultAuthMode: "bearer"}}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		if _, err := h.requireAuth(c); err != ErrUnauthorized {
			t.Fatalf("expected ErrUnauthorized from requireAuth, got %v", err)
		}
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 from requireAuth, got %d body=%s", rec.Code, rec.Body.String())
		}

		req2 := httptest.NewRequest(http.MethodGet, "/", nil)
		rec2 := httptest.NewRecorder()
		c2 := e.NewContext(req2, rec2)
		if _, err := h.requireAdmin(c2); err != ErrUnauthorized {
			t.Fatalf("expected ErrUnauthorized from requireAdmin, got %v", err)
		}
		if rec2.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 from requireAdmin, got %d body=%s", rec2.Code, rec2.Body.String())
		}

		req3 := httptest.NewRequest(http.MethodGet, "/", nil)
		rec3 := httptest.NewRecorder()
		c3 := e.NewContext(req3, rec3)
		if _, err := h.requireAdminForTenant(c3, uuid.New()); err != ErrUnauthorized {
			t.Fatalf("expected ErrUnauthorized from requireAdminForTenant, got %v", err)
		}
		if rec3.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 from requireAdminForTenant, got %d body=%s", rec3.Code, rec3.Body.String())
		}
	})
}
