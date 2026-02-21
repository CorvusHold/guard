package controller

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/corvusHold/guard/internal/config"
	"github.com/labstack/echo/v4"
)

func TestAuthHandlers_NonDBValidationBranches_Extra(t *testing.T) {
	e := echo.New()
	e.Validator = noopValidator{}
	h := &Controller{cfg: config.Config{DefaultAuthMode: "bearer"}}

	t.Run("signup invalid json", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/signup", bytes.NewBufferString("{"))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		if err := h.signup(c); err != nil {
			t.Fatalf("signup returned error: %v", err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("signup invalid tenant id", func(t *testing.T) {
		body := `{"tenant_id":"bad","email":"u@example.com","password":"Password!123"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/signup", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		if err := h.signup(c); err != nil {
			t.Fatalf("signup returned error: %v", err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("login invalid json", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/login", bytes.NewBufferString("{"))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		if err := h.login(c); err != nil {
			t.Fatalf("login returned error: %v", err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("login invalid tenant id", func(t *testing.T) {
		body := `{"tenant_id":"bad","email":"u@example.com","password":"Password!123"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/login", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		if err := h.login(c); err != nil {
			t.Fatalf("login returned error: %v", err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("refresh invalid json", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewBufferString("{"))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		if err := h.refresh(c); err != nil {
			t.Fatalf("refresh returned error: %v", err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("refresh missing token in bearer mode", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewBufferString(`{}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		if err := h.refresh(c); err != nil {
			t.Fatalf("refresh returned error: %v", err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("logout invalid json", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", bytes.NewBufferString("{"))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		if err := h.logout(c); err != nil {
			t.Fatalf("logout returned error: %v", err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("logout cookie mode no token returns 204", func(t *testing.T) {
		hCookie := &Controller{cfg: config.Config{DefaultAuthMode: "cookie"}}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", bytes.NewBufferString(`{}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		if err := hCookie.logout(c); err != nil {
			t.Fatalf("logout returned error: %v", err)
		}
		if rec.Code != http.StatusNoContent {
			t.Fatalf("expected 204, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("me missing token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		if err := h.me(c); err != nil {
			t.Fatalf("me returned error: %v", err)
		}
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("introspect token required", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/introspect", bytes.NewBufferString(`{}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		if err := h.introspect(c); err != nil {
			t.Fatalf("introspect returned error: %v", err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("revoke invalid json", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/revoke", bytes.NewBufferString("{"))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		if err := h.revoke(c); err != nil {
			t.Fatalf("revoke returned error: %v", err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("revoke missing token and token_type", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/revoke", bytes.NewBufferString(`{"token":"","token_type":""}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		if err := h.revoke(c); err != nil {
			t.Fatalf("revoke returned error: %v", err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
		}
	})
}

func TestGenerateEmailSuggestions_ExtraBranches(t *testing.T) {
	if got := generateEmailSuggestions("not-an-email"); got != nil {
		t.Fatalf("expected nil suggestions without @, got %v", got)
	}
	got := generateEmailSuggestions("u@custom-domain.test")
	if len(got) != 3 {
		t.Fatalf("expected 3 suggestions max, got %d (%v)", len(got), got)
	}
}
