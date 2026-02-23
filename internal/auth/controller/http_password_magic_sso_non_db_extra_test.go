package controller

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestPasswordMagicSSOHandlers_NonDBValidationBranches_Extra(t *testing.T) {
	e := echo.New()
	e.Validator = noopValidator{}
	h := &Controller{}

	t.Run("resetPasswordRequest invalid json and invalid tenant", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/reset/request", bytes.NewBufferString("{"))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		if err := h.resetPasswordRequest(c); err != nil {
			t.Fatalf("resetPasswordRequest returned error: %v", err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid json, got %d body=%s", rec.Code, rec.Body.String())
		}

		req2 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/reset/request", bytes.NewBufferString(`{"tenant_id":"bad","email":"u@example.com"}`))
		req2.Header.Set("Content-Type", "application/json")
		rec2 := httptest.NewRecorder()
		c2 := e.NewContext(req2, rec2)
		if err := h.resetPasswordRequest(c2); err != nil {
			t.Fatalf("resetPasswordRequest returned error: %v", err)
		}
		if rec2.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid tenant_id, got %d body=%s", rec2.Code, rec2.Body.String())
		}
	})

	t.Run("resetPasswordConfirm invalid json and invalid tenant", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/reset/confirm", bytes.NewBufferString("{"))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		if err := h.resetPasswordConfirm(c); err != nil {
			t.Fatalf("resetPasswordConfirm returned error: %v", err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid json, got %d body=%s", rec.Code, rec.Body.String())
		}

		body := `{"tenant_id":"bad","token":"t","new_password":"Password!123"}`
		req2 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/reset/confirm", bytes.NewBufferString(body))
		req2.Header.Set("Content-Type", "application/json")
		rec2 := httptest.NewRecorder()
		c2 := e.NewContext(req2, rec2)
		if err := h.resetPasswordConfirm(c2); err != nil {
			t.Fatalf("resetPasswordConfirm returned error: %v", err)
		}
		if rec2.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid tenant_id, got %d body=%s", rec2.Code, rec2.Body.String())
		}
	})

	t.Run("verifyEmail invalid json and token required", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/verify-email", bytes.NewBufferString("{"))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		if err := h.verifyEmail(c); err != nil {
			t.Fatalf("verifyEmail returned error: %v", err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid json, got %d body=%s", rec.Code, rec.Body.String())
		}

		req2 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/verify-email", bytes.NewBufferString(`{}`))
		req2.Header.Set("Content-Type", "application/json")
		rec2 := httptest.NewRecorder()
		c2 := e.NewContext(req2, rec2)
		if err := h.verifyEmail(c2); err != nil {
			t.Fatalf("verifyEmail returned error: %v", err)
		}
		if rec2.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for token required, got %d body=%s", rec2.Code, rec2.Body.String())
		}
	})

	t.Run("sendMagic invalid json and invalid tenant", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/magic/send", bytes.NewBufferString("{"))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		if err := h.sendMagic(c); err != nil {
			t.Fatalf("sendMagic returned error: %v", err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid json, got %d body=%s", rec.Code, rec.Body.String())
		}

		body := `{"tenant_id":"bad","email":"u@example.com"}`
		req2 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/magic/send", bytes.NewBufferString(body))
		req2.Header.Set("Content-Type", "application/json")
		rec2 := httptest.NewRecorder()
		c2 := e.NewContext(req2, rec2)
		if err := h.sendMagic(c2); err != nil {
			t.Fatalf("sendMagic returned error: %v", err)
		}
		if rec2.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid tenant_id, got %d body=%s", rec2.Code, rec2.Body.String())
		}
	})

	t.Run("verifyMagic invalid json branch", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/magic/verify", bytes.NewBufferString("{"))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		if err := h.verifyMagic(c); err != nil {
			t.Fatalf("verifyMagic returned error: %v", err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid json, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("ssoStart unsupported provider, invalid redirect and invalid tenant", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sso/bad/start", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("provider")
		c.SetParamValues("bad")
		if err := h.ssoStart(c); err != nil {
			t.Fatalf("ssoStart returned error: %v", err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for unsupported provider, got %d body=%s", rec.Code, rec.Body.String())
		}

		req2 := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sso/workos/start?tenant_id=x&redirect_url=://bad", nil)
		rec2 := httptest.NewRecorder()
		c2 := e.NewContext(req2, rec2)
		c2.SetParamNames("provider")
		c2.SetParamValues("workos")
		if err := h.ssoStart(c2); err != nil {
			t.Fatalf("ssoStart returned error: %v", err)
		}
		if rec2.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid redirect_url, got %d body=%s", rec2.Code, rec2.Body.String())
		}

		req3 := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sso/workos/start?tenant_id=bad", nil)
		rec3 := httptest.NewRecorder()
		c3 := e.NewContext(req3, rec3)
		c3.SetParamNames("provider")
		c3.SetParamValues("workos")
		if err := h.ssoStart(c3); err != nil {
			t.Fatalf("ssoStart returned error: %v", err)
		}
		if rec3.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid tenant_id, got %d body=%s", rec3.Code, rec3.Body.String())
		}
	})

	t.Run("ssoCallback unsupported provider", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sso/bad/callback", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("provider")
		c.SetParamValues("bad")
		if err := h.ssoCallback(c); err != nil {
			t.Fatalf("ssoCallback returned error: %v", err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for unsupported provider, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("totpActivate invalid json", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/totp/activate", bytes.NewBufferString("{"))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		if err := h.totpActivate(c); err != nil {
			t.Fatalf("totpActivate returned error: %v", err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid json, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("backupConsume invalid json", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/backup/consume", bytes.NewBufferString("{"))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		if err := h.backupConsume(c); err != nil {
			t.Fatalf("backupConsume returned error: %v", err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid json, got %d body=%s", rec.Code, rec.Body.String())
		}
	})
}
