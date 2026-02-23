package controller

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	adomain "github.com/corvusHold/guard/internal/auth/domain"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

func TestEmailDiscovery_ExtraBranches(t *testing.T) {
	e := echo.New()
	e.Validator = noopValidator{}
	svc := &loginOptionsSvcStub{}
	h := &Controller{svc: svc}

	t.Run("invalid request body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/email/discover", bytes.NewBufferString("{"))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		if err := h.emailDiscovery(c); err != nil {
			t.Fatalf("emailDiscovery returned err=%v", err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 invalid request, got %d", rec.Code)
		}
	})

	t.Run("tenant header lookup not found and internal error", func(t *testing.T) {
		svc.getUserErr = adomain.ErrNotFound
		reqNF := httptest.NewRequest(http.MethodPost, "/api/v1/auth/email/discover", bytes.NewBufferString(`{"email":"u@example.com"}`))
		reqNF.Header.Set("Content-Type", "application/json")
		reqNF.Header.Set("X-Tenant-ID", uuid.New().String())
		recNF := httptest.NewRecorder()
		cNF := e.NewContext(reqNF, recNF)
		if err := h.emailDiscovery(cNF); err != nil {
			t.Fatalf("emailDiscovery returned err=%v", err)
		}
		if recNF.Code != http.StatusOK {
			t.Fatalf("expected 200 not-found response, got %d body=%s", recNF.Code, recNF.Body.String())
		}

		svc.getUserErr = errors.New("db failure")
		reqErr := httptest.NewRequest(http.MethodPost, "/api/v1/auth/email/discover", bytes.NewBufferString(`{"email":"u@example.com"}`))
		reqErr.Header.Set("Content-Type", "application/json")
		reqErr.Header.Set("X-Tenant-ID", uuid.New().String())
		recErr := httptest.NewRecorder()
		cErr := e.NewContext(reqErr, recErr)
		if err := h.emailDiscovery(cErr); err != nil {
			t.Fatalf("emailDiscovery returned err=%v", err)
		}
		if recErr.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 internal error, got %d", recErr.Code)
		}

		svc.getUserErr = nil
		svc.getUserOut = &adomain.User{ID: uuid.New()}
		reqOK := httptest.NewRequest(http.MethodPost, "/api/v1/auth/email/discover", bytes.NewBufferString(`{"email":"u@example.com"}`))
		reqOK.Header.Set("Content-Type", "application/json")
		reqOK.Header.Set("X-Tenant-ID", uuid.New().String())
		recOK := httptest.NewRecorder()
		cOK := e.NewContext(reqOK, recOK)
		if err := h.emailDiscovery(cOK); err != nil {
			t.Fatalf("emailDiscovery returned err=%v", err)
		}
		if recOK.Code != http.StatusOK {
			t.Fatalf("expected 200 tenant user-found response, got %d", recOK.Code)
		}
	})

	t.Run("global discovery no tenants one tenant multiple tenants", func(t *testing.T) {
		svc.getUserOut = nil
		svc.findTenantsErr = errors.New("discover failed")
		reqErr := httptest.NewRequest(http.MethodPost, "/api/v1/auth/email/discover", bytes.NewBufferString(`{"email":"u@example.com"}`))
		reqErr.Header.Set("Content-Type", "application/json")
		recErr := httptest.NewRecorder()
		cErr := e.NewContext(reqErr, recErr)
		if err := h.emailDiscovery(cErr); err != nil {
			t.Fatalf("emailDiscovery returned err=%v", err)
		}
		if recErr.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 discover error, got %d", recErr.Code)
		}

		svc.findTenantsErr = nil
		svc.findTenantsOut = nil
		reqNone := httptest.NewRequest(http.MethodPost, "/api/v1/auth/email/discover", bytes.NewBufferString(`{"email":"u@example.com"}`))
		reqNone.Header.Set("Content-Type", "application/json")
		recNone := httptest.NewRecorder()
		cNone := e.NewContext(reqNone, recNone)
		if err := h.emailDiscovery(cNone); err != nil {
			t.Fatalf("emailDiscovery returned err=%v", err)
		}
		if recNone.Code != http.StatusOK {
			t.Fatalf("expected 200 no-tenant response, got %d", recNone.Code)
		}

		svc.findTenantsOut = []adomain.TenantInfo{{ID: uuid.New().String(), Name: "Tenant One"}}
		reqOne := httptest.NewRequest(http.MethodPost, "/api/v1/auth/email/discover", bytes.NewBufferString(`{"email":"u@example.com"}`))
		reqOne.Header.Set("Content-Type", "application/json")
		recOne := httptest.NewRecorder()
		cOne := e.NewContext(reqOne, recOne)
		if err := h.emailDiscovery(cOne); err != nil {
			t.Fatalf("emailDiscovery returned err=%v", err)
		}
		if recOne.Code != http.StatusOK {
			t.Fatalf("expected 200 one-tenant response, got %d", recOne.Code)
		}

		svc.findTenantsOut = []adomain.TenantInfo{{ID: uuid.New().String(), Name: "Tenant A"}, {ID: uuid.New().String(), Name: "Tenant B"}}
		reqMany := httptest.NewRequest(http.MethodPost, "/api/v1/auth/email/discover", bytes.NewBufferString(`{"email":"u@example.com"}`))
		reqMany.Header.Set("Content-Type", "application/json")
		recMany := httptest.NewRecorder()
		cMany := e.NewContext(reqMany, recMany)
		if err := h.emailDiscovery(cMany); err != nil {
			t.Fatalf("emailDiscovery returned err=%v", err)
		}
		if recMany.Code != http.StatusOK {
			t.Fatalf("expected 200 multi-tenant response, got %d", recMany.Code)
		}
	})
}
