package controller

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	adomain "github.com/corvusHold/guard/internal/auth/domain"
	authsvc "github.com/corvusHold/guard/internal/auth/service"
	"github.com/corvusHold/guard/internal/config"
	sdomain "github.com/corvusHold/guard/internal/settings/domain"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type magicSvcStub struct {
	adomain.MagicLinkService
	token string
	err   error
}

func (m *magicSvcStub) CreateForTest(ctx context.Context, in adomain.MagicSendInput) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	return m.token, nil
}

func routeExists(routes []*echo.Route, method, path string) bool {
	for _, r := range routes {
		if r.Method == method && r.Path == path {
			return true
		}
	}
	return false
}

func TestController_ConstructorsAndRouteRegistration_Extra(t *testing.T) {
	h := NewWithConfig(nil, nil, nil, config.Config{PublicBaseURL: "https://app.example"})
	if h == nil {
		t.Fatal("expected NewWithConfig to return controller")
	}

	h2 := New(nil, nil, nil)
	if h2 == nil {
		t.Fatal("expected New to return controller")
	}

	if got := h.WithRateLimit(loginOptionsSettingsStub{}, nil); got != h {
		t.Fatal("expected WithRateLimit to return same controller")
	}
	if got := h.WithPublisher(nil); got != h {
		t.Fatal("expected WithPublisher to return same controller")
	}
	if got := h.WithWebAuthn(&authsvc.WebAuthnService{}); got != h {
		t.Fatal("expected WithWebAuthn to return same controller")
	}

	e := echo.New()
	h.Register(e)
	routes := e.Routes()
	if !routeExists(routes, http.MethodGet, "/.well-known/oauth-authorization-server") {
		t.Fatal("expected oauth metadata route to be registered")
	}
	if !routeExists(routes, http.MethodPost, "/api/v1/auth/password/login") {
		t.Fatal("expected v1 auth route to be registered")
	}

	e2 := echo.New()
	apiV1 := e2.Group("/api/v1")
	h.RegisterV1(apiV1)
	if !routeExists(e2.Routes(), http.MethodPost, "/api/v1/auth/password/login") {
		t.Fatal("expected RegisterV1 auth login route to be registered")
	}
}

func TestController_ResolveTenantForRL_Extra(t *testing.T) {
	e := echo.New()
	tenantID := uuid.New()

	req1 := httptest.NewRequest(http.MethodGet, "/?tenant_id="+tenantID.String(), nil)
	c1 := e.NewContext(req1, httptest.NewRecorder())
	if got := resolveTenantForRL(c1); got == nil || *got != tenantID {
		t.Fatalf("expected tenant from query, got %v", got)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("X-Tenant-ID", "rl-"+tenantID.String())
	c2 := e.NewContext(req2, httptest.NewRecorder())
	if got := resolveTenantForRL(c2); got == nil || *got != tenantID {
		t.Fatalf("expected tenant from header with rl- prefix, got %v", got)
	}

	req3 := httptest.NewRequest(http.MethodGet, "/", nil)
	req3.Header.Set("X-Tenant-ID", "bad")
	c3 := e.NewContext(req3, httptest.NewRecorder())
	if got := resolveTenantForRL(c3); got != nil {
		t.Fatalf("expected nil tenant for invalid uuid, got %v", got)
	}
}

func TestController_MagicTokenForTest_Branches_Extra(t *testing.T) {
	e := echo.New()
	e.Validator = noopValidator{}

	t.Run("production returns not found", func(t *testing.T) {
		h := &Controller{cfg: config.Config{AppEnv: "production"}}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/magic/token-for-test", bytes.NewBufferString(`{"tenant_id":"`+uuid.New().String()+`","email":"u@example.com"}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		if err := h.magicTokenForTest(c); err != nil {
			t.Fatalf("magicTokenForTest returned err=%v", err)
		}
		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", rec.Code)
		}
	})

	t.Run("invalid json and invalid tenant", func(t *testing.T) {
		h := &Controller{cfg: config.Config{AppEnv: "development"}, magic: &magicSvcStub{token: "tok"}}
		reqJSON := httptest.NewRequest(http.MethodPost, "/api/v1/auth/magic/token-for-test", bytes.NewBufferString("{"))
		reqJSON.Header.Set("Content-Type", "application/json")
		recJSON := httptest.NewRecorder()
		cJSON := e.NewContext(reqJSON, recJSON)
		if err := h.magicTokenForTest(cJSON); err != nil {
			t.Fatalf("magicTokenForTest returned err=%v", err)
		}
		if recJSON.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 invalid json, got %d", recJSON.Code)
		}

		reqTen := httptest.NewRequest(http.MethodPost, "/api/v1/auth/magic/token-for-test", bytes.NewBufferString(`{"tenant_id":"bad","email":"u@example.com"}`))
		reqTen.Header.Set("Content-Type", "application/json")
		recTen := httptest.NewRecorder()
		cTen := e.NewContext(reqTen, recTen)
		if err := h.magicTokenForTest(cTen); err != nil {
			t.Fatalf("magicTokenForTest returned err=%v", err)
		}
		if recTen.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 invalid tenant, got %d", recTen.Code)
		}
	})

	t.Run("service error then success", func(t *testing.T) {
		tenantID := uuid.New()
		ms := &magicSvcStub{err: errors.New("create token failed")}
		h := &Controller{cfg: config.Config{AppEnv: "development"}, magic: ms}
		body := `{"tenant_id":"` + tenantID.String() + `","email":"u@example.com","redirect_url":"https://app.example"}`

		reqErr := httptest.NewRequest(http.MethodPost, "/api/v1/auth/magic/token-for-test", bytes.NewBufferString(body))
		reqErr.Header.Set("Content-Type", "application/json")
		recErr := httptest.NewRecorder()
		cErr := e.NewContext(reqErr, recErr)
		if err := h.magicTokenForTest(cErr); err != nil {
			t.Fatalf("magicTokenForTest returned err=%v", err)
		}
		if recErr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 service error, got %d", recErr.Code)
		}

		ms.err = nil
		ms.token = "magic-token"
		reqOK := httptest.NewRequest(http.MethodPost, "/api/v1/auth/magic/token-for-test", bytes.NewBufferString(body))
		reqOK.Header.Set("Content-Type", "application/json")
		recOK := httptest.NewRecorder()
		cOK := e.NewContext(reqOK, recOK)
		if err := h.magicTokenForTest(cOK); err != nil {
			t.Fatalf("magicTokenForTest returned err=%v", err)
		}
		if recOK.Code != http.StatusOK {
			t.Fatalf("expected 200 success, got %d body=%s", recOK.Code, recOK.Body.String())
		}
	})
}

func TestController_RegisterHelpers_StandaloneRoutes(t *testing.T) {
	h := &Controller{}
	e := echo.New()
	g := e.Group("/x")
	h.registerBulkRoutes(g)
	h.registerComplianceRoutes(g)
	h.registerSuperAdminRoutes(g)
	h.registerSelfServiceRoutes(g)

	routes := e.Routes()
	checks := []struct{ method, path string }{
		{http.MethodPost, "/x/bulk/users/import"},
		{http.MethodGet, "/x/compliance/report"},
		{http.MethodGet, "/x/platform/stats"},
		{http.MethodGet, "/x/self/profile"},
	}
	for _, chk := range checks {
		if !routeExists(routes, chk.method, chk.path) {
			t.Fatalf("expected route %s %s", chk.method, chk.path)
		}
	}
}

var _ sdomain.Service = loginOptionsSettingsStub{}
