package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/corvusHold/guard/internal/auth/domain"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type fakeValidator struct {
	key domain.APIKey
	err error
}

func (f *fakeValidator) ValidateAPIKey(_ context.Context, _ string) (domain.APIKey, error) {
	return f.key, f.err
}

func TestRequireAPIKey_NoHeader_PassesThrough(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	called := false
	handler := RequireAPIKey(&fakeValidator{})(func(c echo.Context) error {
		called = true
		return c.String(http.StatusOK, "ok")
	})

	if err := handler(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Error("expected handler to be called when no API key header")
	}
}

func TestRequireAPIKey_ValidHeader(t *testing.T) {
	tenantID := uuid.New()
	v := &fakeValidator{key: domain.APIKey{
		ID:       uuid.New(),
		TenantID: tenantID,
		Scopes:   []string{"read", "write"},
	}}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Guard-API-Key", "gk_test123")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	var capturedCtx context.Context
	handler := RequireAPIKey(v)(func(c echo.Context) error {
		capturedCtx = c.Request().Context()
		return c.String(http.StatusOK, "ok")
	})

	if err := handler(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	key, ok := APIKeyFromContext(capturedCtx)
	if !ok {
		t.Fatal("expected API key in context")
	}
	if key.TenantID != tenantID {
		t.Errorf("expected tenant %s, got %s", tenantID, key.TenantID)
	}
}

func TestRequireAPIKey_BearerGK(t *testing.T) {
	v := &fakeValidator{key: domain.APIKey{ID: uuid.New(), TenantID: uuid.New()}}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer gk_mykey123")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	called := false
	handler := RequireAPIKey(v)(func(c echo.Context) error {
		called = true
		_, ok := APIKeyFromContext(c.Request().Context())
		if !ok {
			t.Error("expected API key in context from Bearer gk_ header")
		}
		return nil
	})

	if err := handler(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Error("expected handler to be called")
	}
}

func TestRequireAPIKey_InvalidKey(t *testing.T) {
	v := &fakeValidator{err: errors.New("invalid key")}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Guard-API-Key", "gk_bad")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := RequireAPIKey(v)(func(c echo.Context) error {
		t.Error("handler should not be called for invalid key")
		return nil
	})

	_ = handler(c)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestAPIKeyHasScope_Wildcard(t *testing.T) {
	key := domain.APIKey{Scopes: []string{"*"}}
	ctx := context.WithValue(context.Background(), ContextKeyAPIKey, key)
	if !APIKeyHasScope(ctx, "anything") {
		t.Error("wildcard scope should match any scope")
	}
}

func TestAPIKeyHasScope_Specific(t *testing.T) {
	key := domain.APIKey{Scopes: []string{"read", "write"}}
	ctx := context.WithValue(context.Background(), ContextKeyAPIKey, key)
	if !APIKeyHasScope(ctx, "read") {
		t.Error("should match 'read' scope")
	}
	if APIKeyHasScope(ctx, "admin") {
		t.Error("should not match 'admin' scope")
	}
}

func TestAPIKeyHasScope_NoKey(t *testing.T) {
	if APIKeyHasScope(context.Background(), "read") {
		t.Error("should return false when no API key in context")
	}
}

func TestAPIKeyTenantID_Present(t *testing.T) {
	tid := uuid.New()
	key := domain.APIKey{TenantID: tid}
	ctx := context.WithValue(context.Background(), ContextKeyAPIKey, key)
	got, ok := APIKeyTenantID(ctx)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if got != tid {
		t.Errorf("expected %s, got %s", tid, got)
	}
}

func TestAPIKeyTenantID_Absent(t *testing.T) {
	_, ok := APIKeyTenantID(context.Background())
	if ok {
		t.Error("expected ok=false when no API key")
	}
}

func TestRequireScopes_NoAPIKey_PassesThrough(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	called := false
	handler := RequireScopes("admin")(func(c echo.Context) error {
		called = true
		return nil
	})
	_ = handler(c)
	if !called {
		t.Error("expected pass-through when no API key")
	}
}

func TestRequireScopes_HasScope(t *testing.T) {
	key := domain.APIKey{Scopes: []string{"admin"}}
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), ContextKeyAPIKey, key))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	called := false
	handler := RequireScopes("admin")(func(c echo.Context) error {
		called = true
		return nil
	})
	_ = handler(c)
	if !called {
		t.Error("expected handler to be called when scope matches")
	}
}

func TestRequireScopes_MissingScope(t *testing.T) {
	key := domain.APIKey{Scopes: []string{"read"}}
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), ContextKeyAPIKey, key))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := RequireScopes("admin")(func(c echo.Context) error {
		t.Error("handler should not be called when scope is missing")
		return nil
	})
	_ = handler(c)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}
