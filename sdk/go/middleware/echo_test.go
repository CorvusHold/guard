package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	guard "github.com/corvusHold/guard/sdk/go"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequireAuth_ValidToken(t *testing.T) {
	// Create echo instance
	e := echo.New()

	// Create mock client with valid introspection
	mockClient := &mockGuardClient{
		introspectFn: func(ctx context.Context, token *string) (*guard.DomainIntrospection, error) {
			return &guard.DomainIntrospection{
				Active:   boolPtr(true),
				UserId:   stringPtr("user-123"),
				TenantId: stringPtr("tenant-123"),
				Email:    stringPtr("user@example.com"),
				Roles:    stringsPtr("user"),
			}, nil
		},
	}

	// Create handler that accesses context
	handler := func(c echo.Context) error {
		userID, _ := GetUserID(c)
		tenantID, _ := GetTenantID(c)
		email, _ := GetEmail(c)
		roles, _ := GetRoles(c)

		return c.JSON(http.StatusOK, map[string]any{
			"user_id":  userID,
			"tenant_id": tenantID,
			"email":    email,
			"roles":    roles,
		})
	}

	// Create request with Bearer token
	req := httptest.NewRequest(http.MethodGet, "/api/profile", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	// Create context and apply middleware
	c := e.NewContext(req, rec)
	h := RequireAuth(mockClient)(handler)

	// Execute
	err := h(c)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "user-123")
	assert.Contains(t, rec.Body.String(), "tenant-123")
	assert.Contains(t, rec.Body.String(), "user@example.com")
}

func TestRequireAuth_MissingToken(t *testing.T) {
	e := echo.New()
	mockClient := &mockGuardClient{}

	handler := func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	}

	// Request without token
	req := httptest.NewRequest(http.MethodGet, "/api/profile", nil)
	rec := httptest.NewRecorder()

	c := e.NewContext(req, rec)
	h := RequireAuth(mockClient)(handler)

	err := h(c)

	// Should return 401
	assert.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	assert.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
}

func TestRequireAuth_InvalidToken(t *testing.T) {
	e := echo.New()

	mockClient := &mockGuardClient{
		introspectFn: func(ctx context.Context, token *string) (*guard.DomainIntrospection, error) {
			return nil, nil // Introspection failed
		},
	}

	handler := func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/profile", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rec := httptest.NewRecorder()

	c := e.NewContext(req, rec)
	h := RequireAuth(mockClient)(handler)

	err := h(c)

	// Should return 401
	assert.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	assert.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
}

func TestRequireAuth_TokenNotActive(t *testing.T) {
	e := echo.New()

	mockClient := &mockGuardClient{
		introspectFn: func(ctx context.Context, token *string) (*guard.DomainIntrospection, error) {
			return &guard.DomainIntrospection{
				Active: boolPtr(false), // Token is inactive
			}, nil
		},
	}

	handler := func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/profile", nil)
	req.Header.Set("Authorization", "Bearer expired-token")
	rec := httptest.NewRecorder()

	c := e.NewContext(req, rec)
	h := RequireAuth(mockClient)(handler)

	err := h(c)

	// Should return 401
	assert.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	assert.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
}

func TestRequireAuth_TenantMismatch(t *testing.T) {
	e := echo.New()

	mockClient := &mockGuardClient{
		introspectFn: func(ctx context.Context, token *string) (*guard.DomainIntrospection, error) {
			return &guard.DomainIntrospection{
				Active:   boolPtr(true),
				UserId:   stringPtr("user-123"),
				TenantId: stringPtr("tenant-123"),
				Email:    stringPtr("user@example.com"),
				Roles:    stringsPtr("user"),
			}, nil
		},
	}

	handler := func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/profile", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	req.Header.Set("X-Tenant-ID", "different-tenant") // Different tenant
	rec := httptest.NewRecorder()

	c := e.NewContext(req, rec)
	h := RequireAuth(mockClient)(handler)

	err := h(c)

	// Should return 403
	assert.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	assert.True(t, ok)
	assert.Equal(t, http.StatusForbidden, httpErr.Code)
}

func TestRequireAuth_TokenFromCookie(t *testing.T) {
	e := echo.New()

	mockClient := &mockGuardClient{
		introspectFn: func(ctx context.Context, token *string) (*guard.DomainIntrospection, error) {
			return &guard.DomainIntrospection{
				Active:   boolPtr(true),
				UserId:   stringPtr("user-123"),
				TenantId: stringPtr("tenant-123"),
				Email:    stringPtr("user@example.com"),
				Roles:    stringsPtr("user"),
			}, nil
		},
	}

	handler := func(c echo.Context) error {
		userID, _ := GetUserID(c)
		return c.String(http.StatusOK, userID)
	}

	// Request with token in cookie instead of header
	req := httptest.NewRequest(http.MethodGet, "/api/profile", nil)
	req.AddCookie(&http.Cookie{
		Name:  "guard_access_token",
		Value: "cookie-token",
	})
	rec := httptest.NewRecorder()

	c := e.NewContext(req, rec)
	h := RequireAuth(mockClient)(handler)

	err := h(c)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "user-123", rec.Body.String())
}

func TestRequireAuth_ContextExtraction(t *testing.T) {
	e := echo.New()

	mockClient := &mockGuardClient{
		introspectFn: func(ctx context.Context, token *string) (*guard.DomainIntrospection, error) {
			return &guard.DomainIntrospection{
				Active:   boolPtr(true),
				UserId:   stringPtr("user-456"),
				TenantId: stringPtr("tenant-456"),
				Email:    stringPtr("test@example.com"),
				Roles:    stringsPtr("admin", "editor"),
			}, nil
		},
	}

	handler := func(c echo.Context) error {
		// Test all context extraction helpers
		introspection, err := GetIntrospection(c)
		require.NoError(t, err)
		assert.NotNil(t, introspection)

		userID, err := GetUserID(c)
		require.NoError(t, err)
		assert.Equal(t, "user-456", userID)

		tenantID, err := GetTenantID(c)
		require.NoError(t, err)
		assert.Equal(t, "tenant-456", tenantID)

		email, err := GetEmail(c)
		require.NoError(t, err)
		assert.Equal(t, "test@example.com", email)

		roles, err := GetRoles(c)
		require.NoError(t, err)
		assert.Equal(t, 2, len(roles))
		assert.Contains(t, roles, "admin")
		assert.Contains(t, roles, "editor")

		return c.String(http.StatusOK, "ok")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/profile", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	c := e.NewContext(req, rec)
	h := RequireAuth(mockClient)(handler)

	err := h(c)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestGetUserID_NoContext(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	_, err := GetUserID(c)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found in context")
}

func TestGetTenantID_NoContext(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	_, err := GetTenantID(c)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found in context")
}
