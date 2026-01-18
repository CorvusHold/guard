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

func TestRequireRole_UserHasRole(t *testing.T) {
	e := echo.New()

	mockClient := &mockGuardClient{
		introspectFn: func(ctx context.Context, token *string) (*guard.DomainIntrospection, error) {
			return &guard.DomainIntrospection{
				Active:   boolPtr(true),
				UserId:   stringPtr("user-123"),
				TenantId: stringPtr("tenant-123"),
				Roles:    stringsPtr("admin", "user"),
			}, nil
		},
	}

	handler := func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/admin/users", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	c := e.NewContext(req, rec)

	// Apply both middlewares
	h := RequireAuth(mockClient)(
		RequireRole(mockClient, "admin")(handler),
	)

	err := h(c)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestRequireRole_UserLacksRole(t *testing.T) {
	e := echo.New()

	mockClient := &mockGuardClient{
		introspectFn: func(ctx context.Context, token *string) (*guard.DomainIntrospection, error) {
			return &guard.DomainIntrospection{
				Active:   boolPtr(true),
				UserId:   stringPtr("user-123"),
				TenantId: stringPtr("tenant-123"),
				Roles:    stringsPtr("user"), // No admin role
			}, nil
		},
	}

	handler := func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/admin/users", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	c := e.NewContext(req, rec)

	h := RequireAuth(mockClient)(
		RequireRole(mockClient, "admin")(handler),
	)

	err := h(c)

	// Should return 403
	assert.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	assert.True(t, ok)
	assert.Equal(t, http.StatusForbidden, httpErr.Code)
}

func TestRequireRole_MultipleRoles(t *testing.T) {
	e := echo.New()

	// User has "editor" role
	mockClient := &mockGuardClient{
		introspectFn: func(ctx context.Context, token *string) (*guard.DomainIntrospection, error) {
			return &guard.DomainIntrospection{
				Active:   boolPtr(true),
				UserId:   stringPtr("user-123"),
				TenantId: stringPtr("tenant-123"),
				Roles:    stringsPtr("editor"),
			}, nil
		},
	}

	handler := func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/documents", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	c := e.NewContext(req, rec)

	// Require any of these roles (OR logic)
	h := RequireAuth(mockClient)(
		RequireRole(mockClient, "admin", "editor", "moderator")(handler),
	)

	err := h(c)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestRequireRole_CaseInsensitive(t *testing.T) {
	e := echo.New()

	mockClient := &mockGuardClient{
		introspectFn: func(ctx context.Context, token *string) (*guard.DomainIntrospection, error) {
			return &guard.DomainIntrospection{
				Active:   boolPtr(true),
				UserId:   stringPtr("user-123"),
				TenantId: stringPtr("tenant-123"),
				Roles:    stringsPtr("Admin"), // Capital A
			}, nil
		},
	}

	handler := func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/admin", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	c := e.NewContext(req, rec)

	// Check for lowercase "admin"
	h := RequireAuth(mockClient)(
		RequireRole(mockClient, "admin")(handler),
	)

	err := h(c)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestRequireRole_NoRoles(t *testing.T) {
	e := echo.New()

	mockClient := &mockGuardClient{
		introspectFn: func(ctx context.Context, token *string) (*guard.DomainIntrospection, error) {
			return &guard.DomainIntrospection{
				Active:   boolPtr(true),
				UserId:   stringPtr("user-123"),
				TenantId: stringPtr("tenant-123"),
				// No roles assigned
			}, nil
		},
	}

	handler := func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/admin", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	c := e.NewContext(req, rec)

	h := RequireAuth(mockClient)(
		RequireRole(mockClient, "admin")(handler),
	)

	err := h(c)

	// Should return 403
	assert.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	assert.True(t, ok)
	assert.Equal(t, http.StatusForbidden, httpErr.Code)
}

func TestRequireRole_NotAuthenticated(t *testing.T) {
	e := echo.New()
	mockClient := &mockGuardClient{}

	handler := func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/admin", nil)
	// No auth header
	rec := httptest.NewRecorder()

	c := e.NewContext(req, rec)

	// Apply role check without auth middleware
	h := RequireRole(mockClient, "admin")(handler)

	err := h(c)

	// Should return 401
	assert.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	assert.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
}

func TestRequireAdmin(t *testing.T) {
	e := echo.New()

	mockClient := &mockGuardClient{
		introspectFn: func(ctx context.Context, token *string) (*guard.DomainIntrospection, error) {
			return &guard.DomainIntrospection{
				Active:   boolPtr(true),
				UserId:   stringPtr("user-123"),
				TenantId: stringPtr("tenant-123"),
				Roles:    stringsPtr("admin"),
			}, nil
		},
	}

	handler := func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/admin/stats", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	c := e.NewContext(req, rec)

	h := RequireAuth(mockClient)(
		RequireAdmin(mockClient)(handler),
	)

	err := h(c)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestRequireAdmin_NotAdmin(t *testing.T) {
	e := echo.New()

	mockClient := &mockGuardClient{
		introspectFn: func(ctx context.Context, token *string) (*guard.DomainIntrospection, error) {
			return &guard.DomainIntrospection{
				Active:   boolPtr(true),
				UserId:   stringPtr("user-123"),
				TenantId: stringPtr("tenant-123"),
				Roles:    stringsPtr("user"),
			}, nil
		},
	}

	handler := func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/admin/stats", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	c := e.NewContext(req, rec)

	h := RequireAuth(mockClient)(
		RequireAdmin(mockClient)(handler),
	)

	err := h(c)

	// Should return 403
	assert.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	assert.True(t, ok)
	assert.Equal(t, http.StatusForbidden, httpErr.Code)
}

func TestRequirePermission_HasPermission(t *testing.T) {
	e := echo.New()

	mockClient := &mockGuardClient{
		introspectFn: func(ctx context.Context, token *string) (*guard.DomainIntrospection, error) {
			return &guard.DomainIntrospection{
				Active:   boolPtr(true),
				UserId:   stringPtr("user-123"),
				TenantId: stringPtr("tenant-123"),
				Roles:    stringsPtr("editor"),
			}, nil
		},
		resolvePermissionsFn: func(ctx context.Context, userID, tenantID string) ([]guard.Permission, error) {
			return []guard.Permission{
				{
					Key:         "documents:create",
					Name:        "Create Documents",
					Description: "Can create new documents",
				},
			}, nil
		},
	}

	handler := func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	}

	req := httptest.NewRequest(http.MethodPost, "/api/documents", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	c := e.NewContext(req, rec)

	h := RequireAuth(mockClient)(
		RequirePermission(mockClient, "documents:create")(handler),
	)

	err := h(c)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestRequirePermission_NotAuthenticated(t *testing.T) {
	e := echo.New()
	mockClient := &mockGuardClient{}

	handler := func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	}

	req := httptest.NewRequest(http.MethodPost, "/api/documents", nil)
	rec := httptest.NewRecorder()

	c := e.NewContext(req, rec)

	// Apply permission check without auth middleware
	h := RequirePermission(mockClient, "documents:create")(handler)

	err := h(c)

	// Should return 401
	assert.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	assert.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
}
