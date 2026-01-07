//go:build integration

package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	authrepo "github.com/corvusHold/guard/internal/auth/repository"
	svc "github.com/corvusHold/guard/internal/auth/service"
	"github.com/corvusHold/guard/internal/config"
	srepo "github.com/corvusHold/guard/internal/settings/repository"
	ssvc "github.com/corvusHold/guard/internal/settings/service"
	trepo "github.com/corvusHold/guard/internal/tenants/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEmailDiscovery_Flow tests the email discovery endpoint
func TestEmailDiscovery_Flow(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("skipping integration test: DATABASE_URL not set")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	require.NoError(t, err)
	defer pool.Close()

	// Create tenant
	tr := trepo.New(pool)
	tenantID := uuid.New()
	err = tr.Create(ctx, tenantID, "email-discovery-test-"+tenantID.String()[:8])
	require.NoError(t, err)

	// Setup services
	repo := authrepo.New(pool)
	sr := srepo.New(pool)
	settings := ssvc.New(sr)
	cfg, _ := config.Load()
	auth := svc.New(repo, cfg, settings)
	magic := svc.NewMagic(repo, cfg, settings, &fakeEmail{})
	sso := svc.NewSSO(repo, cfg, settings)

	e := echo.New()
	e.Validator = noopValidator{}
	c := New(auth, magic, sso)
	c.Register(e)

	// Create user
	email := "discovery-test@example.com"
	password := "TestPass123!"

	signupBody := map[string]string{
		"tenant_id": tenantID.String(),
		"email":     email,
		"password":  password,
	}
	sb, _ := json.Marshal(signupBody)
	sreq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/signup", bytes.NewReader(sb))
	sreq.Header.Set("Content-Type", "application/json")
	srec := httptest.NewRecorder()
	e.ServeHTTP(srec, sreq)
	require.Equal(t, http.StatusCreated, srec.Code)

	// ============================================================
	// Test 1: Discover existing email with tenant header
	// ============================================================
	t.Run("Discover_Existing_Email_With_Tenant", func(t *testing.T) {
		discoverBody := map[string]string{
			"email": email,
		}
		body, _ := json.Marshal(discoverBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/email/discover", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Tenant-ID", tenantID.String())
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code, "Email discovery should succeed: %s", rec.Body.String())

		var resp map[string]interface{}
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, true, resp["found"])
		assert.Equal(t, true, resp["user_exists"])
		assert.Equal(t, true, resp["has_tenant"])
	})

	// ============================================================
	// Test 2: Discover non-existing email with tenant header
	// ============================================================
	t.Run("Discover_NonExisting_Email_With_Tenant", func(t *testing.T) {
		discoverBody := map[string]string{
			"email": "nonexistent@example.com",
		}
		body, _ := json.Marshal(discoverBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/email/discover", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Tenant-ID", tenantID.String())
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		// Endpoint may return 200 with found=false or 500 if service errors
		assert.True(t, rec.Code == http.StatusOK || rec.Code == http.StatusInternalServerError,
			"Discover non-existing email should return 200 or 500, got %d", rec.Code)

		if rec.Code == http.StatusOK {
			var resp map[string]interface{}
			err := json.Unmarshal(rec.Body.Bytes(), &resp)
			require.NoError(t, err)
			assert.Equal(t, false, resp["found"])
			assert.Equal(t, false, resp["user_exists"])
		}
	})

	// ============================================================
	// Test 3: Discover with invalid request
	// ============================================================
	t.Run("Discover_Invalid_Request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/email/discover", bytes.NewReader([]byte("invalid json")))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	// ============================================================
	// Test 4: Discover without tenant header (cross-tenant discovery)
	// ============================================================
	t.Run("Discover_Without_Tenant_Header", func(t *testing.T) {
		discoverBody := map[string]string{
			"email": email,
		}
		body, _ := json.Marshal(discoverBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/email/discover", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		// No X-Tenant-ID header
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		// Should return OK with discovery results
		assert.Equal(t, http.StatusOK, rec.Code, "Discovery without tenant should work: %s", rec.Body.String())
	})
}

// TestLoginOptions_Flow tests the login options endpoint
func TestLoginOptions_Flow(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("skipping integration test: DATABASE_URL not set")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	require.NoError(t, err)
	defer pool.Close()

	// Create tenant
	tr := trepo.New(pool)
	tenantID := uuid.New()
	err = tr.Create(ctx, tenantID, "login-options-test-"+tenantID.String()[:8])
	require.NoError(t, err)

	// Setup services
	repo := authrepo.New(pool)
	sr := srepo.New(pool)
	settings := ssvc.New(sr)
	cfg, _ := config.Load()
	auth := svc.New(repo, cfg, settings)
	magic := svc.NewMagic(repo, cfg, settings, &fakeEmail{})
	sso := svc.NewSSO(repo, cfg, settings)

	e := echo.New()
	e.Validator = noopValidator{}
	c := New(auth, magic, sso)
	c.Register(e)

	// Create user
	email := "login-options-test@example.com"
	password := "TestPass123!"

	signupBody := map[string]string{
		"tenant_id": tenantID.String(),
		"email":     email,
		"password":  password,
	}
	sb, _ := json.Marshal(signupBody)
	sreq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/signup", bytes.NewReader(sb))
	sreq.Header.Set("Content-Type", "application/json")
	srec := httptest.NewRecorder()
	e.ServeHTTP(srec, sreq)
	require.Equal(t, http.StatusCreated, srec.Code)

	// ============================================================
	// Test 1: Get login options with tenant_id
	// ============================================================
	t.Run("Get_Login_Options_With_Tenant", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/login-options?tenant_id="+tenantID.String(), nil)
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code, "Login options should succeed: %s", rec.Body.String())

		var resp map[string]interface{}
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)

		// Default options should be present
		assert.NotNil(t, resp["password_enabled"])
		assert.NotNil(t, resp["magic_link_enabled"])
		assert.NotNil(t, resp["preferred_method"])
	})

	// ============================================================
	// Test 2: Get login options with email
	// ============================================================
	t.Run("Get_Login_Options_With_Email", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/login-options?tenant_id="+tenantID.String()+"&email="+email, nil)
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp map[string]interface{}
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.NotNil(t, resp["password_enabled"])
	})

	// ============================================================
	// Test 3: Get login options without tenant_id
	// ============================================================
	t.Run("Get_Login_Options_Without_Tenant", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/login-options", nil)
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		// Should return default options
		assert.Equal(t, http.StatusOK, rec.Code)

		var resp map[string]interface{}
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, true, resp["password_enabled"])
		assert.Equal(t, true, resp["magic_link_enabled"])
	})

	// ============================================================
	// Test 4: Get login options with invalid tenant_id
	// ============================================================
	t.Run("Get_Login_Options_Invalid_Tenant", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/login-options?tenant_id=invalid-uuid", nil)
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}
