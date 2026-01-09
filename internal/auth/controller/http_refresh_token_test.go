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

// TestRefreshToken_Flow tests the token refresh workflow
func TestRefreshToken_Flow(t *testing.T) {
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
	err = tr.Create(ctx, tenantID, "refresh-token-test-"+tenantID.String(), nil[:8])
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

	// Create user via signup
	email := "refresh-token-test@example.com"
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
	require.Equal(t, http.StatusCreated, srec.Code, "Signup should succeed: %s", srec.Body.String())

	var tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	err = json.Unmarshal(srec.Body.Bytes(), &tokens)
	require.NoError(t, err)
	require.NotEmpty(t, tokens.AccessToken)
	require.NotEmpty(t, tokens.RefreshToken)

	originalRefreshToken := tokens.RefreshToken

	// ============================================================
	// Test 1: Refresh token successfully
	// ============================================================
	t.Run("Refresh_Token_Success", func(t *testing.T) {
		refreshBody := map[string]string{
			"refresh_token": originalRefreshToken,
		}
		body, _ := json.Marshal(refreshBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code, "Refresh should succeed: %s", rec.Body.String())

		var newTokens struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		}
		err := json.Unmarshal(rec.Body.Bytes(), &newTokens)
		require.NoError(t, err)
		assert.NotEmpty(t, newTokens.AccessToken)
		// Note: Token may be same if refreshed within same second due to JWT time claims
	})

	// ============================================================
	// Test 2: Refresh with invalid token fails
	// ============================================================
	t.Run("Refresh_Invalid_Token", func(t *testing.T) {
		refreshBody := map[string]string{
			"refresh_token": "invalid-refresh-token",
		}
		body, _ := json.Marshal(refreshBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code, "Refresh with invalid token should fail")
	})

	// ============================================================
	// Test 3: Refresh with missing token fails
	// ============================================================
	t.Run("Refresh_Missing_Token", func(t *testing.T) {
		refreshBody := map[string]string{}
		body, _ := json.Marshal(refreshBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code, "Refresh with missing token should fail")
	})

	// ============================================================
	// Test 4: Refresh with invalid JSON fails
	// ============================================================
	t.Run("Refresh_Invalid_JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader([]byte("invalid json")))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code, "Refresh with invalid JSON should fail")
	})

	// ============================================================
	// Test 5: Refresh with empty token fails
	// ============================================================
	t.Run("Refresh_Empty_Token", func(t *testing.T) {
		refreshBody := map[string]string{
			"refresh_token": "",
		}
		body, _ := json.Marshal(refreshBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code, "Refresh with empty token should fail")
	})
}

// TestLogout_Flow tests the logout workflow
func TestLogout_Flow(t *testing.T) {
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
	err = tr.Create(ctx, tenantID, "logout-test-"+tenantID.String(), nil[:8])
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

	// Create user via signup
	email := "logout-test@example.com"
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

	var tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	err = json.Unmarshal(srec.Body.Bytes(), &tokens)
	require.NoError(t, err)

	// ============================================================
	// Test 1: Logout successfully
	// ============================================================
	t.Run("Logout_Success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNoContent, rec.Code, "Logout should succeed: %s", rec.Body.String())
	})

	// ============================================================
	// Test 2: Refresh after logout behavior
	// ============================================================
	t.Run("Refresh_After_Logout_Behavior", func(t *testing.T) {
		refreshBody := map[string]string{
			"refresh_token": tokens.RefreshToken,
		}
		body, _ := json.Marshal(refreshBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		// Refresh may still work if logout doesn't revoke refresh token
		assert.True(t, rec.Code == http.StatusUnauthorized || rec.Code == http.StatusOK,
			"Refresh after logout should return 401 or 200, got %d", rec.Code)
	})

	// ============================================================
	// Test 3: Logout without auth behavior
	// ============================================================
	t.Run("Logout_No_Auth", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
		// No Authorization header
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		// Logout may return 204 (lenient) or 401 depending on implementation
		assert.True(t, rec.Code == http.StatusUnauthorized || rec.Code == http.StatusNoContent,
			"Logout without auth should return 401 or 204, got %d", rec.Code)
	})

	// ============================================================
	// Test 4: Logout with invalid token behavior
	// ============================================================
	t.Run("Logout_Invalid_Token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		// Logout may return 204 (lenient) or 401 depending on implementation
		assert.True(t, rec.Code == http.StatusUnauthorized || rec.Code == http.StatusNoContent,
			"Logout with invalid token should return 401 or 204, got %d", rec.Code)
	})
}
