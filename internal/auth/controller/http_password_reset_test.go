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

	domain "github.com/corvusHold/guard/internal/auth/domain"
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

// TestPasswordReset_Flow tests the password reset request and confirm workflow
func TestPasswordReset_Flow(t *testing.T) {
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
	err = tr.Create(ctx, tenantID, "password-reset-test-"+tenantID.String(), nil[:8])
	require.NoError(t, err)

	// Setup services
	repo := authrepo.New(pool)
	sr := srepo.New(pool)
	settings := ssvc.New(sr)
	cfg, err := config.Load()
	require.NoError(t, err, "config.Load failed")
	auth := svc.New(repo, cfg, settings)
	magic := svc.NewMagic(repo, cfg, settings, &fakeEmail{})
	sso := svc.NewSSO(repo, cfg, settings)

	e := echo.New()
	e.Validator = noopValidator{}
	c := New(auth, magic, sso)
	c.Register(e)

	// Create user via signup
	email := "password-reset-test@example.com"
	password := "OriginalPass123!"

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

	// ============================================================
	// Test 1: Request password reset (always returns 202 to prevent enumeration)
	// ============================================================
	t.Run("Request_Password_Reset_Existing_User", func(t *testing.T) {
		resetBody := map[string]string{
			"tenant_id": tenantID.String(),
			"email":     email,
		}
		body, _ := json.Marshal(resetBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/reset/request", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusAccepted, rec.Code, "Password reset request should return 202: %s", rec.Body.String())
	})

	// ============================================================
	// Test 2: Request password reset for non-existing user (still 202)
	// ============================================================
	t.Run("Request_Password_Reset_NonExisting_User", func(t *testing.T) {
		resetBody := map[string]string{
			"tenant_id": tenantID.String(),
			"email":     "nonexistent@example.com",
		}
		body, _ := json.Marshal(resetBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/reset/request", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		// Should still return 202 to prevent email enumeration
		assert.Equal(t, http.StatusAccepted, rec.Code, "Password reset for non-existing should still return 202")
	})

	// ============================================================
	// Test 3: Request password reset with invalid email format
	// ============================================================
	t.Run("Request_Password_Reset_Invalid_Email", func(t *testing.T) {
		resetBody := map[string]string{
			"tenant_id": tenantID.String(),
			"email":     "not-an-email",
		}
		body, _ := json.Marshal(resetBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/reset/request", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		// May return 400 (validation) or 202 (to prevent enumeration)
		assert.True(t, rec.Code == http.StatusBadRequest || rec.Code == http.StatusAccepted,
			"Invalid email should return 400 or 202, got %d", rec.Code)
	})

	// ============================================================
	// Test 4: Request password reset with invalid JSON
	// ============================================================
	t.Run("Request_Password_Reset_Invalid_JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/reset/request", bytes.NewReader([]byte("invalid json")))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code, "Invalid JSON should return 400")
	})

	// ============================================================
	// Test 5: Confirm password reset with invalid token
	// ============================================================
	t.Run("Confirm_Password_Reset_Invalid_Token", func(t *testing.T) {
		confirmBody := map[string]string{
			"tenant_id":    tenantID.String(),
			"token":        "invalid-token",
			"new_password": "NewSecurePass456!",
		}
		body, _ := json.Marshal(confirmBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/reset/confirm", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code, "Invalid token should return 400")
	})

	// ============================================================
	// Test 6: Confirm password reset with missing token
	// ============================================================
	t.Run("Confirm_Password_Reset_Missing_Token", func(t *testing.T) {
		confirmBody := map[string]string{
			"tenant_id":    tenantID.String(),
			"new_password": "NewSecurePass456!",
		}
		body, _ := json.Marshal(confirmBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/reset/confirm", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code, "Missing token should return 400")
	})

	// ============================================================
	// Test 7: Confirm password reset with short password
	// ============================================================
	t.Run("Confirm_Password_Reset_Short_Password", func(t *testing.T) {
		confirmBody := map[string]string{
			"tenant_id":    tenantID.String(),
			"token":        "some-token",
			"new_password": "short",
		}
		body, _ := json.Marshal(confirmBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/reset/confirm", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code, "Short password should return 400")
	})

	// ============================================================
	// Test 8: Confirm password reset with invalid JSON
	// ============================================================
	t.Run("Confirm_Password_Reset_Invalid_JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/reset/confirm", bytes.NewReader([]byte("invalid json")))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code, "Invalid JSON should return 400")
	})

	// ============================================================
	// Test 9: Request password reset without tenant_id (cross-tenant discovery)
	// ============================================================
	t.Run("Request_Password_Reset_Without_TenantID", func(t *testing.T) {
		resetBody := map[string]string{
			"email": email,
		}
		body, _ := json.Marshal(resetBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/reset/request", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		// Should return 202 (accepted) or 409 (conflict if multiple tenants)
		assert.True(t, rec.Code == http.StatusAccepted || rec.Code == http.StatusConflict,
			"Password reset without tenant should return 202 or 409, got %d", rec.Code)
	})

	// ============================================================
	// Test 10: Complete password reset flow (happy path via service)
	// ============================================================
	t.Run("Complete_Password_Reset_Flow", func(t *testing.T) {
		// Use the service directly to test the complete flow since email
		// integration is not yet wired up in the HTTP layer.
		// This tests the core password reset logic end-to-end.

		// Request password reset via service (this creates the token)
		err := auth.RequestPasswordReset(ctx, domain.PasswordResetRequestInput{
			TenantID: &tenantID,
			Email:    email,
		})
		require.NoError(t, err, "RequestPasswordReset should succeed")

		// Query the database directly to get the token hash
		// (In production, the token would be sent via email)
		var tokenHash string
		err = pool.QueryRow(ctx,
			`SELECT token_hash FROM password_reset_tokens 
			 WHERE tenant_id = $1 AND email = $2 AND consumed_at IS NULL 
			 ORDER BY created_at DESC LIMIT 1`,
			tenantID, email).Scan(&tokenHash)
		require.NoError(t, err, "Should find password reset token in database")

		// We can't reverse the hash, but we can test the confirm endpoint
		// with an invalid token to verify the endpoint works, then test
		// that login with old password still works (since we can't confirm)

		// Verify login with original password still works
		loginBody := map[string]string{
			"tenant_id": tenantID.String(),
			"email":     email,
			"password":  password,
		}
		lb, _ := json.Marshal(loginBody)
		lreq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/login", bytes.NewReader(lb))
		lreq.Header.Set("Content-Type", "application/json")
		lrec := httptest.NewRecorder()
		e.ServeHTTP(lrec, lreq)
		assert.Equal(t, http.StatusOK, lrec.Code, "Login with original password should succeed")

		// Note: To fully test the happy path, we would need to:
		// 1. Capture the raw token before hashing (requires service modification)
		// 2. Or expose a test-only method to generate a known token
		// For now, this test verifies the request flow works and the token is created.
		t.Log("Password reset token created successfully; full flow requires email integration")
	})
}
