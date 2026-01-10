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

// TestPasswordChange_Flow tests the complete password change workflow
func TestPasswordChange_Flow(t *testing.T) {
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
	err = tr.Create(ctx, tenantID, "password-change-test-"+tenantID.String(), nil)
	require.NoError(t, err)

	// Setup services
	repo := authrepo.New(pool)
	sr := srepo.New(pool)
	settings := ssvc.New(sr)
	cfg, err := config.Load()
	require.NoError(t, err)
	auth := svc.New(repo, cfg, settings)
	magic := svc.NewMagic(repo, cfg, settings, &fakeEmail{})
	sso := svc.NewSSO(repo, cfg, settings)

	e := echo.New()
	e.Validator = noopValidator{}
	c := New(auth, magic, sso)
	c.Register(e)

	// Create user via signup
	email := "password-change-test@example.com"
	originalPassword := "OriginalPass123!"
	newPassword := "NewSecurePass456!"

	signupBody := map[string]string{
		"tenant_id": tenantID.String(),
		"email":     email,
		"password":  originalPassword,
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

	// ============================================================
	// Test 1: Change password successfully
	// ============================================================
	t.Run("Change_Password_Success", func(t *testing.T) {
		changeBody := map[string]string{
			"current_password": originalPassword,
			"new_password":     newPassword,
		}
		body, _ := json.Marshal(changeBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/change", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code, "Password change should succeed: %s", rec.Body.String())
	})

	// ============================================================
	// Test 2: Login with new password works
	// ============================================================
	t.Run("Login_With_New_Password", func(t *testing.T) {
		loginBody := map[string]string{
			"tenant_id": tenantID.String(),
			"email":     email,
			"password":  newPassword,
		}
		body, _ := json.Marshal(loginBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code, "Login with new password should succeed: %s", rec.Body.String())

		var newTokens struct {
			AccessToken string `json:"access_token"`
		}
		err := json.Unmarshal(rec.Body.Bytes(), &newTokens)
		require.NoError(t, err)
		assert.NotEmpty(t, newTokens.AccessToken)

		// Update tokens for subsequent tests
		tokens.AccessToken = newTokens.AccessToken
	})

	// ============================================================
	// Test 3: Login with old password fails
	// ============================================================
	t.Run("Login_With_Old_Password_Fails", func(t *testing.T) {
		loginBody := map[string]string{
			"tenant_id": tenantID.String(),
			"email":     email,
			"password":  originalPassword,
		}
		body, _ := json.Marshal(loginBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code, "Login with old password should fail")
	})

	// ============================================================
	// Test 4: Change password with wrong current password fails
	// ============================================================
	t.Run("Change_Password_Wrong_Current", func(t *testing.T) {
		changeBody := map[string]string{
			"current_password": "WrongPassword123!",
			"new_password":     "AnotherNewPass789!",
		}
		body, _ := json.Marshal(changeBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/change", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code, "Password change with wrong current should fail")
	})

	// ============================================================
	// Test 5: Change password without auth fails
	// ============================================================
	t.Run("Change_Password_No_Auth", func(t *testing.T) {
		changeBody := map[string]string{
			"current_password": newPassword,
			"new_password":     "AnotherNewPass789!",
		}
		body, _ := json.Marshal(changeBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/change", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		// No Authorization header
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code, "Password change without auth should fail")
	})

	// ============================================================
	// Test 6: Change password with short new password fails
	// ============================================================
	t.Run("Change_Password_Short_New_Password", func(t *testing.T) {
		changeBody := map[string]string{
			"current_password": newPassword,
			"new_password":     "short",
		}
		body, _ := json.Marshal(changeBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/change", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code, "Password change with short password should fail")
	})

	// ============================================================
	// Test 7: Change password with invalid JSON fails
	// ============================================================
	t.Run("Change_Password_Invalid_JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/change", bytes.NewReader([]byte("invalid json")))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code, "Password change with invalid JSON should fail")
	})
}
