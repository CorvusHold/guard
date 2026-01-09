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

// TestTokenRevoke_Flow tests the token revocation workflow
func TestTokenRevoke_Flow(t *testing.T) {
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
	err = tr.Create(ctx, tenantID, "token-revoke-test-"+tenantID.String(), nil[:8])
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
	email := "token-revoke-test@example.com"
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

	// ============================================================
	// Test 1: Revoke refresh token successfully
	// ============================================================
	t.Run("Revoke_Refresh_Token_Success", func(t *testing.T) {
		revokeBody := map[string]string{
			"token":      tokens.RefreshToken,
			"token_type": "refresh",
		}
		body, _ := json.Marshal(revokeBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/revoke", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNoContent, rec.Code, "Token revoke should succeed: %s", rec.Body.String())
	})

	// ============================================================
	// Test 2: Refresh with revoked token fails
	// ============================================================
	t.Run("Refresh_With_Revoked_Token_Fails", func(t *testing.T) {
		refreshBody := map[string]string{
			"refresh_token": tokens.RefreshToken,
		}
		body, _ := json.Marshal(refreshBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code, "Refresh with revoked token should fail")
	})

	// Get new tokens for subsequent tests
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
	require.Equal(t, http.StatusOK, lrec.Code)
	err = json.Unmarshal(lrec.Body.Bytes(), &tokens)
	require.NoError(t, err)

	// ============================================================
	// Test 3: Revoke with missing token - validation behavior
	// ============================================================
	t.Run("Revoke_Missing_Token", func(t *testing.T) {
		revokeBody := map[string]string{
			"token_type": "refresh",
		}
		body, _ := json.Marshal(revokeBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/revoke", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		// Endpoint may return 400 (validation) or 204 (idempotent) depending on implementation
		assert.True(t, rec.Code == http.StatusBadRequest || rec.Code == http.StatusNoContent,
			"Revoke without token should return 400 or 204, got %d", rec.Code)
	})

	// ============================================================
	// Test 4: Revoke with missing token_type fails
	// ============================================================
	t.Run("Revoke_Missing_Token_Type", func(t *testing.T) {
		revokeBody := map[string]string{
			"token": tokens.RefreshToken,
		}
		body, _ := json.Marshal(revokeBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/revoke", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code, "Revoke without token_type should fail")
	})

	// ============================================================
	// Test 5: Revoke with invalid JSON fails
	// ============================================================
	t.Run("Revoke_Invalid_JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/revoke", bytes.NewReader([]byte("invalid json")))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code, "Revoke with invalid JSON should fail")
	})

	// ============================================================
	// Test 6: Revoke already revoked token (idempotent)
	// ============================================================
	t.Run("Revoke_Already_Revoked_Token", func(t *testing.T) {
		// First revoke
		revokeBody := map[string]string{
			"token":      tokens.RefreshToken,
			"token_type": "refresh",
		}
		body, _ := json.Marshal(revokeBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/revoke", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusNoContent, rec.Code)

		// Second revoke (should still succeed or return appropriate error)
		req2 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/revoke", bytes.NewReader(body))
		req2.Header.Set("Content-Type", "application/json")
		rec2 := httptest.NewRecorder()
		e.ServeHTTP(rec2, req2)

		// Either 204 (idempotent) or 400 (already revoked) is acceptable
		assert.True(t, rec2.Code == http.StatusNoContent || rec2.Code == http.StatusBadRequest,
			"Revoke already revoked token should return 204 or 400, got %d", rec2.Code)
	})
}
