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

// TestProfileUpdate_Flow tests the profile update workflow
func TestProfileUpdate_Flow(t *testing.T) {
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
	err = tr.Create(ctx, tenantID, "profile-update-test-"+tenantID.String(), nil[:8])
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
	email := "profile-update-test-" + tenantID.String()[:8] + "@example.com"
	password := "TestPass123!"

	signupBody := map[string]string{
		"tenant_id":  tenantID.String(),
		"email":      email,
		"password":   password,
		"first_name": "Original",
		"last_name":  "Name",
	}
	sb, _ := json.Marshal(signupBody)
	sreq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/signup", bytes.NewReader(sb))
	sreq.Header.Set("Content-Type", "application/json")
	srec := httptest.NewRecorder()
	e.ServeHTTP(srec, sreq)
	require.Equal(t, http.StatusCreated, srec.Code, "Signup should succeed: %s", srec.Body.String())

	var tokens struct {
		AccessToken string `json:"access_token"`
	}
	err = json.Unmarshal(srec.Body.Bytes(), &tokens)
	require.NoError(t, err)
	require.NotEmpty(t, tokens.AccessToken)

	// ============================================================
	// Test 1: Get initial profile
	// ============================================================
	t.Run("Get_Initial_Profile", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var profile map[string]interface{}
		err := json.Unmarshal(rec.Body.Bytes(), &profile)
		require.NoError(t, err)
		assert.Equal(t, "Original", profile["first_name"])
		assert.Equal(t, "Name", profile["last_name"])
	})

	// ============================================================
	// Test 2: Update first name only
	// ============================================================
	t.Run("Update_First_Name_Only", func(t *testing.T) {
		updateBody := map[string]string{
			"first_name": "UpdatedFirst",
		}
		body, _ := json.Marshal(updateBody)
		req := httptest.NewRequest(http.MethodPatch, "/api/v1/auth/profile", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code, "Profile update should succeed: %s", rec.Body.String())

		// Verify via /me
		meReq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
		meReq.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		meRec := httptest.NewRecorder()
		e.ServeHTTP(meRec, meReq)

		var profile map[string]interface{}
		err := json.Unmarshal(meRec.Body.Bytes(), &profile)
		require.NoError(t, err)
		assert.Equal(t, "UpdatedFirst", profile["first_name"])
		assert.Equal(t, "Name", profile["last_name"], "last_name should be preserved")
	})

	// ============================================================
	// Test 3: Update last name only
	// ============================================================
	t.Run("Update_Last_Name_Only", func(t *testing.T) {
		updateBody := map[string]string{
			"last_name": "UpdatedLast",
		}
		body, _ := json.Marshal(updateBody)
		req := httptest.NewRequest(http.MethodPatch, "/api/v1/auth/profile", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		// Verify via /me
		meReq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
		meReq.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		meRec := httptest.NewRecorder()
		e.ServeHTTP(meRec, meReq)

		var profile map[string]interface{}
		err := json.Unmarshal(meRec.Body.Bytes(), &profile)
		require.NoError(t, err)
		assert.Equal(t, "UpdatedLast", profile["last_name"])
		assert.Equal(t, "UpdatedFirst", profile["first_name"], "first_name should be preserved")
	})

	// ============================================================
	// Test 4: Update both names
	// ============================================================
	t.Run("Update_Both_Names", func(t *testing.T) {
		updateBody := map[string]string{
			"first_name": "FinalFirst",
			"last_name":  "FinalLast",
		}
		body, _ := json.Marshal(updateBody)
		req := httptest.NewRequest(http.MethodPatch, "/api/v1/auth/profile", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		// Verify via /me
		meReq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
		meReq.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		meRec := httptest.NewRecorder()
		e.ServeHTTP(meRec, meReq)

		var profile map[string]interface{}
		err := json.Unmarshal(meRec.Body.Bytes(), &profile)
		require.NoError(t, err)
		assert.Equal(t, "FinalFirst", profile["first_name"])
		assert.Equal(t, "FinalLast", profile["last_name"])
	})

	// ============================================================
	// Test 5: Update profile without auth fails
	// ============================================================
	t.Run("Update_Profile_No_Auth", func(t *testing.T) {
		updateBody := map[string]string{
			"first_name": "ShouldFail",
		}
		body, _ := json.Marshal(updateBody)
		req := httptest.NewRequest(http.MethodPatch, "/api/v1/auth/profile", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		// No Authorization header
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	// ============================================================
	// Test 6: Update profile with invalid JSON fails
	// ============================================================
	t.Run("Update_Profile_Invalid_JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPatch, "/api/v1/auth/profile", bytes.NewReader([]byte("invalid json")))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	// ============================================================
	// Test 7: Update profile with invalid token fails
	// ============================================================
	t.Run("Update_Profile_Invalid_Token", func(t *testing.T) {
		updateBody := map[string]string{
			"first_name": "ShouldFail",
		}
		body, _ := json.Marshal(updateBody)
		req := httptest.NewRequest(http.MethodPatch, "/api/v1/auth/profile", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer invalid-token")
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
}
