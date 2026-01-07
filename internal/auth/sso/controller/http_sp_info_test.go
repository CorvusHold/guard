//go:build integration
// +build integration

package controller_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSPInfo_Endpoint tests the SP (Service Provider) info endpoint
func TestSPInfo_Endpoint(t *testing.T) {
	env := setupProviderTestEnv(t)
	defer env.cleanup()

	// ============================================================
	// Test 1: Get SP info with valid auth and slug
	// ============================================================
	t.Run("Get_SP_Info_Success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/sso/sp-info?slug=test-provider", nil)
		req.Header.Set("Authorization", "Bearer "+env.adminToken)
		rec := httptest.NewRecorder()

		env.echo.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code, "SP info should succeed: %s", rec.Body.String())

		var resp map[string]interface{}
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)

		// SP info should contain entity_id and acs_url
		assert.NotNil(t, resp["entity_id"], "SP info should contain entity_id")
		assert.NotNil(t, resp["acs_url"], "SP info should contain acs_url")
		t.Logf("SP Info: %v", resp)
	})

	// ============================================================
	// Test 2: Get SP info without auth fails
	// ============================================================
	t.Run("Get_SP_Info_No_Auth", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/sso/sp-info?slug=test-provider", nil)
		// No Authorization header
		rec := httptest.NewRecorder()

		env.echo.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	// ============================================================
	// Test 3: Get SP info with missing slug
	// ============================================================
	t.Run("Get_SP_Info_Missing_Slug", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/sso/sp-info", nil)
		req.Header.Set("Authorization", "Bearer "+env.adminToken)
		rec := httptest.NewRecorder()

		env.echo.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	// ============================================================
	// Test 4: Get SP info with empty slug
	// ============================================================
	t.Run("Get_SP_Info_Empty_Slug", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/sso/sp-info?slug=", nil)
		req.Header.Set("Authorization", "Bearer "+env.adminToken)
		rec := httptest.NewRecorder()

		env.echo.ServeHTTP(rec, req)

		// Should return 400 for empty slug
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}
