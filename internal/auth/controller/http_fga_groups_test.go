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

// TestFGAGroups_CRUD tests FGA group management endpoints
func TestFGAGroups_CRUD(t *testing.T) {
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
	err = tr.Create(ctx, tenantID, "fga-groups-test-"+tenantID.String()[:8])
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

	// Create admin user
	adminEmail := "fga-groups-admin@example.com"
	adminPassword := "AdminPass123!"

	signupBody := map[string]string{
		"tenant_id": tenantID.String(),
		"email":     adminEmail,
		"password":  adminPassword,
	}
	sb, _ := json.Marshal(signupBody)
	sreq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/signup", bytes.NewReader(sb))
	sreq.Header.Set("Content-Type", "application/json")
	srec := httptest.NewRecorder()
	e.ServeHTTP(srec, sreq)
	require.Equal(t, http.StatusCreated, srec.Code)

	var adminTokens struct {
		AccessToken string `json:"access_token"`
	}
	err = json.Unmarshal(srec.Body.Bytes(), &adminTokens)
	require.NoError(t, err)

	// Get admin user ID and grant admin role
	adminIntr, err := auth.Introspect(ctx, adminTokens.AccessToken)
	require.NoError(t, err)
	adminUserID := adminIntr.UserID
	err = auth.UpdateUserRoles(ctx, adminUserID, []string{"admin"})
	require.NoError(t, err)

	// Re-login to get token with admin role
	loginBody := map[string]string{
		"tenant_id": tenantID.String(),
		"email":     adminEmail,
		"password":  adminPassword,
	}
	lb, _ := json.Marshal(loginBody)
	lreq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/login", bytes.NewReader(lb))
	lreq.Header.Set("Content-Type", "application/json")
	lrec := httptest.NewRecorder()
	e.ServeHTTP(lrec, lreq)
	require.Equal(t, http.StatusOK, lrec.Code)
	err = json.Unmarshal(lrec.Body.Bytes(), &adminTokens)
	require.NoError(t, err)

	var groupID string

	// ============================================================
	// Test 1: Create FGA group
	// ============================================================
	t.Run("Create_FGA_Group", func(t *testing.T) {
		createBody := map[string]string{
			"tenant_id":   tenantID.String(),
			"name":        "engineering",
			"description": "Engineering team",
		}
		body, _ := json.Marshal(createBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/fga/groups", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+adminTokens.AccessToken)
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusCreated, rec.Code, "Create group should succeed: %s", rec.Body.String())

		var resp map[string]interface{}
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.NotEmpty(t, resp["id"])
		assert.Equal(t, "engineering", resp["name"])

		groupID = resp["id"].(string)
		t.Logf("Created group ID: %s", groupID)
	})

	// ============================================================
	// Test 2: List FGA groups
	// ============================================================
	t.Run("List_FGA_Groups", func(t *testing.T) {
		require.NotEmpty(t, groupID, "Group ID required")

		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/fga/groups?tenant_id="+tenantID.String(), nil)
		req.Header.Set("Authorization", "Bearer "+adminTokens.AccessToken)
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp struct {
			Groups []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"groups"`
		}
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(resp.Groups), 1)

		found := false
		for _, g := range resp.Groups {
			if g.ID == groupID {
				assert.Equal(t, "engineering", g.Name)
				found = true
				break
			}
		}
		assert.True(t, found, "Created group should be in list")
	})

	// ============================================================
	// Test 3: Add member to group
	// ============================================================
	t.Run("Add_Group_Member", func(t *testing.T) {
		require.NotEmpty(t, groupID, "Group ID required")

		addBody := map[string]string{
			"user_id": adminUserID.String(),
		}
		body, _ := json.Marshal(addBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/fga/groups/"+groupID+"/members", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+adminTokens.AccessToken)
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNoContent, rec.Code, "Add member should succeed: %s", rec.Body.String())
	})

	// ============================================================
	// Test 4: Remove member from group
	// ============================================================
	t.Run("Remove_Group_Member", func(t *testing.T) {
		require.NotEmpty(t, groupID, "Group ID required")

		removeBody := map[string]string{
			"user_id": adminUserID.String(),
		}
		body, _ := json.Marshal(removeBody)
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/admin/fga/groups/"+groupID+"/members", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+adminTokens.AccessToken)
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNoContent, rec.Code, "Remove member should succeed: %s", rec.Body.String())
	})

	// ============================================================
	// Test 5: Delete FGA group
	// ============================================================
	t.Run("Delete_FGA_Group", func(t *testing.T) {
		require.NotEmpty(t, groupID, "Group ID required")

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/admin/fga/groups/"+groupID+"?tenant_id="+tenantID.String(), nil)
		req.Header.Set("Authorization", "Bearer "+adminTokens.AccessToken)
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNoContent, rec.Code, "Delete group should succeed: %s", rec.Body.String())
	})

	// ============================================================
	// Test 6: Verify group deleted
	// ============================================================
	t.Run("Verify_Group_Deleted", func(t *testing.T) {
		require.NotEmpty(t, groupID, "Group ID required")

		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/fga/groups?tenant_id="+tenantID.String(), nil)
		req.Header.Set("Authorization", "Bearer "+adminTokens.AccessToken)
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp struct {
			Groups []struct {
				ID string `json:"id"`
			} `json:"groups"`
		}
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)

		for _, g := range resp.Groups {
			assert.NotEqual(t, groupID, g.ID, "Deleted group should not be in list")
		}
	})

	// ============================================================
	// Test 7: Create group without auth fails
	// ============================================================
	t.Run("Create_Group_No_Auth", func(t *testing.T) {
		createBody := map[string]string{
			"tenant_id":   tenantID.String(),
			"name":        "unauthorized",
			"description": "Should fail",
		}
		body, _ := json.Marshal(createBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/fga/groups", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		// No Authorization header
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	// ============================================================
	// Test 8: Create group with invalid JSON fails
	// ============================================================
	t.Run("Create_Group_Invalid_JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/fga/groups", bytes.NewReader([]byte("invalid json")))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+adminTokens.AccessToken)
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	// ============================================================
	// Test 9: Delete non-existent group
	// ============================================================
	t.Run("Delete_NonExistent_Group", func(t *testing.T) {
		nonExistentID := uuid.New()
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/admin/fga/groups/"+nonExistentID.String(), nil)
		req.Header.Set("Authorization", "Bearer "+adminTokens.AccessToken)
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		// Should return 204 (idempotent) or 400
		assert.True(t, rec.Code == http.StatusNoContent || rec.Code == http.StatusBadRequest,
			"Delete non-existent group should return 204 or 400, got %d", rec.Code)
	})
}
