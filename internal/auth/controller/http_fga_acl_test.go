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

// TestFGAACLTuples_CRUD tests FGA ACL tuple management endpoints
func TestFGAACLTuples_CRUD(t *testing.T) {
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
	err = tr.Create(ctx, tenantID, "fga-acl-test-"+tenantID.String(), nil)
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

	// Create admin user
	adminEmail := "fga-acl-admin@example.com"
	adminPassword := "AdminPass123!"

	signupBody := map[string]string{
		"tenant_id": tenantID.String(),
		"email":     adminEmail,
		"password":  adminPassword,
	}
	sb, err := json.Marshal(signupBody)
	require.NoError(t, err)
	sreq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/signup?token=json", bytes.NewReader(sb))
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
	lb, err := json.Marshal(loginBody)
	require.NoError(t, err)
	lreq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/login?token=json", bytes.NewReader(lb))
	lreq.Header.Set("Content-Type", "application/json")
	lrec := httptest.NewRecorder()
	e.ServeHTTP(lrec, lreq)
	require.Equal(t, http.StatusOK, lrec.Code)
	err = json.Unmarshal(lrec.Body.Bytes(), &adminTokens)
	require.NoError(t, err)

	// Create a group for ACL testing
	grp, err := auth.CreateGroup(ctx, tenantID, "acl-test-group", "Group for ACL testing")
	require.NoError(t, err)
	groupID := grp.ID

	// Add admin to group
	err = auth.AddGroupMember(ctx, groupID, adminUserID)
	require.NoError(t, err)

	// ============================================================
	// Test 1: Create ACL tuple (grant permission to group)
	// ============================================================
	t.Run("Create_ACL_Tuple", func(t *testing.T) {
		createBody := map[string]interface{}{
			"tenant_id":      tenantID.String(),
			"subject_type":   "group",
			"subject_id":     groupID.String(),
			"permission_key": "settings:read",
			"object_type":    "tenant",
		}
		body, _ := json.Marshal(createBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/fga/acl/tuples", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+adminTokens.AccessToken)
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusCreated, rec.Code, "Create ACL tuple should succeed: %s", rec.Body.String())
	})

	// ============================================================
	// Test 2: Authorize - user should have permission via group
	// ============================================================
	t.Run("Authorize_Via_Group_Membership", func(t *testing.T) {
		authzBody := map[string]string{
			"tenant_id":      tenantID.String(),
			"subject_type":   "self",
			"permission_key": "settings:read",
			"object_type":    "tenant",
		}
		body, _ := json.Marshal(authzBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/authorize", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+adminTokens.AccessToken)
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp struct {
			Allowed bool `json:"allowed"`
		}
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.True(t, resp.Allowed, "User should be authorized via group membership")
	})

	// ============================================================
	// Test 3: Create ACL tuple for user directly
	// ============================================================
	t.Run("Create_ACL_Tuple_For_User", func(t *testing.T) {
		createBody := map[string]interface{}{
			"tenant_id":      tenantID.String(),
			"subject_type":   "user",
			"subject_id":     adminUserID.String(),
			"permission_key": "settings:write",
			"object_type":    "tenant",
		}
		body, _ := json.Marshal(createBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/fga/acl/tuples", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+adminTokens.AccessToken)
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusCreated, rec.Code, "Create ACL tuple for user should succeed: %s", rec.Body.String())
	})

	// ============================================================
	// Test 4: Authorize - user should have direct permission
	// ============================================================
	t.Run("Authorize_Direct_Permission", func(t *testing.T) {
		authzBody := map[string]string{
			"tenant_id":      tenantID.String(),
			"subject_type":   "user",
			"subject_id":     adminUserID.String(),
			"permission_key": "settings:write",
			"object_type":    "tenant",
		}
		body, _ := json.Marshal(authzBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/authorize", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+adminTokens.AccessToken)
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp struct {
			Allowed bool `json:"allowed"`
		}
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.True(t, resp.Allowed, "User should have direct permission")
	})

	// ============================================================
	// Test 5: Delete ACL tuple
	// ============================================================
	t.Run("Delete_ACL_Tuple", func(t *testing.T) {
		deleteBody := map[string]interface{}{
			"tenant_id":      tenantID.String(),
			"subject_type":   "group",
			"subject_id":     groupID.String(),
			"permission_key": "settings:read",
			"object_type":    "tenant",
		}
		body, _ := json.Marshal(deleteBody)
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/admin/fga/acl/tuples", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+adminTokens.AccessToken)
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNoContent, rec.Code, "Delete ACL tuple should succeed: %s", rec.Body.String())
	})

	// ============================================================
	// Test 6: Authorize - permission should be revoked
	// ============================================================
	t.Run("Authorize_After_Revoke", func(t *testing.T) {
		authzBody := map[string]string{
			"tenant_id":      tenantID.String(),
			"subject_type":   "self",
			"permission_key": "settings:read",
			"object_type":    "tenant",
		}
		body, _ := json.Marshal(authzBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/authorize", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+adminTokens.AccessToken)
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp struct {
			Allowed bool `json:"allowed"`
		}
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.False(t, resp.Allowed, "Permission should be revoked after deleting ACL tuple")
	})

	// ============================================================
	// Test 7: Create ACL tuple without auth fails
	// ============================================================
	t.Run("Create_ACL_Tuple_No_Auth", func(t *testing.T) {
		createBody := map[string]interface{}{
			"tenant_id":      tenantID.String(),
			"subject_type":   "user",
			"subject_id":     adminUserID.String(),
			"permission_key": "settings:delete",
			"object_type":    "tenant",
		}
		body, _ := json.Marshal(createBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/fga/acl/tuples", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		// No Authorization header
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	// ============================================================
	// Test 8: Create ACL tuple with invalid JSON fails
	// ============================================================
	t.Run("Create_ACL_Tuple_Invalid_JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/fga/acl/tuples", bytes.NewReader([]byte("invalid json")))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+adminTokens.AccessToken)
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	// ============================================================
	// Test 9: Authorize without auth fails
	// ============================================================
	t.Run("Authorize_No_Auth", func(t *testing.T) {
		authzBody := map[string]string{
			"tenant_id":      tenantID.String(),
			"subject_type":   "self",
			"permission_key": "settings:read",
			"object_type":    "tenant",
		}
		body, _ := json.Marshal(authzBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/authorize", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		// No Authorization header
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
}
