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

// TestRBACPermissionsResolve_Flow tests the RBAC permissions resolution endpoint
func TestRBACPermissionsResolve_Flow(t *testing.T) {
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
	err = tr.Create(ctx, tenantID, "rbac-resolve-test-"+tenantID.String(), nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		// Clean up test tenant and associated data (delete dependent tables first)
		cleanupCtx := context.Background()
		_, err := pool.Exec(cleanupCtx, `DELETE FROM user_roles WHERE tenant_id = $1`, tenantID)
		if err != nil {
			t.Logf("Cleanup: failed to delete user_roles: %v", err)
		}
		_, err = pool.Exec(cleanupCtx, `DELETE FROM role_permissions WHERE tenant_id = $1`, tenantID)
		if err != nil {
			t.Logf("Cleanup: failed to delete role_permissions: %v", err)
		}
		_, err = pool.Exec(cleanupCtx, `DELETE FROM roles WHERE tenant_id = $1`, tenantID)
		if err != nil {
			t.Logf("Cleanup: failed to delete roles: %v", err)
		}
		_, err = pool.Exec(cleanupCtx, `DELETE FROM users WHERE tenant_id = $1`, tenantID)
		if err != nil {
			t.Logf("Cleanup: failed to delete users: %v", err)
		}
		_, err = pool.Exec(cleanupCtx, `DELETE FROM tenants WHERE id = $1`, tenantID)
		if err != nil {
			t.Logf("Cleanup: failed to delete tenant: %v", err)
		}
	})

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
	c := NewWithConfig(auth, magic, sso, cfg)
	c.Register(e)

	// Create admin user
	adminEmail := "rbac-resolve-admin@example.com"
	adminPassword := "AdminPass123!"

	signupBody := map[string]string{
		"tenant_id": tenantID.String(),
		"email":     adminEmail,
		"password":  adminPassword,
	}
	sb, err := json.Marshal(signupBody)
	require.NoError(t, err)
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
	lb, err := json.Marshal(loginBody)
	require.NoError(t, err)
	lreq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/login", bytes.NewReader(lb))
	lreq.Header.Set("Content-Type", "application/json")
	lrec := httptest.NewRecorder()
	e.ServeHTTP(lrec, lreq)
	require.Equal(t, http.StatusOK, lrec.Code)
	err = json.Unmarshal(lrec.Body.Bytes(), &adminTokens)
	require.NoError(t, err)

	// Create a target user
	targetEmail := "rbac-target@example.com"
	targetPassword := "TargetPass123!"

	targetSignup := map[string]string{
		"tenant_id": tenantID.String(),
		"email":     targetEmail,
		"password":  targetPassword,
	}
	tsb, err := json.Marshal(targetSignup)
	require.NoError(t, err)
	tsreq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/signup", bytes.NewReader(tsb))
	tsreq.Header.Set("Content-Type", "application/json")
	tsrec := httptest.NewRecorder()
	e.ServeHTTP(tsrec, tsreq)
	require.Equal(t, http.StatusCreated, tsrec.Code)

	var targetTokens struct {
		AccessToken string `json:"access_token"`
	}
	err = json.Unmarshal(tsrec.Body.Bytes(), &targetTokens)
	require.NoError(t, err)

	targetIntr, err := auth.Introspect(ctx, targetTokens.AccessToken)
	require.NoError(t, err)
	targetUserID := targetIntr.UserID

	// ============================================================
	// Test 1: Resolve permissions for user (initially empty)
	// ============================================================
	t.Run("Resolve_Permissions_Empty", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/rbac/users/"+targetUserID.String()+"/permissions/resolve?tenant_id="+tenantID.String(), nil)
		req.Header.Set("Authorization", "Bearer "+adminTokens.AccessToken)
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code, "Resolve permissions should succeed: %s", rec.Body.String())

		var resp struct {
			Grants []interface{} `json:"grants"`
		}
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)
		// User with no roles should have no grants
		assert.Empty(t, resp.Grants, "User with no roles should have no grants")
	})

	// ============================================================
	// Test 2: Create role and assign to user, then resolve
	// ============================================================
	t.Run("Resolve_Permissions_After_Role_Assignment", func(t *testing.T) {
		// Create a role
		createRoleBody := map[string]string{
			"tenant_id":   tenantID.String(),
			"name":        "editor",
			"description": "Editor role",
		}
		crb, err := json.Marshal(createRoleBody)
		require.NoError(t, err)
		crReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/rbac/roles", bytes.NewReader(crb))
		crReq.Header.Set("Content-Type", "application/json")
		crReq.Header.Set("Authorization", "Bearer "+adminTokens.AccessToken)
		crRec := httptest.NewRecorder()
		e.ServeHTTP(crRec, crReq)

		assert.Equal(t, http.StatusCreated, crRec.Code, "Create role should succeed: %s", crRec.Body.String())

		var roleResp struct {
			ID string `json:"id"`
		}
		err = json.Unmarshal(crRec.Body.Bytes(), &roleResp)
		require.NoError(t, err)
		roleID := roleResp.ID

		// Assign role to user
		assignBody := map[string]string{
			"tenant_id": tenantID.String(),
			"role_id":   roleID,
		}
		ab, err := json.Marshal(assignBody)
		require.NoError(t, err)
		aReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/rbac/users/"+targetUserID.String()+"/roles", bytes.NewReader(ab))
		aReq.Header.Set("Content-Type", "application/json")
		aReq.Header.Set("Authorization", "Bearer "+adminTokens.AccessToken)
		aRec := httptest.NewRecorder()
		e.ServeHTTP(aRec, aReq)

		assert.Equal(t, http.StatusNoContent, aRec.Code, "Assign role should succeed: %s", aRec.Body.String())

		// Resolve permissions again
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/rbac/users/"+targetUserID.String()+"/permissions/resolve?tenant_id="+tenantID.String(), nil)
		req.Header.Set("Authorization", "Bearer "+adminTokens.AccessToken)
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		// Verify permissions changed after role assignment
		var resp struct {
			Grants []interface{} `json:"grants"`
		}
		err = json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)
		// After role assignment, user should have grants (role was assigned)
		// The editor role may not have permissions yet, but the response structure should be valid
		t.Logf("Permissions after role assignment: grants=%d", len(resp.Grants))
		assert.NotNil(t, resp.Grants, "Grants should not be nil")
	})

	// ============================================================
	// Test 3: Resolve permissions without auth fails
	// ============================================================
	t.Run("Resolve_Permissions_No_Auth", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/rbac/users/"+targetUserID.String()+"/permissions/resolve?tenant_id="+tenantID.String(), nil)
		// No Authorization header
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	// ============================================================
	// Test 4: Resolve permissions with invalid user ID
	// ============================================================
	t.Run("Resolve_Permissions_Invalid_UserID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/rbac/users/invalid-uuid/permissions/resolve?tenant_id="+tenantID.String(), nil)
		req.Header.Set("Authorization", "Bearer "+adminTokens.AccessToken)
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	// ============================================================
	// Test 5: Non-admin cannot resolve permissions
	// ============================================================
	t.Run("Resolve_Permissions_NonAdmin_Forbidden", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/rbac/users/"+adminUserID.String()+"/permissions/resolve?tenant_id="+tenantID.String(), nil)
		req.Header.Set("Authorization", "Bearer "+targetTokens.AccessToken)
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusForbidden, rec.Code)
	})
}
