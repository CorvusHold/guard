//go:build integration
// +build integration

package controller_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	authdomain "github.com/corvusHold/guard/internal/auth/domain"
	authrepo "github.com/corvusHold/guard/internal/auth/repository"
	authsvc "github.com/corvusHold/guard/internal/auth/service"
	"github.com/corvusHold/guard/internal/auth/sso/controller"
	"github.com/corvusHold/guard/internal/auth/sso/service"
	"github.com/corvusHold/guard/internal/config"
	srepo "github.com/corvusHold/guard/internal/settings/repository"
	ssvc "github.com/corvusHold/guard/internal/settings/service"
	trepo "github.com/corvusHold/guard/internal/tenants/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ProviderTestEnv holds the test environment for SSO provider CRUD tests
type ProviderTestEnv struct {
	pool          *pgxpool.Pool
	redis         *goredis.Client
	cfg           config.Config
	authService   *authsvc.Service
	authRepo      *authrepo.SQLCRepository
	ssoService    *service.SSOService
	ssoController *controller.SSOController
	echo          *echo.Echo
	tenantID      uuid.UUID
	adminUserID   uuid.UUID
	adminToken    string
	cleanup       func()
}

// setupProviderTestEnv creates a complete test environment for SSO provider tests
func setupProviderTestEnv(t *testing.T) *ProviderTestEnv {
	t.Helper()

	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("skipping integration test: DATABASE_URL not set")
	}

	ctx := context.Background()

	// Connect to database
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	require.NoError(t, err, "failed to connect to database")

	// Connect to Redis
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}
	redisClient := goredis.NewClient(&goredis.Options{
		Addr: redisAddr,
		DB:   15, // Use separate DB for tests
	})
	err = redisClient.Ping(ctx).Err()
	if err != nil {
		pool.Close()
		t.Fatalf("failed to connect to Redis: %v", err)
	}

	// Create test tenant
	tr := trepo.New(pool)
	tenantID := uuid.New()
	tenantName := "sso-provider-test-" + tenantID.String()[:8]
	err = tr.Create(ctx, tenantID, tenantName, nil)
	require.NoError(t, err, "failed to create tenant")

	// Load config
	cfg, err := config.Load()
	require.NoError(t, err, "failed to load config")
	cfg.PublicBaseURL = "http://localhost:8080"

	// Wire up services
	authRepo := authrepo.New(pool)
	settingsRepo := srepo.New(pool)
	settingsService := ssvc.New(settingsRepo)
	authService := authsvc.New(authRepo, cfg, settingsService)
	ssoService := service.New(pool, redisClient, cfg.PublicBaseURL)

	// Create admin user
	adminEmail := fmt.Sprintf("admin-%s@test.com", tenantID.String()[:8])
	signupResp, err := authService.Signup(ctx, authdomain.SignupInput{
		TenantID:  tenantID,
		Email:     adminEmail,
		Password:  "TestPassword123!",
		FirstName: "Admin",
		LastName:  "User",
	})
	require.NoError(t, err, "failed to create admin user")

	// Get admin user ID from auth identity
	aiAdmin, err := authRepo.GetAuthIdentityByEmailTenant(ctx, tenantID, adminEmail)
	require.NoError(t, err, "failed to get admin identity")

	// Grant admin role
	err = authService.UpdateUserRoles(ctx, aiAdmin.UserID, []string{"admin"})
	require.NoError(t, err, "failed to grant admin role")

	// Get fresh token with admin role
	loginResp, err := authService.Login(ctx, authdomain.LoginInput{
		TenantID:  tenantID,
		Email:     adminEmail,
		Password:  "TestPassword123!",
		UserAgent: "test-agent",
		IP:        "127.0.0.1",
	})
	require.NoError(t, err, "failed to login admin user")

	// Create controller
	ssoController := controller.New(ssoService, authService)

	// Setup Echo
	e := echo.New()
	apiV1 := e.Group("/api/v1")
	ssoController.RegisterV1(apiV1)

	env := &ProviderTestEnv{
		pool:          pool,
		redis:         redisClient,
		cfg:           cfg,
		authService:   authService,
		authRepo:      authRepo,
		ssoService:    ssoService,
		ssoController: ssoController,
		echo:          e,
		tenantID:      tenantID,
		adminUserID:   aiAdmin.UserID,
		adminToken:    loginResp.AccessToken,
		cleanup: func() {
			redisClient.FlushDB(ctx)
			redisClient.Close()
			pool.Close()
		},
	}

	// Suppress unused variable warning for signupResp
	_ = signupResp

	return env
}

// TestProviderCRUD_CreateListGetUpdateDelete tests the complete CRUD lifecycle
func TestProviderCRUD_CreateListGetUpdateDelete(t *testing.T) {
	env := setupProviderTestEnv(t)
	defer env.cleanup()

	ctx := context.Background()

	// Create provider directly in database (bypasses OIDC validation which requires live endpoints)
	providerUUID := uuid.New()
	_, err := env.pool.Exec(ctx, `
		INSERT INTO sso_providers (
			id, tenant_id, name, slug, provider_type, enabled, allow_signup, 
			trust_email_verified, domains, issuer, authorization_endpoint, 
			token_endpoint, userinfo_endpoint, jwks_uri, client_id, client_secret,
			scopes, response_type, created_by, updated_by
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20
		)`,
		providerUUID, env.tenantID, "Test OIDC Provider", "test-oidc-crud", "oidc",
		true, true, true, []string{"example.com", "test.com"},
		"https://idp.example.com", "https://idp.example.com/authorize",
		"https://idp.example.com/token", "https://idp.example.com/userinfo",
		"https://idp.example.com/.well-known/jwks.json", "test-client-id", "test-client-secret",
		[]string{"openid", "profile", "email"}, "code", env.adminUserID, env.adminUserID,
	)
	require.NoError(t, err, "Failed to create provider in database")
	providerID := providerUUID.String()
	t.Logf("Created provider ID: %s", providerID)

	// ============================================================
	// TEST 1: List Providers via HTTP API
	// ============================================================
	t.Run("List_Providers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/sso/providers?tenant_id=%s", env.tenantID), nil)
		req.Header.Set("Authorization", "Bearer "+env.adminToken)
		rec := httptest.NewRecorder()

		env.echo.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code, "Expected 200 OK, got %d: %s", rec.Code, rec.Body.String())

		var resp map[string]interface{}
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)

		providers, ok := resp["providers"].([]interface{})
		require.True(t, ok, "Expected providers array")
		require.GreaterOrEqual(t, len(providers), 1, "Expected at least 1 provider")

		// Find our test provider
		found := false
		for _, p := range providers {
			prov := p.(map[string]interface{})
			if prov["slug"] == "test-oidc-crud" {
				assert.Equal(t, providerID, prov["id"])
				assert.Equal(t, "Test OIDC Provider", prov["name"])
				assert.Equal(t, true, prov["enabled"])
				found = true
				break
			}
		}
		require.True(t, found, "Test provider should be in list")
	})

	// ============================================================
	// TEST 2: Get Provider by ID
	// ============================================================
	t.Run("Get_Provider_By_ID", func(t *testing.T) {
		require.NotEmpty(t, providerID, "Provider ID required")

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sso/providers/"+providerID, nil)
		req.Header.Set("Authorization", "Bearer "+env.adminToken)
		rec := httptest.NewRecorder()

		env.echo.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code, "Expected 200 OK, got %d: %s", rec.Code, rec.Body.String())

		var resp map[string]interface{}
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.Equal(t, providerID, resp["id"])
		assert.Equal(t, "Test OIDC Provider", resp["name"])
		assert.Equal(t, "test-oidc-crud", resp["slug"])
		assert.Equal(t, "oidc", resp["provider_type"])
		assert.Equal(t, true, resp["enabled"])
		assert.Equal(t, true, resp["allow_signup"])

		// Verify domains
		domains, ok := resp["domains"].([]interface{})
		require.True(t, ok, "Expected domains array")
		assert.Contains(t, domains, "example.com")
		assert.Contains(t, domains, "test.com")
	})

	// ============================================================
	// TEST 4: Update Provider - Change Name
	// ============================================================
	t.Run("Update_Provider_Name", func(t *testing.T) {
		require.NotEmpty(t, providerID, "Provider ID required")

		updateBody := map[string]interface{}{
			"name": "Updated OIDC Provider Name",
		}

		body, _ := json.Marshal(updateBody)
		req := httptest.NewRequest(http.MethodPut, "/api/v1/sso/providers/"+providerID, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+env.adminToken)
		rec := httptest.NewRecorder()

		env.echo.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code, "Expected 200 OK, got %d: %s", rec.Code, rec.Body.String())

		var resp map[string]interface{}
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.Equal(t, "Updated OIDC Provider Name", resp["name"], "Name should be updated")
		assert.Equal(t, "test-oidc-crud", resp["slug"], "Slug should remain unchanged")
		assert.Equal(t, true, resp["enabled"], "Enabled should remain unchanged")
	})

	// ============================================================
	// TEST 5: Verify Update Persisted - GET after PUT
	// ============================================================
	t.Run("Verify_Update_Persisted", func(t *testing.T) {
		require.NotEmpty(t, providerID, "Provider ID required")

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sso/providers/"+providerID, nil)
		req.Header.Set("Authorization", "Bearer "+env.adminToken)
		rec := httptest.NewRecorder()

		env.echo.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp map[string]interface{}
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.Equal(t, "Updated OIDC Provider Name", resp["name"], "Name update should persist")
	})

	// ============================================================
	// TEST 6: Update Provider - Change Enabled Status
	// ============================================================
	t.Run("Update_Provider_Enabled_Status", func(t *testing.T) {
		require.NotEmpty(t, providerID, "Provider ID required")

		enabled := false
		updateBody := map[string]interface{}{
			"enabled": enabled,
		}

		body, _ := json.Marshal(updateBody)
		req := httptest.NewRequest(http.MethodPut, "/api/v1/sso/providers/"+providerID, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+env.adminToken)
		rec := httptest.NewRecorder()

		env.echo.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code, "Expected 200 OK, got %d: %s", rec.Code, rec.Body.String())

		var resp map[string]interface{}
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.Equal(t, false, resp["enabled"], "Enabled should be updated to false")
	})

	// ============================================================
	// TEST 7: Verify Enabled Status Persisted
	// ============================================================
	t.Run("Verify_Enabled_Status_Persisted", func(t *testing.T) {
		require.NotEmpty(t, providerID, "Provider ID required")

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sso/providers/"+providerID, nil)
		req.Header.Set("Authorization", "Bearer "+env.adminToken)
		rec := httptest.NewRecorder()

		env.echo.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp map[string]interface{}
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.Equal(t, false, resp["enabled"], "Enabled status should persist as false")
	})

	// ============================================================
	// TEST 8: Update Provider - Multiple Fields (non-endpoint fields only)
	// ============================================================
	t.Run("Update_Provider_Multiple_Fields", func(t *testing.T) {
		require.NotEmpty(t, providerID, "Provider ID required")

		enabled := true
		allowSignup := false
		updateBody := map[string]interface{}{
			"name":         "Final Provider Name",
			"enabled":      enabled,
			"allow_signup": allowSignup,
			"domains":      []string{"newdomain.com"},
		}

		body, _ := json.Marshal(updateBody)
		req := httptest.NewRequest(http.MethodPut, "/api/v1/sso/providers/"+providerID, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+env.adminToken)
		rec := httptest.NewRecorder()

		env.echo.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code, "Expected 200 OK, got %d: %s", rec.Code, rec.Body.String())

		var resp map[string]interface{}
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.Equal(t, "Final Provider Name", resp["name"])
		assert.Equal(t, true, resp["enabled"])
		assert.Equal(t, false, resp["allow_signup"])

		domains, ok := resp["domains"].([]interface{})
		require.True(t, ok)
		assert.Contains(t, domains, "newdomain.com")
	})

	// ============================================================
	// TEST 9: Verify Multiple Fields Persisted
	// ============================================================
	t.Run("Verify_Multiple_Fields_Persisted", func(t *testing.T) {
		require.NotEmpty(t, providerID, "Provider ID required")

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sso/providers/"+providerID, nil)
		req.Header.Set("Authorization", "Bearer "+env.adminToken)
		rec := httptest.NewRecorder()

		env.echo.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp map[string]interface{}
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.Equal(t, "Final Provider Name", resp["name"], "Name should persist")
		assert.Equal(t, true, resp["enabled"], "Enabled should persist")
		assert.Equal(t, false, resp["allow_signup"], "AllowSignup should persist")

		domains, ok := resp["domains"].([]interface{})
		require.True(t, ok)
		assert.Contains(t, domains, "newdomain.com", "Domains should persist")
	})

	// ============================================================
	// TEST 10: Delete Provider
	// ============================================================
	t.Run("Delete_Provider", func(t *testing.T) {
		require.NotEmpty(t, providerID, "Provider ID required")

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sso/providers/"+providerID, nil)
		req.Header.Set("Authorization", "Bearer "+env.adminToken)
		rec := httptest.NewRecorder()

		env.echo.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNoContent, rec.Code, "Expected 204 No Content, got %d: %s", rec.Code, rec.Body.String())
	})

	// ============================================================
	// TEST 11: Verify Provider Deleted
	// ============================================================
	t.Run("Verify_Provider_Deleted", func(t *testing.T) {
		require.NotEmpty(t, providerID, "Provider ID required")

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sso/providers/"+providerID, nil)
		req.Header.Set("Authorization", "Bearer "+env.adminToken)
		rec := httptest.NewRecorder()

		env.echo.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code, "Expected 404 Not Found after deletion")
	})

	// ============================================================
	// TEST 12: Verify Provider Not in List
	// ============================================================
	t.Run("Verify_Provider_Not_In_List", func(t *testing.T) {
		require.NotEmpty(t, providerID, "Provider ID required")

		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/sso/providers?tenant_id=%s", env.tenantID), nil)
		req.Header.Set("Authorization", "Bearer "+env.adminToken)
		rec := httptest.NewRecorder()

		env.echo.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp map[string]interface{}
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)

		providers, ok := resp["providers"].([]interface{})
		require.True(t, ok)

		for _, p := range providers {
			provider := p.(map[string]interface{})
			assert.NotEqual(t, providerID, provider["id"], "Deleted provider should not be in list")
		}
	})
}

// TestProviderUpdate_Persistence tests that updates are properly persisted to the database
func TestProviderUpdate_Persistence(t *testing.T) {
	env := setupProviderTestEnv(t)
	defer env.cleanup()

	ctx := context.Background()

	// Create provider directly in database (bypasses OIDC validation)
	providerID := uuid.New()
	_, err := env.pool.Exec(ctx, `
		INSERT INTO sso_providers (
			id, tenant_id, name, slug, provider_type, enabled, allow_signup, 
			trust_email_verified, domains, issuer, authorization_endpoint, 
			token_endpoint, userinfo_endpoint, jwks_uri, client_id, client_secret,
			scopes, response_type, created_by, updated_by
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20
		)`,
		providerID, env.tenantID, "Persistence Test Provider", "persistence-test", "oidc",
		true, true, true, []string{"original.com"},
		"https://original.example.com", "https://original.example.com/authorize",
		"https://original.example.com/token", "https://original.example.com/userinfo",
		"https://original.example.com/.well-known/jwks.json", "original-client-id", "original-client-secret",
		[]string{"openid", "profile"}, "code", env.adminUserID, env.adminUserID,
	)
	require.NoError(t, err)
	t.Logf("Created provider: %s", providerID)

	// ============================================================
	// Test 1: Update name via HTTP API
	// ============================================================
	t.Run("Update_Name_Via_HTTP", func(t *testing.T) {
		updateBody := map[string]interface{}{
			"name": "Updated Persistence Name",
		}

		body, _ := json.Marshal(updateBody)
		req := httptest.NewRequest(http.MethodPut, "/api/v1/sso/providers/"+providerID.String(), bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+env.adminToken)
		rec := httptest.NewRecorder()

		env.echo.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code, "Update should succeed: %s", rec.Body.String())

		// Verify via direct service call (bypasses any caching)
		fetched, err := env.ssoService.GetProvider(ctx, env.tenantID, providerID)
		require.NoError(t, err)
		assert.Equal(t, "Updated Persistence Name", fetched.Name, "Name should be persisted in database")
	})

	// ============================================================
	// Test 2: Update enabled status
	// ============================================================
	t.Run("Update_Enabled_Status", func(t *testing.T) {
		enabled := false
		updateBody := map[string]interface{}{
			"enabled": enabled,
		}

		body, _ := json.Marshal(updateBody)
		req := httptest.NewRequest(http.MethodPut, "/api/v1/sso/providers/"+providerID.String(), bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+env.adminToken)
		rec := httptest.NewRecorder()

		env.echo.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)

		// Verify via direct service call
		fetched, err := env.ssoService.GetProvider(ctx, env.tenantID, providerID)
		require.NoError(t, err)
		assert.Equal(t, false, fetched.Enabled, "Enabled status should be persisted")
	})

	// ============================================================
	// Test 3: Update domains
	// ============================================================
	t.Run("Update_Domains", func(t *testing.T) {
		updateBody := map[string]interface{}{
			"domains": []string{"new1.com", "new2.com", "new3.com"},
		}

		body, _ := json.Marshal(updateBody)
		req := httptest.NewRequest(http.MethodPut, "/api/v1/sso/providers/"+providerID.String(), bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+env.adminToken)
		rec := httptest.NewRecorder()

		env.echo.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)

		// Verify via direct service call
		fetched, err := env.ssoService.GetProvider(ctx, env.tenantID, providerID)
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"new1.com", "new2.com", "new3.com"}, fetched.Domains, "Domains should be persisted")
	})

	// ============================================================
	// Test 4: Update allow_signup and trust_email_verified
	// ============================================================
	t.Run("Update_Signup_Settings", func(t *testing.T) {
		allowSignup := false
		trustEmail := false
		updateBody := map[string]interface{}{
			"allow_signup":         allowSignup,
			"trust_email_verified": trustEmail,
		}

		body, _ := json.Marshal(updateBody)
		req := httptest.NewRequest(http.MethodPut, "/api/v1/sso/providers/"+providerID.String(), bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+env.adminToken)
		rec := httptest.NewRecorder()

		env.echo.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)

		// Verify via direct service call
		fetched, err := env.ssoService.GetProvider(ctx, env.tenantID, providerID)
		require.NoError(t, err)
		assert.Equal(t, false, fetched.AllowSignup, "AllowSignup should be persisted")
		assert.Equal(t, false, fetched.TrustEmailVerified, "TrustEmailVerified should be persisted")
	})
}

// TestProviderUpdate_ErrorCases tests error handling for update operations
func TestProviderUpdate_ErrorCases(t *testing.T) {
	env := setupProviderTestEnv(t)
	defer env.cleanup()

	ctx := context.Background()

	// Create provider directly in database (OIDC requires issuer and client_id per check constraint)
	providerID := uuid.New()
	_, err := env.pool.Exec(ctx, `
		INSERT INTO sso_providers (
			id, tenant_id, name, slug, provider_type, enabled, 
			issuer, client_id, client_secret, scopes, created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		providerID, env.tenantID, "Error Test Provider", "error-test", "oidc",
		true, "https://error.example.com", "error-client-id", "error-client-secret",
		[]string{"openid"}, env.adminUserID, env.adminUserID,
	)
	require.NoError(t, err)

	// ============================================================
	// Test 1: Update non-existent provider
	// ============================================================
	t.Run("Update_NonExistent_Provider", func(t *testing.T) {
		nonExistentID := uuid.New()
		updateBody := map[string]interface{}{
			"name": "Should Fail",
		}

		body, _ := json.Marshal(updateBody)
		req := httptest.NewRequest(http.MethodPut, "/api/v1/sso/providers/"+nonExistentID.String(), bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+env.adminToken)
		rec := httptest.NewRecorder()

		env.echo.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code, "Should return 400 for non-existent provider")
	})

	// ============================================================
	// Test 2: Update with invalid provider ID
	// ============================================================
	t.Run("Update_Invalid_Provider_ID", func(t *testing.T) {
		updateBody := map[string]interface{}{
			"name": "Should Fail",
		}

		body, _ := json.Marshal(updateBody)
		req := httptest.NewRequest(http.MethodPut, "/api/v1/sso/providers/invalid-uuid", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+env.adminToken)
		rec := httptest.NewRecorder()

		env.echo.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code, "Should return 400 for invalid UUID")
	})

	// ============================================================
	// Test 3: Update without authentication
	// ============================================================
	t.Run("Update_Without_Auth", func(t *testing.T) {
		updateBody := map[string]interface{}{
			"name": "Should Fail",
		}

		body, _ := json.Marshal(updateBody)
		req := httptest.NewRequest(http.MethodPut, "/api/v1/sso/providers/"+providerID.String(), bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		// No Authorization header
		rec := httptest.NewRecorder()

		env.echo.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code, "Should return 401 without auth")
	})

	// ============================================================
	// Test 4: Update with invalid JSON body
	// ============================================================
	t.Run("Update_Invalid_JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/api/v1/sso/providers/"+providerID.String(), bytes.NewReader([]byte("invalid json")))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+env.adminToken)
		rec := httptest.NewRecorder()

		env.echo.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code, "Should return 400 for invalid JSON")
	})

	// ============================================================
	// Test 5: Get non-existent provider
	// ============================================================
	t.Run("Get_NonExistent_Provider", func(t *testing.T) {
		nonExistentID := uuid.New()

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sso/providers/"+nonExistentID.String(), nil)
		req.Header.Set("Authorization", "Bearer "+env.adminToken)
		rec := httptest.NewRecorder()

		env.echo.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code, "Should return 404 for non-existent provider")
	})

	// ============================================================
	// Test 6: Delete non-existent provider
	// ============================================================
	t.Run("Delete_NonExistent_Provider", func(t *testing.T) {
		nonExistentID := uuid.New()

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sso/providers/"+nonExistentID.String(), nil)
		req.Header.Set("Authorization", "Bearer "+env.adminToken)
		rec := httptest.NewRecorder()

		env.echo.ServeHTTP(rec, req)

		// Delete of non-existent should still return success (idempotent)
		// or 400 depending on implementation
		assert.True(t, rec.Code == http.StatusNoContent || rec.Code == http.StatusBadRequest,
			"Should return 204 or 400 for non-existent provider")
	})
}

// TestProviderList_Pagination tests list endpoint with pagination
func TestProviderList_Pagination(t *testing.T) {
	env := setupProviderTestEnv(t)
	defer env.cleanup()

	ctx := context.Background()

	// Create multiple providers directly in database (OIDC requires issuer and client_id)
	for i := 0; i < 5; i++ {
		providerID := uuid.New()
		_, err := env.pool.Exec(ctx, `
			INSERT INTO sso_providers (
				id, tenant_id, name, slug, provider_type, enabled, 
				issuer, client_id, client_secret, scopes, created_by, updated_by
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
			providerID, env.tenantID, fmt.Sprintf("Pagination Test Provider %d", i),
			fmt.Sprintf("pagination-test-%d", i), "oidc", true,
			fmt.Sprintf("https://pagination%d.example.com", i),
			fmt.Sprintf("pagination-client-%d", i), fmt.Sprintf("pagination-secret-%d", i),
			[]string{"openid"}, env.adminUserID, env.adminUserID,
		)
		require.NoError(t, err)
	}

	// ============================================================
	// Test: List all providers
	// ============================================================
	t.Run("List_All_Providers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/sso/providers?tenant_id=%s", env.tenantID), nil)
		req.Header.Set("Authorization", "Bearer "+env.adminToken)
		rec := httptest.NewRecorder()

		env.echo.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp map[string]interface{}
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)

		providers, ok := resp["providers"].([]interface{})
		require.True(t, ok)
		assert.GreaterOrEqual(t, len(providers), 5, "Should have at least 5 providers")

		total, ok := resp["total"].(float64)
		require.True(t, ok)
		assert.GreaterOrEqual(t, int(total), 5, "Total should be at least 5")
	})
}

// TestProviderCrossTenant_Isolation tests that providers are isolated between tenants
func TestProviderCrossTenant_Isolation(t *testing.T) {
	env := setupProviderTestEnv(t)
	defer env.cleanup()

	ctx := context.Background()

	// Create provider directly in database (OIDC requires issuer and client_id)
	providerID := uuid.New()
	_, err := env.pool.Exec(ctx, `
		INSERT INTO sso_providers (
			id, tenant_id, name, slug, provider_type, enabled, 
			issuer, client_id, client_secret, scopes, created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		providerID, env.tenantID, "Tenant Isolation Test", "tenant-isolation", "oidc",
		true, "https://isolation.example.com", "isolation-client", "isolation-secret",
		[]string{"openid"}, env.adminUserID, env.adminUserID,
	)
	require.NoError(t, err)

	// Create a second tenant
	tr := trepo.New(env.pool)
	tenant2ID := uuid.New()
	err = tr.Create(ctx, tenant2ID, "tenant-2-"+tenant2ID.String(), nil)
	require.NoError(t, err)

	// ============================================================
	// Test: Cannot access provider from different tenant via service
	// ============================================================
	t.Run("Service_Cross_Tenant_Access_Denied", func(t *testing.T) {
		// Try to get provider using wrong tenant ID
		_, err := env.ssoService.GetProvider(ctx, tenant2ID, providerID)
		assert.Error(t, err, "Should not be able to access provider from different tenant")
	})

	// ============================================================
	// Test: List only shows providers for the tenant
	// ============================================================
	t.Run("List_Only_Shows_Tenant_Providers", func(t *testing.T) {
		// List providers for tenant 2 (should be empty)
		providers, err := env.ssoService.ListProviders(ctx, tenant2ID, 100, 0)
		require.NoError(t, err)
		assert.Empty(t, providers, "Tenant 2 should have no providers")

		// List providers for original tenant (should have our provider)
		providers, err = env.ssoService.ListProviders(ctx, env.tenantID, 100, 0)
		require.NoError(t, err)
		assert.NotEmpty(t, providers, "Original tenant should have providers")

		found := false
		for _, p := range providers {
			if p.ID == providerID {
				found = true
				break
			}
		}
		assert.True(t, found, "Provider should be in original tenant's list")
	})
}

// TestProviderUpdate_UpdatedByTracking tests that UpdatedBy is properly tracked
func TestProviderUpdate_UpdatedByTracking(t *testing.T) {
	env := setupProviderTestEnv(t)
	defer env.cleanup()

	ctx := context.Background()

	// Create provider directly in database (OIDC requires issuer and client_id)
	providerID := uuid.New()
	_, err := env.pool.Exec(ctx, `
		INSERT INTO sso_providers (
			id, tenant_id, name, slug, provider_type, enabled, 
			issuer, client_id, client_secret, scopes, created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		providerID, env.tenantID, "UpdatedBy Tracking Test", "updatedby-test", "oidc",
		true, "https://updatedby.example.com", "updatedby-client", "updatedby-secret",
		[]string{"openid"}, env.adminUserID, env.adminUserID,
	)
	require.NoError(t, err)

	// Wait a moment to ensure timestamp difference
	time.Sleep(100 * time.Millisecond)

	// Update via HTTP
	updateBody := map[string]interface{}{
		"name": "Updated Name for Tracking",
	}

	body, _ := json.Marshal(updateBody)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/sso/providers/"+providerID.String(), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+env.adminToken)
	rec := httptest.NewRecorder()

	env.echo.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	// Fetch updated provider
	updated, err := env.ssoService.GetProvider(ctx, env.tenantID, providerID)
	require.NoError(t, err)

	// Verify UpdatedBy is set to the admin user
	assert.Equal(t, env.adminUserID, updated.UpdatedBy, "UpdatedBy should be set to admin user ID")

	t.Logf("Final UpdatedBy: %s", updated.UpdatedBy)
}
