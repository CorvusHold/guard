package controller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTenantOnboardingIntegration(t *testing.T) {
	suite := setupTestSuite(t)
	defer suite.cleanup()

	t.Run("complete tenant onboarding flow", func(t *testing.T) {
		// Step 1: Create tenant
		tenantName := fmt.Sprintf("Test Company %d", time.Now().Unix())
		tenant := createTenantRequest{
			Name: tenantName,
		}

		tenantBody, _ := json.Marshal(tenant)
		req := httptest.NewRequest("POST", "/tenants", bytes.NewBuffer(tenantBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+suite.adminToken)

		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusCreated, w.Code)

		var tenantResp createTenantResponse
		err := json.Unmarshal(w.Body.Bytes(), &tenantResp)
		require.NoError(t, err)
		require.NotEmpty(t, tenantResp.ID)
		assert.Equal(t, tenantName, tenantResp.Name)
		assert.True(t, tenantResp.IsActive)

		tenantID := tenantResp.ID

		// Step 2: Create admin user for tenant
		adminEmail := fmt.Sprintf("admin_%d@example.com", time.Now().Unix())
		signupReq := passwordSignupRequest{
			Email:     adminEmail,
			Password:  "SecurePass123!",
			FirstName: "Admin",
			LastName:  "User",
		}

		signupBody, _ := json.Marshal(signupReq)
		req = httptest.NewRequest("POST", "/v1/auth/password/signup", bytes.NewBuffer(signupBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Tenant-ID", tenantID)

		w = httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusCreated, w.Code)

		var signupResp passwordSignupResponse
		err = json.Unmarshal(w.Body.Bytes(), &signupResp)
		require.NoError(t, err)
		require.NotEmpty(t, signupResp.UserID)
		assert.Equal(t, adminEmail, signupResp.Email)

		userID := signupResp.UserID

		// Step 3: Enable MFA for admin user
		mfaReq := map[string]interface{}{
			"user_id": userID,
		}

		mfaBody, _ := json.Marshal(mfaReq)
		req = httptest.NewRequest("POST", fmt.Sprintf("/v1/admin/users/%s/mfa/enable", userID), bytes.NewBuffer(mfaBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+suite.adminToken)
		req.Header.Set("X-Tenant-ID", tenantID)

		w = httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		// Step 4: Configure tenant settings
		settings := map[string]interface{}{
			"auth_access_token_ttl":    "30m",
			"auth_refresh_token_ttl":   "720h",
			"app_cors_allowed_origins": "https://app.testcompany.com,https://admin.testcompany.com",
			"sso_provider":             "workos",
			"sso_workos_client_id":     "client_test123",
			"sso_workos_client_secret": "wk_test_secret",
			"email_provider":           "smtp",
			"email_smtp_host":          "smtp.gmail.com",
			"email_smtp_port":          "587",
			"email_smtp_from":          "Test Company <noreply@testcompany.com>",
		}

		settingsBody, _ := json.Marshal(settings)
		req = httptest.NewRequest("PUT", fmt.Sprintf("/v1/tenants/%s/settings", tenantID), bytes.NewBuffer(settingsBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+suite.adminToken)
		req.Header.Set("X-Tenant-ID", tenantID)

		w = httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		// Step 5: Verify tenant configuration
		req = httptest.NewRequest("GET", fmt.Sprintf("/tenants/%s", tenantID), nil)
		req.Header.Set("Authorization", "Bearer "+suite.adminToken)

		w = httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		var getTenantResp getTenantResponse
		err = json.Unmarshal(w.Body.Bytes(), &getTenantResp)
		require.NoError(t, err)
		assert.Equal(t, tenantID, getTenantResp.ID)
		assert.Equal(t, tenantName, getTenantResp.Name)
		assert.True(t, getTenantResp.IsActive)

		// Step 6: Verify tenant settings
		req = httptest.NewRequest("GET", fmt.Sprintf("/v1/tenants/%s/settings", tenantID), nil)
		req.Header.Set("Authorization", "Bearer "+suite.adminToken)
		req.Header.Set("X-Tenant-ID", tenantID)

		w = httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		var settingsResp getSettingsResponse
		err = json.Unmarshal(w.Body.Bytes(), &settingsResp)
		require.NoError(t, err)
		assert.Equal(t, "30m", settingsResp.Settings["auth_access_token_ttl"])
		assert.Equal(t, "workos", settingsResp.Settings["sso_provider"])
		assert.Equal(t, "client_test123", settingsResp.Settings["sso_workos_client_id"])

		// Step 7: Verify admin user can authenticate
		loginReq := passwordLoginRequest{
			Email:    adminEmail,
			Password: "SecurePass123!",
		}

		loginBody, _ := json.Marshal(loginReq)
		req = httptest.NewRequest("POST", "/v1/auth/password/login", bytes.NewBuffer(loginBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Tenant-ID", tenantID)

		w = httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		// Should return 202 (MFA required) since we enabled MFA
		require.Equal(t, http.StatusAccepted, w.Code)

		var loginResp passwordLoginResponse
		err = json.Unmarshal(w.Body.Bytes(), &loginResp)
		require.NoError(t, err)
		assert.Equal(t, "mfa_required", loginResp.Status)
		assert.NotEmpty(t, loginResp.SessionID)
	})

	t.Run("tenant settings management", func(t *testing.T) {
		// Create test tenant
		tenantID := suite.createTestTenant(t, "Settings Test Tenant")

		// Test getting empty settings
		req := httptest.NewRequest("GET", fmt.Sprintf("/v1/tenants/%s/settings", tenantID), nil)
		req.Header.Set("Authorization", "Bearer "+suite.adminToken)
		req.Header.Set("X-Tenant-ID", tenantID)

		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		var settingsResp getSettingsResponse
		err := json.Unmarshal(w.Body.Bytes(), &settingsResp)
		require.NoError(t, err)

		// Test updating settings
		settings := map[string]interface{}{
			"auth_access_token_ttl":    "15m",
			"auth_refresh_token_ttl":   "168h",
			"app_cors_allowed_origins": "https://app.example.com",
			"sso_provider":             "none",
			"email_provider":           "brevo",
			"email_brevo_api_key":      "xkeysib-test-key",
			"email_brevo_sender":       "noreply@example.com",
		}

		settingsBody, _ := json.Marshal(settings)
		req = httptest.NewRequest("PUT", fmt.Sprintf("/v1/tenants/%s/settings", tenantID), bytes.NewBuffer(settingsBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+suite.adminToken)
		req.Header.Set("X-Tenant-ID", tenantID)

		w = httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		// Verify settings were updated
		req = httptest.NewRequest("GET", fmt.Sprintf("/v1/tenants/%s/settings", tenantID), nil)
		req.Header.Set("Authorization", "Bearer "+suite.adminToken)
		req.Header.Set("X-Tenant-ID", tenantID)

		w = httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		err = json.Unmarshal(w.Body.Bytes(), &settingsResp)
		require.NoError(t, err)
		assert.Equal(t, "15m", settingsResp.Settings["auth_access_token_ttl"])
		assert.Equal(t, "168h", settingsResp.Settings["auth_refresh_token_ttl"])
		assert.Equal(t, "brevo", settingsResp.Settings["email_provider"])
		assert.Equal(t, "xkeysib-test-key", settingsResp.Settings["email_brevo_api_key"])

		// Test partial settings update
		partialSettings := map[string]interface{}{
			"auth_access_token_ttl": "45m",
			"sso_provider":          "workos",
		}

		partialBody, _ := json.Marshal(partialSettings)
		req = httptest.NewRequest("PUT", fmt.Sprintf("/v1/tenants/%s/settings", tenantID), bytes.NewBuffer(partialBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+suite.adminToken)
		req.Header.Set("X-Tenant-ID", tenantID)

		w = httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		// Verify partial update worked and other settings preserved
		req = httptest.NewRequest("GET", fmt.Sprintf("/v1/tenants/%s/settings", tenantID), nil)
		req.Header.Set("Authorization", "Bearer "+suite.adminToken)
		req.Header.Set("X-Tenant-ID", tenantID)

		w = httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		err = json.Unmarshal(w.Body.Bytes(), &settingsResp)
		require.NoError(t, err)
		assert.Equal(t, "45m", settingsResp.Settings["auth_access_token_ttl"])
		assert.Equal(t, "workos", settingsResp.Settings["sso_provider"])
		assert.Equal(t, "168h", settingsResp.Settings["auth_refresh_token_ttl"]) // Preserved
		assert.Equal(t, "brevo", settingsResp.Settings["email_provider"])        // Preserved
	})

	t.Run("tenant user management", func(t *testing.T) {
		// Create test tenant
		tenantID := suite.createTestTenant(t, "User Management Test Tenant")

		// Create multiple users
		users := []struct {
			email     string
			firstName string
			lastName  string
			enableMFA bool
		}{
			{"user1@example.com", "John", "Doe", true},
			{"user2@example.com", "Jane", "Smith", false},
			{"user3@example.com", "Bob", "Johnson", true},
		}

		var userIDs []string

		for _, user := range users {
			// Create user
			signupReq := passwordSignupRequest{
				Email:     user.email,
				Password:  "SecurePass123!",
				FirstName: user.firstName,
				LastName:  user.lastName,
			}

			signupBody, _ := json.Marshal(signupReq)
			req := httptest.NewRequest("POST", "/v1/auth/password/signup", bytes.NewBuffer(signupBody))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Tenant-ID", tenantID)

			w := httptest.NewRecorder()
			suite.router.ServeHTTP(w, req)

			require.Equal(t, http.StatusCreated, w.Code)

			var signupResp passwordSignupResponse
			err := json.Unmarshal(w.Body.Bytes(), &signupResp)
			require.NoError(t, err)

			userIDs = append(userIDs, signupResp.UserID)

			// Enable MFA if requested
			if user.enableMFA {
				mfaReq := map[string]interface{}{
					"user_id": signupResp.UserID,
				}

				mfaBody, _ := json.Marshal(mfaReq)
				req = httptest.NewRequest("POST", fmt.Sprintf("/v1/admin/users/%s/mfa/enable", signupResp.UserID), bytes.NewBuffer(mfaBody))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer "+suite.adminToken)
				req.Header.Set("X-Tenant-ID", tenantID)

				w = httptest.NewRecorder()
				suite.router.ServeHTTP(w, req)

				require.Equal(t, http.StatusOK, w.Code)
			}
		}

		// List users and verify count
		req := httptest.NewRequest("GET", "/v1/admin/users", nil)
		req.Header.Set("Authorization", "Bearer "+suite.adminToken)
		req.Header.Set("X-Tenant-ID", tenantID)

		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		var usersResp listUsersResponse
		err := json.Unmarshal(w.Body.Bytes(), &usersResp)
		require.NoError(t, err)
		assert.Len(t, usersResp.Users, 3)

		// Verify user details
		for i, user := range usersResp.Users {
			assert.Equal(t, users[i].email, user.Email)
			assert.Equal(t, users[i].firstName, user.FirstName)
			assert.Equal(t, users[i].lastName, user.LastName)
			assert.Equal(t, users[i].enableMFA, user.MFAEnabled)
		}

		// Test getting individual user
		req = httptest.NewRequest("GET", fmt.Sprintf("/v1/admin/users/%s", userIDs[0]), nil)
		req.Header.Set("Authorization", "Bearer "+suite.adminToken)
		req.Header.Set("X-Tenant-ID", tenantID)

		w = httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		var userResp getUserResponse
		err = json.Unmarshal(w.Body.Bytes(), &userResp)
		require.NoError(t, err)
		assert.Equal(t, userIDs[0], userResp.ID)
		assert.Equal(t, users[0].email, userResp.Email)
		assert.True(t, userResp.MFAEnabled)
	})

	t.Run("tenant authentication flows", func(t *testing.T) {
		// Create test tenant with specific settings
		tenantID := suite.createTestTenant(t, "Auth Flow Test Tenant")

		// Configure tenant with specific auth settings
		settings := map[string]interface{}{
			"auth_access_token_ttl":       "5m",
			"auth_refresh_token_ttl":      "24h",
			"auth_ratelimit_login_limit":  "5",
			"auth_ratelimit_login_window": "1m",
		}

		settingsBody, _ := json.Marshal(settings)
		req := httptest.NewRequest("PUT", fmt.Sprintf("/v1/tenants/%s/settings", tenantID), bytes.NewBuffer(settingsBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+suite.adminToken)
		req.Header.Set("X-Tenant-ID", tenantID)

		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		// Create test user
		userEmail := fmt.Sprintf("authtest_%d@example.com", time.Now().Unix())
		signupReq := passwordSignupRequest{
			Email:     userEmail,
			Password:  "SecurePass123!",
			FirstName: "Auth",
			LastName:  "Test",
		}

		signupBody, _ := json.Marshal(signupReq)
		req = httptest.NewRequest("POST", "/v1/auth/password/signup", bytes.NewBuffer(signupBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Tenant-ID", tenantID)

		w = httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusCreated, w.Code)

		// Test password login
		loginReq := passwordLoginRequest{
			Email:    userEmail,
			Password: "SecurePass123!",
		}

		loginBody, _ := json.Marshal(loginReq)
		req = httptest.NewRequest("POST", "/v1/auth/password/login", bytes.NewBuffer(loginBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Tenant-ID", tenantID)

		w = httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		var loginResp passwordLoginResponse
		err := json.Unmarshal(w.Body.Bytes(), &loginResp)
		require.NoError(t, err)
		assert.Equal(t, "success", loginResp.Status)
		assert.NotEmpty(t, loginResp.AccessToken)
		assert.NotEmpty(t, loginResp.RefreshToken)

		// Test token introspection
		req = httptest.NewRequest("GET", "/v1/auth/me", nil)
		req.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)
		req.Header.Set("X-Tenant-ID", tenantID)

		w = httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		var meResp introspectionResponse
		err = json.Unmarshal(w.Body.Bytes(), &meResp)
		require.NoError(t, err)
		assert.Equal(t, userEmail, meResp.Email)
		assert.Equal(t, tenantID, meResp.TenantID)

		// Test token refresh
		refreshReq := refreshTokenRequest{
			RefreshToken: loginResp.RefreshToken,
		}

		refreshBody, _ := json.Marshal(refreshReq)
		req = httptest.NewRequest("POST", "/v1/auth/refresh", bytes.NewBuffer(refreshBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Tenant-ID", tenantID)

		w = httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		var refreshResp refreshTokenResponse
		err = json.Unmarshal(w.Body.Bytes(), &refreshResp)
		require.NoError(t, err)
		assert.NotEmpty(t, refreshResp.AccessToken)
		assert.NotEmpty(t, refreshResp.RefreshToken)
		assert.NotEqual(t, loginResp.AccessToken, refreshResp.AccessToken)
	})
}

// Helper method to create test tenant
func (s *testSuite) createTestTenant(t *testing.T, name string) string {
	tenant := createTenantRequest{
		Name: name,
	}

	tenantBody, _ := json.Marshal(tenant)
	req := httptest.NewRequest("POST", "/tenants", bytes.NewBuffer(tenantBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.adminToken)

	w := httptest.NewRecorder()
	s.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusCreated, w.Code)

	var tenantResp createTenantResponse
	err := json.Unmarshal(w.Body.Bytes(), &tenantResp)
	require.NoError(t, err)

	return tenantResp.ID
}

// Request/Response types for tenant onboarding
type createTenantRequest struct {
	Name string `json:"name"`
}

type createTenantResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type getTenantResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type getSettingsResponse struct {
	Settings map[string]interface{} `json:"settings"`
}

type listUsersResponse struct {
	Users []userResponse `json:"users"`
}

type userResponse struct {
	ID         string    `json:"id"`
	Email      string    `json:"email"`
	FirstName  string    `json:"first_name"`
	LastName   string    `json:"last_name"`
	IsActive   bool      `json:"is_active"`
	MFAEnabled bool      `json:"mfa_enabled"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type getUserResponse struct {
	ID         string    `json:"id"`
	Email      string    `json:"email"`
	FirstName  string    `json:"first_name"`
	LastName   string    `json:"last_name"`
	IsActive   bool      `json:"is_active"`
	MFAEnabled bool      `json:"mfa_enabled"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}
