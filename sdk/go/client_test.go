package guard_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	guard "github.com/corvusHold/guard/sdk/go"
)

type testTokenStore struct {
	access  string
	refresh string
}

func (s *testTokenStore) Get(_ context.Context) (string, string) {
	return s.access, s.refresh
}

func (s *testTokenStore) Set(_ context.Context, access, refresh string) error {
	s.access = access
	s.refresh = refresh
	return nil
}

func (s *testTokenStore) Clear(_ context.Context) error {
	s.access = ""
	s.refresh = ""
	return nil
}

// TestPasswordSignup tests the PasswordSignup method
func TestPasswordSignup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auth/password/signup" {
			t.Errorf("Expected path /api/v1/auth/password/signup, got %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST method, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{
			"access_token":  "test-access",
			"refresh_token": "test-refresh",
		})
	}))
	defer server.Close()

	client, err := guard.NewGuardClient(server.URL, guard.WithTenantID("test-tenant"))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	req := guard.ControllerSignupReq{
		Email:    "test@example.com",
		Password: "password123",
	}

	tokens, err := client.PasswordSignup(context.Background(), req)
	if err != nil {
		t.Fatalf("PasswordSignup failed: %v", err)
	}

	if tokens == nil {
		t.Fatal("Expected tokens, got nil")
	}
	if tokens.AccessToken == nil || *tokens.AccessToken != "test-access" {
		t.Errorf("Expected access token 'test-access', got %v", tokens.AccessToken)
	}
}

// TestEmailDiscover tests the EmailDiscover method
func TestEmailDiscover(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Email discovery moved to login-options
		if r.URL.Path != "/api/v1/auth/login-options" {
			t.Errorf("Expected path /api/v1/auth/login-options, got %s", r.URL.Path)
		}
		email := r.URL.Query().Get("email")
		if email != "test@example.com" {
			t.Errorf("Expected email query param 'test@example.com', got %s", email)
		}
		w.Header().Set("Content-Type", "application/json")

		found := true
		tenantID := "tenant-123"
		tenantName := "Test Tenant"

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"tenant_id":          tenantID,
			"tenant_name":        tenantName,
			"user_exists":        found,
			"password_enabled":   true,
			"domain_matched_sso": nil,
			"sso_required":       false,
			"sso_providers":      []map[string]string{},
		})
	}))
	defer server.Close()

	client, err := guard.NewGuardClient(server.URL)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	result, err := client.EmailDiscover(context.Background(), "test@example.com", nil)
	if err != nil {
		t.Fatalf("EmailDiscover failed: %v", err)
	}

	if !result.Found {
		t.Error("Expected Found to be true")
	}
	if !result.HasTenant {
		t.Error("Expected HasTenant to be true")
	}
	if result.TenantID == nil || *result.TenantID != "tenant-123" {
		t.Errorf("Expected tenant ID 'tenant-123', got %v", result.TenantID)
	}
}

// TestDiscoverTenants tests the DiscoverTenants method
func TestDiscoverTenants(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// DiscoverTenants uses the tenants list endpoint with a search query
		if r.URL.Path != "/api/v1/tenants" {
			t.Errorf("Expected path /api/v1/tenants, got %s", r.URL.Path)
		}

		q := r.URL.Query().Get("q")
		if q != "test@example.com" {
			t.Errorf("Expected q query param 'test@example.com', got %s", q)
		}
		w.Header().Set("Content-Type", "application/json")

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"items": []map[string]string{
				{"id": "tenant-1", "name": "Tenant One"},
				{"id": "tenant-2", "name": "Tenant Two"},
			},
		})
	}))
	defer server.Close()

	client, err := guard.NewGuardClient(server.URL)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	tenants, err := client.DiscoverTenants(context.Background(), "test@example.com")
	if err != nil {
		t.Fatalf("DiscoverTenants failed: %v", err)
	}

	if len(tenants) != 2 {
		t.Fatalf("Expected 2 tenants, got %d", len(tenants))
	}
	if tenants[0].ID != "tenant-1" {
		t.Errorf("Expected first tenant ID 'tenant-1', got %s", tenants[0].ID)
	}
}

// TestCreateTenant tests the CreateTenant method
func TestCreateTenant(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/tenants" {
			t.Errorf("Expected path /api/v1/tenants, got %s", r.URL.Path)
		}

		var req map[string]string
		json.NewDecoder(r.Body).Decode(&req)

		if req["name"] != "New Tenant" {
			t.Errorf("Expected name 'New Tenant', got %s", req["name"])
		}
		w.Header().Set("Content-Type", "application/json")

		isActive := true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":        "tenant-new",
			"name":      "New Tenant",
			"is_active": isActive,
		})
	}))
	defer server.Close()

	client, err := guard.NewGuardClient(server.URL)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	req := guard.CreateTenantRequest{
		Name: "New Tenant",
	}

	tenant, err := client.CreateTenant(context.Background(), req)
	if err != nil {
		t.Fatalf("CreateTenant failed: %v", err)
	}

	if tenant.ID != "tenant-new" {
		t.Errorf("Expected tenant ID 'tenant-new', got %s", tenant.ID)
	}
	if tenant.Name != "New Tenant" {
		t.Errorf("Expected name 'New Tenant', got %s", tenant.Name)
	}
}

// TestListUsers tests the ListUsers method
func TestListUsers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auth/admin/users" {
			t.Errorf("Expected path /api/v1/auth/admin/users, got %s", r.URL.Path)
		}

		tenantID := r.URL.Query().Get("tenant_id")
		if tenantID != "test-tenant" {
			t.Errorf("Expected tenant_id query param 'test-tenant', got %s", tenantID)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"users": []map[string]interface{}{
				{
					"id":             "user-1",
					"email_verified": true,
					"is_active":      true,
					"first_name":     "John",
					"last_name":      "Doe",
					"roles":          []string{"admin"},
				},
			},
		})
	}))
	defer server.Close()

	client, err := guard.NewGuardClient(server.URL, guard.WithTenantID("test-tenant"))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	users, err := client.ListUsers(context.Background(), "")
	if err != nil {
		t.Fatalf("ListUsers failed: %v", err)
	}

	if len(users) != 1 {
		t.Fatalf("Expected 1 user, got %d", len(users))
	}
	if users[0].FirstName != "John" {
		t.Errorf("Expected first_name 'John', got %s", users[0].FirstName)
	}
}

// TestListPermissions tests the ListPermissions method
func TestListPermissions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auth/admin/rbac/permissions" {
			t.Errorf("Expected path /api/v1/auth/admin/rbac/permissions, got %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		desc := "Read permission"
		json.NewEncoder(w).Encode(map[string]interface{}{
			"permissions": []map[string]interface{}{
				{
					"key":         "resource:read",
					"name":        "Read Resource",
					"description": desc,
				},
			},
		})
	}))
	defer server.Close()

	client, err := guard.NewGuardClient(server.URL)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	perms, err := client.ListPermissions(context.Background())
	if err != nil {
		t.Fatalf("ListPermissions failed: %v", err)
	}

	if len(perms) != 1 {
		t.Fatalf("Expected 1 permission, got %d", len(perms))
	}
	if perms[0].Key != "resource:read" {
		t.Errorf("Expected key 'resource:read', got %s", perms[0].Key)
	}
}

// TestCreateRole tests the CreateRole method
func TestCreateRole(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auth/admin/rbac/roles" {
			t.Errorf("Expected path /api/v1/auth/admin/rbac/roles, got %s", r.URL.Path)
		}

		var req map[string]interface{}
		json.NewDecoder(r.Body).Decode(&req)

		if req["name"] != "Editor" {
			t.Errorf("Expected name 'Editor', got %v", req["name"])
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":        "role-123",
			"tenant_id": "test-tenant",
			"name":      "Editor",
		})
	}))
	defer server.Close()

	client, err := guard.NewGuardClient(server.URL, guard.WithTenantID("test-tenant"))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	req := guard.CreateRoleRequest{
		Name:        "Editor",
		Description: "Can edit resources",
	}

	role, err := client.CreateRole(context.Background(), req)
	if err != nil {
		t.Fatalf("CreateRole failed: %v", err)
	}

	if role.ID != "role-123" {
		t.Errorf("Expected role ID 'role-123', got %s", role.ID)
	}
}

// TestListFGAGroups tests the ListFGAGroups method
func TestListFGAGroups(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auth/admin/fga/groups" {
			t.Errorf("Expected path /api/v1/auth/admin/fga/groups, got %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		desc := "Engineering team"
		json.NewEncoder(w).Encode(map[string]interface{}{
			"groups": []map[string]interface{}{
				{
					"id":          "group-1",
					"tenant_id":   "test-tenant",
					"name":        "Engineers",
					"description": desc,
				},
			},
		})
	}))
	defer server.Close()

	client, err := guard.NewGuardClient(server.URL, guard.WithTenantID("test-tenant"))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	groups, err := client.ListFGAGroups(context.Background(), "")
	if err != nil {
		t.Fatalf("ListFGAGroups failed: %v", err)
	}

	if len(groups) != 1 {
		t.Fatalf("Expected 1 group, got %d", len(groups))
	}
	if groups[0].Name != "Engineers" {
		t.Errorf("Expected name 'Engineers', got %s", groups[0].Name)
	}
}

// TestCreateFGAACLTuple tests the CreateFGAACLTuple method
func TestCreateFGAACLTuple(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auth/admin/fga/acl/tuples" {
			t.Errorf("Expected path /api/v1/auth/admin/fga/acl/tuples, got %s", r.URL.Path)
		}

		var req map[string]interface{}
		json.NewDecoder(r.Body).Decode(&req)

		if req["subject_type"] != "user" {
			t.Errorf("Expected subject_type 'user', got %v", req["subject_type"])
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":             "tuple-123",
			"tenant_id":      "test-tenant",
			"subject_type":   "user",
			"subject_id":     "user-1",
			"permission_key": "resource:read",
			"object_type":    "document",
		})
	}))
	defer server.Close()

	client, err := guard.NewGuardClient(server.URL, guard.WithTenantID("test-tenant"))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	req := guard.CreateFGAACLTupleRequest{
		SubjectType:   "user",
		SubjectID:     "user-1",
		PermissionKey: "resource:read",
		ObjectType:    "document",
	}

	tuple, err := client.CreateFGAACLTuple(context.Background(), req)
	if err != nil {
		t.Fatalf("CreateFGAACLTuple failed: %v", err)
	}

	if tuple.ID != "tuple-123" {
		t.Errorf("Expected tuple ID 'tuple-123', got %s", tuple.ID)
	}
}

// TestFGAAuthorize tests the FGAAuthorize method
func TestFGAAuthorize(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auth/authorize" {
			t.Errorf("Expected path /api/v1/auth/authorize, got %s", r.URL.Path)
		}

		allowed := true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"allowed": allowed,
		})
	}))
	defer server.Close()

	client, err := guard.NewGuardClient(server.URL, guard.WithTenantID("test-tenant"))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	subjectID := "user-1"
	req := guard.FGAAuthorizeRequest{
		SubjectType:   "user",
		SubjectID:     &subjectID,
		PermissionKey: "resource:read",
		ObjectType:    "document",
	}

	result, err := client.FGAAuthorize(context.Background(), req)
	if err != nil {
		t.Fatalf("FGAAuthorize failed: %v", err)
	}

	if !result.Allowed {
		t.Error("Expected Allowed to be true")
	}
}

// TestListSSOProviders tests the ListSSOProviders method
func TestListSSOProviders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sso/providers" {
			t.Errorf("Expected path /api/v1/sso/providers, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")

		enabled := true
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"providers": []map[string]interface{}{
				{
					"id":            "provider-1",
					"tenant_id":     "test-tenant",
					"name":          "Google SSO",
					"slug":          "google",
					"provider_type": "oidc",
					"enabled":       enabled,
				},
			},
		})
	}))
	defer server.Close()

	client, err := guard.NewGuardClient(server.URL, guard.WithTenantID("test-tenant"))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	providers, err := client.ListSSOProviders(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListSSOProviders failed: %v", err)
	}

	if len(providers) != 1 {
		t.Fatalf("Expected 1 provider, got %d", len(providers))
	}
	if providers[0].Name != "Google SSO" {
		t.Errorf("Expected name 'Google SSO', got %s", providers[0].Name)
	}
	if providers[0].ProviderType != "oidc" {
		t.Errorf("Expected provider_type 'oidc', got %s", providers[0].ProviderType)
	}
}

// TestSSOPortalSession tests the SSOPortalSession helper
func TestSSOPortalSession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sso/portal/session" {
			t.Errorf("Expected path /api/v1/sso/portal/session, got %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST, got %s", r.Method)
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["token"] != "tok-1" {
			t.Errorf("Expected token 'tok-1', got %s", body["token"])
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"tenant_id":       "tenant-1",
			"provider_slug":   "oidc-main",
			"portal_token_id": "pt-1",
		})
	}))
	defer server.Close()

	client, err := guard.NewGuardClient(server.URL)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ps, err := client.SSOPortalSession(context.Background(), "tok-1")
	if err != nil {
		t.Fatalf("SSOPortalSession failed: %v", err)
	}
	if ps.TenantID != "tenant-1" || ps.ProviderSlug != "oidc-main" || ps.PortalTokenID != "pt-1" {
		t.Fatalf("unexpected portal session: %+v", ps)
	}
}

// TestSSOPortalProvider tests the SSOPortalProvider helper
func TestSSOPortalProvider(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sso/portal/provider" {
			t.Errorf("Expected path /api/v1/sso/portal/provider, got %s", r.URL.Path)
		}
		if r.Method != http.MethodGet {
			t.Errorf("Expected GET, got %s", r.Method)
		}
		if r.Header.Get("X-Portal-Token") != "tok-1" {
			t.Errorf("Expected X-Portal-Token 'tok-1', got %s", r.Header.Get("X-Portal-Token"))
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id":            "provider-1",
			"tenant_id":     "tenant-1",
			"name":          "OIDC Main",
			"slug":          "oidc-main",
			"provider_type": "oidc",
			"enabled":       true,
		})
	}))
	defer server.Close()

	client, err := guard.NewGuardClient(server.URL)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	provider, err := client.SSOPortalProvider(context.Background(), "tok-1")
	if err != nil {
		t.Fatalf("SSOPortalProvider failed: %v", err)
	}
	if provider.ID != "provider-1" || provider.Slug != "oidc-main" {
		t.Fatalf("unexpected provider: %+v", provider)
	}
}

// TestCookieMode tests that cookie mode sets the correct header
func TestCookieMode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authMode := r.Header.Get("X-Auth-Mode")
		if authMode != "cookie" {
			t.Errorf("Expected X-Auth-Mode header to be 'cookie', got %s", authMode)
		}

		// Should not have Authorization header in cookie mode
		if auth := r.Header.Get("Authorization"); auth != "" {
			t.Errorf("Expected no Authorization header in cookie mode, got %s", auth)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":    "user-123",
			"email": "test@example.com",
		})
	}))
	defer server.Close()

	client, err := guard.NewGuardClient(
		server.URL,
		guard.WithAuthMode(guard.AuthModeCookie),
		guard.WithCookieJar(),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	_, err = client.Me(context.Background())
	if err != nil {
		t.Fatalf("Me request failed: %v", err)
	}
}

func TestBuildOAuth2AuthorizeURL(t *testing.T) {
	client, err := guard.NewGuardClient("https://guard.example.com")
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	prompt := "login"
	loginHint := "user@example.com"

	authorizeURL, err := client.BuildOAuth2AuthorizeURL(guard.OAuth2AuthorizeParams{
		ClientID:      "client-123",
		RedirectURI:   "http://localhost:3004/callback",
		Scope:         "openid profile email offline_access",
		State:         "state-123",
		Nonce:         "nonce-123",
		CodeChallenge: "challenge-123",
		Prompt:        &prompt,
		LoginHint:     &loginHint,
	})
	if err != nil {
		t.Fatalf("BuildOAuth2AuthorizeURL failed: %v", err)
	}

	parsed, err := url.Parse(authorizeURL)
	if err != nil {
		t.Fatalf("failed to parse URL: %v", err)
	}
	if parsed.Path != "/oauth/authorize" {
		t.Fatalf("expected /oauth/authorize path, got %s", parsed.Path)
	}
	q := parsed.Query()
	if q.Get("client_id") != "client-123" {
		t.Fatalf("expected client_id=client-123, got %s", q.Get("client_id"))
	}
	if q.Get("redirect_uri") != "http://localhost:3004/callback" {
		t.Fatalf("unexpected redirect_uri: %s", q.Get("redirect_uri"))
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Fatalf("expected default code_challenge_method S256, got %s", q.Get("code_challenge_method"))
	}
	if q.Get("prompt") != "login" {
		t.Fatalf("expected prompt=login, got %s", q.Get("prompt"))
	}
	if q.Get("login_hint") != "user@example.com" {
		t.Fatalf("expected login_hint=user@example.com, got %s", q.Get("login_hint"))
	}
}

func TestExchangeOAuth2Code(t *testing.T) {
	store := &testTokenStore{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			if r.Method != http.MethodPost {
				t.Fatalf("expected POST, got %s", r.Method)
			}
			if err := r.ParseForm(); err != nil {
				t.Fatalf("ParseForm failed: %v", err)
			}
			if r.Form.Get("grant_type") != "authorization_code" {
				t.Fatalf("expected authorization_code grant, got %s", r.Form.Get("grant_type"))
			}
			if r.Form.Get("code") != "code-123" {
				t.Fatalf("expected code-123, got %s", r.Form.Get("code"))
			}
			if r.Form.Get("code_verifier") != "verifier-123" {
				t.Fatalf("expected verifier-123, got %s", r.Form.Get("code_verifier"))
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "oauth-access-1",
				"refresh_token": "oauth-refresh-1",
				"token_type":    "Bearer",
			})
		case "/api/v1/auth/me":
			if got := r.Header.Get("Authorization"); got != "Bearer oauth-access-1" {
				t.Fatalf("expected Authorization Bearer oauth-access-1, got %s", got)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "u1", "email": "user@example.com"})
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client, err := guard.NewGuardClient(server.URL, guard.WithTokenStore(store))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	resp, err := client.ExchangeOAuth2Code(context.Background(), guard.OAuth2CodeExchangeRequest{
		Code:         "code-123",
		CodeVerifier: "verifier-123",
		RedirectURI:  "http://localhost:3004/callback",
	})
	if err != nil {
		t.Fatalf("ExchangeOAuth2Code failed: %v", err)
	}
	if resp.AccessToken == nil || *resp.AccessToken != "oauth-access-1" {
		t.Fatalf("unexpected access token: %+v", resp.AccessToken)
	}
	if store.access != "oauth-access-1" || store.refresh != "oauth-refresh-1" {
		t.Fatalf("tokens not persisted in store, got access=%s refresh=%s", store.access, store.refresh)
	}

	if _, err := client.Me(context.Background()); err != nil {
		t.Fatalf("Me after exchange failed: %v", err)
	}
}

func TestOAuth2RefreshUsesTokenStore(t *testing.T) {
	store := &testTokenStore{refresh: "refresh-from-store"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/token" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm failed: %v", err)
		}
		if r.Form.Get("grant_type") != "refresh_token" {
			t.Fatalf("expected refresh_token grant, got %s", r.Form.Get("grant_type"))
		}
		if r.Form.Get("refresh_token") != "refresh-from-store" {
			t.Fatalf("expected refresh-from-store, got %s", r.Form.Get("refresh_token"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "oauth-access-2",
			"refresh_token": "oauth-refresh-2",
			"token_type":    "Bearer",
		})
	}))
	defer server.Close()

	client, err := guard.NewGuardClient(server.URL, guard.WithTokenStore(store))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	resp, err := client.OAuth2Refresh(context.Background(), guard.OAuth2RefreshRequest{})
	if err != nil {
		t.Fatalf("OAuth2Refresh failed: %v", err)
	}
	if resp.AccessToken == nil || *resp.AccessToken != "oauth-access-2" {
		t.Fatalf("unexpected access token: %+v", resp.AccessToken)
	}
	if store.access != "oauth-access-2" || store.refresh != "oauth-refresh-2" {
		t.Fatalf("tokens not persisted, got access=%s refresh=%s", store.access, store.refresh)
	}
}

func TestOAuth2RefreshWithoutStoredToken(t *testing.T) {
	client, err := guard.NewGuardClient("http://localhost:8080")
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	_, err = client.OAuth2Refresh(context.Background(), guard.OAuth2RefreshRequest{})
	if err == nil || !strings.Contains(err.Error(), "no refresh token available") {
		t.Fatalf("expected no refresh token error, got %v", err)
	}
}

// TestBearerMode tests that bearer mode sets the Authorization header
func TestBearerMode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// For login endpoint, don't expect auth header
		if strings.Contains(r.URL.Path, "login") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{
				"access_token":  "test-access-token",
				"refresh_token": "test-refresh-token",
			})
			return
		}

		// For other endpoints, expect Authorization header
		auth := r.Header.Get("Authorization")
		if auth == "" {
			t.Error("Expected Authorization header in bearer mode")
		}
		if !strings.HasPrefix(auth, "Bearer ") {
			t.Errorf("Expected Authorization header to start with 'Bearer ', got %s", auth)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":    "user-123",
			"email": "test@example.com",
		})
	}))
	defer server.Close()

	client, err := guard.NewGuardClient(
		server.URL,
		guard.WithAuthMode(guard.AuthModeBearer),
		guard.WithTenantID("test-tenant"),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// First login to get tokens
	loginReq := guard.ControllerLoginReq{
		Email:    "test@example.com",
		Password: "password123",
	}
	_, _, err = client.PasswordLogin(context.Background(), loginReq)
	if err != nil {
		t.Fatalf("PasswordLogin failed: %v", err)
	}

	// Now make an authenticated request
	_, err = client.Me(context.Background())
	if err != nil {
		t.Fatalf("Me request failed: %v", err)
	}
}
