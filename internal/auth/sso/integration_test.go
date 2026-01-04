//go:build integration
// +build integration

package sso_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/corvusHold/guard/internal/auth/domain"
	authrepo "github.com/corvusHold/guard/internal/auth/repository"
	authsvc "github.com/corvusHold/guard/internal/auth/service"
	"github.com/corvusHold/guard/internal/auth/sso/controller"
	"github.com/corvusHold/guard/internal/auth/sso/service"
	"github.com/corvusHold/guard/internal/config"
	srepo "github.com/corvusHold/guard/internal/settings/repository"
	ssvc "github.com/corvusHold/guard/internal/settings/service"
	trepo "github.com/corvusHold/guard/internal/tenants/repository"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	goredis "github.com/redis/go-redis/v9"
)

// TestEnv holds the test environment dependencies
type TestEnv struct {
	pool          *pgxpool.Pool
	redis         *goredis.Client
	cfg           config.Config
	authService   domain.Service
	ssoService    *service.SSOService
	ssoController *controller.SSOController
	echo          *echo.Echo
	tenantID      uuid.UUID
	cleanup       func()
}

// setupTestEnvironment creates a complete test environment with database, Redis, and services
func setupTestEnvironment(t *testing.T) *TestEnv {
	t.Helper()

	// Check environment variables
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("skipping integration test: DATABASE_URL not set")
	}

	ctx := context.Background()

	// Connect to database
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatalf("failed to connect to database: %v", err)
	}

	// Connect to Redis
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}
	redisClient := goredis.NewClient(&goredis.Options{
		Addr: redisAddr,
		DB:   15, // Use separate DB for tests
	})
	if err := redisClient.Ping(ctx).Err(); err != nil {
		pool.Close()
		t.Fatalf("failed to connect to Redis: %v", err)
	}

	// Create test tenant
	tr := trepo.New(pool)
	tenantID := uuid.New()
	tenantName := "sso-itest-" + tenantID.String()
	if err := tr.Create(ctx, tenantID, tenantName); err != nil {
		pool.Close()
		redisClient.Close()
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Load config
	cfg, err := config.Load()
	if err != nil {
		pool.Close()
		redisClient.Close()
		t.Fatalf("failed to load config: %v", err)
	}

	// Override base URL for testing
	cfg.PublicBaseURL = "http://localhost:8080"

	// Wire up services
	authRepo := authrepo.New(pool)
	settingsRepo := srepo.New(pool)
	settingsService := ssvc.New(settingsRepo)

	authService := authsvc.New(authRepo, cfg, settingsService)
	ssoService := service.New(pool, redisClient, cfg.PublicBaseURL)

	// Create controller
	ssoController := controller.New(ssoService, authService)

	// Setup Echo
	e := echo.New()

	// Register SSO routes
	ssoController.Register(e)

	env := &TestEnv{
		pool:          pool,
		redis:         redisClient,
		cfg:           cfg,
		authService:   authService,
		ssoService:    ssoService,
		ssoController: ssoController,
		echo:          e,
		tenantID:      tenantID,
		cleanup: func() {
			// Cleanup test data
			redisClient.FlushDB(ctx)
			redisClient.Close()
			pool.Close()
		},
	}

	return env
}

// mockOIDCServer creates a complete mock OIDC provider
type mockOIDCServer struct {
	server     *httptest.Server
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	issuer     string
	clientID   string
	mu         sync.Mutex
	codeNonce  map[string]string
}

func newMockOIDCServer(t *testing.T) *mockOIDCServer {
	t.Helper()

	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	mock := &mockOIDCServer{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		clientID:   "test-client-id",
		codeNonce:  make(map[string]string),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", mock.handleDiscovery)
	mux.HandleFunc("/jwks", mock.handleJWKS)
	mux.HandleFunc("/authorize", mock.handleAuthorize)
	mux.HandleFunc("/token", mock.handleToken)
	mux.HandleFunc("/userinfo", mock.handleUserInfo)

	mock.server = httptest.NewServer(mux)
	mock.issuer = mock.server.URL

	return mock
}

func (m *mockOIDCServer) Close() {
	m.server.Close()
}

func (m *mockOIDCServer) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	discovery := map[string]interface{}{
		"issuer":                                m.issuer,
		"authorization_endpoint":                m.issuer + "/authorize",
		"token_endpoint":                        m.issuer + "/token",
		"userinfo_endpoint":                     m.issuer + "/userinfo",
		"jwks_uri":                              m.issuer + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(discovery)
}

func (m *mockOIDCServer) handleJWKS(w http.ResponseWriter, r *http.Request) {
	jwk := jose.JSONWebKey{
		Key:       m.publicKey,
		KeyID:     "test-key-id",
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{jwk},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

func (m *mockOIDCServer) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	state := query.Get("state")
	redirectURI := query.Get("redirect_uri")
	nonce := query.Get("nonce")

	// Generate mock authorization code
	code := base64.URLEncoding.EncodeToString([]byte("mock-auth-code-" + state))

	m.mu.Lock()
	m.codeNonce[code] = nonce
	m.mu.Unlock()

	redirectURL, _ := url.Parse(redirectURI)
	q := redirectURL.Query()
	q.Set("code", code)
	q.Set("state", state)
	redirectURL.RawQuery = q.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

func (m *mockOIDCServer) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	code := r.FormValue("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	m.mu.Lock()
	nonce := m.codeNonce[code]
	delete(m.codeNonce, code)
	m.mu.Unlock()

	// Create ID token
	idToken, err := m.createIDToken(nonce, map[string]interface{}{
		"email":          "oidc-test@example.com",
		"email_verified": true,
		"given_name":     "OIDC",
		"family_name":    "Test",
		"name":           "OIDC Test",
	})
	if err != nil {
		http.Error(w, "failed to create ID token", http.StatusInternalServerError)
		return
	}

	// Create access token
	accessToken := base64.URLEncoding.EncodeToString([]byte("mock-access-token"))

	response := map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (m *mockOIDCServer) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	userInfo := map[string]interface{}{
		"sub":            "oidc-user-123",
		"email":          "oidc-test@example.com",
		"email_verified": true,
		"given_name":     "OIDC",
		"family_name":    "Test",
		"name":           "OIDC Test",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
}

func (m *mockOIDCServer) createIDToken(nonce string, claims map[string]interface{}) (string, error) {
	now := time.Now()

	allClaims := map[string]interface{}{
		"iss":   m.issuer,
		"sub":   "oidc-user-123",
		"aud":   m.clientID,
		"exp":   now.Add(1 * time.Hour).Unix(),
		"iat":   now.Unix(),
		"nonce": nonce,
	}

	// Merge custom claims
	for k, v := range claims {
		allClaims[k] = v
	}

	// Create signer
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: m.privateKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test-key-id"),
	)
	if err != nil {
		return "", err
	}

	// Build and sign token
	builder := jwt.Signed(signer).Claims(allClaims)
	token, err := builder.Serialize()
	if err != nil {
		return "", err
	}

	return token, nil
}

// TestOIDCFlow_EndToEnd tests the complete OIDC SSO flow
func TestOIDCFlow_EndToEnd(t *testing.T) {
	env := setupTestEnvironment(t)
	defer env.cleanup()

	ctx := context.Background()

	// 1. Start mock OIDC server
	mockIdP := newMockOIDCServer(t)
	defer mockIdP.Close()

	// 2. Create OIDC provider in database
	providerConfig, err := env.ssoService.CreateProvider(ctx, service.CreateProviderRequest{
		TenantID:              env.tenantID,
		Name:                  "Test OIDC Provider",
		Slug:                  "test-oidc",
		ProviderType:          "oidc",
		Enabled:               true,
		AllowSignup:           true,
		TrustEmailVerified:    true,
		Domains:               []string{"example.com"},
		Issuer:                mockIdP.issuer,
		AuthorizationEndpoint: mockIdP.issuer + "/authorize",
		TokenEndpoint:         mockIdP.issuer + "/token",
		UserinfoEndpoint:      mockIdP.issuer + "/userinfo",
		JWKSUri:               mockIdP.issuer + "/jwks",
		ClientID:              mockIdP.clientID,
		ClientSecret:          "test-secret",
		Scopes:                []string{"openid", "profile", "email"},
		ResponseType:          "code",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	t.Logf("Created provider: %s", providerConfig.ID)

	// 3. Initiate SSO flow (GET /api/v1/auth/sso/t/:tenant_id/test-oidc/login)
	initiateURL := fmt.Sprintf("/api/v1/auth/sso/t/%s/test-oidc/login?redirect_url=https://app.example.com/dashboard", env.tenantID)
	req := httptest.NewRequest(http.MethodGet, initiateURL, nil)
	rec := httptest.NewRecorder()

	env.echo.ServeHTTP(rec, req)

	// Should redirect to IdP authorization URL
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", rec.Code, rec.Body.String())
	}

	authURL := rec.Header().Get("Location")
	if authURL == "" {
		t.Fatal("expected Location header with authorization URL")
	}

	t.Logf("Authorization URL: %s", authURL)

	// 4. Extract state from authorization URL
	parsedURL, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("failed to parse authorization URL: %v", err)
	}

	stateToken := parsedURL.Query().Get("state")
	if stateToken == "" {
		t.Fatal("expected state parameter in authorization URL")
	}

	t.Logf("State token: %s", stateToken)

	// 5. Simulate user authorization at IdP (mock IdP will return code)
	// Call the mock authorize endpoint to get the code
	mockAuthReq := httptest.NewRequest(http.MethodGet, authURL, nil)
	mockAuthRec := httptest.NewRecorder()
	mockIdP.server.Config.Handler.ServeHTTP(mockAuthRec, mockAuthReq)

	if mockAuthRec.Code != http.StatusFound {
		t.Fatalf("expected 302 from mock IdP, got %d", mockAuthRec.Code)
	}

	callbackURL := mockAuthRec.Header().Get("Location")
	parsedCallback, err := url.Parse(callbackURL)
	if err != nil {
		t.Fatalf("failed to parse callback URL: %v", err)
	}

	code := parsedCallback.Query().Get("code")
	returnedState := parsedCallback.Query().Get("state")

	if code == "" {
		t.Fatal("expected code in callback URL")
	}
	if returnedState != stateToken {
		t.Fatalf("state mismatch: expected %s, got %s", stateToken, returnedState)
	}

	t.Logf("Authorization code: %s", code)

	// 6. Call SSO callback endpoint using the actual callback URL from mock IdP
	// This validates that the service uses the correct versioned format
	callbackReq := httptest.NewRequest(http.MethodGet, parsedCallback.RequestURI(), nil)
	callbackRec := httptest.NewRecorder()

	env.echo.ServeHTTP(callbackRec, callbackReq)

	// With redirect_url set during initiation, the callback should redirect to the app
	if callbackRec.Code != http.StatusFound {
		t.Fatalf("expected 302 from callback, got %d: %s", callbackRec.Code, callbackRec.Body.String())
	}

	location := callbackRec.Header().Get("Location")
	if location == "" {
		t.Fatal("expected Location header from callback redirect")
	}

	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("failed to parse callback redirect location: %v", err)
	}

	// Tokens are returned in the URL fragment to avoid leaking them in logs/referrers
	fragmentValues, err := url.ParseQuery(redirectURL.Fragment)
	if err != nil {
		t.Fatalf("failed to parse fragment query: %v", err)
	}

	accessTokens := fragmentValues["access_token"]
	if len(accessTokens) == 0 || accessTokens[0] == "" {
		t.Fatalf("expected access_token in redirect fragment, got: %v", fragmentValues)
	}
	accessToken := accessTokens[0]

	refreshTokens := fragmentValues["refresh_token"]
	if len(refreshTokens) == 0 || refreshTokens[0] == "" {
		t.Fatalf("expected refresh_token in redirect fragment, got: %v", fragmentValues)
	}
	refreshToken := refreshTokens[0]

	t.Logf("Access token: %s...", accessToken[:20])
	t.Logf("Refresh token: %s...", refreshToken[:20])

	// 8. Verify user was created
	introspection, err := env.authService.Introspect(ctx, accessToken)
	if err != nil {
		t.Fatalf("failed to introspect token: %v", err)
	}

	if !introspection.Active {
		t.Fatal("expected token to be active")
	}

	if introspection.Email != "oidc-test@example.com" {
		t.Fatalf("expected email oidc-test@example.com, got %s", introspection.Email)
	}

	t.Logf("User created: %s (email: %s)", introspection.UserID, introspection.Email)

	// 9. Verify session was created (refresh token stored)
	sessions, err := env.authService.ListUserSessions(ctx, introspection.UserID, env.tenantID)
	if err != nil {
		t.Fatalf("failed to list sessions: %v", err)
	}

	if len(sessions) == 0 {
		t.Fatal("expected at least one session")
	}

	t.Logf("Sessions: %d", len(sessions))

	// 10. Verify refresh token works
	refreshResp, err := env.authService.Refresh(ctx, domain.RefreshInput{
		RefreshToken: refreshToken,
		UserAgent:    "test-agent",
		IP:           "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("failed to refresh token: %v", err)
	}

	if refreshResp.AccessToken == "" {
		t.Fatal("expected new access token from refresh")
	}

	t.Log("✓ OIDC end-to-end flow completed successfully")
}

// TestSSOFlow_InvalidState tests that invalid state tokens are rejected
func TestSSOFlow_InvalidState(t *testing.T) {
	env := setupTestEnvironment(t)
	defer env.cleanup()

	ctx := context.Background()

	mockIdP := newMockOIDCServer(t)
	defer mockIdP.Close()

	// Create provider
	_, err := env.ssoService.CreateProvider(ctx, service.CreateProviderRequest{
		TenantID:              env.tenantID,
		Name:                  "Test OIDC Provider",
		Slug:                  "test-oidc",
		ProviderType:          "oidc",
		Enabled:               true,
		AllowSignup:           true,
		TrustEmailVerified:    true,
		Issuer:                mockIdP.issuer,
		AuthorizationEndpoint: mockIdP.issuer + "/authorize",
		TokenEndpoint:         mockIdP.issuer + "/token",
		UserinfoEndpoint:      mockIdP.issuer + "/userinfo",
		JWKSUri:               mockIdP.issuer + "/jwks",
		ClientID:              mockIdP.clientID,
		ClientSecret:          "test-secret",
		Scopes:                []string{"openid", "profile", "email"},
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	// Initiate SSO flow to get the actual callback URL format
	initiateURL := fmt.Sprintf("/api/v1/auth/sso/t/%s/test-oidc/login", env.tenantID)
	initReq := httptest.NewRequest(http.MethodGet, initiateURL, nil)
	initRec := httptest.NewRecorder()
	env.echo.ServeHTTP(initRec, initRec)

	if initRec.Code != http.StatusFound {
		t.Fatalf("expected 302 from initiation, got %d: %s", initRec.Code, initRec.Body.String())
	}

	authURL := initRec.Header().Get("Location")
	parsedAuthURL, _ := url.Parse(authURL)

	// Call mock IdP authorize to get the callback URL with state
	mockAuthReq := httptest.NewRequest(http.MethodGet, authURL, nil)
	mockAuthRec := httptest.NewRecorder()
	mockIdP.server.Config.Handler.ServeHTTP(mockAuthRec, mockAuthReq)

	if mockAuthRec.Code != http.StatusFound {
		t.Fatalf("expected 302 from mock IdP, got %d", mockAuthRec.Code)
	}

	callbackURL := mockAuthRec.Header().Get("Location")
	parsedCallback, _ := url.Parse(callbackURL)

	// Replace the state with an invalid one
	q := parsedCallback.Query()
	q.Set("state", "invalid-state")
	parsedCallback.RawQuery = q.Encode()

	// Try callback with invalid state using the actual callback URL format
	req := httptest.NewRequest(http.MethodGet, parsedCallback.RequestURI(), nil)
	rec := httptest.NewRecorder()

	env.echo.ServeHTTP(rec, req)

	// Should fail with 400
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}

	var errResp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &errResp)

	if errMsg, ok := errResp["error"].(string); !ok || !strings.Contains(errMsg, "state") {
		t.Fatalf("expected error about state, got: %v", errResp)
	}

	t.Log("✓ Invalid state rejected correctly")
}

// TestSSOFlow_DisabledProvider tests that disabled providers cannot be used
func TestSSOFlow_DisabledProvider(t *testing.T) {
	env := setupTestEnvironment(t)
	defer env.cleanup()

	ctx := context.Background()

	mockIdP := newMockOIDCServer(t)
	defer mockIdP.Close()

	// Create disabled provider
	_, err := env.ssoService.CreateProvider(ctx, service.CreateProviderRequest{
		TenantID:              env.tenantID,
		Name:                  "Disabled Provider",
		Slug:                  "disabled-oidc",
		ProviderType:          "oidc",
		Enabled:               false, // Disabled
		AllowSignup:           true,
		TrustEmailVerified:    true,
		Issuer:                mockIdP.issuer,
		AuthorizationEndpoint: mockIdP.issuer + "/authorize",
		TokenEndpoint:         mockIdP.issuer + "/token",
		UserinfoEndpoint:      mockIdP.issuer + "/userinfo",
		JWKSUri:               mockIdP.issuer + "/jwks",
		ClientID:              mockIdP.clientID,
		ClientSecret:          "test-secret",
		Scopes:                []string{"openid", "profile", "email"},
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	// Try to initiate SSO with disabled provider using tenant-scoped URL
	initiateURL := fmt.Sprintf("/api/v1/auth/sso/t/%s/disabled-oidc/login", env.tenantID)
	req := httptest.NewRequest(http.MethodGet, initiateURL, nil)
	rec := httptest.NewRecorder()

	env.echo.ServeHTTP(rec, req)

	// Should fail with 400
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}

	var errResp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &errResp)

	if errMsg, ok := errResp["error"].(string); !ok || !strings.Contains(errMsg, "disabled") {
		t.Fatalf("expected error about disabled provider, got: %v", errResp)
	}

	t.Log("✓ Disabled provider rejected correctly")
}

// TestSSOFlow_SignupDisabled tests that signup can be disabled
func TestSSOFlow_SignupDisabled(t *testing.T) {
	env := setupTestEnvironment(t)
	defer env.cleanup()

	ctx := context.Background()

	mockIdP := newMockOIDCServer(t)
	defer mockIdP.Close()

	// Create provider with signup disabled
	providerConfig, err := env.ssoService.CreateProvider(ctx, service.CreateProviderRequest{
		TenantID:              env.tenantID,
		Name:                  "No Signup Provider",
		Slug:                  "no-signup-oidc",
		ProviderType:          "oidc",
		Enabled:               true,
		AllowSignup:           false, // Signup disabled
		TrustEmailVerified:    true,
		Issuer:                mockIdP.issuer,
		AuthorizationEndpoint: mockIdP.issuer + "/authorize",
		TokenEndpoint:         mockIdP.issuer + "/token",
		UserinfoEndpoint:      mockIdP.issuer + "/userinfo",
		JWKSUri:               mockIdP.issuer + "/jwks",
		ClientID:              mockIdP.clientID,
		ClientSecret:          "test-secret",
		Scopes:                []string{"openid", "profile", "email"},
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	// Initiate flow using tenant-scoped URL
	initiateURL := fmt.Sprintf("/api/v1/auth/sso/t/%s/no-signup-oidc/login", env.tenantID)
	req := httptest.NewRequest(http.MethodGet, initiateURL, nil)
	rec := httptest.NewRecorder()

	env.echo.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}

	authURL := rec.Header().Get("Location")
	parsedURL, _ := url.Parse(authURL)
	stateToken := parsedURL.Query().Get("state")

	// Get authorization code from mock IdP
	mockAuthReq := httptest.NewRequest(http.MethodGet, authURL, nil)
	mockAuthRec := httptest.NewRecorder()
	mockIdP.server.Config.Handler.ServeHTTP(mockAuthRec, mockAuthReq)

	callbackURL := mockAuthRec.Header().Get("Location")
	parsedCallback, _ := url.Parse(callbackURL)
	code := parsedCallback.Query().Get("code")

	// Try callback using the actual callback URL from mock IdP
	// This validates that the service uses the correct versioned format
	// (should fail since user doesn't exist and signup is disabled)
	callbackReq := httptest.NewRequest(http.MethodGet, parsedCallback.RequestURI(), nil)
	callbackRec := httptest.NewRecorder()

	env.echo.ServeHTTP(callbackRec, callbackReq)

	// Should fail with 400
	if callbackRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", callbackRec.Code, callbackRec.Body.String())
	}

	var errResp map[string]interface{}
	json.Unmarshal(callbackRec.Body.Bytes(), &errResp)

	if errMsg, ok := errResp["error"].(string); !ok || !strings.Contains(strings.ToLower(errMsg), "signup") {
		t.Fatalf("expected error about signup disabled, got: %v", errResp)
	}

	t.Log("✓ Signup disabled works correctly")
	t.Logf("Provider config: enabled=%v, allow_signup=%v", providerConfig.Enabled, providerConfig.AllowSignup)
}

// TestSAMLFlow_EndToEnd tests the complete SAML SSO flow
func TestSAMLFlow_EndToEnd(t *testing.T) {
	env := setupTestEnvironment(t)
	defer env.cleanup()

	ctx := context.Background()

	// Create SAML provider with minimal configuration
	// In real implementation, we would need proper SAML IdP metadata
	// For now, we'll create the provider and test the flow as much as possible

	// Minimal IdP metadata XML for testing
	minimalIdPMetadata := `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`

	_, err := env.ssoService.CreateProvider(ctx, service.CreateProviderRequest{
		TenantID:             env.tenantID,
		Name:                 "Test SAML Provider",
		Slug:                 "test-saml",
		ProviderType:         "saml",
		Enabled:              true,
		AllowSignup:          true,
		TrustEmailVerified:   true,
		Domains:              []string{"example.com"},
		EntityID:             "https://guard.example.com/saml",
		ACSUrl:               fmt.Sprintf("/api/v1/auth/sso/t/%s/test-saml/callback", env.tenantID),
		IdPMetadataXML:       minimalIdPMetadata, // Required for SAML provider validation
		IdPEntityID:          "https://idp.example.com",
		IdPSSOUrl:            "https://idp.example.com/sso",
		WantAssertionsSigned: false, // For testing without real signatures
		WantResponseSigned:   false,
		SignRequests:         false,
	})
	if err != nil {
		t.Fatalf("failed to create SAML provider: %v", err)
	}

	// Test SAML metadata endpoint using tenant-scoped URL
	metadataURL := fmt.Sprintf("/api/v1/auth/sso/t/%s/test-saml/metadata", env.tenantID)
	req := httptest.NewRequest(http.MethodGet, metadataURL, nil)
	rec := httptest.NewRecorder()

	env.echo.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for metadata, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify it returns XML
	contentType := rec.Header().Get("Content-Type")
	if !strings.Contains(contentType, "xml") {
		t.Logf("Warning: expected XML content type, got: %s", contentType)
	}

	metadata := rec.Body.String()
	if !strings.Contains(metadata, "EntityDescriptor") {
		t.Fatalf("expected SAML metadata with EntityDescriptor, got: %s", metadata)
	}

	t.Log("✓ SAML metadata endpoint works")

	// Test initiation using tenant-scoped URL
	initiateURL := fmt.Sprintf("/api/v1/auth/sso/t/%s/test-saml/login", env.tenantID)
	initReq := httptest.NewRequest(http.MethodGet, initiateURL, nil)
	initRec := httptest.NewRecorder()

	env.echo.ServeHTTP(initRec, initReq)

	// Should redirect to IdP
	if initRec.Code != http.StatusFound {
		t.Fatalf("expected 302 for SAML initiation, got %d: %s", initRec.Code, initRec.Body.String())
	}

	location := initRec.Header().Get("Location")
	if location == "" {
		t.Fatal("expected Location header for SAML redirect")
	}

	t.Logf("SAML SSO URL: %s", location)
	t.Log("✓ SAML initiation works")

	// Note: Full SAML flow testing would require generating valid signed SAML responses
	// which is complex and requires certificate management. The provider-level tests
	// cover this in detail. Here we're testing the integration layer.
}
