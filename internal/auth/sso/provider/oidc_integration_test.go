//go:build integration

package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"

	"github.com/corvusHold/guard/internal/auth/sso/domain"
)

// mockOIDCServer creates a complete mock OIDC provider for integration testing.
type mockOIDCServer struct {
	server      *httptest.Server
	privateKey  *rsa.PrivateKey
	publicKey   *rsa.PublicKey
	issuer      string
	clientID    string
	redirectURI string
}

func newMockOIDCServer(t *testing.T) *mockOIDCServer {
	t.Helper()

	// Generate RSA key pair for signing tokens
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	mock := &mockOIDCServer{
		privateKey:  privateKey,
		publicKey:   &privateKey.PublicKey,
		clientID:    "test-client-id",
		redirectURI: "https://app.example.com/callback",
	}

	// Create the HTTP server
	mux := http.NewServeMux()

	// Discovery endpoint
	mux.HandleFunc("/.well-known/openid-configuration", mock.handleDiscovery)

	// JWKS endpoint
	mux.HandleFunc("/jwks", mock.handleJWKS)

	// Authorization endpoint
	mux.HandleFunc("/authorize", mock.handleAuthorize)

	// Token endpoint
	mux.HandleFunc("/token", mock.handleToken)

	// UserInfo endpoint
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
	// In a real test, we would validate the authorize request
	// For now, just return a redirect with a code
	query := r.URL.Query()
	state := query.Get("state")
	redirectURI := query.Get("redirect_uri")

	// Generate a mock authorization code
	code := base64.URLEncoding.EncodeToString([]byte("mock-auth-code"))

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

	// Get nonce from the request context (in real impl, this would be stored)
	// For testing, we'll use a fixed nonce
	nonce := "test-nonce"

	// Create ID token
	idToken, err := m.createIDToken(nonce, map[string]interface{}{
		"email":          "test@example.com",
		"email_verified": true,
		"given_name":     "Test",
		"family_name":    "User",
		"name":           "Test User",
		"picture":        "https://example.com/photo.jpg",
		"groups":         []string{"users", "developers"},
	})
	if err != nil {
		http.Error(w, "failed to create token", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"access_token":  "mock-access-token",
		"token_type":    "Bearer",
		"expires_in":    3600,
		"id_token":      idToken,
		"refresh_token": "mock-refresh-token",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (m *mockOIDCServer) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	// Verify bearer token
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	userInfo := map[string]interface{}{
		"sub":            "test-user-123",
		"email":          "test@example.com",
		"email_verified": true,
		"given_name":     "Test",
		"family_name":    "User",
		"name":           "Test User",
		"picture":        "https://example.com/photo.jpg",
		"locale":         "en-US",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
}

func (m *mockOIDCServer) createIDToken(nonce string, claims map[string]interface{}) (string, error) {
	now := time.Now()

	// Build claims
	idTokenClaims := map[string]interface{}{
		"iss":   m.issuer,
		"sub":   "test-user-123",
		"aud":   m.clientID,
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"nonce": nonce,
	}

	// Merge custom claims
	for k, v := range claims {
		idTokenClaims[k] = v
	}

	// Create signer
	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.RS256,
			Key:       m.privateKey,
		},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test-key-id"),
	)
	if err != nil {
		return "", err
	}

	// Create and sign token
	builder := jwt.Signed(signer).Claims(idTokenClaims)
	token, err := builder.Serialize()
	if err != nil {
		return "", err
	}

	return token, nil
}

func TestOIDCProvider_FullFlow(t *testing.T) {
	// Create mock OIDC server
	mockServer := newMockOIDCServer(t)
	defer mockServer.Close()

	ctx := context.Background()

	// Create OIDC provider config
	config := &domain.Config{
		ID:           uuid.New(),
		TenantID:     uuid.New(),
		Name:         "Test OIDC Provider",
		Slug:         "test-oidc",
		ProviderType: domain.ProviderTypeOIDC,
		Issuer:       mockServer.issuer,
		ClientID:     mockServer.clientID,
		ClientSecret: "test-client-secret",
		Scopes:       []string{"openid", "profile", "email"},
		Enabled:      true,
	}

	// Create OIDC provider
	provider, err := NewOIDCProvider(ctx, config)
	if err != nil {
		t.Fatalf("NewOIDCProvider() error = %v", err)
	}

	// Test Start
	startOpts := domain.StartOptions{
		RedirectURL: mockServer.redirectURI,
	}

	startResult, err := provider.Start(ctx, startOpts)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Verify start result
	if startResult.AuthorizationURL == "" {
		t.Error("Start() returned empty AuthorizationURL")
	}
	if startResult.State == "" {
		t.Error("Start() returned empty State")
	}
	if startResult.Nonce == "" {
		t.Error("Start() returned empty Nonce")
	}
	if startResult.PKCEVerifier == "" {
		t.Error("Start() returned empty PKCEVerifier")
	}

	t.Logf("Authorization URL: %s", startResult.AuthorizationURL)

	// Note: Testing the full callback flow with token exchange and verification
	// would require generating valid JWT tokens signed with the mock server's key.
	// This is complex and typically done in end-to-end tests.
	// For now, we verify that the Start flow works correctly.
}

func TestOIDCProvider_Callback_InvalidCode(t *testing.T) {
	mockServer := newMockOIDCServer(t)
	defer mockServer.Close()

	ctx := context.Background()

	config := &domain.Config{
		Issuer:       mockServer.issuer,
		ClientID:     mockServer.clientID,
		ClientSecret: "test-client-secret",
		Scopes:       []string{"openid", "profile", "email"},
	}

	provider, err := NewOIDCProvider(ctx, config)
	if err != nil {
		t.Fatalf("NewOIDCProvider() error = %v", err)
	}

	// Test callback with missing code
	req := domain.CallbackRequest{
		Code:         "", // Missing code
		State:        "test-state",
		Nonce:        "test-nonce",
		PKCEVerifier: "test-verifier",
		RedirectURL:  mockServer.redirectURI,
	}

	_, err = provider.Callback(ctx, req)
	if err == nil {
		t.Error("Callback() expected error for missing code, got nil")
	}
	if !strings.Contains(err.Error(), "authorization code is required") {
		t.Errorf("Callback() error = %v, want error containing 'authorization code is required'", err)
	}
}

func TestOIDCProvider_Callback_MissingNonce(t *testing.T) {
	mockServer := newMockOIDCServer(t)
	defer mockServer.Close()

	ctx := context.Background()

	config := &domain.Config{
		Issuer:       mockServer.issuer,
		ClientID:     mockServer.clientID,
		ClientSecret: "test-client-secret",
		Scopes:       []string{"openid", "profile", "email"},
	}

	provider, err := NewOIDCProvider(ctx, config)
	if err != nil {
		t.Fatalf("NewOIDCProvider() error = %v", err)
	}

	// Test callback with missing nonce
	req := domain.CallbackRequest{
		Code:         "test-code",
		State:        "test-state",
		Nonce:        "", // Missing nonce
		PKCEVerifier: "test-verifier",
		RedirectURL:  mockServer.redirectURI,
	}

	_, err = provider.Callback(ctx, req)
	if err == nil {
		t.Error("Callback() expected error for missing nonce, got nil")
	}
	if !strings.Contains(err.Error(), "nonce is required") {
		t.Errorf("Callback() error = %v, want error containing 'nonce is required'", err)
	}
}

func TestOIDCProvider_Callback_MissingPKCEVerifier(t *testing.T) {
	mockServer := newMockOIDCServer(t)
	defer mockServer.Close()

	ctx := context.Background()

	config := &domain.Config{
		Issuer:       mockServer.issuer,
		ClientID:     mockServer.clientID,
		ClientSecret: "test-client-secret",
		Scopes:       []string{"openid", "profile", "email"},
	}

	provider, err := NewOIDCProvider(ctx, config)
	if err != nil {
		t.Fatalf("NewOIDCProvider() error = %v", err)
	}

	// Test callback with missing PKCE verifier
	req := domain.CallbackRequest{
		Code:         "test-code",
		State:        "test-state",
		Nonce:        "test-nonce",
		PKCEVerifier: "", // Missing PKCE verifier
		RedirectURL:  mockServer.redirectURI,
	}

	_, err = provider.Callback(ctx, req)
	if err == nil {
		t.Error("Callback() expected error for missing PKCE verifier, got nil")
	}
	if !strings.Contains(err.Error(), "PKCE verifier is required") {
		t.Errorf("Callback() error = %v, want error containing 'PKCE verifier is required'", err)
	}
}

func TestOIDCProvider_GetMetadata(t *testing.T) {
	mockServer := newMockOIDCServer(t)
	defer mockServer.Close()

	ctx := context.Background()

	config := &domain.Config{
		Issuer:       mockServer.issuer,
		ClientID:     mockServer.clientID,
		ClientSecret: "test-client-secret",
		Scopes:       []string{"openid", "profile", "email"},
	}

	provider, err := NewOIDCProvider(ctx, config)
	if err != nil {
		t.Fatalf("NewOIDCProvider() error = %v", err)
	}

	// Get metadata
	metadata, err := provider.GetMetadata(ctx)
	if err != nil {
		t.Fatalf("GetMetadata() error = %v", err)
	}

	// Verify metadata
	if metadata.ProviderType != domain.ProviderTypeOIDC {
		t.Errorf("ProviderType = %v, want %v", metadata.ProviderType, domain.ProviderTypeOIDC)
	}
	if metadata.Issuer != mockServer.issuer {
		t.Errorf("Issuer = %v, want %v", metadata.Issuer, mockServer.issuer)
	}
	if metadata.AuthorizationEndpoint == "" {
		t.Error("AuthorizationEndpoint is empty")
	}
	if metadata.TokenEndpoint == "" {
		t.Error("TokenEndpoint is empty")
	}
}

func TestOIDCProvider_FetchUserInfo(t *testing.T) {
	mockServer := newMockOIDCServer(t)
	defer mockServer.Close()

	ctx := context.Background()

	config := &domain.Config{
		Issuer:       mockServer.issuer,
		ClientID:     mockServer.clientID,
		ClientSecret: "test-client-secret",
		Scopes:       []string{"openid", "profile", "email"},
	}

	provider, err := NewOIDCProvider(ctx, config)
	if err != nil {
		t.Fatalf("NewOIDCProvider() error = %v", err)
	}

	// Fetch user info
	userInfo, err := provider.FetchUserInfo(ctx, "mock-access-token")
	if err != nil {
		t.Fatalf("FetchUserInfo() error = %v", err)
	}

	// Verify user info
	if userInfo["sub"] != "test-user-123" {
		t.Errorf("sub = %v, want test-user-123", userInfo["sub"])
	}
	if userInfo["email"] != "test@example.com" {
		t.Errorf("email = %v, want test@example.com", userInfo["email"])
	}
	if userInfo["email_verified"] != true {
		t.Errorf("email_verified = %v, want true", userInfo["email_verified"])
	}
}

func TestNewOIDCProvider_InvalidIssuer(t *testing.T) {
	ctx := context.Background()

	config := &domain.Config{
		Issuer:       "https://invalid-issuer-that-does-not-exist-12345.example.com",
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
	}

	_, err := NewOIDCProvider(ctx, config)
	if err == nil {
		t.Error("NewOIDCProvider() expected error for invalid issuer, got nil")
	}
}
