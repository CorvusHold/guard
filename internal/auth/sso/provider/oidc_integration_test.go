//go:build integration

package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
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
	mu          sync.Mutex
	authCodes   map[string]*authCodeEntry
}

type authCodeEntry struct {
	nonce               string
	codeChallenge       string
	codeChallengeMethod string
	redirectURI         string
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
		authCodes:   make(map[string]*authCodeEntry),
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
	query := r.URL.Query()
	state := query.Get("state")
	redirectURI := query.Get("redirect_uri")
	nonce := query.Get("nonce")
	codeChallenge := query.Get("code_challenge")
	codeChallengeMethod := query.Get("code_challenge_method")

	// Generate a mock authorization code
	code := uuid.NewString()
	m.saveAuthCode(code, &authCodeEntry{
		nonce:               nonce,
		codeChallenge:       codeChallenge,
		codeChallengeMethod: codeChallengeMethod,
		redirectURI:         redirectURI,
	})

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
	codeVerifier := r.FormValue("code_verifier")
	if codeVerifier == "" {
		http.Error(w, "missing code_verifier", http.StatusBadRequest)
		return
	}
	entry, ok := m.consumeAuthCode(code)
	if !ok {
		http.Error(w, "invalid authorization code", http.StatusBadRequest)
		return
	}
	if entry.redirectURI != "" {
		if redirectURI := r.FormValue("redirect_uri"); redirectURI != "" && redirectURI != entry.redirectURI {
			http.Error(w, "redirect_uri mismatch", http.StatusBadRequest)
			return
		}
	}
	if entry.codeChallengeMethod == "S256" {
		expected := pkceChallengeFromVerifier(codeVerifier)
		if expected != entry.codeChallenge {
			http.Error(w, "invalid code_verifier", http.StatusBadRequest)
			return
		}
	}

	nonce := entry.nonce

	// Create ID token
	idToken, err := m.createIDToken(nonce, map[string]interface{}{
		"email":          "test@example.com",
		"email_verified": true,
		"given_name":     "Test",
		"family_name":    "User",
		"name":           "Test User",
		"picture":        "https://example.com/photo.jpg",
		"locale":         "en-US",
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

func (m *mockOIDCServer) saveAuthCode(code string, entry *authCodeEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.authCodes[code] = entry
}

func (m *mockOIDCServer) consumeAuthCode(code string) (*authCodeEntry, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.authCodes[code]
	if ok {
		delete(m.authCodes, code)
	}
	return entry, ok
}

func pkceChallengeFromVerifier(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
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

func TestOIDCProvider_Callback_HappyPath(t *testing.T) {
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

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(startResult.AuthorizationURL)
	if err != nil {
		t.Fatalf("GET authorize error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d, want 302", resp.StatusCode)
	}
	location := resp.Header.Get("Location")
	if location == "" {
		t.Fatal("authorize response missing Location header")
	}
	callbackURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("failed to parse callback location: %v", err)
	}
	callbackQuery := callbackURL.Query()
	code := callbackQuery.Get("code")
	if code == "" {
		t.Fatal("callback missing code")
	}
	stateFromCallback := callbackQuery.Get("state")
	if stateFromCallback != startResult.State {
		t.Fatalf("state mismatch: expected %s, got %s", startResult.State, stateFromCallback)
	}

	profile, err := provider.Callback(ctx, domain.CallbackRequest{
		Code:         code,
		State:        startResult.State,
		Nonce:        startResult.Nonce,
		PKCEVerifier: startResult.PKCEVerifier,
		RedirectURL:  mockServer.redirectURI,
	})
	if err != nil {
		t.Fatalf("Callback() error = %v", err)
	}
	if profile == nil {
		t.Fatal("Callback() returned nil profile")
	}
	if profile.IDToken == "" {
		t.Fatal("profile.IDToken is empty")
	}
	if profile.AccessToken != "mock-access-token" {
		t.Fatalf("profile.AccessToken = %s, want mock-access-token", profile.AccessToken)
	}
	if profile.Subject != "test-user-123" {
		t.Fatalf("Subject = %s, want test-user-123", profile.Subject)
	}
	if profile.Email != "test@example.com" {
		t.Fatalf("Email = %s, want test@example.com", profile.Email)
	}
	if !profile.EmailVerified {
		t.Fatal("EmailVerified = false, want true")
	}
	if profile.FirstName != "Test" || profile.LastName != "User" {
		t.Fatalf("name claims mismatch: first=%s last=%s", profile.FirstName, profile.LastName)
	}
	if profile.Name != "Test User" {
		t.Fatalf("Name = %s, want Test User", profile.Name)
	}
	if profile.Picture != "https://example.com/photo.jpg" {
		t.Fatalf("Picture = %s, want https://example.com/photo.jpg", profile.Picture)
	}
	if profile.Locale != "en-US" {
		t.Fatalf("Locale = %s, want en-US", profile.Locale)
	}
	if len(profile.Groups) != 2 || profile.Groups[0] != "users" || profile.Groups[1] != "developers" {
		t.Fatalf("Groups = %v, want [users developers]", profile.Groups)
	}
	if profile.RawAttributes == nil {
		t.Fatal("RawAttributes is nil")
	}
	if nonceClaim, ok := profile.RawAttributes["nonce"].(string); !ok || nonceClaim != startResult.Nonce {
		t.Fatalf("nonce claim = %v, want %s", nonceClaim, startResult.Nonce)
	}
	if profile.ExpiresAt == nil {
		t.Fatal("ExpiresAt is nil")
	}
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
