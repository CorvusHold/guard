package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/corvusHold/guard/internal/auth/sso/domain"
)

func TestValidateOIDCConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *domain.Config
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
			errMsg:  "config is nil",
		},
		{
			name: "missing issuer",
			config: &domain.Config{
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
			},
			wantErr: true,
			errMsg:  "issuer is required",
		},
		{
			name: "missing client_id",
			config: &domain.Config{
				Issuer:       "https://issuer.example.com",
				ClientSecret: "test-client-secret",
			},
			wantErr: true,
			errMsg:  "client_id is required",
		},
		{
			name: "missing client_secret",
			config: &domain.Config{
				Issuer:   "https://issuer.example.com",
				ClientID: "test-client-id",
			},
			wantErr: true,
			errMsg:  "client_secret is required",
		},
		{
			name: "valid config",
			config: &domain.Config{
				Issuer:       "https://issuer.example.com",
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOIDCConfig(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateOIDCConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("validateOIDCConfig() error = %v, want error containing %q", err, tt.errMsg)
			}
		})
	}
}

func TestOIDCProvider_Type(t *testing.T) {
	provider := &OIDCProvider{
		config: &domain.Config{
			ProviderType: domain.ProviderTypeOIDC,
		},
	}

	if got := provider.Type(); got != domain.ProviderTypeOIDC {
		t.Errorf("Type() = %v, want %v", got, domain.ProviderTypeOIDC)
	}
}

func TestOIDCProvider_ValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *domain.Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: &domain.Config{
				Issuer:       "https://issuer.example.com",
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
			},
			wantErr: false,
		},
		{
			name: "invalid config - missing issuer",
			config: &domain.Config{
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &OIDCProvider{
				config: tt.config,
			}
			err := p.ValidateConfig()
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGenerateNonce(t *testing.T) {
	// Generate multiple nonces and verify they are unique
	nonces := make(map[string]bool)
	for i := 0; i < 100; i++ {
		nonce, err := generateNonce()
		if err != nil {
			t.Fatalf("generateNonce() error = %v", err)
		}
		if nonce == "" {
			t.Error("generateNonce() returned empty string")
		}
		if nonces[nonce] {
			t.Errorf("generateNonce() returned duplicate nonce: %s", nonce)
		}
		nonces[nonce] = true

		// Verify nonce is at least 32 bytes (256 bits) when base64 decoded
		// Base64 encoding of 32 bytes is 44 characters (with padding) or 43 (without)
		if len(nonce) < 43 {
			t.Errorf("generateNonce() returned nonce too short: %d characters", len(nonce))
		}
	}
}

func TestGenerateState(t *testing.T) {
	// Generate multiple states and verify they are unique
	states := make(map[string]bool)
	for i := 0; i < 100; i++ {
		state, err := generateState()
		if err != nil {
			t.Fatalf("generateState() error = %v", err)
		}
		if state == "" {
			t.Error("generateState() returned empty string")
		}
		if states[state] {
			t.Errorf("generateState() returned duplicate state: %s", state)
		}
		states[state] = true

		// Verify state is at least 32 bytes (256 bits) when base64 decoded
		if len(state) < 43 {
			t.Errorf("generateState() returned state too short: %d characters", len(state))
		}
	}
}

func TestGeneratePKCEVerifier(t *testing.T) {
	// Generate multiple verifiers and verify they are unique
	verifiers := make(map[string]bool)
	for i := 0; i < 100; i++ {
		verifier, err := generatePKCEVerifier()
		if err != nil {
			t.Fatalf("generatePKCEVerifier() error = %v", err)
		}
		if verifier == "" {
			t.Error("generatePKCEVerifier() returned empty string")
		}
		if verifiers[verifier] {
			t.Errorf("generatePKCEVerifier() returned duplicate verifier: %s", verifier)
		}
		verifiers[verifier] = true

		// PKCE verifier must be between 43 and 128 characters
		if len(verifier) < 43 || len(verifier) > 128 {
			t.Errorf("generatePKCEVerifier() returned verifier with invalid length: %d characters", len(verifier))
		}
	}
}

func TestGeneratePKCEChallenge(t *testing.T) {
	verifier := "test-verifier-string-1234567890"
	challenge := generatePKCEChallenge(verifier)

	if challenge == "" {
		t.Error("generatePKCEChallenge() returned empty string")
	}

	// Verify challenge is deterministic
	challenge2 := generatePKCEChallenge(verifier)
	if challenge != challenge2 {
		t.Errorf("generatePKCEChallenge() not deterministic: %s != %s", challenge, challenge2)
	}

	// Verify different verifiers produce different challenges
	verifier2 := "different-verifier-string-0987654321"
	challenge3 := generatePKCEChallenge(verifier2)
	if challenge == challenge3 {
		t.Errorf("generatePKCEChallenge() produced same challenge for different verifiers")
	}
}

func TestOIDCProvider_Start(t *testing.T) {
	// Create a mock OIDC discovery server
	var discoveryServer *httptest.Server
	discoveryServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			discovery := map[string]interface{}{
				"issuer":                 discoveryServer.URL,
				"authorization_endpoint": discoveryServer.URL + "/authorize",
				"token_endpoint":         discoveryServer.URL + "/token",
				"jwks_uri":              discoveryServer.URL + "/jwks",
				"response_types_supported": []string{"code"},
				"subject_types_supported":  []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(discovery)
			return
		}
		http.NotFound(w, r)
	}))
	defer discoveryServer.Close()

	ctx := context.Background()
	config := &domain.Config{
		Issuer:       discoveryServer.URL,
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		Scopes:       []string{"openid", "profile", "email"},
	}

	provider, err := NewOIDCProvider(ctx, config)
	if err != nil {
		t.Fatalf("NewOIDCProvider() error = %v", err)
	}

	tests := []struct {
		name    string
		opts    domain.StartOptions
		wantErr bool
	}{
		{
			name: "basic start",
			opts: domain.StartOptions{
				RedirectURL: "https://app.example.com/callback",
			},
			wantErr: false,
		},
		{
			name: "start with custom state",
			opts: domain.StartOptions{
				RedirectURL: "https://app.example.com/callback",
				State:       "custom-state-123",
			},
			wantErr: false,
		},
		{
			name: "start with force authn",
			opts: domain.StartOptions{
				RedirectURL: "https://app.example.com/callback",
				ForceAuthn:  true,
			},
			wantErr: false,
		},
		{
			name: "start with login hint",
			opts: domain.StartOptions{
				RedirectURL: "https://app.example.com/callback",
				LoginHint:   "user@example.com",
			},
			wantErr: false,
		},
		{
			name: "start with custom scopes",
			opts: domain.StartOptions{
				RedirectURL: "https://app.example.com/callback",
				Scopes:      []string{"openid", "email"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := provider.Start(ctx, tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("Start() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			// Verify result
			if result.AuthorizationURL == "" {
				t.Error("Start() returned empty AuthorizationURL")
			}
			if result.State == "" {
				t.Error("Start() returned empty State")
			}
			if result.Nonce == "" {
				t.Error("Start() returned empty Nonce")
			}
			if result.PKCEVerifier == "" {
				t.Error("Start() returned empty PKCEVerifier")
			}

			// Verify custom state is preserved
			if tt.opts.State != "" && result.State != tt.opts.State {
				t.Errorf("Start() State = %v, want %v", result.State, tt.opts.State)
			}

			// Verify authorization URL contains required parameters
			if !strings.Contains(result.AuthorizationURL, "response_type=code") {
				t.Error("AuthorizationURL missing response_type=code")
			}
			if !strings.Contains(result.AuthorizationURL, "client_id=test-client-id") {
				t.Error("AuthorizationURL missing client_id")
			}
			if !strings.Contains(result.AuthorizationURL, "redirect_uri=") {
				t.Error("AuthorizationURL missing redirect_uri")
			}
			if !strings.Contains(result.AuthorizationURL, "state=") {
				t.Error("AuthorizationURL missing state")
			}
			if !strings.Contains(result.AuthorizationURL, "nonce=") {
				t.Error("AuthorizationURL missing nonce")
			}
			if !strings.Contains(result.AuthorizationURL, "code_challenge=") {
				t.Error("AuthorizationURL missing code_challenge (PKCE)")
			}
			if !strings.Contains(result.AuthorizationURL, "code_challenge_method=S256") {
				t.Error("AuthorizationURL missing code_challenge_method=S256")
			}

			// Verify optional parameters
			if tt.opts.ForceAuthn && !strings.Contains(result.AuthorizationURL, "prompt=login") {
				t.Error("AuthorizationURL missing prompt=login when ForceAuthn is true")
			}
			if tt.opts.LoginHint != "" && !strings.Contains(result.AuthorizationURL, "login_hint=") {
				t.Error("AuthorizationURL missing login_hint")
			}
		})
	}
}

func TestApplyAttributeMapping(t *testing.T) {
	tests := []struct {
		name    string
		profile *domain.Profile
		mapping map[string][]string
		want    *domain.Profile
	}{
		{
			name: "default mapping - standard claims",
			profile: &domain.Profile{
				RawAttributes: map[string]interface{}{
					"email":       "user@example.com",
					"given_name":  "John",
					"family_name": "Doe",
					"name":        "John Doe",
					"picture":     "https://example.com/photo.jpg",
				},
			},
			mapping: nil, // Use default mapping
			want: &domain.Profile{
				Email:     "user@example.com",
				FirstName: "John",
				LastName:  "Doe",
				Name:      "John Doe",
				Picture:   "https://example.com/photo.jpg",
				RawAttributes: map[string]interface{}{
					"email":       "user@example.com",
					"given_name":  "John",
					"family_name": "Doe",
					"name":        "John Doe",
					"picture":     "https://example.com/photo.jpg",
				},
			},
		},
		{
			name: "custom mapping - alternative attribute names",
			profile: &domain.Profile{
				RawAttributes: map[string]interface{}{
					"mail":        "user@example.com",
					"givenName":   "Jane",
					"surname":     "Smith",
					"displayName": "Jane Smith",
				},
			},
			mapping: map[string][]string{
				"email":      {"mail", "email"},
				"first_name": {"givenName", "given_name"},
				"last_name":  {"surname", "family_name"},
				"name":       {"displayName", "name"},
			},
			want: &domain.Profile{
				Email:     "user@example.com",
				FirstName: "Jane",
				LastName:  "Smith",
				Name:      "Jane Smith",
				RawAttributes: map[string]interface{}{
					"mail":        "user@example.com",
					"givenName":   "Jane",
					"surname":     "Smith",
					"displayName": "Jane Smith",
				},
			},
		},
		{
			name: "mapping with groups as array",
			profile: &domain.Profile{
				RawAttributes: map[string]interface{}{
					"email":  "user@example.com",
					"groups": []interface{}{"admin", "users", "developers"},
				},
			},
			mapping: nil,
			want: &domain.Profile{
				Email:  "user@example.com",
				Groups: []string{"admin", "users", "developers"},
				RawAttributes: map[string]interface{}{
					"email":  "user@example.com",
					"groups": []interface{}{"admin", "users", "developers"},
				},
			},
		},
		{
			name: "mapping with groups as string array",
			profile: &domain.Profile{
				RawAttributes: map[string]interface{}{
					"email":  "user@example.com",
					"groups": []string{"admin", "users"},
				},
			},
			mapping: nil,
			want: &domain.Profile{
				Email:  "user@example.com",
				Groups: []string{"admin", "users"},
				RawAttributes: map[string]interface{}{
					"email":  "user@example.com",
					"groups": []string{"admin", "users"},
				},
			},
		},
		{
			name: "mapping preserves existing values",
			profile: &domain.Profile{
				Email:     "existing@example.com",
				FirstName: "Existing",
				RawAttributes: map[string]interface{}{
					"email":      "new@example.com",
					"given_name": "New",
				},
			},
			mapping: nil,
			want: &domain.Profile{
				Email:     "existing@example.com", // Should preserve existing
				FirstName: "Existing",             // Should preserve existing
				RawAttributes: map[string]interface{}{
					"email":      "new@example.com",
					"given_name": "New",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domain.ApplyAttributeMapping(tt.profile, tt.mapping)

			if tt.profile.Email != tt.want.Email {
				t.Errorf("Email = %v, want %v", tt.profile.Email, tt.want.Email)
			}
			if tt.profile.FirstName != tt.want.FirstName {
				t.Errorf("FirstName = %v, want %v", tt.profile.FirstName, tt.want.FirstName)
			}
			if tt.profile.LastName != tt.want.LastName {
				t.Errorf("LastName = %v, want %v", tt.profile.LastName, tt.want.LastName)
			}
			if tt.profile.Name != tt.want.Name {
				t.Errorf("Name = %v, want %v", tt.profile.Name, tt.want.Name)
			}
			if tt.profile.Picture != tt.want.Picture {
				t.Errorf("Picture = %v, want %v", tt.profile.Picture, tt.want.Picture)
			}

			// Compare groups
			if len(tt.profile.Groups) != len(tt.want.Groups) {
				t.Errorf("Groups length = %v, want %v", len(tt.profile.Groups), len(tt.want.Groups))
			} else {
				for i, g := range tt.profile.Groups {
					if g != tt.want.Groups[i] {
						t.Errorf("Groups[%d] = %v, want %v", i, g, tt.want.Groups[i])
					}
				}
			}
		})
	}
}

func TestOIDCProvider_Callback_Errors(t *testing.T) {
	// Create a mock OIDC discovery server
	var discoveryServer *httptest.Server
	discoveryServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			discovery := map[string]interface{}{
				"issuer":                 discoveryServer.URL,
				"authorization_endpoint": discoveryServer.URL + "/authorize",
				"token_endpoint":         discoveryServer.URL + "/token",
				"jwks_uri":              discoveryServer.URL + "/jwks",
				"response_types_supported": []string{"code"},
				"subject_types_supported":  []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(discovery)
			return
		}
		http.NotFound(w, r)
	}))
	defer discoveryServer.Close()

	ctx := context.Background()
	config := &domain.Config{
		Issuer:       discoveryServer.URL,
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		Scopes:       []string{"openid", "profile", "email"},
	}

	provider, err := NewOIDCProvider(ctx, config)
	if err != nil {
		t.Fatalf("NewOIDCProvider() error = %v", err)
	}

	tests := []struct {
		name    string
		req     domain.CallbackRequest
		wantErr string
	}{
		{
			name: "missing code",
			req: domain.CallbackRequest{
				State:        "test-state",
				Nonce:        "test-nonce",
				PKCEVerifier: "test-verifier",
				RedirectURL:  "https://app.example.com/callback",
			},
			wantErr: "authorization code is required",
		},
		{
			name: "missing PKCE verifier",
			req: domain.CallbackRequest{
				Code:        "test-code",
				State:       "test-state",
				Nonce:       "test-nonce",
				RedirectURL: "https://app.example.com/callback",
			},
			wantErr: "PKCE verifier is required",
		},
		{
			name: "missing nonce",
			req: domain.CallbackRequest{
				Code:         "test-code",
				State:        "test-state",
				PKCEVerifier: "test-verifier",
				RedirectURL:  "https://app.example.com/callback",
			},
			wantErr: "nonce is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := provider.Callback(ctx, tt.req)
			if err == nil {
				t.Error("Callback() expected error, got nil")
				return
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Callback() error = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestDefaultAttributeMapping(t *testing.T) {
	mapping := domain.DefaultAttributeMapping()

	// Verify essential mappings exist
	if _, ok := mapping["email"]; !ok {
		t.Error("DefaultAttributeMapping() missing 'email' mapping")
	}
	if _, ok := mapping["first_name"]; !ok {
		t.Error("DefaultAttributeMapping() missing 'first_name' mapping")
	}
	if _, ok := mapping["last_name"]; !ok {
		t.Error("DefaultAttributeMapping() missing 'last_name' mapping")
	}
	if _, ok := mapping["name"]; !ok {
		t.Error("DefaultAttributeMapping() missing 'name' mapping")
	}

	// Verify email mapping includes common attribute names
	emailMapping := mapping["email"]
	if len(emailMapping) == 0 {
		t.Error("email mapping is empty")
	}

	// Check that common email attribute names are included
	hasEmail := false
	hasMail := false
	for _, attr := range emailMapping {
		if attr == "email" {
			hasEmail = true
		}
		if attr == "mail" {
			hasMail = true
		}
	}
	if !hasEmail {
		t.Error("email mapping does not include 'email' attribute")
	}
	if !hasMail {
		t.Error("email mapping does not include 'mail' attribute")
	}
}

func TestNewOIDCProvider_DefaultScopes(t *testing.T) {
	var discoveryServer *httptest.Server
	discoveryServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			discovery := map[string]interface{}{
				"issuer":                 discoveryServer.URL,
				"authorization_endpoint": discoveryServer.URL + "/authorize",
				"token_endpoint":         discoveryServer.URL + "/token",
				"jwks_uri":              discoveryServer.URL + "/jwks",
				"response_types_supported": []string{"code"},
				"subject_types_supported":  []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(discovery)
			return
		}
		http.NotFound(w, r)
	}))
	defer discoveryServer.Close()

	ctx := context.Background()
	config := &domain.Config{
		Issuer:       discoveryServer.URL,
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		// No scopes configured - should use defaults
	}

	provider, err := NewOIDCProvider(ctx, config)
	if err != nil {
		t.Fatalf("NewOIDCProvider() error = %v", err)
	}

	// Verify default scopes are set
	if len(provider.oauth2Config.Scopes) == 0 {
		t.Error("NewOIDCProvider() did not set default scopes")
	}

	// Verify default scopes include openid
	hasOpenID := false
	for _, scope := range provider.oauth2Config.Scopes {
		if scope == "openid" {
			hasOpenID = true
			break
		}
	}
	if !hasOpenID {
		t.Error("Default scopes do not include 'openid'")
	}
}

func TestMarshalUnmarshalConfig(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	tenantID := uuid.New()
	createdBy := uuid.New()

	config := &domain.Config{
		ID:                 uuid.New(),
		TenantID:           tenantID,
		Name:               "Test Provider",
		Slug:               "test-provider",
		ProviderType:       domain.ProviderTypeOIDC,
		Enabled:            true,
		AllowSignup:        true,
		TrustEmailVerified: true,
		Domains:            []string{"example.com", "test.com"},
		Issuer:             "https://issuer.example.com",
		ClientID:           "test-client-id",
		ClientSecret:       "test-client-secret",
		Scopes:             []string{"openid", "profile", "email"},
		ResponseType:       "code",
		AttributeMapping: map[string][]string{
			"email":      {"mail", "email"},
			"first_name": {"givenName", "given_name"},
		},
		CreatedAt: now,
		UpdatedAt: now,
		CreatedBy: createdBy,
		UpdatedBy: createdBy,
	}

	// Marshal
	data, err := MarshalConfig(config)
	if err != nil {
		t.Fatalf("MarshalConfig() error = %v", err)
	}

	// Unmarshal
	unmarshaled, err := UnmarshalConfig(data)
	if err != nil {
		t.Fatalf("UnmarshalConfig() error = %v", err)
	}

	// Verify
	if unmarshaled.ID != config.ID {
		t.Errorf("ID = %v, want %v", unmarshaled.ID, config.ID)
	}
	if unmarshaled.Name != config.Name {
		t.Errorf("Name = %v, want %v", unmarshaled.Name, config.Name)
	}
	if unmarshaled.Issuer != config.Issuer {
		t.Errorf("Issuer = %v, want %v", unmarshaled.Issuer, config.Issuer)
	}
	if unmarshaled.ClientID != config.ClientID {
		t.Errorf("ClientID = %v, want %v", unmarshaled.ClientID, config.ClientID)
	}
}
