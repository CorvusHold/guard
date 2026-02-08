package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/corvusHold/guard/internal/oauth/domain"
)

// --- In-memory mock repository ---

type mockRepo struct {
	clients  map[string]domain.OAuthClient // keyed by client_id
	byID     map[uuid.UUID]domain.OAuthClient
	codes    map[string]domain.AuthorizationCode // keyed by code_hash
	consents map[string]domain.ConsentGrant      // keyed by userID:clientID
}

func newMockRepo() *mockRepo {
	return &mockRepo{
		clients: make(map[string]domain.OAuthClient),
		byID:    make(map[uuid.UUID]domain.OAuthClient),
		codes:   make(map[string]domain.AuthorizationCode),
	}
}

func (m *mockRepo) CreateOAuthClient(_ context.Context, c domain.OAuthClient) (domain.OAuthClient, error) {
	c.CreatedAt = time.Now()
	c.UpdatedAt = time.Now()
	m.clients[c.ClientID] = c
	m.byID[c.ID] = c
	return c, nil
}

func (m *mockRepo) GetOAuthClientByClientID(_ context.Context, clientID string) (domain.OAuthClient, error) {
	c, ok := m.clients[clientID]
	if !ok {
		return domain.OAuthClient{}, domain.ErrNotFound
	}
	return c, nil
}

func (m *mockRepo) GetOAuthClientByID(_ context.Context, id, tenantID uuid.UUID) (domain.OAuthClient, error) {
	c, ok := m.byID[id]
	if !ok || c.TenantID != tenantID {
		return domain.OAuthClient{}, domain.ErrNotFound
	}
	return c, nil
}

func (m *mockRepo) ListOAuthClientsByTenant(_ context.Context, tenantID uuid.UUID) ([]domain.OAuthClient, error) {
	var out []domain.OAuthClient
	for _, c := range m.clients {
		if c.TenantID == tenantID {
			out = append(out, c)
		}
	}
	return out, nil
}

func (m *mockRepo) UpdateOAuthClient(_ context.Context, id, tenantID uuid.UUID, in domain.UpdateOAuthClientInput) error {
	c, ok := m.byID[id]
	if !ok || c.TenantID != tenantID {
		return domain.ErrNotFound
	}
	if in.Name != nil {
		c.Name = *in.Name
	}
	if in.RedirectURIs != nil {
		c.RedirectURIs = in.RedirectURIs
	}
	if in.IsActive != nil {
		c.IsActive = *in.IsActive
	}
	c.UpdatedAt = time.Now()
	m.byID[id] = c
	m.clients[c.ClientID] = c
	return nil
}

func (m *mockRepo) DeleteOAuthClient(_ context.Context, id, tenantID uuid.UUID) error {
	c, ok := m.byID[id]
	if !ok || c.TenantID != tenantID {
		return domain.ErrNotFound
	}
	delete(m.byID, id)
	delete(m.clients, c.ClientID)
	return nil
}

func (m *mockRepo) CreateAuthorizationCode(_ context.Context, code domain.AuthorizationCode) (domain.AuthorizationCode, error) {
	code.CreatedAt = time.Now()
	m.codes[code.CodeHash] = code
	return code, nil
}

func (m *mockRepo) GetAuthorizationCodeByHash(_ context.Context, codeHash string) (domain.AuthorizationCode, error) {
	c, ok := m.codes[codeHash]
	if !ok || c.ConsumedAt != nil || c.ExpiresAt.Before(time.Now()) {
		return domain.AuthorizationCode{}, domain.ErrNotFound
	}
	return c, nil
}

func (m *mockRepo) ConsumeAuthorizationCode(_ context.Context, codeHash string) error {
	c, ok := m.codes[codeHash]
	if !ok {
		return domain.ErrNotFound
	}
	now := time.Now()
	c.ConsumedAt = &now
	m.codes[codeHash] = c
	return nil
}

func (m *mockRepo) UpsertConsentGrant(_ context.Context, userID, tenantID uuid.UUID, clientID string, scopes []string) (domain.ConsentGrant, error) {
	key := userID.String() + ":" + clientID
	g := domain.ConsentGrant{
		ID:        uuid.New(),
		UserID:    userID,
		TenantID:  tenantID,
		ClientID:  clientID,
		Scopes:    scopes,
		GrantedAt: time.Now(),
	}
	if m.consents == nil {
		m.consents = make(map[string]domain.ConsentGrant)
	}
	m.consents[key] = g
	return g, nil
}

func (m *mockRepo) GetConsentGrant(_ context.Context, userID uuid.UUID, clientID string) (domain.ConsentGrant, error) {
	if m.consents == nil {
		return domain.ConsentGrant{}, domain.ErrNotFound
	}
	key := userID.String() + ":" + clientID
	g, ok := m.consents[key]
	if !ok || g.RevokedAt != nil {
		return domain.ConsentGrant{}, domain.ErrNotFound
	}
	return g, nil
}

func (m *mockRepo) RevokeConsentGrant(_ context.Context, userID uuid.UUID, clientID string) error {
	if m.consents == nil {
		return nil
	}
	key := userID.String() + ":" + clientID
	g, ok := m.consents[key]
	if ok {
		now := time.Now()
		g.RevokedAt = &now
		m.consents[key] = g
	}
	return nil
}

// --- Tests ---

func TestCreateClient_Confidential(t *testing.T) {
	repo := newMockRepo()
	svc := New(repo)

	tenantID := uuid.New()
	client, secret, err := svc.CreateClient(context.Background(), domain.CreateOAuthClientInput{
		TenantID:     tenantID,
		Name:         "Test App",
		ClientType:   "confidential",
		RedirectURIs: []string{"https://example.com/callback"},
	})
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}

	if client.Name != "Test App" {
		t.Errorf("expected name 'Test App', got '%s'", client.Name)
	}
	if client.ClientType != "confidential" {
		t.Errorf("expected client_type 'confidential', got '%s'", client.ClientType)
	}
	if secret == "" {
		t.Error("expected non-empty client_secret for confidential client")
	}
	if client.ClientID == "" {
		t.Error("expected non-empty client_id")
	}
	if !client.IsActive {
		t.Error("expected is_active=true")
	}

	// Verify secret hashes correctly
	if err := bcrypt.CompareHashAndPassword([]byte(client.ClientSecretHash), []byte(secret)); err != nil {
		t.Errorf("client_secret does not match hash: %v", err)
	}
}

func TestCreateClient_Public(t *testing.T) {
	repo := newMockRepo()
	svc := New(repo)

	client, secret, err := svc.CreateClient(context.Background(), domain.CreateOAuthClientInput{
		TenantID:     uuid.New(),
		Name:         "SPA App",
		ClientType:   "public",
		RedirectURIs: []string{"https://spa.example.com/callback"},
	})
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	if secret != "" {
		t.Error("expected empty client_secret for public client")
	}
	if client.ClientSecretHash != "" {
		t.Error("expected empty client_secret_hash for public client")
	}
}

func TestCreateClient_ValidationErrors(t *testing.T) {
	repo := newMockRepo()
	svc := New(repo)

	tests := []struct {
		name  string
		input domain.CreateOAuthClientInput
	}{
		{"missing name", domain.CreateOAuthClientInput{TenantID: uuid.New(), RedirectURIs: []string{"https://x.com/cb"}}},
		{"missing redirect_uris", domain.CreateOAuthClientInput{TenantID: uuid.New(), Name: "App"}},
		{"invalid client_type", domain.CreateOAuthClientInput{TenantID: uuid.New(), Name: "App", ClientType: "invalid", RedirectURIs: []string{"https://x.com/cb"}}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := svc.CreateClient(context.Background(), tc.input)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestListClients(t *testing.T) {
	repo := newMockRepo()
	svc := New(repo)

	tenantID := uuid.New()
	otherTenant := uuid.New()

	_, _, _ = svc.CreateClient(context.Background(), domain.CreateOAuthClientInput{
		TenantID: tenantID, Name: "App1", RedirectURIs: []string{"https://a.com/cb"},
	})
	_, _, _ = svc.CreateClient(context.Background(), domain.CreateOAuthClientInput{
		TenantID: tenantID, Name: "App2", RedirectURIs: []string{"https://b.com/cb"},
	})
	_, _, _ = svc.CreateClient(context.Background(), domain.CreateOAuthClientInput{
		TenantID: otherTenant, Name: "Other", RedirectURIs: []string{"https://c.com/cb"},
	})

	clients, err := svc.ListClients(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	if len(clients) != 2 {
		t.Errorf("expected 2 clients for tenant, got %d", len(clients))
	}
}

func TestValidateAuthorizeRequest(t *testing.T) {
	repo := newMockRepo()
	svc := New(repo)

	tenantID := uuid.New()
	client, _, _ := svc.CreateClient(context.Background(), domain.CreateOAuthClientInput{
		TenantID:     tenantID,
		Name:         "Test",
		ClientType:   "confidential",
		RedirectURIs: []string{"https://example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid", "profile"},
	})

	// Valid request
	_, err := svc.ValidateAuthorizeRequest(context.Background(), domain.AuthorizeInput{
		ClientID:     client.ClientID,
		RedirectURI:  "https://example.com/callback",
		ResponseType: "code",
		Scope:        "openid",
	})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Invalid response_type
	_, err = svc.ValidateAuthorizeRequest(context.Background(), domain.AuthorizeInput{
		ClientID:     client.ClientID,
		RedirectURI:  "https://example.com/callback",
		ResponseType: "token",
		Scope:        "openid",
	})
	if err == nil {
		t.Error("expected error for unsupported response_type")
	}

	// Invalid redirect_uri
	_, err = svc.ValidateAuthorizeRequest(context.Background(), domain.AuthorizeInput{
		ClientID:     client.ClientID,
		RedirectURI:  "https://evil.com/callback",
		ResponseType: "code",
		Scope:        "openid",
	})
	if err == nil {
		t.Error("expected error for invalid redirect_uri")
	}

	// Invalid scope
	_, err = svc.ValidateAuthorizeRequest(context.Background(), domain.AuthorizeInput{
		ClientID:     client.ClientID,
		RedirectURI:  "https://example.com/callback",
		ResponseType: "code",
		Scope:        "admin",
	})
	if err == nil {
		t.Error("expected error for invalid scope")
	}
}

func TestValidateAuthorizeRequest_PKCERequired(t *testing.T) {
	repo := newMockRepo()
	svc := New(repo)

	client, _, _ := svc.CreateClient(context.Background(), domain.CreateOAuthClientInput{
		TenantID:     uuid.New(),
		Name:         "SPA",
		ClientType:   "public",
		RedirectURIs: []string{"https://spa.com/cb"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid"},
	})

	// Public client without PKCE should fail
	_, err := svc.ValidateAuthorizeRequest(context.Background(), domain.AuthorizeInput{
		ClientID:     client.ClientID,
		RedirectURI:  "https://spa.com/cb",
		ResponseType: "code",
		Scope:        "openid",
	})
	if err == nil {
		t.Error("expected error: PKCE required for public clients")
	}

	// Public client with PKCE should succeed
	_, err = svc.ValidateAuthorizeRequest(context.Background(), domain.AuthorizeInput{
		ClientID:            client.ClientID,
		RedirectURI:         "https://spa.com/cb",
		ResponseType:        "code",
		Scope:               "openid",
		CodeChallenge:       "test-challenge",
		CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("expected no error with PKCE, got: %v", err)
	}
}

func TestCreateAndExchangeAuthorizationCode(t *testing.T) {
	repo := newMockRepo()
	svc := New(repo)

	tenantID := uuid.New()
	userID := uuid.New()
	client, secret, _ := svc.CreateClient(context.Background(), domain.CreateOAuthClientInput{
		TenantID:     tenantID,
		Name:         "Test",
		ClientType:   "confidential",
		RedirectURIs: []string{"https://example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid", "profile"},
	})

	// Create authorization code
	result, err := svc.CreateAuthorizationCode(context.Background(), domain.AuthorizeInput{
		ClientID:    client.ClientID,
		RedirectURI: "https://example.com/callback",
		Scope:       "openid profile",
		UserID:      userID,
		TenantID:    tenantID,
	})
	if err != nil {
		t.Fatalf("CreateAuthorizationCode: %v", err)
	}
	if result.Code == "" {
		t.Error("expected non-empty code")
	}

	// Exchange code
	code, exchangedClient, err := svc.ExchangeAuthorizationCode(context.Background(), domain.TokenRequest{
		GrantType:    "authorization_code",
		Code:         result.Code,
		RedirectURI:  "https://example.com/callback",
		ClientID:     client.ClientID,
		ClientSecret: secret,
	})
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	if code.UserID != userID {
		t.Errorf("expected user_id %s, got %s", userID, code.UserID)
	}
	if exchangedClient.ClientID != client.ClientID {
		t.Errorf("expected client_id %s, got %s", client.ClientID, exchangedClient.ClientID)
	}

	// Code should be consumed — second exchange should fail
	_, _, err = svc.ExchangeAuthorizationCode(context.Background(), domain.TokenRequest{
		GrantType:    "authorization_code",
		Code:         result.Code,
		RedirectURI:  "https://example.com/callback",
		ClientID:     client.ClientID,
		ClientSecret: secret,
	})
	if err == nil {
		t.Error("expected error on second code exchange (single-use)")
	}
}

func TestExchangeAuthorizationCode_PKCEVerification(t *testing.T) {
	repo := newMockRepo()
	svc := New(repo)

	tenantID := uuid.New()
	userID := uuid.New()
	client, _, _ := svc.CreateClient(context.Background(), domain.CreateOAuthClientInput{
		TenantID:     tenantID,
		Name:         "SPA",
		ClientType:   "public",
		RedirectURIs: []string{"https://spa.com/cb"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid"},
	})

	// Generate PKCE verifier and challenge
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	result, err := svc.CreateAuthorizationCode(context.Background(), domain.AuthorizeInput{
		ClientID:            client.ClientID,
		RedirectURI:         "https://spa.com/cb",
		Scope:               "openid",
		UserID:              userID,
		TenantID:            tenantID,
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("CreateAuthorizationCode: %v", err)
	}

	// Exchange with correct verifier
	_, _, err = svc.ExchangeAuthorizationCode(context.Background(), domain.TokenRequest{
		GrantType:    "authorization_code",
		Code:         result.Code,
		RedirectURI:  "https://spa.com/cb",
		ClientID:     client.ClientID,
		CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("expected success with correct verifier, got: %v", err)
	}
}

func TestExchangeAuthorizationCode_PKCEWrongVerifier(t *testing.T) {
	repo := newMockRepo()
	svc := New(repo)

	tenantID := uuid.New()
	userID := uuid.New()
	client, _, _ := svc.CreateClient(context.Background(), domain.CreateOAuthClientInput{
		TenantID:     tenantID,
		Name:         "SPA",
		ClientType:   "public",
		RedirectURIs: []string{"https://spa.com/cb"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid"},
	})

	verifier := "correct-verifier"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	result, _ := svc.CreateAuthorizationCode(context.Background(), domain.AuthorizeInput{
		ClientID:            client.ClientID,
		RedirectURI:         "https://spa.com/cb",
		Scope:               "openid",
		UserID:              userID,
		TenantID:            tenantID,
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})

	// Exchange with wrong verifier
	_, _, err := svc.ExchangeAuthorizationCode(context.Background(), domain.TokenRequest{
		GrantType:    "authorization_code",
		Code:         result.Code,
		RedirectURI:  "https://spa.com/cb",
		ClientID:     client.ClientID,
		CodeVerifier: "wrong-verifier",
	})
	if err == nil {
		t.Error("expected error with wrong code_verifier")
	}
}

func TestAuthenticateClient(t *testing.T) {
	repo := newMockRepo()
	svc := New(repo)

	client, secret, _ := svc.CreateClient(context.Background(), domain.CreateOAuthClientInput{
		TenantID:     uuid.New(),
		Name:         "M2M App",
		ClientType:   "confidential",
		RedirectURIs: []string{"https://m2m.com/cb"},
		GrantTypes:   []string{"client_credentials"},
		Scopes:       []string{"openid"},
	})

	// Correct credentials
	authenticated, err := svc.AuthenticateClient(context.Background(), client.ClientID, secret)
	if err != nil {
		t.Fatalf("AuthenticateClient: %v", err)
	}
	if authenticated.ClientID != client.ClientID {
		t.Errorf("expected client_id %s, got %s", client.ClientID, authenticated.ClientID)
	}

	// Wrong secret
	_, err = svc.AuthenticateClient(context.Background(), client.ClientID, "wrong-secret")
	if err == nil {
		t.Error("expected error with wrong secret")
	}

	// Non-existent client
	_, err = svc.AuthenticateClient(context.Background(), "nonexistent", secret)
	if err == nil {
		t.Error("expected error with non-existent client")
	}
}

func TestAuthenticateClient_PublicClientDenied(t *testing.T) {
	repo := newMockRepo()
	svc := New(repo)

	client, _, _ := svc.CreateClient(context.Background(), domain.CreateOAuthClientInput{
		TenantID:     uuid.New(),
		Name:         "SPA",
		ClientType:   "public",
		RedirectURIs: []string{"https://spa.com/cb"},
		GrantTypes:   []string{"authorization_code", "client_credentials"},
		Scopes:       []string{"openid"},
	})

	_, err := svc.AuthenticateClient(context.Background(), client.ClientID, "any-secret")
	if err == nil {
		t.Error("expected error: client_credentials requires confidential client")
	}
}

func TestExchangeAuthorizationCode_RedirectURIMismatch(t *testing.T) {
	repo := newMockRepo()
	svc := New(repo)

	tenantID := uuid.New()
	client, secret, _ := svc.CreateClient(context.Background(), domain.CreateOAuthClientInput{
		TenantID:     tenantID,
		Name:         "Test",
		ClientType:   "confidential",
		RedirectURIs: []string{"https://example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid"},
	})

	result, _ := svc.CreateAuthorizationCode(context.Background(), domain.AuthorizeInput{
		ClientID:    client.ClientID,
		RedirectURI: "https://example.com/callback",
		Scope:       "openid",
		UserID:      uuid.New(),
		TenantID:    tenantID,
	})

	_, _, err := svc.ExchangeAuthorizationCode(context.Background(), domain.TokenRequest{
		GrantType:    "authorization_code",
		Code:         result.Code,
		RedirectURI:  "https://evil.com/callback",
		ClientID:     client.ClientID,
		ClientSecret: secret,
	})
	if err == nil {
		t.Error("expected error for redirect_uri mismatch")
	}
}
