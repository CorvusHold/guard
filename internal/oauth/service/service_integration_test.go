//go:build integration

package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/corvusHold/guard/internal/oauth/domain"
	repo "github.com/corvusHold/guard/internal/oauth/repository"
	trepo "github.com/corvusHold/guard/internal/tenants/repository"
)

func setupIntegration(t *testing.T) (*Service, uuid.UUID) {
	t.Helper()
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("skipping integration test: DATABASE_URL not set")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Fatalf("db connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	// Create a test tenant
	tr := trepo.New(pool)
	tenantID := uuid.New()
	name := "oauth-integration-" + tenantID.String()[:8]
	if err := tr.Create(ctx, tenantID, name, nil); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	time.Sleep(25 * time.Millisecond)

	r := repo.New(pool)
	svc := New(r)
	return svc, tenantID
}

func createIntegrationUser(t *testing.T, userID uuid.UUID) {
	t.Helper()
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("skipping integration test: DATABASE_URL not set")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Fatalf("db connect for user create: %v", err)
	}
	defer pool.Close()

	if _, err := pool.Exec(ctx, "INSERT INTO users (id) VALUES ($1)", userID); err != nil {
		t.Fatalf("create user: %v", err)
	}
}

func TestIntegration_ClientCRUD(t *testing.T) {
	svc, tenantID := setupIntegration(t)
	ctx := context.Background()

	// Create
	client, secret, err := svc.CreateClient(ctx, domain.CreateOAuthClientInput{
		TenantID:     tenantID,
		Name:         "Integration Test App",
		ClientType:   "confidential",
		RedirectURIs: []string{"https://example.com/callback"},
		Scopes:       []string{"openid", "profile"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
	})
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	if secret == "" {
		t.Fatal("expected non-empty secret for confidential client")
	}

	// Get by ID
	got, err := svc.GetClient(ctx, client.ID, tenantID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if got.Name != "Integration Test App" {
		t.Errorf("expected name 'Integration Test App', got '%s'", got.Name)
	}

	// List
	clients, err := svc.ListClients(ctx, tenantID)
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	found := false
	for _, c := range clients {
		if c.ID == client.ID {
			found = true
		}
	}
	if !found {
		t.Error("created client not found in list")
	}

	// Update
	newName := "Updated App"
	err = svc.UpdateClient(ctx, client.ID, tenantID, domain.UpdateOAuthClientInput{
		Name: &newName,
	})
	if err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	got, _ = svc.GetClient(ctx, client.ID, tenantID)
	if got.Name != "Updated App" {
		t.Errorf("expected updated name, got '%s'", got.Name)
	}

	// Delete
	err = svc.DeleteClient(ctx, client.ID, tenantID)
	if err != nil {
		t.Fatalf("DeleteClient: %v", err)
	}
	_, err = svc.GetClient(ctx, client.ID, tenantID)
	if err == nil {
		t.Error("expected error after delete, got nil")
	}
}

func TestIntegration_AuthorizationCodeFlow(t *testing.T) {
	svc, tenantID := setupIntegration(t)
	ctx := context.Background()

	client, secret, _ := svc.CreateClient(ctx, domain.CreateOAuthClientInput{
		TenantID:     tenantID,
		Name:         "Code Flow App",
		ClientType:   "confidential",
		RedirectURIs: []string{"https://example.com/callback"},
		Scopes:       []string{"openid", "profile"},
		GrantTypes:   []string{"authorization_code"},
	})

	userID := uuid.New()
	createIntegrationUser(t, userID)

	// Create authorization code
	result, err := svc.CreateAuthorizationCode(ctx, domain.AuthorizeInput{
		ClientID:    client.ClientID,
		RedirectURI: "https://example.com/callback",
		Scope:       "openid profile",
		UserID:      userID,
		TenantID:    tenantID,
	})
	if err != nil {
		t.Fatalf("CreateAuthorizationCode: %v", err)
	}

	// Exchange code
	code, exchangedClient, err := svc.ExchangeAuthorizationCode(ctx, domain.TokenRequest{
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

	// Second exchange should fail (single-use)
	_, _, err = svc.ExchangeAuthorizationCode(ctx, domain.TokenRequest{
		GrantType:    "authorization_code",
		Code:         result.Code,
		RedirectURI:  "https://example.com/callback",
		ClientID:     client.ClientID,
		ClientSecret: secret,
	})
	if err == nil {
		t.Error("expected error on second code exchange")
	}
}

func TestIntegration_PKCEFlow(t *testing.T) {
	svc, tenantID := setupIntegration(t)
	ctx := context.Background()

	client, _, _ := svc.CreateClient(ctx, domain.CreateOAuthClientInput{
		TenantID:     tenantID,
		Name:         "PKCE SPA",
		ClientType:   "public",
		RedirectURIs: []string{"https://spa.example.com/cb"},
		Scopes:       []string{"openid"},
		GrantTypes:   []string{"authorization_code"},
	})

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	userID := uuid.New()
	createIntegrationUser(t, userID)

	result, err := svc.CreateAuthorizationCode(ctx, domain.AuthorizeInput{
		ClientID:            client.ClientID,
		RedirectURI:         "https://spa.example.com/cb",
		Scope:               "openid",
		UserID:              userID,
		TenantID:            tenantID,
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("CreateAuthorizationCode: %v", err)
	}

	// Correct verifier
	_, _, err = svc.ExchangeAuthorizationCode(ctx, domain.TokenRequest{
		GrantType:    "authorization_code",
		Code:         result.Code,
		RedirectURI:  "https://spa.example.com/cb",
		ClientID:     client.ClientID,
		CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("expected success with correct verifier: %v", err)
	}
}

func TestIntegration_ConsentPersistence(t *testing.T) {
	svc, tenantID := setupIntegration(t)
	ctx := context.Background()

	userID := uuid.New()
	createIntegrationUser(t, userID)
	clientID := "test-consent-client-" + uuid.New().String()[:8]
	scopes := []string{"openid", "profile"}

	// No consent initially
	if svc.HasConsent(ctx, userID, tenantID, clientID, scopes) {
		t.Error("expected no consent initially")
	}

	// Save consent
	err := svc.SaveConsent(ctx, userID, tenantID, clientID, scopes)
	if err != nil {
		t.Fatalf("SaveConsent: %v", err)
	}

	// Now has consent
	if !svc.HasConsent(ctx, userID, tenantID, clientID, scopes) {
		t.Error("expected consent after save")
	}

	// Subset of scopes should also pass
	if !svc.HasConsent(ctx, userID, tenantID, clientID, []string{"openid"}) {
		t.Error("expected consent for subset of scopes")
	}

	// Superset should fail
	if svc.HasConsent(ctx, userID, tenantID, clientID, []string{"openid", "profile", "email"}) {
		t.Error("expected no consent for superset of scopes")
	}

	// Revoke
	err = svc.RevokeConsent(ctx, userID, tenantID, clientID)
	if err != nil {
		t.Fatalf("RevokeConsent: %v", err)
	}

	// No consent after revoke
	if svc.HasConsent(ctx, userID, tenantID, clientID, scopes) {
		t.Error("expected no consent after revoke")
	}
}

func TestIntegration_ClientAuthentication(t *testing.T) {
	svc, tenantID := setupIntegration(t)
	ctx := context.Background()

	client, secret, _ := svc.CreateClient(ctx, domain.CreateOAuthClientInput{
		TenantID:     tenantID,
		Name:         "M2M App",
		ClientType:   "confidential",
		RedirectURIs: []string{"https://m2m.example.com/cb"},
		Scopes:       []string{"openid"},
		GrantTypes:   []string{"client_credentials"},
	})

	// Correct credentials
	authenticated, err := svc.AuthenticateClient(ctx, client.ClientID, secret)
	if err != nil {
		t.Fatalf("AuthenticateClient: %v", err)
	}
	if authenticated.ClientID != client.ClientID {
		t.Errorf("expected client_id %s, got %s", client.ClientID, authenticated.ClientID)
	}

	// Wrong secret
	_, err = svc.AuthenticateClient(ctx, client.ClientID, "wrong-secret")
	if err == nil {
		t.Error("expected error with wrong secret")
	}
}
