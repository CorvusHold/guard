package db

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

func setupTestDB(t *testing.T) (*pgxpool.Pool, *Queries) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("skipping integration test: DATABASE_URL not set")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatalf("failed to connect to db: %v", err)
	}

	return pool, New(pool)
}

func toPgUUID(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: id, Valid: true}
}

func toPgText(s string) pgtype.Text {
	return pgtype.Text{String: s, Valid: s != ""}
}

func toPgBool(b bool) pgtype.Bool {
	return pgtype.Bool{Bool: b, Valid: true}
}

func TestCreateSSOProvider(t *testing.T) {
	pool, q := setupTestDB(t)
	defer pool.Close()

	ctx := context.Background()

	// Create a test tenant first
	tenantID := uuid.New()
	_, err := pool.Exec(ctx, "INSERT INTO tenants (id, name) VALUES ($1, $2)", tenantID, "test-tenant-"+tenantID.String())
	if err != nil {
		t.Fatalf("failed to create test tenant: %v", err)
	}

	// Create a test user for created_by/updated_by
	userID := uuid.New()
	_, err = pool.Exec(ctx, "INSERT INTO users (id) VALUES ($1)", userID)
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	tests := []struct {
		name         string
		providerType string
		slug         string
		setupFunc    func() CreateSSOProviderParams
		wantErr      bool
	}{
		{
			name:         "Create OIDC provider",
			providerType: "oidc",
			slug:         "google-" + uuid.New().String(),
			setupFunc: func() CreateSSOProviderParams {
				return CreateSSOProviderParams{
					TenantID:     toPgUUID(tenantID),
					Name:         "Google Workspace",
					Slug:         "google-" + uuid.New().String(),
					ProviderType: "oidc",
					Issuer:       toPgText("https://accounts.google.com"),
					ClientID:     toPgText("test-client-id"),
					ClientSecret: toPgText("test-client-secret"),
					Scopes:       []string{"openid", "profile", "email"},
					Enabled:      toPgBool(true),
					AllowSignup:  toPgBool(true),
					Domains:      []string{"example.com", "test.com"},
					CreatedBy:    toPgUUID(userID),
					UpdatedBy:    toPgUUID(userID),
				}
			},
			wantErr: false,
		},
		{
			name:         "Create SAML provider",
			providerType: "saml",
			slug:         "okta-" + uuid.New().String(),
			setupFunc: func() CreateSSOProviderParams {
				return CreateSSOProviderParams{
					TenantID:             toPgUUID(tenantID),
					Name:                 "Okta SAML",
					Slug:                 "okta-" + uuid.New().String(),
					ProviderType:         "saml",
					EntityID:             toPgText("https://guard.example.com"),
					IdpEntityID:          toPgText("https://okta.example.com"),
					IdpSsoUrl:            toPgText("https://okta.example.com/sso"),
					WantAssertionsSigned: toPgBool(true),
					Enabled:              toPgBool(true),
					AllowSignup:          toPgBool(false),
					Domains:              []string{"company.com"},
					CreatedBy:            toPgUUID(userID),
					UpdatedBy:            toPgUUID(userID),
				}
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := tt.setupFunc()
			provider, err := q.CreateSSOProvider(ctx, params)
			if (err != nil) != tt.wantErr {
				t.Fatalf("CreateSSOProvider() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if !provider.ID.Valid {
				t.Error("expected valid provider ID")
			}
			if provider.TenantID.Bytes != tenantID {
				t.Errorf("expected tenant_id %v, got %v", tenantID, provider.TenantID)
			}
			if provider.ProviderType != tt.providerType {
				t.Errorf("expected provider_type %s, got %s", tt.providerType, provider.ProviderType)
			}
		})
	}
}

func TestGetSSOProviderBySlug(t *testing.T) {
	pool, q := setupTestDB(t)
	defer pool.Close()

	ctx := context.Background()

	// Create test tenant
	tenantID := uuid.New()
	_, err := pool.Exec(ctx, "INSERT INTO tenants (id, name) VALUES ($1, $2)", tenantID, "test-tenant-"+tenantID.String())
	if err != nil {
		t.Fatalf("failed to create test tenant: %v", err)
	}

	// Create a test user
	userID := uuid.New()
	_, err = pool.Exec(ctx, "INSERT INTO users (id) VALUES ($1)", userID)
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	// Create an OIDC provider
	slug := "google-" + uuid.New().String()
	provider, err := q.CreateSSOProvider(ctx, CreateSSOProviderParams{
		TenantID:     toPgUUID(tenantID),
		Name:         "Google Workspace",
		Slug:         slug,
		ProviderType: "oidc",
		Issuer:       toPgText("https://accounts.google.com"),
		ClientID:     toPgText("test-client-id"),
		ClientSecret: toPgText("test-client-secret"),
		CreatedBy:    toPgUUID(userID),
		UpdatedBy:    toPgUUID(userID),
	})
	if err != nil {
		t.Fatalf("failed to create SSO provider: %v", err)
	}

	// Retrieve by slug
	retrieved, err := q.GetSSOProviderBySlug(ctx, GetSSOProviderBySlugParams{
		TenantID: toPgUUID(tenantID),
		Slug:     slug,
	})
	if err != nil {
		t.Fatalf("GetSSOProviderBySlug() error = %v", err)
	}

	if retrieved.ID.Bytes != provider.ID.Bytes {
		t.Errorf("expected ID %v, got %v", provider.ID, retrieved.ID)
	}
	if retrieved.Slug != slug {
		t.Errorf("expected slug %s, got %s", slug, retrieved.Slug)
	}
}

func TestFindSSOProviderByDomain(t *testing.T) {
	pool, q := setupTestDB(t)
	defer pool.Close()

	ctx := context.Background()

	// Create test tenant
	tenantID := uuid.New()
	_, err := pool.Exec(ctx, "INSERT INTO tenants (id, name) VALUES ($1, $2)", tenantID, "test-tenant-"+tenantID.String())
	if err != nil {
		t.Fatalf("failed to create test tenant: %v", err)
	}

	// Create a test user
	userID := uuid.New()
	_, err = pool.Exec(ctx, "INSERT INTO users (id) VALUES ($1)", userID)
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	// Create a provider with domain routing
	domains := []string{"acme.com", "acme.io"}
	slug := "okta-" + uuid.New().String()
	_, err = q.CreateSSOProvider(ctx, CreateSSOProviderParams{
		TenantID:     toPgUUID(tenantID),
		Name:         "Okta",
		Slug:         slug,
		ProviderType: "saml",
		EntityID:     toPgText("https://guard.example.com"),
		IdpEntityID:  toPgText("https://okta.example.com"),
		Enabled:      toPgBool(true),
		Domains:      domains,
		CreatedBy:    toPgUUID(userID),
		UpdatedBy:    toPgUUID(userID),
	})
	if err != nil {
		t.Fatalf("failed to create SSO provider: %v", err)
	}

	// Find by domain
	provider, err := q.FindSSOProviderByDomain(ctx, FindSSOProviderByDomainParams{
		TenantID: toPgUUID(tenantID),
		Column2:  "acme.com",
	})
	if err != nil {
		t.Fatalf("FindSSOProviderByDomain() error = %v", err)
	}

	if provider.Slug != slug {
		t.Errorf("expected slug %s, got %s", slug, provider.Slug)
	}

	// Test with second domain
	provider2, err := q.FindSSOProviderByDomain(ctx, FindSSOProviderByDomainParams{
		TenantID: toPgUUID(tenantID),
		Column2:  "acme.io",
	})
	if err != nil {
		t.Fatalf("FindSSOProviderByDomain() error = %v", err)
	}

	if provider2.Slug != slug {
		t.Errorf("expected slug %s, got %s", slug, provider2.Slug)
	}
}

func TestSSOAuthAttempts(t *testing.T) {
	pool, q := setupTestDB(t)
	defer pool.Close()

	ctx := context.Background()

	// Create test tenant
	tenantID := uuid.New()
	_, err := pool.Exec(ctx, "INSERT INTO tenants (id, name) VALUES ($1, $2)", tenantID, "test-tenant-"+tenantID.String())
	if err != nil {
		t.Fatalf("failed to create test tenant: %v", err)
	}

	// Create a test user
	userID := uuid.New()
	_, err = pool.Exec(ctx, "INSERT INTO users (id) VALUES ($1)", userID)
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	// Create an SSO provider
	provider, err := q.CreateSSOProvider(ctx, CreateSSOProviderParams{
		TenantID:     toPgUUID(tenantID),
		Name:         "Google",
		Slug:         "google-" + uuid.New().String(),
		ProviderType: "oidc",
		Issuer:       toPgText("https://accounts.google.com"),
		ClientID:     toPgText("test-client-id"),
		CreatedBy:    toPgUUID(userID),
		UpdatedBy:    toPgUUID(userID),
	})
	if err != nil {
		t.Fatalf("failed to create SSO provider: %v", err)
	}

	// Create an auth attempt
	state := uuid.New().String()
	attempt, err := q.CreateSSOAuthAttempt(ctx, CreateSSOAuthAttemptParams{
		TenantID:   toPgUUID(tenantID),
		ProviderID: provider.ID,
		State:      pgtype.Text{String: state, Valid: true},
		Status:     "initiated",
		IpAddress:  pgtype.Text{String: "192.168.1.1", Valid: true},
		UserAgent:  pgtype.Text{String: "Mozilla/5.0", Valid: true},
	})
	if err != nil {
		t.Fatalf("CreateSSOAuthAttempt() error = %v", err)
	}

	if !attempt.ID.Valid {
		t.Error("expected valid attempt ID")
	}

	// Retrieve by state
	retrieved, err := q.GetSSOAuthAttemptByState(ctx, pgtype.Text{String: state, Valid: true})
	if err != nil {
		t.Fatalf("GetSSOAuthAttemptByState() error = %v", err)
	}

	if retrieved.ID.Bytes != attempt.ID.Bytes {
		t.Errorf("expected ID %v, got %v", attempt.ID, retrieved.ID)
	}
	if retrieved.Status != "initiated" {
		t.Errorf("expected status 'initiated', got %s", retrieved.Status)
	}

	// Update the attempt to success
	err = q.UpdateSSOAuthAttempt(ctx, UpdateSSOAuthAttemptParams{
		Status:   "success",
		UserID:   toPgUUID(userID),
		ID:       attempt.ID,
	})
	if err != nil {
		t.Fatalf("UpdateSSOAuthAttempt() error = %v", err)
	}

	// Verify the update
	time.Sleep(50 * time.Millisecond)
	attempts, err := q.ListSSOAuthAttemptsByProvider(ctx, ListSSOAuthAttemptsByProviderParams{
		ProviderID: provider.ID,
		Limit:      10,
		Offset:     0,
	})
	if err != nil {
		t.Fatalf("ListSSOAuthAttemptsByProvider() error = %v", err)
	}

	if len(attempts) == 0 {
		t.Fatal("expected at least one attempt")
	}

	found := false
	for _, a := range attempts {
		if a.ID.Bytes == attempt.ID.Bytes {
			if a.Status != "success" {
				t.Errorf("expected status 'success', got %s", a.Status)
			}
			found = true
			break
		}
	}
	if !found {
		t.Error("updated attempt not found in list")
	}
}

func TestSSOSessions(t *testing.T) {
	pool, q := setupTestDB(t)
	defer pool.Close()

	ctx := context.Background()

	// Create test tenant
	tenantID := uuid.New()
	_, err := pool.Exec(ctx, "INSERT INTO tenants (id, name) VALUES ($1, $2)", tenantID, "test-tenant-"+tenantID.String())
	if err != nil {
		t.Fatalf("failed to create test tenant: %v", err)
	}

	// Create a test user
	userID := uuid.New()
	_, err = pool.Exec(ctx, "INSERT INTO users (id) VALUES ($1)", userID)
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	// Create an SSO provider
	provider, err := q.CreateSSOProvider(ctx, CreateSSOProviderParams{
		TenantID:     toPgUUID(tenantID),
		Name:         "Okta",
		Slug:         "okta-" + uuid.New().String(),
		ProviderType: "saml",
		EntityID:     toPgText("https://guard.example.com"),
		IdpEntityID:  toPgText("https://okta.example.com"),
		CreatedBy:    toPgUUID(userID),
		UpdatedBy:    toPgUUID(userID),
	})
	if err != nil {
		t.Fatalf("failed to create SSO provider: %v", err)
	}

	// Create an SSO session
	sessionIndex := uuid.New().String()
	expiresAt := time.Now().Add(24 * time.Hour)
	session, err := q.CreateSSOSession(ctx, CreateSSOSessionParams{
		TenantID:     toPgUUID(tenantID),
		ProviderID:   provider.ID,
		UserID:       toPgUUID(userID),
		SessionIndex: pgtype.Text{String: sessionIndex, Valid: true},
		NameID:       pgtype.Text{String: "user@example.com", Valid: true},
		ExpiresAt:    pgtype.Timestamptz{Time: expiresAt, Valid: true},
	})
	if err != nil {
		t.Fatalf("CreateSSOSession() error = %v", err)
	}

	if !session.ID.Valid {
		t.Error("expected valid session ID")
	}

	// Get active sessions
	activeSessions, err := q.GetActiveSSOSessions(ctx, toPgUUID(userID))
	if err != nil {
		t.Fatalf("GetActiveSSOSessions() error = %v", err)
	}

	if len(activeSessions) == 0 {
		t.Fatal("expected at least one active session")
	}

	found := false
	for _, s := range activeSessions {
		if s.ID.Bytes == session.ID.Bytes {
			found = true
			break
		}
	}
	if !found {
		t.Error("created session not found in active sessions")
	}

	// Terminate the session
	err = q.TerminateSSOSession(ctx, session.ID)
	if err != nil {
		t.Fatalf("TerminateSSOSession() error = %v", err)
	}

	// Verify session is terminated
	time.Sleep(50 * time.Millisecond)
	activeSessions2, err := q.GetActiveSSOSessions(ctx, toPgUUID(userID))
	if err != nil {
		t.Fatalf("GetActiveSSOSessions() error = %v", err)
	}

	for _, s := range activeSessions2 {
		if s.ID.Bytes == session.ID.Bytes {
			t.Error("terminated session still appears in active sessions")
		}
	}
}

func TestListSSOProviders(t *testing.T) {
	pool, q := setupTestDB(t)
	defer pool.Close()

	ctx := context.Background()

	// Create test tenant
	tenantID := uuid.New()
	_, err := pool.Exec(ctx, "INSERT INTO tenants (id, name) VALUES ($1, $2)", tenantID, "test-tenant-"+tenantID.String())
	if err != nil {
		t.Fatalf("failed to create test tenant: %v", err)
	}

	// Create a test user
	userID := uuid.New()
	_, err = pool.Exec(ctx, "INSERT INTO users (id) VALUES ($1)", userID)
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	// Create multiple providers
	for i := 0; i < 3; i++ {
		_, err := q.CreateSSOProvider(ctx, CreateSSOProviderParams{
			TenantID:     toPgUUID(tenantID),
			Name:         "Provider " + uuid.New().String(),
			Slug:         "provider-" + uuid.New().String(),
			ProviderType: "oidc",
			Issuer:       toPgText("https://example.com"),
			ClientID:     toPgText("client-id-" + uuid.New().String()),
			CreatedBy:    toPgUUID(userID),
			UpdatedBy:    toPgUUID(userID),
		})
		if err != nil {
			t.Fatalf("failed to create SSO provider: %v", err)
		}
	}

	// List providers
	providers, err := q.ListSSOProviders(ctx, ListSSOProvidersParams{
		TenantID: toPgUUID(tenantID),
		Limit:    10,
		Offset:   0,
	})
	if err != nil {
		t.Fatalf("ListSSOProviders() error = %v", err)
	}

	if len(providers) < 3 {
		t.Errorf("expected at least 3 providers, got %d", len(providers))
	}

	// Verify all returned providers belong to the tenant
	for _, p := range providers {
		if p.TenantID.Bytes != tenantID {
			t.Errorf("provider has wrong tenant_id: expected %v, got %v", tenantID, p.TenantID)
		}
	}
}

func TestDeleteSSOProvider(t *testing.T) {
	pool, q := setupTestDB(t)
	defer pool.Close()

	ctx := context.Background()

	// Create test tenant
	tenantID := uuid.New()
	_, err := pool.Exec(ctx, "INSERT INTO tenants (id, name) VALUES ($1, $2)", tenantID, "test-tenant-"+tenantID.String())
	if err != nil {
		t.Fatalf("failed to create test tenant: %v", err)
	}

	// Create a test user
	userID := uuid.New()
	_, err = pool.Exec(ctx, "INSERT INTO users (id) VALUES ($1)", userID)
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	// Create a provider
	provider, err := q.CreateSSOProvider(ctx, CreateSSOProviderParams{
		TenantID:     toPgUUID(tenantID),
		Name:         "Test Provider",
		Slug:         "test-" + uuid.New().String(),
		ProviderType: "oidc",
		Issuer:       toPgText("https://example.com"),
		ClientID:     toPgText("client-id"),
		CreatedBy:    toPgUUID(userID),
		UpdatedBy:    toPgUUID(userID),
	})
	if err != nil {
		t.Fatalf("failed to create SSO provider: %v", err)
	}

	// Delete the provider
	err = q.DeleteSSOProvider(ctx, DeleteSSOProviderParams{
		ID:       provider.ID,
		TenantID: toPgUUID(tenantID),
	})
	if err != nil {
		t.Fatalf("DeleteSSOProvider() error = %v", err)
	}

	// Verify it's deleted
	_, err = q.GetSSOProvider(ctx, GetSSOProviderParams{
		ID:       provider.ID,
		TenantID: toPgUUID(tenantID),
	})
	if err == nil {
		t.Error("expected error when retrieving deleted provider, got nil")
	}
}

func TestAttributeMapping(t *testing.T) {
	pool, q := setupTestDB(t)
	defer pool.Close()

	ctx := context.Background()

	// Create test tenant
	tenantID := uuid.New()
	_, err := pool.Exec(ctx, "INSERT INTO tenants (id, name) VALUES ($1, $2)", tenantID, "test-tenant-"+tenantID.String())
	if err != nil {
		t.Fatalf("failed to create test tenant: %v", err)
	}

	// Create a test user
	userID := uuid.New()
	_, err = pool.Exec(ctx, "INSERT INTO users (id) VALUES ($1)", userID)
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	// Custom attribute mapping
	attributeMapping := map[string][]string{
		"email":      {"emailAddress", "mail"},
		"first_name": ["givenName"],
		"last_name":  {"sn", "surname"},
		"phone":      {"telephoneNumber"},
	}
	mappingJSON, err := json.Marshal(attributeMapping)
	if err != nil {
		t.Fatalf("failed to marshal attribute mapping: %v", err)
	}

	// Create provider with custom attribute mapping
	provider, err := q.CreateSSOProvider(ctx, CreateSSOProviderParams{
		TenantID:         toPgUUID(tenantID),
		Name:             "Custom Mapping Provider",
		Slug:             "custom-" + uuid.New().String(),
		ProviderType:     "saml",
		EntityID:         toPgText("https://guard.example.com"),
		IdpEntityID:      toPgText("https://idp.example.com"),
		AttributeMapping: mappingJSON,
		CreatedBy:        toPgUUID(userID),
		UpdatedBy:        toPgUUID(userID),
	})
	if err != nil {
		t.Fatalf("failed to create SSO provider: %v", err)
	}

	// Retrieve and verify attribute mapping
	retrieved, err := q.GetSSOProvider(ctx, GetSSOProviderParams{
		ID:       provider.ID,
		TenantID: toPgUUID(tenantID),
	})
	if err != nil {
		t.Fatalf("GetSSOProvider() error = %v", err)
	}

	var retrievedMapping map[string][]string
	err = json.Unmarshal(retrieved.AttributeMapping, &retrievedMapping)
	if err != nil {
		t.Fatalf("failed to unmarshal attribute mapping: %v", err)
	}

	if len(retrievedMapping["phone"]) != 1 || retrievedMapping["phone"][0] != "telephoneNumber" {
		t.Errorf("attribute mapping not preserved correctly")
	}
}
