package service

import (
	"context"
	"errors"
	"os"
	"testing"

	authdomain "github.com/corvusHold/guard/internal/auth/domain"
	ssodomain "github.com/corvusHold/guard/internal/auth/sso/domain"
	ssosvc "github.com/corvusHold/guard/internal/auth/sso/service"
	"github.com/corvusHold/guard/internal/config"
	db "github.com/corvusHold/guard/internal/db/sqlc"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

func setupTestSSOInfra(t *testing.T, enabled bool) (*SSO, *fakeRepo, uuid.UUID, uuid.UUID, uuid.UUID, string) {
	t.Helper()

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("skipping integration test: DATABASE_URL not set")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("failed to connect to db: %v", err)
	}

	t.Cleanup(func() {
		pool.Close()
	})

	queries := db.New(pool)

	tenantID := uuid.New()
	if _, err := pool.Exec(ctx, "INSERT INTO tenants (id, name) VALUES ($1, $2)", tenantID, "test-tenant-"+tenantID.String()); err != nil {
		t.Fatalf("failed to create test tenant: %v", err)
	}

	userID := uuid.New()
	if _, err := pool.Exec(ctx, "INSERT INTO users (id) VALUES ($1)", userID); err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	slug := "portal-provider-" + uuid.New().String()

	provider, err := queries.CreateSSOProvider(ctx, db.CreateSSOProviderParams{
		TenantID:     toPgUUID(tenantID),
		Name:         "Portal Test Provider",
		Slug:         slug,
		ProviderType: "oidc",
		Issuer:       toPgText("https://accounts.example.com"),
		ClientID:     toPgText("client-id"),
		Enabled:      toPgBool(enabled),
		CreatedBy:    toPgUUID(userID),
		UpdatedBy:    toPgUUID(userID),
	})
	if err != nil {
		t.Fatalf("failed to create SSO provider: %v", err)
	}

	redisClient := redis.NewClient(&redis.Options{Addr: "127.0.0.1:0"})
	ssoSvc := ssosvc.New(pool, redisClient, "https://guard.example.test")

	repo := &fakeRepo{}
	cfg := config.Config{PublicBaseURL: "https://guard.example.test"}
	settings := fakeSettings{strings: map[string]string{}}

	s := NewSSO(repo, cfg, settings)
	s.SetSSOProviderService(ssoSvc)

	return s, repo, tenantID, userID, uuid.UUID(provider.ID.Bytes), provider.Slug
}

func TestOrganizationPortalLinkGenerator_DisabledProviderReturnsTypedError(t *testing.T) {
	s, _, tenantID, userID, _, slug := setupTestSSOInfra(t, false)

	ctx := context.Background()
	in := authdomain.SSOOrganizationPortalLinkGeneratorInput{
		Provider:  slug,
		TenantID:  tenantID,
		Intent:    "sso-configure",
		CreatedBy: userID,
	}

	_, err := s.OrganizationPortalLinkGenerator(ctx, in)
	if err == nil {
		t.Fatal("expected error for disabled provider, got nil")
	}

	var typedErr ssodomain.ErrProviderDisabled
	if !errors.As(err, &typedErr) {
		t.Fatalf("expected ErrProviderDisabled, got %T: %v", err, err)
	}
	if typedErr.ProviderSlug != slug {
		t.Fatalf("expected ProviderSlug %q, got %q", slug, typedErr.ProviderSlug)
	}
}

func TestOrganizationPortalLinkGenerator_NativeProviderSingleUseToken(t *testing.T) {
	s, repo, tenantID, userID, providerID, slug := setupTestSSOInfra(t, true)

	ctx := context.Background()
	in := authdomain.SSOOrganizationPortalLinkGeneratorInput{
		Provider:  slug,
		TenantID:  tenantID,
		Intent:    "sso-configure",
		CreatedBy: userID,
	}

	link, err := s.OrganizationPortalLinkGenerator(ctx, in)
	if err != nil {
		t.Fatalf("OrganizationPortalLinkGenerator error: %v", err)
	}
	if link.Link == "" {
		t.Fatal("expected non-empty portal link")
	}

	if repo.lastPortalToken.MaxUses != 10 {
		t.Fatalf("expected max_uses=10, got %d", repo.lastPortalToken.MaxUses)
	}
	if repo.lastPortalToken.TenantID != tenantID {
		t.Fatalf("expected TenantID %s, got %s", tenantID, repo.lastPortalToken.TenantID)
	}
	if repo.lastPortalToken.SSOProviderID == nil || *repo.lastPortalToken.SSOProviderID != providerID {
		t.Fatalf("expected SSOProviderID %s, got %v", providerID, repo.lastPortalToken.SSOProviderID)
	}
	if repo.lastPortalToken.ProviderSlug != slug {
		t.Fatalf("expected ProviderSlug %q, got %q", slug, repo.lastPortalToken.ProviderSlug)
	}
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
