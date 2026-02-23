package service

import (
	"context"
	"errors"
	"testing"

	"github.com/corvusHold/guard/internal/auth/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type discoveryRepoStub struct {
	fakeRepo
	identities         []domain.AuthIdentity
	identitiesErr      error
	tenantByID         map[uuid.UUID]domain.Tenant
	authIdentityByMail domain.AuthIdentity
	authIdentityErr    error
	userByID           domain.User
	userErr            error
	enabledProviders   []domain.PublicSSOProvider

	listTenantsLimit int
	listUsersLimit   int
	auditLimit       int
}

func (r *discoveryRepoStub) FindAuthIdentitiesByEmail(ctx context.Context, email string) ([]domain.AuthIdentity, error) {
	if r.identitiesErr != nil {
		return nil, r.identitiesErr
	}
	return r.identities, nil
}

func (r *discoveryRepoStub) GetTenantByID(ctx context.Context, tenantID uuid.UUID) (domain.Tenant, error) {
	if t, ok := r.tenantByID[tenantID]; ok {
		return t, nil
	}
	return domain.Tenant{}, errors.New("not found")
}

func (r *discoveryRepoStub) GetAuthIdentityByEmailTenant(ctx context.Context, tenantID uuid.UUID, email string) (domain.AuthIdentity, error) {
	if r.authIdentityErr != nil {
		return domain.AuthIdentity{}, r.authIdentityErr
	}
	return r.authIdentityByMail, nil
}

func (r *discoveryRepoStub) GetUserByID(ctx context.Context, userID uuid.UUID) (domain.User, error) {
	if r.userErr != nil {
		return domain.User{}, r.userErr
	}
	return r.userByID, nil
}

func (r *discoveryRepoStub) ListEnabledSSOProviders(ctx context.Context, tenantID uuid.UUID) ([]domain.PublicSSOProvider, error) {
	return r.enabledProviders, nil
}

func (r *discoveryRepoStub) ListAllTenantsWithStats(ctx context.Context, limit, offset int) ([]domain.TenantStats, error) {
	r.listTenantsLimit = limit
	return []domain.TenantStats{}, nil
}

func (r *discoveryRepoStub) QueryAuditLogs(ctx context.Context, tenantID *uuid.UUID, userID *uuid.UUID, action string, limit, offset int) ([]domain.AuditLogEntry, int, error) {
	r.auditLimit = limit
	return nil, 0, nil
}

func (r *discoveryRepoStub) ListUsersByTenant(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]domain.UserExport, error) {
	r.listUsersLimit = limit
	return nil, nil
}

func TestService_EmailDiscoveryAndUserLookup(t *testing.T) {
	tenantA := uuid.New()
	tenantB := uuid.New()
	uid := uuid.New()
	repo := &discoveryRepoStub{
		identities: []domain.AuthIdentity{
			{TenantID: tenantA, UserID: uid},
			{TenantID: tenantA, UserID: uid},
			{TenantID: tenantB, UserID: uid},
		},
		tenantByID: map[uuid.UUID]domain.Tenant{tenantA: {ID: tenantA, Name: "Acme"}},
		authIdentityByMail: domain.AuthIdentity{UserID: uid, TenantID: tenantA, Email: "user@example.com"},
		userByID:           domain.User{ID: uid, IsActive: true},
		enabledProviders:   []domain.PublicSSOProvider{{Slug: "workos"}},
	}
	s := &Service{repo: repo}

	tenants, err := s.FindTenantsByUserEmail(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("FindTenantsByUserEmail error: %v", err)
	}
	if len(tenants) != 2 {
		t.Fatalf("expected deduped 2 tenants, got %d: %#v", len(tenants), tenants)
	}

	u, err := s.GetUserByEmail(context.Background(), "user@example.com", tenantA.String())
	if err != nil {
		t.Fatalf("GetUserByEmail error: %v", err)
	}
	if u.ID != uid {
		t.Fatalf("unexpected user id: got %s want %s", u.ID, uid)
	}

	providers, err := s.ListSSOProvidersPublic(context.Background(), tenantA)
	if err != nil || len(providers) != 1 {
		t.Fatalf("ListSSOProvidersPublic expected one provider, got %v err=%v", providers, err)
	}
}

func TestService_GetUserByEmail_ErrorPaths(t *testing.T) {
	s := &Service{repo: &discoveryRepoStub{}}
	if _, err := s.GetUserByEmail(context.Background(), "u@example.com", "bad-uuid"); err == nil {
		t.Fatal("expected invalid tenant id error")
	}

	repo := &discoveryRepoStub{authIdentityErr: pgx.ErrNoRows}
	s = &Service{repo: repo}
	if _, err := s.GetUserByEmail(context.Background(), "u@example.com", uuid.NewString()); err == nil || !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected ErrNotFound wrapped error, got %v", err)
	}

	repo.authIdentityErr = nil
	repo.authIdentityByMail = domain.AuthIdentity{UserID: uuid.New(), TenantID: uuid.New(), Email: "u@example.com"}
	repo.userErr = errors.New("db down")
	if _, err := s.GetUserByEmail(context.Background(), "u@example.com", repo.authIdentityByMail.TenantID.String()); err == nil {
		t.Fatal("expected user lookup error")
	}
}

func TestService_PlatformAdmin_DefaultLimits(t *testing.T) {
	repo := &discoveryRepoStub{}
	s := &Service{repo: repo}

	if _, err := s.ListAllTenantsWithStats(context.Background(), 0, 0); err != nil {
		t.Fatalf("ListAllTenantsWithStats error: %v", err)
	}
	if repo.listTenantsLimit != 50 {
		t.Fatalf("expected default tenants limit 50, got %d", repo.listTenantsLimit)
	}

	if _, _, err := s.QueryAuditLogs(context.Background(), nil, nil, "", 0, 0); err != nil {
		t.Fatalf("QueryAuditLogs error: %v", err)
	}
	if repo.auditLimit != 50 {
		t.Fatalf("expected default audit limit 50, got %d", repo.auditLimit)
	}

	if _, err := s.ListUsersByTenant(context.Background(), uuid.New(), 0, 0); err != nil {
		t.Fatalf("ListUsersByTenant error: %v", err)
	}
	if repo.listUsersLimit != 1000 {
		t.Fatalf("expected default users export limit 1000, got %d", repo.listUsersLimit)
	}
}
