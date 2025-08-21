package service

import (
	"context"
	"testing"
	"time"

	"github.com/corvusHold/guard/internal/auth/domain"
	"github.com/google/uuid"
)

type fakeRepo struct {
	capturedUserID uuid.UUID
	capturedRoles  []string
}

func (f *fakeRepo) CreateUser(ctx context.Context, id uuid.UUID, firstName, lastName string, roles []string) error {
	return nil
}
func (f *fakeRepo) CreateAuthIdentity(ctx context.Context, id uuid.UUID, userID uuid.UUID, tenantID uuid.UUID, email, passwordHash string) error {
	return nil
}
func (f *fakeRepo) GetAuthIdentityByEmailTenant(ctx context.Context, tenantID uuid.UUID, email string) (domain.AuthIdentity, error) {
	return domain.AuthIdentity{}, nil
}
func (f *fakeRepo) UpdateUserLoginAt(ctx context.Context, userID uuid.UUID) error { return nil }
func (f *fakeRepo) AddUserToTenant(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) error { return nil }
func (f *fakeRepo) InsertRefreshToken(ctx context.Context, id uuid.UUID, userID uuid.UUID, tenantID uuid.UUID, tokenHash string, parentID *uuid.UUID, userAgent, ip string, expiresAt time.Time) error {
	return nil
}
func (f *fakeRepo) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (domain.RefreshToken, error) {
	return domain.RefreshToken{}, nil
}
func (f *fakeRepo) RevokeTokenChain(ctx context.Context, id uuid.UUID) error { return nil }
func (f *fakeRepo) CreateMagicLink(ctx context.Context, id uuid.UUID, userID *uuid.UUID, tenantID uuid.UUID, email, tokenHash, redirectURL string, expiresAt time.Time) error {
	return nil
}
func (f *fakeRepo) GetMagicLinkByHash(ctx context.Context, tokenHash string) (domain.MagicLink, error) {
	return domain.MagicLink{}, nil
}
func (f *fakeRepo) ConsumeMagicLink(ctx context.Context, tokenHash string) error { return nil }
func (f *fakeRepo) GetUserByID(ctx context.Context, userID uuid.UUID) (domain.User, error) {
	return domain.User{ID: userID}, nil
}
func (f *fakeRepo) GetAuthIdentitiesByUser(ctx context.Context, userID uuid.UUID) ([]domain.AuthIdentity, error) {
	return nil, nil
}
func (f *fakeRepo) UpdateUserRoles(ctx context.Context, userID uuid.UUID, roles []string) error {
	f.capturedUserID = userID
	f.capturedRoles = append([]string{}, roles...)
	return nil
}
func (f *fakeRepo) UpsertMFASecret(ctx context.Context, userID uuid.UUID, secret string, enabled bool) error {
	return nil
}
func (f *fakeRepo) GetMFASecret(ctx context.Context, userID uuid.UUID) (domain.MFASecret, error) {
	return domain.MFASecret{}, nil
}
func (f *fakeRepo) InsertMFABackupCode(ctx context.Context, id uuid.UUID, userID uuid.UUID, codeHash string) error { return nil }
func (f *fakeRepo) CountRemainingMFABackupCodes(ctx context.Context, userID uuid.UUID) (int64, error) { return 0, nil }
func (f *fakeRepo) ConsumeMFABackupCode(ctx context.Context, userID uuid.UUID, codeHash string) (bool, error) {
	return false, nil
}

// New methods required by domain.Repository
func (f *fakeRepo) ListTenantUsers(ctx context.Context, tenantID uuid.UUID) ([]domain.User, error) {
	return nil, nil
}
func (f *fakeRepo) SetUserActive(ctx context.Context, userID uuid.UUID, active bool) error { return nil }
func (f *fakeRepo) UpdateUserNames(ctx context.Context, userID uuid.UUID, firstName, lastName string) error {
	return nil
}
func (f *fakeRepo) ListUserSessions(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) ([]domain.RefreshToken, error) {
	return nil, nil
}

// --- RBAC v2 stubs to satisfy domain.Repository ---
// Permissions
func (f *fakeRepo) ListPermissions(ctx context.Context) ([]domain.Permission, error) {
	return nil, nil
}
func (f *fakeRepo) GetPermissionByKey(ctx context.Context, key string) (domain.Permission, error) {
	return domain.Permission{}, nil
}

// Roles
func (f *fakeRepo) ListRolesByTenant(ctx context.Context, tenantID uuid.UUID) ([]domain.Role, error) {
	return nil, nil
}
func (f *fakeRepo) CreateRole(ctx context.Context, id uuid.UUID, tenantID uuid.UUID, name, description string) (domain.Role, error) {
	return domain.Role{}, nil
}
func (f *fakeRepo) UpdateRole(ctx context.Context, roleID uuid.UUID, tenantID uuid.UUID, name, description string) (domain.Role, error) {
	return domain.Role{}, nil
}
func (f *fakeRepo) DeleteRole(ctx context.Context, roleID uuid.UUID, tenantID uuid.UUID) error { return nil }
func (f *fakeRepo) GetRoleByName(ctx context.Context, tenantID uuid.UUID, name string) (domain.Role, error) {
	return domain.Role{}, nil
}

// User role assignments
func (f *fakeRepo) ListUserRoleIDs(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) ([]uuid.UUID, error) {
	return nil, nil
}
func (f *fakeRepo) AddUserRole(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID, roleID uuid.UUID) error {
	return nil
}
func (f *fakeRepo) RemoveUserRole(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID, roleID uuid.UUID) error {
	return nil
}

// Role-permissions
func (f *fakeRepo) ListRolePermissionKeys(ctx context.Context, roleIDs []uuid.UUID) ([]domain.RolePermissionGrant, error) {
	return nil, nil
}
func (f *fakeRepo) UpsertRolePermission(ctx context.Context, roleID uuid.UUID, permissionID uuid.UUID, scopeType string, resourceType, resourceID *string) error {
	return nil
}
func (f *fakeRepo) DeleteRolePermission(ctx context.Context, roleID uuid.UUID, permissionID uuid.UUID, scopeType string, resourceType, resourceID *string) error {
	return nil
}

// Groups and ACL
func (f *fakeRepo) ListUserGroups(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error) { return nil, nil }
func (f *fakeRepo) ListACLPermissionKeysForUser(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID) ([]domain.PermissionGrant, error) {
	return nil, nil
}
func (f *fakeRepo) ListACLPermissionKeysForGroups(ctx context.Context, tenantID uuid.UUID, groupIDs []uuid.UUID) ([]domain.GroupPermissionGrant, error) {
	return nil, nil
}

func TestService_UpdateUserRoles_NormalizesAndDedupes(t *testing.T) {
	repo := &fakeRepo{}
	s := &Service{repo: repo}
	uid := uuid.New()
	in := []string{" Admin ", "member", "ADMIN", "", "member", "Editor", "editor "}
	if err := s.UpdateUserRoles(context.Background(), uid, in); err != nil {
		t.Fatalf("UpdateUserRoles error: %v", err)
	}
	if repo.capturedUserID != uid {
		t.Fatalf("user id mismatch: got %s want %s", repo.capturedUserID, uid)
	}
	want := []string{"admin", "member", "editor"}
	if len(repo.capturedRoles) != len(want) {
		t.Fatalf("roles length mismatch: got %v want %v", repo.capturedRoles, want)
	}
	for i, r := range want {
		if repo.capturedRoles[i] != r {
			t.Fatalf("role[%d]=%q want %q (got=%v)", i, repo.capturedRoles[i], r, repo.capturedRoles)
		}
	}
}
