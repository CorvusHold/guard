package service

import (
	"context"
	"errors"
	"testing"

	"github.com/corvusHold/guard/internal/auth/domain"
	"github.com/google/uuid"
)

type rbacRepoStub struct {
	fakeRepo

	listPermissionsOut []domain.Permission
	listRolesOut       []domain.Role
	createRoleOut      domain.Role
	updateRoleOut      domain.Role
	listRoleIDsOut     []uuid.UUID
	listUserRolesOut   []domain.Role
	listRolePermsOut   []domain.RolePermissionGrant
	listUserACLOut     []domain.PermissionGrant
	listGroupsOut      []uuid.UUID
	listGroupACLOut    []domain.GroupPermissionGrant
	permissionByKeyOut domain.Permission

	listRolePermsErr   error
	listUserACLErr     error
	listGroupsErr      error
	listGroupACLErr    error
	permissionByKeyErr error
	setUserActiveErr   error
	revokeAllErr       error

	createRoleName  string
	updateRoleName  string
	upsertPermID    uuid.UUID
	deletePermID    uuid.UUID
	setUserActiveOn bool
	revokeAllCalled bool
}

func (r *rbacRepoStub) ListPermissions(ctx context.Context) ([]domain.Permission, error) {
	return r.listPermissionsOut, nil
}

func (r *rbacRepoStub) ListRolesByTenant(ctx context.Context, tenantID uuid.UUID) ([]domain.Role, error) {
	return r.listRolesOut, nil
}

func (r *rbacRepoStub) CreateRole(ctx context.Context, id, tenantID uuid.UUID, name, description string) (domain.Role, error) {
	r.createRoleName = name
	if r.createRoleOut.ID == uuid.Nil {
		r.createRoleOut = domain.Role{ID: id, TenantID: tenantID, Name: name, Description: description}
	}
	return r.createRoleOut, nil
}

func (r *rbacRepoStub) UpdateRole(ctx context.Context, roleID, tenantID uuid.UUID, name, description string) (domain.Role, error) {
	r.updateRoleName = name
	if r.updateRoleOut.ID == uuid.Nil {
		r.updateRoleOut = domain.Role{ID: roleID, TenantID: tenantID, Name: name, Description: description}
	}
	return r.updateRoleOut, nil
}

func (r *rbacRepoStub) ListUserRoleIDs(ctx context.Context, userID, tenantID uuid.UUID) ([]uuid.UUID, error) {
	return r.listRoleIDsOut, nil
}

func (r *rbacRepoStub) ListUserRoles(ctx context.Context, userID, tenantID uuid.UUID) ([]domain.Role, error) {
	return r.listUserRolesOut, nil
}

func (r *rbacRepoStub) AddUserRole(ctx context.Context, userID, tenantID, roleID uuid.UUID) error {
	return nil
}

func (r *rbacRepoStub) RemoveUserRole(ctx context.Context, userID, tenantID, roleID uuid.UUID) error {
	return nil
}

func (r *rbacRepoStub) GetPermissionByKey(ctx context.Context, key string) (domain.Permission, error) {
	if r.permissionByKeyErr != nil {
		return domain.Permission{}, r.permissionByKeyErr
	}
	if r.permissionByKeyOut.ID == uuid.Nil {
		r.permissionByKeyOut = domain.Permission{ID: uuid.New(), Key: key}
	}
	return r.permissionByKeyOut, nil
}

func (r *rbacRepoStub) UpsertRolePermission(ctx context.Context, roleID uuid.UUID, permissionID uuid.UUID, scopeType string, resourceType, resourceID *string) error {
	r.upsertPermID = permissionID
	return nil
}

func (r *rbacRepoStub) DeleteRolePermission(ctx context.Context, roleID uuid.UUID, permissionID uuid.UUID, scopeType string, resourceType, resourceID *string) error {
	r.deletePermID = permissionID
	return nil
}

func (r *rbacRepoStub) ListRolePermissionKeys(ctx context.Context, roleIDs []uuid.UUID) ([]domain.RolePermissionGrant, error) {
	if r.listRolePermsErr != nil {
		return nil, r.listRolePermsErr
	}
	return r.listRolePermsOut, nil
}

func (r *rbacRepoStub) ListACLPermissionKeysForUser(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID) ([]domain.PermissionGrant, error) {
	if r.listUserACLErr != nil {
		return nil, r.listUserACLErr
	}
	return r.listUserACLOut, nil
}

func (r *rbacRepoStub) ListUserGroups(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error) {
	if r.listGroupsErr != nil {
		return nil, r.listGroupsErr
	}
	return r.listGroupsOut, nil
}

func (r *rbacRepoStub) ListACLPermissionKeysForGroups(ctx context.Context, tenantID uuid.UUID, groupIDs []uuid.UUID) ([]domain.GroupPermissionGrant, error) {
	if r.listGroupACLErr != nil {
		return nil, r.listGroupACLErr
	}
	return r.listGroupACLOut, nil
}

func (r *rbacRepoStub) SetUserActive(ctx context.Context, userID uuid.UUID, active bool) error {
	r.setUserActiveOn = active
	return r.setUserActiveErr
}

func (r *rbacRepoStub) RevokeAllUserSessions(ctx context.Context, userID uuid.UUID) (int64, error) {
	r.revokeAllCalled = true
	if r.revokeAllErr != nil {
		return 0, r.revokeAllErr
	}
	return 1, nil
}

func TestService_RoleAndPermissionWrappers(t *testing.T) {
	repo := &rbacRepoStub{permissionByKeyOut: domain.Permission{ID: uuid.New(), Key: "users:read"}}
	s := &Service{repo: repo}
	tenantID := uuid.New()
	roleID := uuid.New()

	if _, err := s.CreateRole(context.Background(), tenantID, "   ", "desc"); err == nil {
		t.Fatal("expected role name required error")
	}
	if _, err := s.UpdateRole(context.Background(), roleID, tenantID, "", "desc"); err == nil {
		t.Fatal("expected role name required error")
	}
	if _, err := s.CreateRole(context.Background(), tenantID, " Admin ", "desc"); err != nil {
		t.Fatalf("CreateRole error: %v", err)
	}
	if repo.createRoleName != "admin" {
		t.Fatalf("expected normalized role name admin, got %q", repo.createRoleName)
	}
	if _, err := s.UpdateRole(context.Background(), roleID, tenantID, " Reader ", "desc"); err != nil {
		t.Fatalf("UpdateRole error: %v", err)
	}
	if repo.updateRoleName != "reader" {
		t.Fatalf("expected normalized role name reader, got %q", repo.updateRoleName)
	}

	repo.permissionByKeyErr = errors.New("missing permission")
	if err := s.UpsertRolePermission(context.Background(), roleID, "users:read", "tenant", nil, nil); err == nil {
		t.Fatal("expected permission lookup error for upsert")
	}
	repo.permissionByKeyErr = nil
	if err := s.UpsertRolePermission(context.Background(), roleID, "users:read", "tenant", nil, nil); err != nil {
		t.Fatalf("UpsertRolePermission error: %v", err)
	}
	if repo.upsertPermID != repo.permissionByKeyOut.ID {
		t.Fatalf("expected resolved permission id %s, got %s", repo.permissionByKeyOut.ID, repo.upsertPermID)
	}
	if err := s.DeleteRolePermission(context.Background(), roleID, "users:read", "tenant", nil, nil); err != nil {
		t.Fatalf("DeleteRolePermission error: %v", err)
	}
	if repo.deletePermID != repo.permissionByKeyOut.ID {
		t.Fatalf("expected resolved permission id %s, got %s", repo.permissionByKeyOut.ID, repo.deletePermID)
	}
}

func TestService_ResolveAndHasPermission(t *testing.T) {
	objectID := "obj-1"
	repo := &rbacRepoStub{
		listRoleIDsOut: []uuid.UUID{uuid.New()},
		listRolePermsOut: []domain.RolePermissionGrant{
			{Key: "users:read", ResourceType: nil, ResourceID: nil},
			{Key: "users:write", ResourceType: strPtr("user"), ResourceID: nil},
		},
		listUserACLOut: []domain.PermissionGrant{{Key: "users:write", ObjectType: "user", ObjectID: nil}},
		listGroupsOut:  []uuid.UUID{uuid.New()},
		listGroupACLOut: []domain.GroupPermissionGrant{
			{Key: "users:write", ObjectType: "user", ObjectID: &objectID},
		},
	}
	s := &Service{repo: repo}
	userID := uuid.New()
	tenantID := uuid.New()

	resolved, err := s.ResolveUserPermissions(context.Background(), userID, tenantID)
	if err != nil {
		t.Fatalf("ResolveUserPermissions error: %v", err)
	}
	if len(resolved.Grants) != 3 {
		t.Fatalf("expected 3 deduped grants, got %d: %#v", len(resolved.Grants), resolved.Grants)
	}

	ok, err := s.HasPermission(context.Background(), userID, tenantID, "users:read", "any", nil)
	if err != nil || !ok {
		t.Fatalf("expected wildcard grant allow, ok=%v err=%v", ok, err)
	}
	ok, err = s.HasPermission(context.Background(), userID, tenantID, "users:write", "user", nil)
	if err != nil || !ok {
		t.Fatalf("expected type grant allow, ok=%v err=%v", ok, err)
	}
	ok, err = s.HasPermission(context.Background(), userID, tenantID, "users:write", "user", &objectID)
	if err != nil || !ok {
		t.Fatalf("expected object grant allow, ok=%v err=%v", ok, err)
	}
	other := "obj-2"
	ok, err = s.HasPermission(context.Background(), userID, tenantID, "users:write", "project", &other)
	if err != nil {
		t.Fatalf("unexpected error for denied path: %v", err)
	}
	if ok {
		t.Fatal("expected denied for mismatched object type")
	}
}

func TestService_Authorize_GroupAndInvalidSubject(t *testing.T) {
	objectID := "u-1"
	repo := &rbacRepoStub{listGroupACLOut: []domain.GroupPermissionGrant{{
		GroupID:    uuid.New(),
		Key:        "users:read",
		ObjectType: "user",
		ObjectID:   &objectID,
	}}}
	s := &Service{repo: repo}
	tenantID := uuid.New()
	groupID := uuid.New()

	ok, reason, err := s.Authorize(context.Background(), tenantID, "group", groupID, "users:read", "user", &objectID)
	if err != nil || !ok || reason != "granted" {
		t.Fatalf("expected group authorization granted, ok=%v reason=%q err=%v", ok, reason, err)
	}

	ok, reason, err = s.Authorize(context.Background(), tenantID, "robot", groupID, "users:read", "user", &objectID)
	if err == nil || ok || reason != "invalid_subject_type" {
		t.Fatalf("expected invalid subject type, ok=%v reason=%q err=%v", ok, reason, err)
	}
}

func TestService_SetUserActive_DeactivationRevokesSessionsBestEffort(t *testing.T) {
	uid := uuid.New()
	repo := &rbacRepoStub{revokeAllErr: errors.New("db down")}
	s := &Service{repo: repo}

	if err := s.SetUserActive(context.Background(), uid, true); err != nil {
		t.Fatalf("SetUserActive(active=true) error: %v", err)
	}
	if repo.revokeAllCalled {
		t.Fatal("did not expect revoke all sessions when setting active=true")
	}

	if err := s.SetUserActive(context.Background(), uid, false); err != nil {
		t.Fatalf("SetUserActive(active=false) should ignore revoke errors, got %v", err)
	}
	if !repo.revokeAllCalled {
		t.Fatal("expected revoke all sessions call on deactivation")
	}
}

func strPtr(s string) *string { return &s }
