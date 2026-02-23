package service

import (
	"context"
	"errors"
	"testing"

	"github.com/corvusHold/guard/internal/auth/domain"
	"github.com/google/uuid"
)

type passthroughRepoStub struct {
	fakeRepo

	listPermissionsOut []domain.Permission
	listPermissionsErr error

	listRolesOut []domain.Role
	listRolesErr error
	listRolesTID uuid.UUID

	deleteRoleErr error
	deleteRoleID  uuid.UUID
	deleteRoleTID uuid.UUID

	listUserRoleIDsOut []uuid.UUID
	listUserRoleIDsErr error
	listUserRoleUID    uuid.UUID
	listUserRoleTID    uuid.UUID

	listUserRolesOut []domain.Role
	listUserRolesErr error

	addUserRoleErr error
	addUserRoleUID uuid.UUID
	addUserRoleTID uuid.UUID
	addUserRoleRID uuid.UUID

	removeUserRoleErr error

	listTenantUsersOut []domain.User
	listTenantUsersErr error
	listTenantUsersTID uuid.UUID

	updateUserNamesErr error
	updatedUID         uuid.UUID
	updatedFirstName   string
	updatedLastName    string

	unlockErr error
	unlockUID uuid.UUID

	setUserEmailVerifiedErr      error
	setUserEmailVerifiedUID      uuid.UUID
	setUserEmailVerifiedVerified bool

	listSessionsOut []domain.RefreshToken
	listSessionsErr error
	revokeChainErr  error
	revokeChainID   uuid.UUID

	listTenantsOut    []domain.TenantStats
	listTenantsErr    error
	listTenantsLimit  int
	listTenantsOffset int

	searchUsersOut   []domain.UserSearchResult
	searchUsersErr   error
	searchUsersQuery string

	queryAuditOut      []domain.AuditLogEntry
	queryAuditTotal    int
	queryAuditErr      error
	queryAuditLimit    int
	queryAuditOffset   int
	queryAuditAction   string
	queryAuditTenantID *uuid.UUID
	queryAuditUserID   *uuid.UUID

	platformStatsOut domain.PlatformStatsResult
	platformStatsErr error

	listUsersByTenantOut    []domain.UserExport
	listUsersByTenantErr    error
	listUsersByTenantTID    uuid.UUID
	listUsersByTenantLimit  int
	listUsersByTenantOffset int

	createGroupOut  domain.Group
	createGroupErr  error
	createGroupName string

	listGroupsOut []domain.Group
	listGroupsErr error

	deleteGroupErr error
	deleteGroupID  uuid.UUID
	deleteGroupTID uuid.UUID

	addGroupMemberErr error
	addGroupID        uuid.UUID
	addGroupUserID    uuid.UUID

	removeGroupMemberErr error

	permissionByKey    domain.Permission
	permissionByKeyErr error

	createTupleOut       domain.ACLTuple
	createTupleErr       error
	createTupleSubjectTy string
	createTupleObjectTy  string

	deleteTupleErr       error
	deleteTupleSubjectTy string
	deleteTupleObjectTy  string

	listRolePermsOut []domain.RolePermissionGrant
	listRolePermsErr error

	userACLPermsOut []domain.PermissionGrant
	userACLPermsErr error

	userGroupsOut []uuid.UUID
	userGroupsErr error

	groupACLPermsOut []domain.GroupPermissionGrant
	groupACLPermsErr error
}

func (r *passthroughRepoStub) ListPermissions(context.Context) ([]domain.Permission, error) {
	return r.listPermissionsOut, r.listPermissionsErr
}
func (r *passthroughRepoStub) ListRolesByTenant(ctx context.Context, tenantID uuid.UUID) ([]domain.Role, error) {
	r.listRolesTID = tenantID
	return r.listRolesOut, r.listRolesErr
}
func (r *passthroughRepoStub) DeleteRole(ctx context.Context, roleID uuid.UUID, tenantID uuid.UUID) error {
	r.deleteRoleID = roleID
	r.deleteRoleTID = tenantID
	return r.deleteRoleErr
}
func (r *passthroughRepoStub) ListUserRoleIDs(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) ([]uuid.UUID, error) {
	r.listUserRoleUID = userID
	r.listUserRoleTID = tenantID
	return r.listUserRoleIDsOut, r.listUserRoleIDsErr
}
func (r *passthroughRepoStub) ListUserRoles(context.Context, uuid.UUID, uuid.UUID) ([]domain.Role, error) {
	return r.listUserRolesOut, r.listUserRolesErr
}
func (r *passthroughRepoStub) AddUserRole(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID, roleID uuid.UUID) error {
	r.addUserRoleUID = userID
	r.addUserRoleTID = tenantID
	r.addUserRoleRID = roleID
	return r.addUserRoleErr
}
func (r *passthroughRepoStub) RemoveUserRole(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) error {
	return r.removeUserRoleErr
}
func (r *passthroughRepoStub) ListTenantUsers(ctx context.Context, tenantID uuid.UUID) ([]domain.User, error) {
	r.listTenantUsersTID = tenantID
	return r.listTenantUsersOut, r.listTenantUsersErr
}
func (r *passthroughRepoStub) UpdateUserNames(ctx context.Context, userID uuid.UUID, firstName, lastName string) error {
	r.updatedUID = userID
	r.updatedFirstName = firstName
	r.updatedLastName = lastName
	return r.updateUserNamesErr
}
func (r *passthroughRepoStub) UnlockAccount(ctx context.Context, userID uuid.UUID) error {
	r.unlockUID = userID
	return r.unlockErr
}
func (r *passthroughRepoStub) SetUserEmailVerified(ctx context.Context, userID uuid.UUID, verified bool) error {
	r.setUserEmailVerifiedUID = userID
	r.setUserEmailVerifiedVerified = verified
	return r.setUserEmailVerifiedErr
}
func (r *passthroughRepoStub) ListUserSessions(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) ([]domain.RefreshToken, error) {
	return r.listSessionsOut, r.listSessionsErr
}
func (r *passthroughRepoStub) RevokeTokenChain(ctx context.Context, tokenID uuid.UUID) error {
	r.revokeChainID = tokenID
	return r.revokeChainErr
}
func (r *passthroughRepoStub) ListAllTenantsWithStats(ctx context.Context, limit, offset int) ([]domain.TenantStats, error) {
	r.listTenantsLimit = limit
	r.listTenantsOffset = offset
	return r.listTenantsOut, r.listTenantsErr
}
func (r *passthroughRepoStub) SearchUsersGlobal(ctx context.Context, query string) ([]domain.UserSearchResult, error) {
	r.searchUsersQuery = query
	return r.searchUsersOut, r.searchUsersErr
}
func (r *passthroughRepoStub) QueryAuditLogs(ctx context.Context, tenantID *uuid.UUID, userID *uuid.UUID, action string, limit, offset int) ([]domain.AuditLogEntry, int, error) {
	r.queryAuditTenantID = tenantID
	r.queryAuditUserID = userID
	r.queryAuditAction = action
	r.queryAuditLimit = limit
	r.queryAuditOffset = offset
	return r.queryAuditOut, r.queryAuditTotal, r.queryAuditErr
}
func (r *passthroughRepoStub) PlatformStats(context.Context) (domain.PlatformStatsResult, error) {
	return r.platformStatsOut, r.platformStatsErr
}
func (r *passthroughRepoStub) ListUsersByTenant(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]domain.UserExport, error) {
	r.listUsersByTenantTID = tenantID
	r.listUsersByTenantLimit = limit
	r.listUsersByTenantOffset = offset
	return r.listUsersByTenantOut, r.listUsersByTenantErr
}
func (r *passthroughRepoStub) CreateGroup(ctx context.Context, id uuid.UUID, tenantID uuid.UUID, name, description string) (domain.Group, error) {
	r.createGroupName = name
	if r.createGroupErr != nil {
		return domain.Group{}, r.createGroupErr
	}
	if r.createGroupOut.ID == uuid.Nil {
		r.createGroupOut = domain.Group{ID: id, TenantID: tenantID, Name: name, Description: description}
	}
	return r.createGroupOut, nil
}
func (r *passthroughRepoStub) ListGroups(ctx context.Context, tenantID uuid.UUID) ([]domain.Group, error) {
	return r.listGroupsOut, r.listGroupsErr
}
func (r *passthroughRepoStub) DeleteGroup(ctx context.Context, id uuid.UUID, tenantID uuid.UUID) error {
	r.deleteGroupID = id
	r.deleteGroupTID = tenantID
	return r.deleteGroupErr
}
func (r *passthroughRepoStub) AddGroupMember(ctx context.Context, groupID uuid.UUID, userID uuid.UUID) error {
	r.addGroupID = groupID
	r.addGroupUserID = userID
	return r.addGroupMemberErr
}
func (r *passthroughRepoStub) RemoveGroupMember(ctx context.Context, groupID uuid.UUID, userID uuid.UUID) error {
	return r.removeGroupMemberErr
}
func (r *passthroughRepoStub) GetPermissionByKey(ctx context.Context, key string) (domain.Permission, error) {
	if r.permissionByKeyErr != nil {
		return domain.Permission{}, r.permissionByKeyErr
	}
	if r.permissionByKey.ID == uuid.Nil {
		r.permissionByKey = domain.Permission{ID: uuid.New(), Key: key}
	}
	return r.permissionByKey, nil
}
func (r *passthroughRepoStub) CreateACLTuple(ctx context.Context, id uuid.UUID, tenantID uuid.UUID, subjectType string, subjectID uuid.UUID, permissionID uuid.UUID, objectType string, objectID *string, createdBy *uuid.UUID) (domain.ACLTuple, error) {
	r.createTupleSubjectTy = subjectType
	r.createTupleObjectTy = objectType
	if r.createTupleErr != nil {
		return domain.ACLTuple{}, r.createTupleErr
	}
	if r.createTupleOut.ID == uuid.Nil {
		r.createTupleOut = domain.ACLTuple{ID: id, TenantID: tenantID, SubjectType: subjectType, SubjectID: subjectID, PermissionID: permissionID, ObjectType: objectType, ObjectID: objectID, CreatedBy: createdBy}
	}
	return r.createTupleOut, nil
}
func (r *passthroughRepoStub) DeleteACLTuple(ctx context.Context, tenantID uuid.UUID, subjectType string, subjectID uuid.UUID, permissionID uuid.UUID, objectType string, objectID *string) error {
	r.deleteTupleSubjectTy = subjectType
	r.deleteTupleObjectTy = objectType
	return r.deleteTupleErr
}
func (r *passthroughRepoStub) ListRolePermissionKeys(ctx context.Context, roleIDs []uuid.UUID) ([]domain.RolePermissionGrant, error) {
	return r.listRolePermsOut, r.listRolePermsErr
}
func (r *passthroughRepoStub) ListACLPermissionKeysForUser(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID) ([]domain.PermissionGrant, error) {
	return r.userACLPermsOut, r.userACLPermsErr
}
func (r *passthroughRepoStub) ListUserGroups(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error) {
	return r.userGroupsOut, r.userGroupsErr
}
func (r *passthroughRepoStub) ListACLPermissionKeysForGroups(ctx context.Context, tenantID uuid.UUID, groupIDs []uuid.UUID) ([]domain.GroupPermissionGrant, error) {
	return r.groupACLPermsOut, r.groupACLPermsErr
}

func TestService_PassthroughAndAdminBranches(t *testing.T) {
	repo := &passthroughRepoStub{}
	s := &Service{repo: repo}
	ctx := context.Background()
	tid := uuid.New()
	uid := uuid.New()
	rid := uuid.New()

	repo.listPermissionsOut = []domain.Permission{{Key: "users:read"}}
	perms, err := s.ListPermissions(ctx)
	if err != nil || len(perms) != 1 {
		t.Fatalf("ListPermissions unexpected result perms=%v err=%v", perms, err)
	}

	repo.listRolesOut = []domain.Role{{ID: rid, TenantID: tid, Name: "admin"}}
	roles, err := s.ListRoles(ctx, tid)
	if err != nil || len(roles) != 1 || repo.listRolesTID != tid {
		t.Fatalf("ListRoles unexpected result roles=%v err=%v tenant=%s", roles, err, repo.listRolesTID)
	}

	if err := s.DeleteRole(ctx, rid, tid); err != nil || repo.deleteRoleID != rid || repo.deleteRoleTID != tid {
		t.Fatalf("DeleteRole unexpected err=%v role=%s tenant=%s", err, repo.deleteRoleID, repo.deleteRoleTID)
	}

	repo.listUserRoleIDsOut = []uuid.UUID{rid}
	ids, err := s.ListUserRoleIDs(ctx, uid, tid)
	if err != nil || len(ids) != 1 || repo.listUserRoleUID != uid || repo.listUserRoleTID != tid {
		t.Fatalf("ListUserRoleIDs unexpected ids=%v err=%v", ids, err)
	}

	repo.listUserRolesOut = []domain.Role{{ID: rid, TenantID: tid, Name: "admin"}}
	userRoles, err := s.ListUserRoles(ctx, uid, tid)
	if err != nil || len(userRoles) != 1 {
		t.Fatalf("ListUserRoles unexpected roles=%v err=%v", userRoles, err)
	}

	if err := s.AddUserRole(ctx, uid, tid, rid); err != nil || repo.addUserRoleUID != uid || repo.addUserRoleTID != tid || repo.addUserRoleRID != rid {
		t.Fatalf("AddUserRole unexpected err=%v args=%s/%s/%s", err, repo.addUserRoleUID, repo.addUserRoleTID, repo.addUserRoleRID)
	}
	if err := s.RemoveUserRole(ctx, uid, tid, rid); err != nil {
		t.Fatalf("RemoveUserRole unexpected err=%v", err)
	}

	repo.listTenantUsersOut = []domain.User{{ID: uid}}
	users, err := s.ListTenantUsers(ctx, tid)
	if err != nil || len(users) != 1 || repo.listTenantUsersTID != tid {
		t.Fatalf("ListTenantUsers unexpected users=%v err=%v tenant=%s", users, err, repo.listTenantUsersTID)
	}

	if err := s.UpdateUserNames(ctx, uid, "  First  ", "  Last  "); err != nil {
		t.Fatalf("UpdateUserNames unexpected err=%v", err)
	}
	if repo.updatedUID != uid || repo.updatedFirstName != "First" || repo.updatedLastName != "Last" {
		t.Fatalf("UpdateUserNames expected trimmed names, got uid=%s first=%q last=%q", repo.updatedUID, repo.updatedFirstName, repo.updatedLastName)
	}

	if err := s.UnlockAccount(ctx, uid); err != nil || repo.unlockUID != uid {
		t.Fatalf("UnlockAccount unexpected err=%v uid=%s", err, repo.unlockUID)
	}
	if err := s.SetUserEmailVerified(ctx, uid, true); err != nil || repo.setUserEmailVerifiedUID != uid || !repo.setUserEmailVerifiedVerified {
		t.Fatalf("SetUserEmailVerified unexpected err=%v uid=%s verified=%v", err, repo.setUserEmailVerifiedUID, repo.setUserEmailVerifiedVerified)
	}
}

func TestService_RevokeSession_Branches(t *testing.T) {
	repo := &passthroughRepoStub{}
	s := &Service{repo: repo}
	ctx := context.Background()
	uid := uuid.New()
	tid := uuid.New()
	sid := uuid.New()

	repo.listSessionsErr = errors.New("list failed")
	if err := s.RevokeSession(ctx, uid, tid, sid); err == nil {
		t.Fatal("expected list sessions error")
	}

	repo.listSessionsErr = nil
	repo.listSessionsOut = []domain.RefreshToken{{ID: uuid.New()}}
	if err := s.RevokeSession(ctx, uid, tid, sid); err == nil || err.Error() != "session not found" {
		t.Fatalf("expected session not found, got %v", err)
	}

	repo.listSessionsOut = []domain.RefreshToken{{ID: sid}}
	repo.revokeChainErr = errors.New("revoke failed")
	if err := s.RevokeSession(ctx, uid, tid, sid); err == nil {
		t.Fatal("expected revoke chain error")
	}

	repo.revokeChainErr = nil
	if err := s.RevokeSession(ctx, uid, tid, sid); err != nil {
		t.Fatalf("unexpected revoke session err=%v", err)
	}
	if repo.revokeChainID != sid {
		t.Fatalf("expected revoke chain id %s, got %s", sid, repo.revokeChainID)
	}
}

func TestService_PlatformAdmin_PassthroughAndDefaults_Extra(t *testing.T) {
	repo := &passthroughRepoStub{}
	s := &Service{repo: repo}
	ctx := context.Background()
	tid := uuid.New()
	uid := uuid.New()

	repo.listTenantsOut = []domain.TenantStats{{ID: tid}}
	tenants, err := s.ListAllTenantsWithStats(ctx, 0, 9)
	if err != nil || len(tenants) != 1 || repo.listTenantsLimit != 50 || repo.listTenantsOffset != 9 {
		t.Fatalf("ListAllTenantsWithStats unexpected tenants=%v err=%v limit=%d offset=%d", tenants, err, repo.listTenantsLimit, repo.listTenantsOffset)
	}

	repo.searchUsersOut = []domain.UserSearchResult{{ID: uid}}
	results, err := s.SearchUsersGlobal(ctx, "alice")
	if err != nil || len(results) != 1 || repo.searchUsersQuery != "alice" {
		t.Fatalf("SearchUsersGlobal unexpected results=%v err=%v query=%q", results, err, repo.searchUsersQuery)
	}

	repo.queryAuditOut = []domain.AuditLogEntry{{Action: "login"}}
	repo.queryAuditTotal = 1
	logs, total, err := s.QueryAuditLogs(ctx, &tid, &uid, "login", -1, 3)
	if err != nil || len(logs) != 1 || total != 1 || repo.queryAuditLimit != 50 || repo.queryAuditOffset != 3 {
		t.Fatalf("QueryAuditLogs unexpected logs=%v total=%d err=%v limit=%d offset=%d", logs, total, err, repo.queryAuditLimit, repo.queryAuditOffset)
	}

	repo.platformStatsOut = domain.PlatformStatsResult{TotalUsers: 42}
	stats, err := s.PlatformStats(ctx)
	if err != nil || stats.TotalUsers != 42 {
		t.Fatalf("PlatformStats unexpected stats=%+v err=%v", stats, err)
	}

	repo.listUsersByTenantOut = []domain.UserExport{{Email: "u@example.com"}}
	exports, err := s.ListUsersByTenant(ctx, tid, 0, 7)
	if err != nil || len(exports) != 1 || repo.listUsersByTenantTID != tid || repo.listUsersByTenantLimit != 1000 || repo.listUsersByTenantOffset != 7 {
		t.Fatalf("ListUsersByTenant unexpected exports=%v err=%v tenant=%s limit=%d offset=%d", exports, err, repo.listUsersByTenantTID, repo.listUsersByTenantLimit, repo.listUsersByTenantOffset)
	}
}

func TestService_FGAWrappers_ValidationAndPassthrough(t *testing.T) {
	repo := &passthroughRepoStub{}
	s := &Service{repo: repo}
	ctx := context.Background()
	tid := uuid.New()
	uid := uuid.New()
	gid := uuid.New()
	objID := "obj-1"

	if _, err := s.CreateGroup(ctx, tid, "   ", "desc"); err == nil {
		t.Fatal("expected group name required error")
	}

	g, err := s.CreateGroup(ctx, tid, "  Team A  ", "  Desc  ")
	if err != nil {
		t.Fatalf("CreateGroup unexpected err=%v", err)
	}
	if g.ID == uuid.Nil || repo.createGroupName != "Team A" {
		t.Fatalf("CreateGroup expected trimmed name and non-empty id, got name=%q group=%+v", repo.createGroupName, g)
	}

	repo.listGroupsOut = []domain.Group{{ID: gid, TenantID: tid, Name: "Team A"}}
	groups, err := s.ListGroups(ctx, tid)
	if err != nil || len(groups) != 1 {
		t.Fatalf("ListGroups unexpected groups=%v err=%v", groups, err)
	}

	if err := s.DeleteGroup(ctx, gid, tid); err != nil || repo.deleteGroupID != gid || repo.deleteGroupTID != tid {
		t.Fatalf("DeleteGroup unexpected err=%v id=%s tenant=%s", err, repo.deleteGroupID, repo.deleteGroupTID)
	}

	if err := s.AddGroupMember(ctx, gid, uid); err != nil || repo.addGroupID != gid || repo.addGroupUserID != uid {
		t.Fatalf("AddGroupMember unexpected err=%v group=%s user=%s", err, repo.addGroupID, repo.addGroupUserID)
	}
	if err := s.RemoveGroupMember(ctx, gid, uid); err != nil {
		t.Fatalf("RemoveGroupMember unexpected err=%v", err)
	}

	repo.permissionByKeyErr = errors.New("perm lookup failed")
	if _, err := s.CreateACLTuple(ctx, tid, "user", uid, "users:read", "user", &objID, nil); err == nil {
		t.Fatal("expected CreateACLTuple permission lookup error")
	}
	repo.permissionByKeyErr = nil

	if _, err := s.CreateACLTuple(ctx, tid, "bad", uid, "users:read", "user", &objID, nil); err == nil {
		t.Fatal("expected CreateACLTuple subject type validation error")
	}
	if _, err := s.CreateACLTuple(ctx, tid, "user", uid, "users:read", "   ", &objID, nil); err == nil {
		t.Fatal("expected CreateACLTuple object type required error")
	}

	tuple, err := s.CreateACLTuple(ctx, tid, "  USER ", uid, "users:read", " document ", &objID, nil)
	if err != nil {
		t.Fatalf("CreateACLTuple unexpected err=%v", err)
	}
	if tuple.ID == uuid.Nil || repo.createTupleSubjectTy != "user" || repo.createTupleObjectTy != "document" {
		t.Fatalf("CreateACLTuple expected normalized fields, got tuple=%+v subject=%q object=%q", tuple, repo.createTupleSubjectTy, repo.createTupleObjectTy)
	}

	repo.permissionByKeyErr = errors.New("perm lookup failed")
	if err := s.DeleteACLTuple(ctx, tid, "group", gid, "users:read", "document", &objID); err == nil {
		t.Fatal("expected DeleteACLTuple permission lookup error")
	}
	repo.permissionByKeyErr = nil

	if err := s.DeleteACLTuple(ctx, tid, "bad", gid, "users:read", "document", &objID); err == nil {
		t.Fatal("expected DeleteACLTuple subject type validation error")
	}
	if err := s.DeleteACLTuple(ctx, tid, "group", gid, "users:read", "  ", &objID); err == nil {
		t.Fatal("expected DeleteACLTuple object type required error")
	}

	if err := s.DeleteACLTuple(ctx, tid, " GROUP ", gid, "users:read", " doc ", &objID); err != nil {
		t.Fatalf("DeleteACLTuple unexpected err=%v", err)
	}
	if repo.deleteTupleSubjectTy != "group" || repo.deleteTupleObjectTy != "doc" {
		t.Fatalf("DeleteACLTuple expected normalized fields, got subject=%q object=%q", repo.deleteTupleSubjectTy, repo.deleteTupleObjectTy)
	}

	repo.listSessionsOut = []domain.RefreshToken{{ID: uuid.New()}}
	sessions, err := s.ListUserSessions(ctx, uid, tid)
	if err != nil || len(sessions) != 1 {
		t.Fatalf("ListUserSessions unexpected sessions=%v err=%v", sessions, err)
	}
}

func TestService_Authorize_Branches(t *testing.T) {
	repo := &passthroughRepoStub{}
	s := &Service{repo: repo}
	ctx := context.Background()
	tid := uuid.New()
	uid := uuid.New()
	objID := "u-1"

	allowed, reason, err := s.Authorize(ctx, tid, "service", uid, "users:read", "user", &objID)
	if err == nil || reason != "invalid_subject_type" || allowed {
		t.Fatalf("expected invalid subject_type rejection, got allowed=%v reason=%q err=%v", allowed, reason, err)
	}

	repo.listUserRoleIDsOut = []uuid.UUID{uuid.New()}
	repo.listRolePermsOut = []domain.RolePermissionGrant{{Key: "users:read", ResourceType: nil, ResourceID: nil}}
	allowed, reason, err = s.Authorize(ctx, tid, "user", uid, "users:read", "user", nil)
	if err != nil || !allowed || reason != "granted" {
		t.Fatalf("expected user global grant, got allowed=%v reason=%q err=%v", allowed, reason, err)
	}

	repo.listRolePermsOut = nil
	repo.userACLPermsOut = []domain.PermissionGrant{{Key: "users:read", ObjectType: "user", ObjectID: &objID}}
	allowed, reason, err = s.Authorize(ctx, tid, "user", uid, "users:read", "user", &objID)
	if err != nil || !allowed || reason != "granted" {
		t.Fatalf("expected user object grant, got allowed=%v reason=%q err=%v", allowed, reason, err)
	}

	repo.userACLPermsOut = nil
	allowed, reason, err = s.Authorize(ctx, tid, "user", uid, "users:read", "user", &objID)
	if err != nil || allowed || reason != "denied" {
		t.Fatalf("expected user denied branch, got allowed=%v reason=%q err=%v", allowed, reason, err)
	}

	repo.groupACLPermsErr = errors.New("group acl failed")
	allowed, reason, err = s.Authorize(ctx, tid, "group", uid, "users:read", "user", &objID)
	if err == nil || reason != "error" || allowed {
		t.Fatalf("expected group error branch, got allowed=%v reason=%q err=%v", allowed, reason, err)
	}

	repo.groupACLPermsErr = nil
	repo.groupACLPermsOut = []domain.GroupPermissionGrant{{GroupID: uid, Key: "users:read", ObjectType: "*", ObjectID: nil}}
	allowed, reason, err = s.Authorize(ctx, tid, "group", uid, "users:read", "user", &objID)
	if err != nil || !allowed || reason != "granted" {
		t.Fatalf("expected group wildcard grant, got allowed=%v reason=%q err=%v", allowed, reason, err)
	}

	repo.groupACLPermsOut = nil
	allowed, reason, err = s.Authorize(ctx, tid, "group", uid, "users:read", "user", &objID)
	if err != nil || allowed || reason != "denied" {
		t.Fatalf("expected group denied, got allowed=%v reason=%q err=%v", allowed, reason, err)
	}
}
