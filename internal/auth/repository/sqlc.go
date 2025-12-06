package repository

import (
	"context"
	"errors"
	"time"

	domain "github.com/corvusHold/guard/internal/auth/domain"
	db "github.com/corvusHold/guard/internal/db/sqlc"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SQLCRepository struct {
	q    *db.Queries
	pool *pgxpool.Pool
}

func mapGroup(g db.Group) domain.Group {
	return domain.Group{
		ID:          toUUID(g.ID),
		TenantID:    toUUID(g.TenantID),
		Name:        g.Name,
		Description: g.Description.String,
		CreatedAt:   g.CreatedAt.Time,
		UpdatedAt:   g.UpdatedAt.Time,
	}
}

func mapACLTuple(t db.AclTuple) domain.ACLTuple {
	var oid *string
	if t.ObjectID.Valid {
		s := t.ObjectID.String
		oid = &s
	}
	var cb *uuid.UUID
	if t.CreatedBy.Valid {
		u := toUUID(t.CreatedBy)
		cb = &u
	}
	return domain.ACLTuple{
		ID:           toUUID(t.ID),
		TenantID:     toUUID(t.TenantID),
		SubjectType:  t.SubjectType,
		SubjectID:    toUUID(t.SubjectID),
		PermissionID: toUUID(t.PermissionID),
		ObjectType:   t.ObjectType,
		ObjectID:     oid,
		CreatedBy:    cb,
		CreatedAt:    t.CreatedAt.Time,
	}
}

// --- RBAC v2 mappings ---
func mapRole(r db.Role) domain.Role {
	return domain.Role{
		ID:          toUUID(r.ID),
		TenantID:    toUUID(r.TenantID),
		Name:        r.Name,
		Description: r.Description.String,
		CreatedAt:   r.CreatedAt.Time,
		UpdatedAt:   r.UpdatedAt.Time,
	}
}

func mapPermission(p db.Permission) domain.Permission {
	return domain.Permission{
		ID:          toUUID(p.ID),
		Key:         p.Key,
		Description: p.Description.String,
		CreatedAt:   p.CreatedAt.Time,
		UpdatedAt:   p.UpdatedAt.Time,
	}
}

func mapRolePermissionKeyRow(r db.ListRolePermissionKeysRow) domain.RolePermissionGrant {
	var rt *string
	if r.ResourceType.Valid {
		s := r.ResourceType.String
		rt = &s
	}
	var rid *string
	if r.ResourceID.Valid {
		s := r.ResourceID.String
		rid = &s
	}
	return domain.RolePermissionGrant{
		RoleID:       toUUID(r.RoleID),
		Key:          r.Key,
		ScopeType:    r.ScopeType,
		ResourceType: rt,
		ResourceID:   rid,
	}
}

// --- Admin/user management ---

// ListTenantUsers returns all users that belong to the given tenant.
func (r *SQLCRepository) ListTenantUsers(ctx context.Context, tenantID uuid.UUID) ([]domain.User, error) {
	items, err := r.q.ListTenantUsers(ctx, toPgUUID(tenantID))
	if err != nil {
		return nil, err
	}
	out := make([]domain.User, 0, len(items))
	for _, u := range items {
		out = append(out, mapUser(u))
	}
	return out, nil
}

// SetUserActive toggles the active state of a user.
func (r *SQLCRepository) SetUserActive(ctx context.Context, userID uuid.UUID, active bool) error {
	return r.q.SetUserActive(ctx, db.SetUserActiveParams{ID: toPgUUID(userID), IsActive: active})
}

// UpdateUserNames updates only first and last name for a user, preserving roles.
func (r *SQLCRepository) UpdateUserNames(ctx context.Context, userID uuid.UUID, firstName, lastName string) error {
	// Load current roles to preserve
	u, err := r.q.GetUserByID(ctx, toPgUUID(userID))
	if err != nil {
		return err
	}
	return r.q.UpdateUserProfile(ctx, db.UpdateUserProfileParams{
		ID:        toPgUUID(userID),
		FirstName: toPgText(firstName),
		LastName:  toPgText(lastName),
		Roles:     u.Roles,
	})
}

// ListUserSessions lists refresh tokens (sessions) for a user within a tenant.
func (r *SQLCRepository) ListUserSessions(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) ([]domain.RefreshToken, error) {
	items, err := r.q.ListUserSessions(ctx, db.ListUserSessionsParams{UserID: toPgUUID(userID), TenantID: toPgUUID(tenantID)})
	if err != nil {
		return nil, err
	}
	out := make([]domain.RefreshToken, 0, len(items))
	for _, rt := range items {
		out = append(out, mapRefreshToken(rt))
	}
	return out, nil
}

func mapMFASecret(ms db.MfaSecret) domain.MFASecret {
	return domain.MFASecret{
		UserID:    toUUID(ms.UserID),
		Secret:    ms.Secret,
		Enabled:   ms.Enabled,
		CreatedAt: ms.CreatedAt.Time,
	}
}

func mapUser(u db.User) domain.User {
	var last *time.Time
	if u.LastLoginAt.Valid {
		t := u.LastLoginAt.Time
		last = &t
	}
	return domain.User{
		ID:            toUUID(u.ID),
		EmailVerified: u.EmailVerified,
		IsActive:      u.IsActive,
		FirstName:     u.FirstName.String,
		LastName:      u.LastName.String,
		Roles:         u.Roles,
		CreatedAt:     u.CreatedAt.Time,
		UpdatedAt:     u.UpdatedAt.Time,
		LastLoginAt:   last,
	}
}

func New(pg *pgxpool.Pool) *SQLCRepository { return &SQLCRepository{q: db.New(pg), pool: pg} }

func toPgUUID(u uuid.UUID) pgtype.UUID        { return pgtype.UUID{Bytes: u, Valid: true} }
func toPgText(s string) pgtype.Text           { return pgtype.Text{String: s, Valid: s != ""} }
func toPgTime(t time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: t, Valid: true} }
func toPgUUIDNullable(u *uuid.UUID) pgtype.UUID {
	if u == nil {
		return pgtype.UUID{}
	}
	return toPgUUID(*u)
}
func toPgTextNullable(s *string) pgtype.Text {
	if s == nil {
		return pgtype.Text{}
	}
	return toPgText(*s)
}

func toUUID(u pgtype.UUID) uuid.UUID { return uuid.UUID(u.Bytes) }

func mapAuthIdentity(ai db.AuthIdentity) domain.AuthIdentity {
	return domain.AuthIdentity{
		ID:           toUUID(ai.ID),
		UserID:       toUUID(ai.UserID),
		TenantID:     toUUID(ai.TenantID),
		Email:        ai.Email,
		PasswordHash: ai.PasswordHash.String,
	}
}

func mapRefreshToken(rt db.RefreshToken) domain.RefreshToken {
	return domain.RefreshToken{
		ID:        toUUID(rt.ID),
		UserID:    toUUID(rt.UserID),
		TenantID:  toUUID(rt.TenantID),
		Revoked:   rt.Revoked,
		ExpiresAt: rt.ExpiresAt.Time,
		CreatedAt: rt.CreatedAt.Time,
		UserAgent: rt.UserAgent.String,
		IP:        rt.Ip.String,
	}
}

func mapMagicLink(ml db.MagicLink) domain.MagicLink {
	var uid *uuid.UUID
	if ml.UserID.Valid {
		u := toUUID(ml.UserID)
		uid = &u
	}
	var consumed *time.Time
	if ml.ConsumedAt.Valid {
		t := ml.ConsumedAt.Time
		consumed = &t
	}
	return domain.MagicLink{
		ID:          toUUID(ml.ID),
		UserID:      uid,
		TenantID:    toUUID(ml.TenantID),
		Email:       ml.Email.String,
		TokenHash:   ml.TokenHash,
		RedirectURL: ml.RedirectUrl.String,
		CreatedAt:   ml.CreatedAt.Time,
		ExpiresAt:   ml.ExpiresAt.Time,
		ConsumedAt:  consumed,
	}
}

func mapSSOPortalToken(t db.SsoPortalToken) domain.SSOPortalToken {
	var providerID *uuid.UUID
	if t.SsoProviderID.Valid {
		u := toUUID(t.SsoProviderID)
		providerID = &u
	}
	var revokedAt *time.Time
	if t.RevokedAt.Valid {
		v := t.RevokedAt.Time
		revokedAt = &v
	}
	var lastUsedAt *time.Time
	if t.LastUsedAt.Valid {
		v := t.LastUsedAt.Time
		lastUsedAt = &v
	}
	return domain.SSOPortalToken{
		ID:            toUUID(t.ID),
		TenantID:      toUUID(t.TenantID),
		SSOProviderID: providerID,
		ProviderSlug:  t.ProviderSlug,
		TokenHash:     t.TokenHash,
		Intent:        t.Intent,
		CreatedBy:     toUUID(t.CreatedBy),
		ExpiresAt:     t.ExpiresAt.Time,
		RevokedAt:     revokedAt,
		MaxUses:       t.MaxUses,
		UseCount:      t.UseCount,
		LastUsedAt:    lastUsedAt,
		CreatedAt:     t.CreatedAt.Time,
	}
}

func (r *SQLCRepository) CreateUser(ctx context.Context, id uuid.UUID, firstName, lastName string, roles []string) error {
	return r.q.CreateUser(ctx, db.CreateUserParams{
		ID:            toPgUUID(id),
		EmailVerified: false,
		IsActive:      true,
		FirstName:     toPgText(firstName),
		LastName:      toPgText(lastName),
		Roles:         roles,
	})
}

func (r *SQLCRepository) CreateAuthIdentity(ctx context.Context, id uuid.UUID, userID uuid.UUID, tenantID uuid.UUID, email, passwordHash string) error {
	return r.q.CreateAuthIdentity(ctx, db.CreateAuthIdentityParams{
		ID:           toPgUUID(id),
		UserID:       toPgUUID(userID),
		TenantID:     toPgUUID(tenantID),
		Email:        email,
		PasswordHash: toPgText(passwordHash),
	})
}

func (r *SQLCRepository) GetAuthIdentityByEmailTenant(ctx context.Context, tenantID uuid.UUID, email string) (domain.AuthIdentity, error) {
	ai, err := r.q.GetAuthIdentityByEmailTenant(ctx, db.GetAuthIdentityByEmailTenantParams{
		TenantID: toPgUUID(tenantID),
		Email:    email,
	})
	if err != nil {
		return domain.AuthIdentity{}, err
	}
	return mapAuthIdentity(db.AuthIdentity{
		ID:           ai.ID,
		UserID:       ai.UserID,
		TenantID:     ai.TenantID,
		Email:        ai.Email,
		PasswordHash: ai.PasswordHash,
	}), nil
}

func (r *SQLCRepository) UpdateUserLoginAt(ctx context.Context, userID uuid.UUID) error {
	return r.q.UpdateUserLastLogin(ctx, toPgUUID(userID))
}

func (r *SQLCRepository) AddUserToTenant(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) error {
	return r.q.AddUserToTenant(ctx, db.AddUserToTenantParams{UserID: toPgUUID(userID), TenantID: toPgUUID(tenantID)})
}

func (r *SQLCRepository) InsertRefreshToken(ctx context.Context, id uuid.UUID, userID uuid.UUID, tenantID uuid.UUID, tokenHash string, parentID *uuid.UUID, userAgent, ip string, expiresAt time.Time) error {
	pid := pgtype.UUID{}
	if parentID != nil {
		pid = toPgUUID(*parentID)
	}
	return r.q.InsertRefreshToken(ctx, db.InsertRefreshTokenParams{
		ID:        toPgUUID(id),
		UserID:    toPgUUID(userID),
		TenantID:  toPgUUID(tenantID),
		TokenHash: tokenHash,
		ParentID:  pid,
		UserAgent: toPgText(userAgent),
		Ip:        toPgText(ip),
		ExpiresAt: toPgTime(expiresAt),
	})
}

func (r *SQLCRepository) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (domain.RefreshToken, error) {
	rt, err := r.q.GetRefreshTokenByHash(ctx, tokenHash)
	if err != nil {
		return domain.RefreshToken{}, err
	}
	return mapRefreshToken(rt), nil
}

func (r *SQLCRepository) RevokeTokenChain(ctx context.Context, id uuid.UUID) error {
	return r.q.RevokeTokenChain(ctx, toPgUUID(id))
}

// Magic link operations
func (r *SQLCRepository) CreateMagicLink(ctx context.Context, id uuid.UUID, userID *uuid.UUID, tenantID uuid.UUID, email, tokenHash, redirectURL string, expiresAt time.Time) error {
	return r.q.CreateMagicLink(ctx, db.CreateMagicLinkParams{
		ID:          toPgUUID(id),
		UserID:      toPgUUIDNullable(userID),
		TenantID:    toPgUUID(tenantID),
		Email:       toPgText(email),
		TokenHash:   tokenHash,
		RedirectUrl: toPgText(redirectURL),
		ExpiresAt:   toPgTime(expiresAt),
	})
}

func (r *SQLCRepository) GetMagicLinkByHash(ctx context.Context, tokenHash string) (domain.MagicLink, error) {
	ml, err := r.q.GetMagicLinkByHash(ctx, tokenHash)
	if err != nil {
		return domain.MagicLink{}, err
	}
	return mapMagicLink(ml), nil
}

func (r *SQLCRepository) ConsumeMagicLink(ctx context.Context, tokenHash string) error {
	return r.q.ConsumeMagicLink(ctx, tokenHash)
}

func (r *SQLCRepository) CreateSSOPortalToken(ctx context.Context, tenantID uuid.UUID, ssoProviderID *uuid.UUID, providerSlug, tokenHash, intent string, createdBy uuid.UUID, expiresAt time.Time, maxUses int32) (domain.SSOPortalToken, error) {
	row, err := r.q.CreateSSOPortalToken(ctx, db.CreateSSOPortalTokenParams{
		TenantID:      toPgUUID(tenantID),
		SsoProviderID: toPgUUIDNullable(ssoProviderID),
		ProviderSlug:  providerSlug,
		TokenHash:     tokenHash,
		Intent:        intent,
		CreatedBy:     toPgUUID(createdBy),
		ExpiresAt:     toPgTime(expiresAt),
		MaxUses:       maxUses,
	})
	if err != nil {
		return domain.SSOPortalToken{}, err
	}
	return mapSSOPortalToken(row), nil
}

// Additional lookups for profile/introspection
func (r *SQLCRepository) GetUserByID(ctx context.Context, userID uuid.UUID) (domain.User, error) {
	u, err := r.q.GetUserByID(ctx, toPgUUID(userID))
	if err != nil {
		return domain.User{}, err
	}
	return mapUser(u), nil
}

func (r *SQLCRepository) GetAuthIdentitiesByUser(ctx context.Context, userID uuid.UUID) ([]domain.AuthIdentity, error) {
	items, err := r.q.GetAuthIdentitiesByUser(ctx, toPgUUID(userID))
	if err != nil {
		return nil, err
	}
	out := make([]domain.AuthIdentity, 0, len(items))
	for _, ai := range items {
		out = append(out, mapAuthIdentity(db.AuthIdentity{
			ID:           ai.ID,
			UserID:       ai.UserID,
			TenantID:     ai.TenantID,
			Email:        ai.Email,
			PasswordHash: ai.PasswordHash,
		}))
	}
	return out, nil
}

// UpdateUserRoles updates only the roles column while preserving other profile fields.
func (r *SQLCRepository) UpdateUserRoles(ctx context.Context, userID uuid.UUID, roles []string) error {
	// Load current profile fields to preserve first/last name
	u, err := r.q.GetUserByID(ctx, toPgUUID(userID))
	if err != nil {
		return err
	}
	return r.q.UpdateUserProfile(ctx, db.UpdateUserProfileParams{
		ID:        toPgUUID(userID),
		FirstName: u.FirstName,
		LastName:  u.LastName,
		Roles:     roles,
	})
}

// MFA persistence
func (r *SQLCRepository) UpsertMFASecret(ctx context.Context, userID uuid.UUID, secret string, enabled bool) error {
	return r.q.UpsertMFASecret(ctx, db.UpsertMFASecretParams{
		UserID:  toPgUUID(userID),
		Secret:  secret,
		Enabled: enabled,
	})
}

func (r *SQLCRepository) GetMFASecret(ctx context.Context, userID uuid.UUID) (domain.MFASecret, error) {
	ms, err := r.q.GetMFASecret(ctx, toPgUUID(userID))
	if err != nil {
		return domain.MFASecret{}, err
	}
	return mapMFASecret(ms), nil
}

func (r *SQLCRepository) InsertMFABackupCode(ctx context.Context, id uuid.UUID, userID uuid.UUID, codeHash string) error {
	return r.q.InsertMFABackupCode(ctx, db.InsertMFABackupCodeParams{
		ID:       toPgUUID(id),
		UserID:   toPgUUID(userID),
		CodeHash: codeHash,
	})
}

func (r *SQLCRepository) CountRemainingMFABackupCodes(ctx context.Context, userID uuid.UUID) (int64, error) {
	return r.q.CountRemainingMFABackupCodes(ctx, toPgUUID(userID))
}

func (r *SQLCRepository) ConsumeMFABackupCode(ctx context.Context, userID uuid.UUID, codeHash string) (bool, error) {
	_, err := r.q.ConsumeMFABackupCode(ctx, db.ConsumeMFABackupCodeParams{UserID: toPgUUID(userID), CodeHash: codeHash})
	if err != nil {
		if err == pgx.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// --- RBAC v2 repository methods ---

// Permissions
func (r *SQLCRepository) ListPermissions(ctx context.Context) ([]domain.Permission, error) {
	items, err := r.q.ListPermissions(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Permission, 0, len(items))
	for _, p := range items {
		out = append(out, mapPermission(p))
	}
	return out, nil
}

func (r *SQLCRepository) GetPermissionByKey(ctx context.Context, key string) (domain.Permission, error) {
	p, err := r.q.GetPermissionByKey(ctx, key)
	if err != nil {
		return domain.Permission{}, err
	}
	return mapPermission(p), nil
}

// Roles
func (r *SQLCRepository) ListRolesByTenant(ctx context.Context, tenantID uuid.UUID) ([]domain.Role, error) {
	items, err := r.q.ListRolesByTenant(ctx, toPgUUID(tenantID))
	if err != nil {
		return nil, err
	}
	out := make([]domain.Role, 0, len(items))
	for _, it := range items {
		out = append(out, mapRole(it))
	}
	return out, nil
}

func (r *SQLCRepository) CreateRole(ctx context.Context, id uuid.UUID, tenantID uuid.UUID, name, description string) (domain.Role, error) {
	it, err := r.q.CreateRole(ctx, db.CreateRoleParams{
		ID:          toPgUUID(id),
		TenantID:    toPgUUID(tenantID),
		Name:        name,
		Description: toPgText(description),
	})
	if err != nil {
		return domain.Role{}, err
	}
	return mapRole(it), nil
}

func (r *SQLCRepository) UpdateRole(ctx context.Context, roleID uuid.UUID, tenantID uuid.UUID, name, description string) (domain.Role, error) {
	it, err := r.q.UpdateRole(ctx, db.UpdateRoleParams{
		ID:          toPgUUID(roleID),
		TenantID:    toPgUUID(tenantID),
		Name:        name,
		Description: toPgText(description),
	})
	if err != nil {
		return domain.Role{}, err
	}
	return mapRole(it), nil
}

func (r *SQLCRepository) DeleteRole(ctx context.Context, roleID uuid.UUID, tenantID uuid.UUID) error {
	return r.q.DeleteRole(ctx, db.DeleteRoleParams{ID: toPgUUID(roleID), TenantID: toPgUUID(tenantID)})
}

func (r *SQLCRepository) GetRoleByName(ctx context.Context, tenantID uuid.UUID, name string) (domain.Role, error) {
	it, err := r.q.GetRoleByName(ctx, db.GetRoleByNameParams{TenantID: toPgUUID(tenantID), Name: name})
	if err != nil {
		return domain.Role{}, err
	}
	return mapRole(it), nil
}

// User role assignments
func (r *SQLCRepository) ListUserRoleIDs(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := r.q.ListUserRoleIDs(ctx, db.ListUserRoleIDsParams{UserID: toPgUUID(userID), TenantID: toPgUUID(tenantID)})
	if err != nil {
		return nil, err
	}
	out := make([]uuid.UUID, 0, len(rows))
	for _, v := range rows {
		out = append(out, toUUID(v))
	}
	return out, nil
}

func (r *SQLCRepository) AddUserRole(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID, roleID uuid.UUID) error {
	return r.q.AddUserRole(ctx, db.AddUserRoleParams{UserID: toPgUUID(userID), TenantID: toPgUUID(tenantID), RoleID: toPgUUID(roleID)})
}

func (r *SQLCRepository) RemoveUserRole(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID, roleID uuid.UUID) error {
	return r.q.RemoveUserRole(ctx, db.RemoveUserRoleParams{UserID: toPgUUID(userID), TenantID: toPgUUID(tenantID), RoleID: toPgUUID(roleID)})
}

// Role-permissions
func (r *SQLCRepository) ListRolePermissionKeys(ctx context.Context, roleIDs []uuid.UUID) ([]domain.RolePermissionGrant, error) {
	arr := make([]pgtype.UUID, 0, len(roleIDs))
	for _, id := range roleIDs {
		arr = append(arr, toPgUUID(id))
	}
	rows, err := r.q.ListRolePermissionKeys(ctx, arr)
	if err != nil {
		return nil, err
	}
	out := make([]domain.RolePermissionGrant, 0, len(rows))
	for _, row := range rows {
		out = append(out, mapRolePermissionKeyRow(row))
	}
	return out, nil
}

func (r *SQLCRepository) UpsertRolePermission(ctx context.Context, roleID uuid.UUID, permissionID uuid.UUID, scopeType string, resourceType, resourceID *string) error {
	return r.q.UpsertRolePermission(ctx, db.UpsertRolePermissionParams{
		RoleID:       toPgUUID(roleID),
		PermissionID: toPgUUID(permissionID),
		ScopeType:    scopeType,
		ResourceType: toPgTextNullable(resourceType),
		ResourceID:   toPgTextNullable(resourceID),
	})
}

func (r *SQLCRepository) DeleteRolePermission(ctx context.Context, roleID uuid.UUID, permissionID uuid.UUID, scopeType string, resourceType, resourceID *string) error {
	return r.q.DeleteRolePermission(ctx, db.DeleteRolePermissionParams{
		RoleID:       toPgUUID(roleID),
		PermissionID: toPgUUID(permissionID),
		ScopeType:    scopeType,
		ResourceType: toPgTextNullable(resourceType),
		ResourceID:   toPgTextNullable(resourceID),
	})
}

// --- FGA repository methods (groups, memberships, ACL tuples) ---

// Groups
func (r *SQLCRepository) CreateGroup(ctx context.Context, id uuid.UUID, tenantID uuid.UUID, name, description string) (domain.Group, error) {
	it, err := r.q.CreateGroup(ctx, db.CreateGroupParams{
		ID:          toPgUUID(id),
		TenantID:    toPgUUID(tenantID),
		Name:        name,
		Description: toPgText(description),
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == "23505" { // unique_violation
				return domain.Group{}, domain.ErrDuplicateGroup
			}
		}
		return domain.Group{}, err
	}
	return mapGroup(it), nil
}

func (r *SQLCRepository) ListGroups(ctx context.Context, tenantID uuid.UUID) ([]domain.Group, error) {
	items, err := r.q.ListGroups(ctx, toPgUUID(tenantID))
	if err != nil {
		return nil, err
	}
	out := make([]domain.Group, 0, len(items))
	for _, g := range items {
		out = append(out, mapGroup(g))
	}
	return out, nil
}

func (r *SQLCRepository) DeleteGroup(ctx context.Context, id uuid.UUID, tenantID uuid.UUID) error {
	return r.q.DeleteGroup(ctx, db.DeleteGroupParams{ID: toPgUUID(id), TenantID: toPgUUID(tenantID)})
}

// Group membership
func (r *SQLCRepository) AddGroupMember(ctx context.Context, groupID uuid.UUID, userID uuid.UUID) error {
	return r.q.AddGroupMember(ctx, db.AddGroupMemberParams{GroupID: toPgUUID(groupID), UserID: toPgUUID(userID)})
}

func (r *SQLCRepository) RemoveGroupMember(ctx context.Context, groupID uuid.UUID, userID uuid.UUID) error {
	return r.q.RemoveGroupMember(ctx, db.RemoveGroupMemberParams{GroupID: toPgUUID(groupID), UserID: toPgUUID(userID)})
}

// ACL tuples
func (r *SQLCRepository) CreateACLTuple(ctx context.Context, id uuid.UUID, tenantID uuid.UUID, subjectType string, subjectID uuid.UUID, permissionID uuid.UUID, objectType string, objectID *string, createdBy *uuid.UUID) (domain.ACLTuple, error) {
	it, err := r.q.CreateACLTuple(ctx, db.CreateACLTupleParams{
		ID:           toPgUUID(id),
		TenantID:     toPgUUID(tenantID),
		SubjectType:  subjectType,
		SubjectID:    toPgUUID(subjectID),
		PermissionID: toPgUUID(permissionID),
		ObjectType:   objectType,
		ObjectID:     toPgTextNullable(objectID),
		CreatedBy:    toPgUUIDNullable(createdBy),
	})
	if err != nil {
		return domain.ACLTuple{}, err
	}
	return mapACLTuple(it), nil
}

func (r *SQLCRepository) DeleteACLTuple(ctx context.Context, tenantID uuid.UUID, subjectType string, subjectID uuid.UUID, permissionID uuid.UUID, objectType string, objectID *string) error {
	return r.q.DeleteACLTuple(ctx, db.DeleteACLTupleParams{
		TenantID:     toPgUUID(tenantID),
		SubjectType:  subjectType,
		SubjectID:    toPgUUID(subjectID),
		PermissionID: toPgUUID(permissionID),
		ObjectType:   objectType,
		ObjectID:     toPgTextNullable(objectID),
	})
}

// Convenience wrappers to match domain.FGARepository naming
func (r *SQLCRepository) ListACLForUser(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID) ([]domain.PermissionGrant, error) {
	return r.ListACLPermissionKeysForUser(ctx, tenantID, userID)
}

func (r *SQLCRepository) ListACLForGroups(ctx context.Context, tenantID uuid.UUID, groupIDs []uuid.UUID) ([]domain.GroupPermissionGrant, error) {
	return r.ListACLPermissionKeysForGroups(ctx, tenantID, groupIDs)
}

// Groups and ACL
func (r *SQLCRepository) ListUserGroups(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := r.q.ListUserGroups(ctx, toPgUUID(userID))
	if err != nil {
		return nil, err
	}
	out := make([]uuid.UUID, 0, len(rows))
	for _, v := range rows {
		out = append(out, toUUID(v))
	}
	return out, nil
}

func (r *SQLCRepository) ListACLPermissionKeysForUser(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID) ([]domain.PermissionGrant, error) {
	rows, err := r.q.ListACLPermissionKeysForUser(ctx, db.ListACLPermissionKeysForUserParams{TenantID: toPgUUID(tenantID), SubjectID: toPgUUID(userID)})
	if err != nil {
		return nil, err
	}
	out := make([]domain.PermissionGrant, 0, len(rows))
	for _, row := range rows {
		var oid *string
		if row.ObjectID.Valid {
			s := row.ObjectID.String
			oid = &s
		}
		out = append(out, domain.PermissionGrant{Key: row.Key, ObjectType: row.ObjectType, ObjectID: oid})
	}
	return out, nil
}

func (r *SQLCRepository) ListACLPermissionKeysForGroups(ctx context.Context, tenantID uuid.UUID, groupIDs []uuid.UUID) ([]domain.GroupPermissionGrant, error) {
	arr := make([]pgtype.UUID, 0, len(groupIDs))
	for _, id := range groupIDs {
		arr = append(arr, toPgUUID(id))
	}
	rows, err := r.q.ListACLPermissionKeysForGroups(ctx, db.ListACLPermissionKeysForGroupsParams{TenantID: toPgUUID(tenantID), Column2: arr})
	if err != nil {
		return nil, err
	}
	out := make([]domain.GroupPermissionGrant, 0, len(rows))
	for _, row := range rows {
		var oid *string
		if row.ObjectID.Valid {
			s := row.ObjectID.String
			oid = &s
		}
		out = append(out, domain.GroupPermissionGrant{GroupID: toUUID(row.GroupID), Key: row.Key, ObjectType: row.ObjectType, ObjectID: oid})
	}
	return out, nil
}

// FindAuthIdentitiesByEmail finds all auth identities with the given email across all tenants
func (r *SQLCRepository) FindAuthIdentitiesByEmail(ctx context.Context, email string) ([]domain.AuthIdentity, error) {
	if r.pool == nil {
		return nil, errors.New("repository pool is nil")
	}
	rows, err := r.pool.Query(ctx, `
        SELECT id, user_id, tenant_id, email, password_hash 
        FROM auth_identities 
        WHERE email = $1
    `, email)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var identities []domain.AuthIdentity
	for rows.Next() {
		var identity domain.AuthIdentity
		err := rows.Scan(
			&identity.ID,
			&identity.UserID,
			&identity.TenantID,
			&identity.Email,
			&identity.PasswordHash,
		)
		if err != nil {
			return nil, err
		}
		identities = append(identities, identity)
	}

	return identities, rows.Err()
}
