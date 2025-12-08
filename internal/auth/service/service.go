package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/corvusHold/guard/internal/auth/domain"
	"github.com/corvusHold/guard/internal/config"
	evdomain "github.com/corvusHold/guard/internal/events/domain"
	evsvc "github.com/corvusHold/guard/internal/events/service"
	"github.com/corvusHold/guard/internal/metrics"
	sdomain "github.com/corvusHold/guard/internal/settings/domain"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"
)

type Service struct {
	repo     domain.Repository
	cfg      config.Config
	settings sdomain.Service
	pub      evdomain.Publisher
	log      zerolog.Logger
}

// --- FGA: Groups, Memberships, ACL Tuples, Authorization ---

// CreateGroup creates a tenant-scoped group.
func (s *Service) CreateGroup(ctx context.Context, tenantID uuid.UUID, name, description string) (domain.Group, error) {
	n := strings.TrimSpace(name)
	if n == "" {
		return domain.Group{}, errors.New("group name required")
	}
	return s.repo.CreateGroup(ctx, uuid.New(), tenantID, n, strings.TrimSpace(description))
}

// ListGroups lists groups for a tenant.
func (s *Service) ListGroups(ctx context.Context, tenantID uuid.UUID) ([]domain.Group, error) {
	return s.repo.ListGroups(ctx, tenantID)
}

// DeleteGroup deletes a group within a tenant.
func (s *Service) DeleteGroup(ctx context.Context, groupID uuid.UUID, tenantID uuid.UUID) error {
	return s.repo.DeleteGroup(ctx, groupID, tenantID)
}

// AddGroupMember adds a user to a group.
func (s *Service) AddGroupMember(ctx context.Context, groupID uuid.UUID, userID uuid.UUID) error {
	return s.repo.AddGroupMember(ctx, groupID, userID)
}

// RemoveGroupMember removes a user from a group.
func (s *Service) RemoveGroupMember(ctx context.Context, groupID uuid.UUID, userID uuid.UUID) error {
	return s.repo.RemoveGroupMember(ctx, groupID, userID)
}

// CreateACLTuple creates a direct permission grant (tuple).
func (s *Service) CreateACLTuple(ctx context.Context, tenantID uuid.UUID, subjectType string, subjectID uuid.UUID, permissionKey string, objectType string, objectID *string, createdBy *uuid.UUID) (domain.ACLTuple, error) {
	// Resolve permission ID by key
	p, err := s.repo.GetPermissionByKey(ctx, permissionKey)
	if err != nil {
		return domain.ACLTuple{}, err
	}
	st := strings.ToLower(strings.TrimSpace(subjectType))
	if st != "user" && st != "group" {
		return domain.ACLTuple{}, errors.New("subject_type must be 'user' or 'group'")
	}
	ot := strings.TrimSpace(objectType)
	if ot == "" {
		return domain.ACLTuple{}, errors.New("object_type required")
	}
	return s.repo.CreateACLTuple(ctx, uuid.New(), tenantID, st, subjectID, p.ID, ot, objectID, createdBy)
}

// DeleteACLTuple deletes a direct permission grant (tuple).
func (s *Service) DeleteACLTuple(ctx context.Context, tenantID uuid.UUID, subjectType string, subjectID uuid.UUID, permissionKey string, objectType string, objectID *string) error {
	p, err := s.repo.GetPermissionByKey(ctx, permissionKey)
	if err != nil {
		return err
	}
	st := strings.ToLower(strings.TrimSpace(subjectType))
	if st != "user" && st != "group" {
		return errors.New("subject_type must be 'user' or 'group'")
	}
	ot := strings.TrimSpace(objectType)
	if ot == "" {
		return errors.New("object_type required")
	}
	return s.repo.DeleteACLTuple(ctx, tenantID, st, subjectID, p.ID, ot, objectID)
}

// Authorize returns whether subject has permissionKey on object within tenant.
func (s *Service) Authorize(ctx context.Context, tenantID uuid.UUID, subjectType string, subjectID uuid.UUID, permissionKey string, objectType string, objectID *string) (bool, string, error) {
	st := strings.ToLower(strings.TrimSpace(subjectType))
	oid := ""
	if objectID != nil {
		oid = *objectID
	}
	s.log.Debug().
		Str("tenant_id", tenantID.String()).
		Str("subject_type", st).
		Str("subject_id", subjectID.String()).
		Str("permission", permissionKey).
		Str("object_type", objectType).
		Str("object_id", oid).
		Msg("authorize:start")
	switch st {
	case "user":
		ok, err := s.HasPermission(ctx, subjectID, tenantID, permissionKey, objectType, objectID)
		if err != nil {
			return false, "error", err
		}
		if ok {
			s.log.Debug().
				Str("tenant_id", tenantID.String()).
				Str("user_id", subjectID.String()).
				Str("permission", permissionKey).
				Str("object_type", objectType).
				Str("object_id", oid).
				Msg("authorize:granted")
			return true, "granted", nil
		}
		s.log.Debug().
			Str("tenant_id", tenantID.String()).
			Str("user_id", subjectID.String()).
			Str("permission", permissionKey).
			Str("object_type", objectType).
			Str("object_id", oid).
			Msg("authorize:denied")
		return false, "denied", nil
	case "group":
		// Evaluate group ACL directly
		grants, err := s.repo.ListACLPermissionKeysForGroups(ctx, tenantID, []uuid.UUID{subjectID})
		if err != nil {
			return false, "error", err
		}
		s.log.Debug().
			Str("tenant_id", tenantID.String()).
			Str("group_id", subjectID.String()).
			Int("grants_count", len(grants)).
			Msg("authorize:group:grants_fetched")
		// Apply same matching logic as HasPermission
		for _, g := range grants {
			if g.Key != permissionKey {
				continue
			}
			if g.ObjectType == "*" {
				return true, "granted", nil
			}
			if objectID == nil {
				if g.ObjectType == objectType && g.ObjectID == nil {
					return true, "granted", nil
				}
				continue
			}
			if g.ObjectType != objectType {
				continue
			}
			if g.ObjectID == nil || (g.ObjectID != nil && *g.ObjectID == *objectID) {
				return true, "granted", nil
			}
		}
		s.log.Debug().
			Str("tenant_id", tenantID.String()).
			Str("group_id", subjectID.String()).
			Str("permission", permissionKey).
			Str("object_type", objectType).
			Str("object_id", oid).
			Msg("authorize:group:denied")
		return false, "denied", nil
	default:
		return false, "invalid_subject_type", errors.New("unsupported subject_type")
	}
}

// --- RBAC v2 ---

// ListPermissions returns all known permissions.
func (s *Service) ListPermissions(ctx context.Context) ([]domain.Permission, error) {
	return s.repo.ListPermissions(ctx)
}

// ListRoles returns all roles for a tenant.
func (s *Service) ListRoles(ctx context.Context, tenantID uuid.UUID) ([]domain.Role, error) {
	return s.repo.ListRolesByTenant(ctx, tenantID)
}

// CreateRole creates a role in a tenant.
func (s *Service) CreateRole(ctx context.Context, tenantID uuid.UUID, name, description string) (domain.Role, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return domain.Role{}, errors.New("role name required")
	}
	return s.repo.CreateRole(ctx, uuid.New(), tenantID, n, description)
}

// UpdateRole updates a role in a tenant.
func (s *Service) UpdateRole(ctx context.Context, roleID uuid.UUID, tenantID uuid.UUID, name, description string) (domain.Role, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return domain.Role{}, errors.New("role name required")
	}
	return s.repo.UpdateRole(ctx, roleID, tenantID, n, description)
}

// DeleteRole deletes a role in a tenant.
func (s *Service) DeleteRole(ctx context.Context, roleID uuid.UUID, tenantID uuid.UUID) error {
	return s.repo.DeleteRole(ctx, roleID, tenantID)
}

// User role assignments
func (s *Service) ListUserRoleIDs(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) ([]uuid.UUID, error) {
	return s.repo.ListUserRoleIDs(ctx, userID, tenantID)
}

func (s *Service) AddUserRole(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID, roleID uuid.UUID) error {
	return s.repo.AddUserRole(ctx, userID, tenantID, roleID)
}

func (s *Service) RemoveUserRole(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID, roleID uuid.UUID) error {
	return s.repo.RemoveUserRole(ctx, userID, tenantID, roleID)
}

// Role-permission mapping management (permissionKey is the unique permission key).
func (s *Service) UpsertRolePermission(ctx context.Context, roleID uuid.UUID, permissionKey, scopeType string, resourceType, resourceID *string) error {
	// Resolve permission ID by key
	p, err := s.repo.GetPermissionByKey(ctx, permissionKey)
	if err != nil {
		return err
	}
	return s.repo.UpsertRolePermission(ctx, roleID, p.ID, scopeType, resourceType, resourceID)
}

func (s *Service) DeleteRolePermission(ctx context.Context, roleID uuid.UUID, permissionKey, scopeType string, resourceType, resourceID *string) error {
	p, err := s.repo.GetPermissionByKey(ctx, permissionKey)
	if err != nil {
		return err
	}
	return s.repo.DeleteRolePermission(ctx, roleID, p.ID, scopeType, resourceType, resourceID)
}

// ResolveUserPermissions aggregates permissions from roles, user ACL, and group ACL.
func (s *Service) ResolveUserPermissions(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) (domain.ResolvedPermissions, error) {
	s.log.Debug().
		Str("tenant_id", tenantID.String()).
		Str("user_id", userID.String()).
		Msg("resolve_user_permissions:start")
	// Role-derived grants
	roleIDs, err := s.repo.ListUserRoleIDs(ctx, userID, tenantID)
	if err != nil {
		return domain.ResolvedPermissions{}, err
	}
	s.log.Debug().
		Str("tenant_id", tenantID.String()).
		Str("user_id", userID.String()).
		Int("role_ids_count", len(roleIDs)).
		Msg("resolve_user_permissions:roles_fetched")
	rolePerms, err := s.repo.ListRolePermissionKeys(ctx, roleIDs)
	if err != nil {
		return domain.ResolvedPermissions{}, err
	}
	s.log.Debug().
		Str("tenant_id", tenantID.String()).
		Str("user_id", userID.String()).
		Int("role_perms_count", len(rolePerms)).
		Msg("resolve_user_permissions:role_perms_fetched")
	// Direct user ACL
	userACL, err := s.repo.ListACLPermissionKeysForUser(ctx, tenantID, userID)
	if err != nil {
		return domain.ResolvedPermissions{}, err
	}
	s.log.Debug().
		Str("tenant_id", tenantID.String()).
		Str("user_id", userID.String()).
		Int("user_acl_count", len(userACL)).
		Msg("resolve_user_permissions:user_acl_fetched")
	// Group ACL via memberships
	groups, err := s.repo.ListUserGroups(ctx, userID)
	if err != nil {
		return domain.ResolvedPermissions{}, err
	}
	// Represent groups as strings for logging
	gs := make([]string, 0, len(groups))
	for _, gid := range groups {
		gs = append(gs, gid.String())
	}
	s.log.Debug().
		Str("tenant_id", tenantID.String()).
		Str("user_id", userID.String()).
		Int("groups_count", len(groups)).
		Strs("groups", gs).
		Msg("resolve_user_permissions:user_groups_fetched")
	groupACL, err := s.repo.ListACLPermissionKeysForGroups(ctx, tenantID, groups)
	if err != nil {
		return domain.ResolvedPermissions{}, err
	}
	s.log.Debug().
		Str("tenant_id", tenantID.String()).
		Str("user_id", userID.String()).
		Int("group_acl_count", len(groupACL)).
		Msg("resolve_user_permissions:group_acl_fetched")

	// Merge and deduplicate
	dedup := make(map[string]struct{})
	appendGrant := func(gs *[]domain.PermissionGrant, g domain.PermissionGrant) {
		id := ""
		if g.ObjectID != nil {
			id = *g.ObjectID
		}
		k := g.Key + "|" + g.ObjectType + "|" + id
		if _, ok := dedup[k]; ok {
			return
		}
		dedup[k] = struct{}{}
		*gs = append(*gs, g)
	}

	grants := make([]domain.PermissionGrant, 0, len(rolePerms)+len(userACL)+len(groupACL))
	// Map role perms: global when no resource_type/resource_id
	for _, rp := range rolePerms {
		if rp.ResourceType != nil {
			appendGrant(&grants, domain.PermissionGrant{Key: rp.Key, ObjectType: *rp.ResourceType, ObjectID: rp.ResourceID})
		} else {
			appendGrant(&grants, domain.PermissionGrant{Key: rp.Key, ObjectType: "*", ObjectID: nil})
		}
	}
	for _, ua := range userACL {
		appendGrant(&grants, ua)
	}
	for _, ga := range groupACL {
		appendGrant(&grants, domain.PermissionGrant{Key: ga.Key, ObjectType: ga.ObjectType, ObjectID: ga.ObjectID})
	}

	s.log.Debug().
		Str("tenant_id", tenantID.String()).
		Str("user_id", userID.String()).
		Int("grants_count", len(grants)).
		Msg("resolve_user_permissions:done")
	return domain.ResolvedPermissions{Grants: grants}, nil
}

// HasPermission checks whether user has a permission, optionally scoped to an object.
func (s *Service) HasPermission(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID, key, objectType string, objectID *string) (bool, error) {
	oid := ""
	if objectID != nil {
		oid = *objectID
	}
	s.log.Debug().
		Str("tenant_id", tenantID.String()).
		Str("user_id", userID.String()).
		Str("permission", key).
		Str("object_type", objectType).
		Str("object_id", oid).
		Msg("has_permission:start")
	rp, err := s.ResolveUserPermissions(ctx, userID, tenantID)
	if err != nil {
		return false, err
	}
	for _, g := range rp.Grants {
		if g.Key != key {
			continue
		}
		if g.ObjectType == "*" {
			return true, nil
		}
		if objectID == nil {
			// Global check for a specific type requires an unscoped grant for that type
			if g.ObjectType == objectType && g.ObjectID == nil {
				return true, nil
			}
			continue
		}
		if g.ObjectType != objectType {
			continue
		}
		if g.ObjectID == nil || (g.ObjectID != nil && *g.ObjectID == *objectID) {
			return true, nil
		}
	}
	s.log.Debug().
		Str("tenant_id", tenantID.String()).
		Str("user_id", userID.String()).
		Str("permission", key).
		Str("object_type", objectType).
		Str("object_id", oid).
		Msg("has_permission:denied")
	return false, nil
}

// --- Admin/user management ---

// ListTenantUsers returns all users that belong to the given tenant.
func (s *Service) ListTenantUsers(ctx context.Context, tenantID uuid.UUID) ([]domain.User, error) {
	return s.repo.ListTenantUsers(ctx, tenantID)
}

// UpdateUserNames updates only first and last name for a user, preserving roles.
func (s *Service) UpdateUserNames(ctx context.Context, userID uuid.UUID, firstName, lastName string) error {
	fn := strings.TrimSpace(firstName)
	ln := strings.TrimSpace(lastName)
	return s.repo.UpdateUserNames(ctx, userID, fn, ln)
}

// SetUserActive toggles the active state of a user.
func (s *Service) SetUserActive(ctx context.Context, userID uuid.UUID, active bool) error {
	return s.repo.SetUserActive(ctx, userID, active)
}

// SetUserEmailVerified sets the email_verified flag for a user.
func (s *Service) SetUserEmailVerified(ctx context.Context, userID uuid.UUID, verified bool) error {
	return s.repo.SetUserEmailVerified(ctx, userID, verified)
}

// ListUserSessions lists refresh tokens (sessions) for a user within a tenant.
func (s *Service) ListUserSessions(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) ([]domain.RefreshToken, error) {
	return s.repo.ListUserSessions(ctx, userID, tenantID)
}

// RevokeSession revokes a specific session (refresh token) by ID for the given user and tenant.
func (s *Service) RevokeSession(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID, sessionID uuid.UUID) error {
	// Ensure the session belongs to this user and tenant
	sessions, err := s.repo.ListUserSessions(ctx, userID, tenantID)
	if err != nil {
		return err
	}
	ok := false
	for _, rt := range sessions {
		if rt.ID == sessionID {
			ok = true
			break
		}
	}
	if !ok {
		return errors.New("session not found")
	}
	return s.repo.RevokeTokenChain(ctx, sessionID)
}

// RevokeUserSessions revokes all active refresh tokens for a user within a tenant.
// Returns the number of tokens revoked.
func (s *Service) RevokeUserSessions(ctx context.Context, userID, tenantID uuid.UUID) (int64, error) {
	return s.repo.RevokeUserSessions(ctx, userID, tenantID)
}

// VerifyMFA validates a provided MFA factor against a challenge token and issues tokens on success.
func (s *Service) VerifyMFA(ctx context.Context, in domain.MFAVerifyInput) (toks domain.AccessTokens, err error) {
	defer func() {
		if err == nil {
			metrics.IncAuthOutcome("mfa", "success")
			metrics.IncMFAOutcome(in.Method, "success")
		} else {
			metrics.IncAuthOutcome("mfa", "failure")
			metrics.IncMFAOutcome(in.Method, "failure")
		}
	}()
	if in.ChallengeToken == "" || in.Method == "" || in.Code == "" {
		return domain.AccessTokens{}, errors.New("challenge_token, method and code are required")
	}
	// First decode without verification to extract tenant/user
	tok, _ := jwt.ParseWithClaims(in.ChallengeToken, jwt.MapClaims{}, func(t *jwt.Token) (interface{}, error) {
		return []byte(""), nil
	}, jwt.WithoutClaimsValidation())
	if tok == nil {
		return domain.AccessTokens{}, errors.New("invalid challenge token")
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return domain.AccessTokens{}, errors.New("invalid challenge claims")
	}
	tenStr, _ := claims["ten"].(string)
	subStr, _ := claims["sub"].(string)
	uid, err := uuid.Parse(subStr)
	if err != nil {
		return domain.AccessTokens{}, errors.New("invalid subject in challenge")
	}
	tid, err := uuid.Parse(tenStr)
	if err != nil {
		return domain.AccessTokens{}, errors.New("invalid tenant in challenge")
	}
	// Verify signature and expiry with tenant signing key
	signingKey, _ := s.settings.GetString(ctx, sdomain.KeyJWTSigning, &tid, s.cfg.JWTSigningKey)
	parsed, err := jwt.Parse(in.ChallengeToken, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(signingKey), nil
	})
	if err != nil || !parsed.Valid {
		return domain.AccessTokens{}, errors.New("invalid or expired challenge token")
	}
	// Validate method
	switch in.Method {
	case "totp":
		ms, err := s.repo.GetMFASecret(ctx, uid)
		if err != nil || !ms.Enabled {
			return domain.AccessTokens{}, errors.New("mfa not enabled")
		}
		if !totp.Validate(in.Code, ms.Secret) {
			return domain.AccessTokens{}, errors.New("invalid totp code")
		}
	case "backup_code":
		ok, err := s.ConsumeBackupCode(ctx, uid, in.Code)
		if err != nil {
			return domain.AccessTokens{}, err
		}
		if !ok {
			return domain.AccessTokens{}, errors.New("invalid backup code")
		}
	default:
		return domain.AccessTokens{}, errors.New("unsupported method")
	}
	// Issue tokens and publish login success audit event
	toks, err = s.issueTokens(ctx, uid, tid, in.UserAgent, in.IP, nil, "password", nil)
	if err != nil {
		return domain.AccessTokens{}, err
	}
	_ = s.repo.UpdateUserLoginAt(ctx, uid)
	_ = s.pub.Publish(ctx, evdomain.Event{
		Type:     "auth.password.login.success",
		TenantID: tid,
		UserID:   uid,
		Meta:     map[string]string{"provider": "password", "mfa": "true", "ip": in.IP, "user_agent": in.UserAgent},
		Time:     time.Now(),
	})
	return toks, nil
}

func New(repo domain.Repository, cfg config.Config, settings sdomain.Service) *Service {
	return &Service{repo: repo, cfg: cfg, settings: settings, pub: evsvc.NewLogger(), log: zerolog.Nop()}
}

// SetPublisher allows tests or callers to override the event publisher.
func (s *Service) SetPublisher(p evdomain.Publisher) { s.pub = p }

// SetLogger allows injection of a structured logger for debug tracing.
func (s *Service) SetLogger(l zerolog.Logger) { s.log = l }

func (s *Service) Signup(ctx context.Context, in domain.SignupInput) (domain.AccessTokens, error) {
	// Normalize email to lowercase and trim spaces to ensure consistent storage
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	if in.Email == "" || in.Password == "" {
		return domain.AccessTokens{}, errors.New("email and password are required")
	}
	userID := uuid.New()
	authID := uuid.New()
	// naive roles default empty
	if err := s.repo.CreateUser(ctx, userID, in.FirstName, in.LastName, []string{}); err != nil {
		return domain.AccessTokens{}, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		return domain.AccessTokens{}, err
	}
	if err := s.repo.CreateAuthIdentity(ctx, authID, userID, in.TenantID, in.Email, string(hash)); err != nil {
		return domain.AccessTokens{}, err
	}
	if err := s.repo.AddUserToTenant(ctx, userID, in.TenantID); err != nil {
		return domain.AccessTokens{}, err
	}
	return s.issueTokens(ctx, userID, in.TenantID, "", "", nil, "password", nil)
}

func (s *Service) Login(ctx context.Context, in domain.LoginInput) (domain.AccessTokens, error) {
	// Normalize email to lowercase and trim spaces to ensure consistent lookup
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	if in.Email == "" || in.Password == "" {
		return domain.AccessTokens{}, errors.New("email and password are required")
	}
	ai, err := s.repo.GetAuthIdentityByEmailTenant(ctx, in.TenantID, in.Email)
	if err != nil {
		metrics.IncAuthOutcome("password", "failure")
		return domain.AccessTokens{}, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(ai.PasswordHash), []byte(in.Password)); err != nil {
		metrics.IncAuthOutcome("password", "failure")
		return domain.AccessTokens{}, errors.New("invalid credentials")
	}
	// If MFA is enabled for this user, return an MFA challenge instead of issuing tokens now.
	if ms, err := s.repo.GetMFASecret(ctx, ai.UserID); err == nil && ms.Enabled {
		// Build short-lived challenge token (5m) signed with tenant's signing key
		signingKey, _ := s.settings.GetString(ctx, sdomain.KeyJWTSigning, &ai.TenantID, s.cfg.JWTSigningKey)
		claims := jwt.MapClaims{
			"typ":   "mfa_challenge",
			"sub":   ai.UserID.String(),
			"ten":   ai.TenantID.String(),
			"email": ai.Email,
			"amr":   []string{"totp", "backup_code"},
			"exp":   time.Now().Add(5 * time.Minute).Unix(),
			"iat":   time.Now().Unix(),
		}
		t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		ch, err := t.SignedString([]byte(signingKey))
		if err != nil {
			return domain.AccessTokens{}, err
		}
		return domain.AccessTokens{}, domain.ErrMFARequired{ChallengeToken: ch, Methods: []string{"totp", "backup_code"}}
	}
	if err := s.repo.UpdateUserLoginAt(ctx, ai.UserID); err != nil {
		return domain.AccessTokens{}, err
	}
	toks, err := s.issueTokens(ctx, ai.UserID, ai.TenantID, in.UserAgent, in.IP, nil, "password", nil)
	if err != nil {
		return domain.AccessTokens{}, err
	}
	// Publish audit event for successful password login
	_ = s.pub.Publish(ctx, evdomain.Event{
		Type:     "auth.password.login.success",
		TenantID: ai.TenantID,
		UserID:   ai.UserID,
		Meta:     map[string]string{"provider": "password", "ip": in.IP, "user_agent": in.UserAgent, "email": in.Email},
		Time:     time.Now(),
	})
	metrics.IncAuthOutcome("password", "success")
	return toks, nil
}

func (s *Service) Refresh(ctx context.Context, in domain.RefreshInput) (domain.AccessTokens, error) {
	if in.RefreshToken == "" {
		return domain.AccessTokens{}, errors.New("refresh token required")
	}
	h := sha256.Sum256([]byte(in.RefreshToken))
	hashB64 := base64.RawURLEncoding.EncodeToString(h[:])
	rt, err := s.repo.GetRefreshTokenByHash(ctx, hashB64)
	if err != nil {
		return domain.AccessTokens{}, err
	}
	if rt.Revoked || time.Now().After(rt.ExpiresAt) {
		return domain.AccessTokens{}, errors.New("refresh token expired or revoked")
	}
	// rotate: revoke chain and issue a fresh pair with parent=rt.ID
	if err := s.repo.RevokeTokenChain(ctx, rt.ID); err != nil {
		return domain.AccessTokens{}, err
	}
	// Preserve the original auth method from the refresh token for the new token
	originalAuthMethod := "password"
	if rt.AuthMethod != "" {
		originalAuthMethod = rt.AuthMethod
	}
	toks, err := s.issueTokens(ctx, rt.UserID, rt.TenantID, in.UserAgent, in.IP, &rt.ID, originalAuthMethod, rt.SSOProviderID)
	if err != nil {
		return domain.AccessTokens{}, err
	}
	// Publish audit event for successful token refresh
	_ = s.pub.Publish(ctx, evdomain.Event{
		Type:     "auth.token.refresh.success",
		TenantID: rt.TenantID,
		UserID:   rt.UserID,
		Meta:     map[string]string{"ip": in.IP, "user_agent": in.UserAgent},
		Time:     time.Now(),
	})
	return toks, nil
}

func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	if refreshToken == "" {
		return nil
	}
	h := sha256.Sum256([]byte(refreshToken))
	hashB64 := base64.RawURLEncoding.EncodeToString(h[:])
	rt, err := s.repo.GetRefreshTokenByHash(ctx, hashB64)
	if err != nil {
		return err
	}
	return s.repo.RevokeTokenChain(ctx, rt.ID)
}

// IssueTokensForSSO issues access and refresh tokens for SSO-authenticated users.
// This is used after successful SSO callback to create a session for the user.
func (s *Service) IssueTokensForSSO(ctx context.Context, in domain.SSOTokenInput) (domain.AccessTokens, error) {
	// Update last login timestamp
	if err := s.repo.UpdateUserLoginAt(ctx, in.UserID); err != nil {
		return domain.AccessTokens{}, err
	}
	// Issue tokens for SSO-authenticated users with provider ID for session tracking
	return s.issueTokens(ctx, in.UserID, in.TenantID, in.UserAgent, in.IP, nil, "sso", in.SSOProviderID)
}

func (s *Service) issueTokens(ctx context.Context, userID, tenantID uuid.UUID, userAgent, ip string, parent *uuid.UUID, authMethod string, ssoProviderID *uuid.UUID) (domain.AccessTokens, error) {
	// Resolve settings with tenant override and env defaults
	accessTTL, _ := s.settings.GetDuration(ctx, sdomain.KeyAccessTTL, &tenantID, s.cfg.AccessTokenTTL)
	refreshTTL, _ := s.settings.GetDuration(ctx, sdomain.KeyRefreshTTL, &tenantID, s.cfg.RefreshTokenTTL)
	signingKey, _ := s.settings.GetString(ctx, sdomain.KeyJWTSigning, &tenantID, s.cfg.JWTSigningKey)
	issuer, _ := s.settings.GetString(ctx, sdomain.KeyJWTIssuer, &tenantID, s.cfg.PublicBaseURL)
	audience, _ := s.settings.GetString(ctx, sdomain.KeyJWTAudience, &tenantID, s.cfg.PublicBaseURL)

	// Access JWT
	claims := jwt.MapClaims{
		"sub": userID.String(),
		"ten": tenantID.String(),
		"exp": time.Now().Add(accessTTL).Unix(),
		"iat": time.Now().Unix(),
		"iss": issuer,
		"aud": audience,
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	access, err := t.SignedString([]byte(signingKey))
	if err != nil {
		return domain.AccessTokens{}, err
	}
	// Refresh token: random
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return domain.AccessTokens{}, err
	}
	rt := base64.RawURLEncoding.EncodeToString(raw)
	h := sha256.Sum256([]byte(rt))
	hashB64 := base64.RawURLEncoding.EncodeToString(h[:])
	expiresAt := time.Now().Add(refreshTTL)
	// Build metadata for the refresh token
	createdVia := "login"
	if parent != nil {
		createdVia = "refresh"
	}
	metadata := &domain.RefreshTokenMetadata{
		AuthMethod: authMethod,
		CreatedVia: createdVia,
	}
	if err := s.repo.InsertRefreshToken(ctx, uuid.New(), userID, tenantID, hashB64, parent, userAgent, ip, expiresAt, authMethod, ssoProviderID, metadata); err != nil {
		return domain.AccessTokens{}, err
	}
	return domain.AccessTokens{AccessToken: access, RefreshToken: rt}, nil
}

// Me returns the current user's profile in a tenant context.
func (s *Service) Me(ctx context.Context, userID, tenantID uuid.UUID) (domain.UserProfile, error) {
	u, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return domain.UserProfile{}, err
	}
	ids, err := s.repo.GetAuthIdentitiesByUser(ctx, userID)
	if err != nil {
		return domain.UserProfile{}, err
	}
	email := ""
	for _, ai := range ids {
		if ai.TenantID == tenantID {
			email = ai.Email
			break
		}
	}
	// Determine MFA enabled state
	mfaEnabled := false
	if ms, err := s.repo.GetMFASecret(ctx, userID); err == nil {
		mfaEnabled = ms.Enabled
	}
	prof := domain.UserProfile{
		ID:            u.ID,
		TenantID:      tenantID,
		Email:         email,
		FirstName:     u.FirstName,
		LastName:      u.LastName,
		Roles:         u.Roles,
		MFAEnabled:    mfaEnabled,
		EmailVerified: u.EmailVerified,
		LastLoginAt:   u.LastLoginAt,
	}
	return prof, nil
}

// Introspect validates an access token and returns claims and user context.
func (s *Service) Introspect(ctx context.Context, token string) (domain.Introspection, error) {
	if token == "" {
		return domain.Introspection{Active: false}, errors.New("token required")
	}

	// Step 1: Decode JWT without verification to extract tenant claim.
	// We need the tenant ID to determine which signing key to use for verification.
	tok, _ := jwt.ParseWithClaims(token, jwt.MapClaims{}, func(t *jwt.Token) (interface{}, error) {
		return []byte(""), nil
	}, jwt.WithoutClaimsValidation())
	if tok == nil {
		return domain.Introspection{Active: false}, errors.New("invalid token format")
	}
	unverifiedClaims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return domain.Introspection{Active: false}, errors.New("invalid claims")
	}

	// Step 2: Extract tenant ID from unverified claims
	tenStr, _ := unverifiedClaims["ten"].(string)
	tid, err := uuid.Parse(tenStr)
	if err != nil {
		return domain.Introspection{Active: false}, errors.New("invalid ten")
	}

	// Step 3: Load tenant-specific settings (issuer/audience/signing key may be overridden per tenant)
	issuer, _ := s.settings.GetString(ctx, sdomain.KeyJWTIssuer, &tid, s.cfg.PublicBaseURL)
	audience, _ := s.settings.GetString(ctx, sdomain.KeyJWTAudience, &tid, s.cfg.PublicBaseURL)
	signingKey, _ := s.settings.GetString(ctx, sdomain.KeyJWTSigning, &tid, s.cfg.JWTSigningKey)

	// Step 4: Verify signature with correct tenant-specific signing key
	parsed, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		// HS256 only
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(signingKey), nil
	})
	if err != nil || !parsed.Valid {
		return domain.Introspection{Active: false}, errors.New("invalid token")
	}

	// Step 5: Extract verified claims
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return domain.Introspection{Active: false}, errors.New("invalid claims")
	}

	subStr, _ := claims["sub"].(string)
	issStr, _ := claims["iss"].(string)
	audStr, _ := claims["aud"].(string)
	var expInt int64
	switch v := claims["exp"].(type) {
	case float64:
		expInt = int64(v)
	case int64:
		expInt = v
	}
	var iatInt int64
	switch v := claims["iat"].(type) {
	case float64:
		iatInt = int64(v)
	case int64:
		iatInt = v
	}

	uid, err := uuid.Parse(subStr)
	if err != nil {
		return domain.Introspection{Active: false}, errors.New("invalid sub")
	}

	// Step 6: Validate issuer/audience if present
	if issStr != "" && issStr != issuer {
		return domain.Introspection{Active: false}, errors.New("issuer mismatch")
	}
	if audStr != "" && audStr != audience {
		return domain.Introspection{Active: false}, errors.New("audience mismatch")
	}

	// Step 7: Exp validation
	if expInt != 0 && time.Now().Unix() > expInt {
		return domain.Introspection{Active: false}, errors.New("token expired")
	}

	// Step 8: Load user context
	u, err := s.repo.GetUserByID(ctx, uid)
	if err != nil {
		return domain.Introspection{Active: false}, err
	}
	ids, err := s.repo.GetAuthIdentitiesByUser(ctx, uid)
	if err != nil {
		return domain.Introspection{Active: false}, err
	}
	email := ""
	for _, ai := range ids {
		if ai.TenantID == tid {
			email = ai.Email
			break
		}
	}

	return domain.Introspection{
		Active:        true,
		UserID:        uid,
		TenantID:      tid,
		Email:         email,
		Roles:         u.Roles,
		MFAVerified:   false,
		EmailVerified: u.EmailVerified,
		Exp:           expInt,
		Iat:           iatInt,
	}, nil
}

// Revoke invalidates a token (refresh tokens supported).
func (s *Service) Revoke(ctx context.Context, token string, tokenType string) error {
	switch tokenType {
	case "refresh", "refresh_token", "rt":
		return s.Logout(ctx, token)
	default:
		return errors.New("unsupported token type")
	}
}

// UpdateUserRoles updates the roles array for the specified user.
func (s *Service) UpdateUserRoles(ctx context.Context, userID uuid.UUID, roles []string) error {
	// Normalize: trim spaces and drop empties, and lowercase role names for consistency.
	out := make([]string, 0, len(roles))
	seen := make(map[string]struct{}, len(roles))
	for _, r := range roles {
		v := strings.ToLower(strings.TrimSpace(r))
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return s.repo.UpdateUserRoles(ctx, userID, out)
}

// --- MFA (TOTP + Backup Codes) ---

// StartTOTPEnrollment generates and stores a TOTP secret (disabled), and returns the secret and otpauth URI.
func (s *Service) StartTOTPEnrollment(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) (string, string, error) {
	issuer, _ := s.settings.GetString(ctx, sdomain.KeyJWTIssuer, &tenantID, s.cfg.PublicBaseURL)
	// Determine account name (prefer email in this tenant)
	acct := userID.String()
	ids, err := s.repo.GetAuthIdentitiesByUser(ctx, userID)
	if err == nil {
		for _, ai := range ids {
			if ai.TenantID == tenantID && ai.Email != "" {
				acct = ai.Email
				break
			}
		}
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: issuer, AccountName: acct})
	if err != nil {
		return "", "", err
	}
	secret := key.Secret()
	if err := s.repo.UpsertMFASecret(ctx, userID, secret, false); err != nil {
		return "", "", err
	}
	return secret, key.URL(), nil
}

// ActivateTOTP verifies a TOTP code for the stored secret and marks MFA as enabled.
func (s *Service) ActivateTOTP(ctx context.Context, userID uuid.UUID, code string) error {
	ms, err := s.repo.GetMFASecret(ctx, userID)
	if err != nil {
		return err
	}
	ok := totp.Validate(code, ms.Secret)
	if !ok {
		return errors.New("invalid TOTP code")
	}
	return s.repo.UpsertMFASecret(ctx, userID, ms.Secret, true)
}

// DisableTOTP disables TOTP for the user (keeps secret for potential reactivation).
func (s *Service) DisableTOTP(ctx context.Context, userID uuid.UUID) error {
	ms, err := s.repo.GetMFASecret(ctx, userID)
	if err != nil {
		return err
	}
	return s.repo.UpsertMFASecret(ctx, userID, ms.Secret, false)
}

// GenerateBackupCodes creates N backup codes, stores their hashes, and returns the plaintext codes.
func (s *Service) GenerateBackupCodes(ctx context.Context, userID uuid.UUID, count int) ([]string, error) {
	if count <= 0 {
		return nil, errors.New("count must be > 0")
	}
	out := make([]string, 0, count)
	for i := 0; i < count; i++ {
		code, err := generateBackupCode(10)
		if err != nil {
			return nil, err
		}
		hash := hashCode(code)
		if err := s.repo.InsertMFABackupCode(ctx, uuid.New(), userID, hash); err != nil {
			return nil, err
		}
		out = append(out, code)
	}
	return out, nil
}

// ConsumeBackupCode attempts to consume a backup code; returns true if it was valid and unused.
func (s *Service) ConsumeBackupCode(ctx context.Context, userID uuid.UUID, code string) (bool, error) {
	if code == "" {
		return false, errors.New("code required")
	}
	hash := hashCode(code)
	return s.repo.ConsumeMFABackupCode(ctx, userID, hash)
}

// CountRemainingBackupCodes returns the number of unused backup codes.
func (s *Service) CountRemainingBackupCodes(ctx context.Context, userID uuid.UUID) (int64, error) {
	return s.repo.CountRemainingMFABackupCodes(ctx, userID)
}

// --- Helpers ---
func hashCode(sv string) string {
	h := sha256.Sum256([]byte(sv))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func generateBackupCode(n int) (string, error) {
	// n is number of random bytes; base32 (no padding) yields ~1.6x chars
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	return enc.EncodeToString(b), nil
}

// --- Password Reset ---

// RequestPasswordReset sends a password reset email to the user.
// TenantID is required because identity is scoped by (tenant_id, email).
// If TenantID is nil and email exists in multiple tenants, sends an email
// with tenant selection options instead of returning them in the API response
// to avoid leaking cross-tenant membership information.
func (s *Service) RequestPasswordReset(ctx context.Context, in domain.PasswordResetRequestInput) error {
	email := strings.TrimSpace(strings.ToLower(in.Email))
	if email == "" {
		return errors.New("email is required")
	}

	var ai domain.AuthIdentity
	var tenantID uuid.UUID

	if in.TenantID != nil {
		// Look up the user by email and specific tenant
		found, err := s.repo.GetAuthIdentityByEmailTenant(ctx, *in.TenantID, email)
		if err != nil {
			// Don't reveal whether user exists - always return success
			return nil
		}
		ai = found
		tenantID = *in.TenantID
	} else {
		// No tenant specified - look up by email to see how many tenants have this email
		identities, err := s.repo.FindAuthIdentitiesByEmail(ctx, email)
		if err != nil || len(identities) == 0 {
			// Don't reveal whether user exists - always return success
			return nil
		}
		// If email exists in exactly one tenant, we can proceed
		if len(identities) == 1 {
			ai = identities[0]
			tenantID = ai.TenantID
		} else {
			// Email exists in multiple tenants - send an email with tenant selection options
			// instead of returning them in the API response to avoid leaking cross-tenant membership.
			// Build tenant options for the email
			tenantOpts := make([]domain.TenantOption, 0, len(identities))
			for _, ident := range identities {
				// Look up tenant name
				tenant, err := s.repo.GetTenantByID(ctx, ident.TenantID)
				name := ""
				if err == nil {
					name = tenant.Name
				}
				tenantOpts = append(tenantOpts, domain.TenantOption{
					TenantID:   ident.TenantID,
					TenantName: name,
				})
			}
			// TODO: Send email with tenant selection options
			// In production, integrate with email service:
			// if err := s.emailService.SendTenantSelectionEmail(ctx, email, tenantOpts); err != nil { ... }
			s.log.Info().
				Str("email", email).
				Int("tenant_count", len(tenantOpts)).
				Msg("password reset requested for email in multiple tenants - tenant selection email would be sent")
			// Always return success to avoid leaking tenant membership
			return nil
		}
	}

	// Resolve TTL for password reset (use magic link TTL as default)
	ttl, _ := s.settings.GetDuration(ctx, sdomain.KeyMagicLinkTTL, &tenantID, s.cfg.MagicLinkTTL)

	// Generate token and store hashed
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	h := sha256.Sum256([]byte(token))
	tokenHash := base64.RawURLEncoding.EncodeToString(h[:])
	exp := time.Now().Add(ttl)

	if err := s.repo.CreatePasswordResetToken(ctx, uuid.New(), ai.UserID, tenantID, email, tokenHash, exp); err != nil {
		return err
	}

	// TODO: Send reset link via email service
	// Build reset link for email delivery
	baseURL, _ := s.settings.GetString(ctx, sdomain.KeyPublicBaseURL, &tenantID, s.cfg.PublicBaseURL)
	resetLink := baseURL + "/reset-password?token=" + token
	// In production, integrate with email service:
	// if err := s.emailService.SendPasswordResetEmail(ctx, email, resetLink); err != nil { ... }
	_ = resetLink // Suppress unused variable until email service integration

	// Publish audit event
	_ = s.pub.Publish(ctx, evdomain.Event{
		Type:     "auth.password.reset.requested",
		TenantID: tenantID,
		UserID:   ai.UserID,
		Meta:     map[string]string{"email": email},
		Time:     time.Now(),
	})

	// Log the request (in production, this would send an email with resetLink)
	s.log.Info().
		Str("email", email).
		Str("tenant_id", tenantID.String()).
		Msg("password reset requested")

	return nil
}

// ConfirmPasswordReset verifies the token and sets the new password.
func (s *Service) ConfirmPasswordReset(ctx context.Context, in domain.PasswordResetConfirmInput) error {
	if in.Token == "" {
		return errors.New("token required")
	}
	if len(in.NewPassword) < 8 {
		return errors.New("password must be at least 8 characters")
	}

	// Hash the token and look it up
	h := sha256.Sum256([]byte(in.Token))
	tokenHash := base64.RawURLEncoding.EncodeToString(h[:])

	prt, err := s.repo.GetPasswordResetTokenByHash(ctx, tokenHash)
	if err != nil {
		return errors.New("invalid or expired token")
	}

	// Check if token is expired or already consumed
	if prt.ConsumedAt != nil || time.Now().After(prt.ExpiresAt) {
		return errors.New("token expired or already used")
	}

	// Verify tenant matches if provided
	if in.TenantID != nil && prt.TenantID != *in.TenantID {
		return errors.New("invalid token")
	}

	// Hash the new password
	hash, err := bcrypt.GenerateFromPassword([]byte(in.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// Update the password first (before consuming token for atomicity)
	// If password update fails, user can retry with the same token
	rowsAffected, err := s.repo.UpdateAuthIdentityPassword(ctx, prt.TenantID, prt.Email, string(hash))
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return errors.New("user not found")
	}

	// Consume the token only after password update succeeds
	rowsConsumed, err := s.repo.ConsumePasswordResetToken(ctx, tokenHash)
	if err != nil {
		return err
	}
	if rowsConsumed == 0 {
		// Token was already consumed or expired between check and now (race condition)
		// Password was already updated, so this is acceptable
		s.log.Warn().Str("email", prt.Email).Msg("password reset token already consumed during update")
	}

	// Publish audit event
	_ = s.pub.Publish(ctx, evdomain.Event{
		Type:     "auth.password.reset.completed",
		TenantID: prt.TenantID,
		UserID:   prt.UserID,
		Meta:     map[string]string{"email": prt.Email},
		Time:     time.Now(),
	})

	return nil
}

// ChangePassword changes the password for a logged-in user.
func (s *Service) ChangePassword(ctx context.Context, in domain.PasswordChangeInput) error {
	if len(in.NewPassword) < 8 {
		return errors.New("password must be at least 8 characters")
	}

	// Get the user's auth identity
	identities, err := s.repo.GetAuthIdentitiesByUser(ctx, in.UserID)
	if err != nil {
		return err
	}

	// Find the identity for this tenant
	var ai *domain.AuthIdentity
	for _, identity := range identities {
		if identity.TenantID == in.TenantID {
			ai = &identity
			break
		}
	}
	if ai == nil {
		return errors.New("user not found in tenant")
	}

	// Verify current password
	if err := bcrypt.CompareHashAndPassword([]byte(ai.PasswordHash), []byte(in.CurrentPassword)); err != nil {
		return errors.New("current password is incorrect")
	}

	// Hash the new password
	hash, err := bcrypt.GenerateFromPassword([]byte(in.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// Update the password
	rowsAffected, err := s.repo.UpdateAuthIdentityPassword(ctx, in.TenantID, ai.Email, string(hash))
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return errors.New("user not found")
	}

	// Publish audit event
	_ = s.pub.Publish(ctx, evdomain.Event{
		Type:     "auth.password.changed",
		TenantID: in.TenantID,
		UserID:   in.UserID,
		Meta:     map[string]string{"email": ai.Email},
		Time:     time.Now(),
	})

	return nil
}

// UpdateProfile updates the user's profile (first name, last name).
func (s *Service) UpdateProfile(ctx context.Context, userID uuid.UUID, firstName, lastName string) error {
	return s.repo.UpdateUserNames(ctx, userID, strings.TrimSpace(firstName), strings.TrimSpace(lastName))
}
