package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type PortalLink struct {
	Link string `json:"link"`
}
// AccessTokens represents the issued tokens payload.
type AccessTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// ErrMFARequired signals that an MFA verification step is required to complete login.
type ErrMFARequired struct {
	ChallengeToken string
	Methods        []string
}

func (e ErrMFARequired) Error() string { return "mfa_required" }

// MFASecret reflects the mfa_secrets table record.
type MFASecret struct {
	UserID    uuid.UUID
	Secret    string
	Enabled   bool
	CreatedAt time.Time
}

type SignupInput struct {
	TenantID   uuid.UUID
	Email      string
	Password   string
	FirstName  string
	LastName   string
}

type LoginInput struct {
	TenantID uuid.UUID
	Email    string
	Password string
	UserAgent string
	IP        string
}

type RefreshInput struct {
	RefreshToken string
	UserAgent    string
	IP           string
}

type Service interface {
	Signup(ctx context.Context, in SignupInput) (AccessTokens, error)
	Login(ctx context.Context, in LoginInput) (AccessTokens, error)
	Refresh(ctx context.Context, in RefreshInput) (AccessTokens, error)
	Logout(ctx context.Context, refreshToken string) error
	// Me returns the current user's profile within a tenant context.
	Me(ctx context.Context, userID, tenantID uuid.UUID) (UserProfile, error)
	// Introspect validates a JWT and returns token/user claims.
	Introspect(ctx context.Context, token string) (Introspection, error)
	// Revoke invalidates a token. Currently supports refresh tokens.
	Revoke(ctx context.Context, token string, tokenType string) error

	// UpdateUserRoles updates the roles array for the specified user.
	UpdateUserRoles(ctx context.Context, userID uuid.UUID, roles []string) error

	// Admin/user management
	// ListTenantUsers returns all users that belong to the given tenant.
	ListTenantUsers(ctx context.Context, tenantID uuid.UUID) ([]User, error)
	// UpdateUserNames updates only first and last name for a user, preserving roles.
	UpdateUserNames(ctx context.Context, userID uuid.UUID, firstName, lastName string) error
	// SetUserActive toggles the active state of a user.
	SetUserActive(ctx context.Context, userID uuid.UUID, active bool) error
	// ListUserSessions lists refresh tokens (sessions) for a user within a tenant.
	ListUserSessions(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) ([]RefreshToken, error)
	// RevokeSession revokes a specific session (refresh token) by ID for the given user and tenant.
	RevokeSession(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID, sessionID uuid.UUID) error

	// MFA (TOTP + backup codes)
	// StartTOTPEnrollment generates and stores a TOTP secret (disabled), and returns the secret and otpauth URI.
	StartTOTPEnrollment(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) (secret string, otpauthURL string, err error)
	// ActivateTOTP verifies a TOTP code for the stored secret and marks MFA as enabled.
	ActivateTOTP(ctx context.Context, userID uuid.UUID, code string) error
	// DisableTOTP disables TOTP for the user (keeps secret for potential reactivation).
	DisableTOTP(ctx context.Context, userID uuid.UUID) error
	// GenerateBackupCodes creates N backup codes, stores their hashes, and returns the plaintext codes.
	GenerateBackupCodes(ctx context.Context, userID uuid.UUID, count int) ([]string, error)
	// ConsumeBackupCode attempts to consume a backup code; returns true if it was valid and unused.
	ConsumeBackupCode(ctx context.Context, userID uuid.UUID, code string) (bool, error)
	// CountRemainingBackupCodes returns the number of unused backup codes.
	CountRemainingBackupCodes(ctx context.Context, userID uuid.UUID) (int64, error)

	// VerifyMFA validates a provided MFA factor against a challenge token and issues tokens on success.
	VerifyMFA(ctx context.Context, in MFAVerifyInput) (AccessTokens, error)

	// --- RBAC v2 ---
	// ListPermissions returns all known permissions.
	ListPermissions(ctx context.Context) ([]Permission, error)
	// ListRoles returns all roles for a tenant.
	ListRoles(ctx context.Context, tenantID uuid.UUID) ([]Role, error)
	// CreateRole creates a role in a tenant.
	CreateRole(ctx context.Context, tenantID uuid.UUID, name, description string) (Role, error)
	// UpdateRole updates a role in a tenant.
	UpdateRole(ctx context.Context, roleID uuid.UUID, tenantID uuid.UUID, name, description string) (Role, error)
	// DeleteRole deletes a role in a tenant.
	DeleteRole(ctx context.Context, roleID uuid.UUID, tenantID uuid.UUID) error
	// User role assignments in normalized table.
	ListUserRoleIDs(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) ([]uuid.UUID, error)
	AddUserRole(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID, roleID uuid.UUID) error
	RemoveUserRole(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID, roleID uuid.UUID) error
	// Role-permission mapping management (permissionKey is the unique permission key).
	UpsertRolePermission(ctx context.Context, roleID uuid.UUID, permissionKey, scopeType string, resourceType, resourceID *string) error
	DeleteRolePermission(ctx context.Context, roleID uuid.UUID, permissionKey, scopeType string, resourceType, resourceID *string) error
	// ResolveUserPermissions aggregates permissions from roles, user ACL, and group ACL.
	ResolveUserPermissions(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) (ResolvedPermissions, error)
	// HasPermission checks whether user has a permission, optionally scoped to an object.
	HasPermission(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID, key, objectType string, objectID *string) (bool, error)

	// Email discovery methods
	FindTenantsByUserEmail(ctx context.Context, email string) ([]TenantInfo, error)
	GetUserByEmail(ctx context.Context, email, tenantID string) (*User, error)

    // --- FGA ---
    // Group management
    CreateGroup(ctx context.Context, tenantID uuid.UUID, name, description string) (Group, error)
    ListGroups(ctx context.Context, tenantID uuid.UUID) ([]Group, error)
    DeleteGroup(ctx context.Context, groupID uuid.UUID, tenantID uuid.UUID) error
    // Group membership
    AddGroupMember(ctx context.Context, groupID uuid.UUID, userID uuid.UUID) error
    RemoveGroupMember(ctx context.Context, groupID uuid.UUID, userID uuid.UUID) error
    // ACL tuples
    CreateACLTuple(ctx context.Context, tenantID uuid.UUID, subjectType string, subjectID uuid.UUID, permissionKey string, objectType string, objectID *string, createdBy *uuid.UUID) (ACLTuple, error)
    DeleteACLTuple(ctx context.Context, tenantID uuid.UUID, subjectType string, subjectID uuid.UUID, permissionKey string, objectType string, objectID *string) error
    // Authorization decision
    Authorize(ctx context.Context, tenantID uuid.UUID, subjectType string, subjectID uuid.UUID, permissionKey string, objectType string, objectID *string) (allowed bool, reason string, err error)
}

// Magic-link inputs
type MagicSendInput struct {
	TenantID    uuid.UUID
	Email       string
	RedirectURL string
}

type MagicVerifyInput struct {
	Token     string
	UserAgent string
	IP        string
}

// MFAVerifyInput is the payload for verifying MFA after a password login challenge.
type MFAVerifyInput struct {
	ChallengeToken string
	Code           string
	Method         string // "totp" | "backup_code"
	UserAgent      string
	IP             string
}

// MagicLinkService defines the contract for magic-link flows.
type MagicLinkService interface {
	Send(ctx context.Context, in MagicSendInput) error
	Verify(ctx context.Context, in MagicVerifyInput) (AccessTokens, error)
	// CreateForTest creates and stores a magic link token and returns the raw token (no email).
	// Intended for CI/testing environments only.
	CreateForTest(ctx context.Context, in MagicSendInput) (string, error)
}

// SSO inputs
type SSOStartInput struct {
	Provider    string
	TenantID    uuid.UUID
	RedirectURL string
	State       string
	ConnectionID string
	OrganizationID string
}

type SSOCallbackInput struct {
	Provider  string
	Query     map[string][]string
	UserAgent string
	IP        string
}

type SSOOrganizationPortalLinkGeneratorInput struct {
	Provider string
	TenantID uuid.UUID
	Intent   string
	OrganizationID string
}

// SSOService defines the contract for SSO/Social login flows.
type SSOService interface {
	Start(ctx context.Context, in SSOStartInput) (authURL string, err error)
	Callback(ctx context.Context, in SSOCallbackInput) (AccessTokens, error)
	OrganizationPortalLinkGenerator(ctx context.Context, in SSOOrganizationPortalLinkGeneratorInput) (PortalLink, error)
}

// Repository abstracts data access needed by the auth service.
type Repository interface {
	CreateUser(ctx context.Context, id uuid.UUID, firstName, lastName string, roles []string) error
	CreateAuthIdentity(ctx context.Context, id uuid.UUID, userID uuid.UUID, tenantID uuid.UUID, email, passwordHash string) error
	GetAuthIdentityByEmailTenant(ctx context.Context, tenantID uuid.UUID, email string) (AuthIdentity, error)
	UpdateUserLoginAt(ctx context.Context, userID uuid.UUID) error
	AddUserToTenant(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) error

	InsertRefreshToken(ctx context.Context, id uuid.UUID, userID uuid.UUID, tenantID uuid.UUID, tokenHash string, parentID *uuid.UUID, userAgent, ip string, expiresAt time.Time) error
	GetRefreshTokenByHash(ctx context.Context, tokenHash string) (RefreshToken, error)
	RevokeTokenChain(ctx context.Context, id uuid.UUID) error

	// Magic link operations
	CreateMagicLink(ctx context.Context, id uuid.UUID, userID *uuid.UUID, tenantID uuid.UUID, email, tokenHash, redirectURL string, expiresAt time.Time) error
	GetMagicLinkByHash(ctx context.Context, tokenHash string) (MagicLink, error)
	ConsumeMagicLink(ctx context.Context, tokenHash string) error

	// User/profile lookups
	GetUserByID(ctx context.Context, userID uuid.UUID) (User, error)
	GetAuthIdentitiesByUser(ctx context.Context, userID uuid.UUID) ([]AuthIdentity, error)

	// UpdateUserRoles updates only the roles column for a user, preserving other profile fields.
	UpdateUserRoles(ctx context.Context, userID uuid.UUID, roles []string) error

	// MFA persistence
	UpsertMFASecret(ctx context.Context, userID uuid.UUID, secret string, enabled bool) error
	GetMFASecret(ctx context.Context, userID uuid.UUID) (MFASecret, error)
	InsertMFABackupCode(ctx context.Context, id uuid.UUID, userID uuid.UUID, codeHash string) error
	CountRemainingMFABackupCodes(ctx context.Context, userID uuid.UUID) (int64, error)
	// ConsumeMFABackupCode returns true when a code was valid and consumed.
	ConsumeMFABackupCode(ctx context.Context, userID uuid.UUID, codeHash string) (bool, error)

	// Admin/user management
	// ListTenantUsers returns all users that belong to the given tenant.
	ListTenantUsers(ctx context.Context, tenantID uuid.UUID) ([]User, error)
	// SetUserActive toggles the active state of a user.
	SetUserActive(ctx context.Context, userID uuid.UUID, active bool) error
	// UpdateUserNames updates only first and last name for a user, preserving roles.
	UpdateUserNames(ctx context.Context, userID uuid.UUID, firstName, lastName string) error
	// ListUserSessions lists refresh tokens (sessions) for a user within a tenant.
	ListUserSessions(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) ([]RefreshToken, error)

	// --- RBAC v2 ---
	// Permissions
	ListPermissions(ctx context.Context) ([]Permission, error)
	GetPermissionByKey(ctx context.Context, key string) (Permission, error)
	// Roles
	ListRolesByTenant(ctx context.Context, tenantID uuid.UUID) ([]Role, error)
	CreateRole(ctx context.Context, id uuid.UUID, tenantID uuid.UUID, name, description string) (Role, error)
	UpdateRole(ctx context.Context, roleID uuid.UUID, tenantID uuid.UUID, name, description string) (Role, error)
	DeleteRole(ctx context.Context, roleID uuid.UUID, tenantID uuid.UUID) error
	GetRoleByName(ctx context.Context, tenantID uuid.UUID, name string) (Role, error)
	// User role assignments
	ListUserRoleIDs(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) ([]uuid.UUID, error)
	AddUserRole(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID, roleID uuid.UUID) error
	RemoveUserRole(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID, roleID uuid.UUID) error
	// Role-permissions
	ListRolePermissionKeys(ctx context.Context, roleIDs []uuid.UUID) ([]RolePermissionGrant, error)
	UpsertRolePermission(ctx context.Context, roleID uuid.UUID, permissionID uuid.UUID, scopeType string, resourceType, resourceID *string) error
	DeleteRolePermission(ctx context.Context, roleID uuid.UUID, permissionID uuid.UUID, scopeType string, resourceType, resourceID *string) error
	// Groups and ACL
	ListUserGroups(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error)
	ListACLPermissionKeysForUser(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID) ([]PermissionGrant, error)
	ListACLPermissionKeysForGroups(ctx context.Context, tenantID uuid.UUID, groupIDs []uuid.UUID) ([]GroupPermissionGrant, error)

	// Email discovery methods
	FindAuthIdentitiesByEmail(ctx context.Context, email string) ([]AuthIdentity, error)

    // --- FGA repository methods (groups, memberships, ACL tuples) ---
    // Groups
    CreateGroup(ctx context.Context, id uuid.UUID, tenantID uuid.UUID, name, description string) (Group, error)
    ListGroups(ctx context.Context, tenantID uuid.UUID) ([]Group, error)
    DeleteGroup(ctx context.Context, id uuid.UUID, tenantID uuid.UUID) error
    // Group membership
    AddGroupMember(ctx context.Context, groupID uuid.UUID, userID uuid.UUID) error
    RemoveGroupMember(ctx context.Context, groupID uuid.UUID, userID uuid.UUID) error
    // ACL tuples
    CreateACLTuple(ctx context.Context, id uuid.UUID, tenantID uuid.UUID, subjectType string, subjectID uuid.UUID, permissionID uuid.UUID, objectType string, objectID *string, createdBy *uuid.UUID) (ACLTuple, error)
    DeleteACLTuple(ctx context.Context, tenantID uuid.UUID, subjectType string, subjectID uuid.UUID, permissionID uuid.UUID, objectType string, objectID *string) error
}

type AuthIdentity struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	TenantID  uuid.UUID
	Email     string
	PasswordHash string
}

type RefreshToken struct {
	ID       uuid.UUID
	UserID   uuid.UUID
	TenantID uuid.UUID
	Revoked  bool
	ExpiresAt time.Time
	CreatedAt time.Time
	UserAgent string
	IP        string
}

type MagicLink struct {
	ID         uuid.UUID
	UserID     *uuid.UUID
	TenantID   uuid.UUID
	Email      string
	TokenHash  string
	RedirectURL string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	ConsumedAt *time.Time
}

// User reflects the users table record.
type User struct {
	ID           uuid.UUID
	EmailVerified bool
	IsActive     bool
	FirstName    string
	LastName     string
	Roles        []string
	CreatedAt    time.Time
	UpdatedAt    time.Time
	LastLoginAt  *time.Time
}

// UserProfile is returned by the Me endpoint.
type UserProfile struct {
	ID           uuid.UUID `json:"id"`
	TenantID     uuid.UUID `json:"tenant_id"`
	Email        string    `json:"email"`
	FirstName    string    `json:"first_name"`
	LastName     string    `json:"last_name"`
	Roles        []string  `json:"roles"`
	MFAEnabled   bool      `json:"mfa_enabled"`
	EmailVerified bool     `json:"email_verified"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
}

// Introspection is the response for /auth/introspect.
type Introspection struct {
	Active       bool       `json:"active"`
	UserID       uuid.UUID  `json:"user_id"`
	TenantID     uuid.UUID  `json:"tenant_id"`
	Email        string     `json:"email"`
	Roles        []string   `json:"roles"`
	MFAVerified  bool       `json:"mfa_verified"`
	EmailVerified bool      `json:"email_verified"`
	Exp          int64      `json:"exp"`
	Iat          int64      `json:"iat"`
}

// --- RBAC v2 domain types ---

// Role represents a tenant-scoped role.
type Role struct {
	ID          uuid.UUID
	TenantID    uuid.UUID
	Name        string
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Permission represents a global permission definition.
type Permission struct {
	ID          uuid.UUID
	Key         string
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// RolePermissionGrant captures a role's permission grant with optional resource scoping.
type RolePermissionGrant struct {
	RoleID       uuid.UUID
	Key          string
	ScopeType    string
	ResourceType *string
	ResourceID   *string
}

// PermissionGrant is a resolved permission possibly scoped to an object (type, id).
type PermissionGrant struct {
	Key        string
	ObjectType string
	ObjectID   *string
}

// GroupPermissionGrant is an ACL grant via group membership.
type GroupPermissionGrant struct {
	GroupID    uuid.UUID
	Key        string
	ObjectType string
	ObjectID   *string
}

// ResolvedPermissions aggregates all grants for a user.
type ResolvedPermissions struct {
	Grants []PermissionGrant
}

// TenantInfo represents basic tenant information for discovery
type TenantInfo struct {
	ID   string
	Name string
}
