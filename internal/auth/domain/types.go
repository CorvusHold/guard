package domain

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// ErrTokenInvalid is returned when a verification token is not found, already consumed, or expired.
var ErrTokenInvalid = errors.New("token not found, already used, or expired")

// ErrNotFound is returned when a requested resource does not exist.
var ErrNotFound = errors.New("not found")

// Cookie names shared across auth and SSO controllers.
const (
	CookieAccessToken  = "guard_access_token"
	CookieRefreshToken = "guard_refresh_token"
)

type PortalLink struct {
	Link string `json:"link"`
}

// PublicSSOProvider contains public info about an SSO provider for login options
type PublicSSOProvider struct {
	Slug         string
	Name         string
	ProviderType string
	Domains      []string
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
	TenantID  uuid.UUID
	Email     string
	Password  string
	FirstName string
	LastName  string
}

type LoginInput struct {
	TenantID  uuid.UUID
	Email     string
	Password  string
	UserAgent string
	IP        string
}

type RefreshInput struct {
	RefreshToken string
	UserAgent    string
	IP           string
}

type SSOTokenInput struct {
	UserID        uuid.UUID
	TenantID      uuid.UUID
	SSOProviderID *uuid.UUID // Optional: SSO provider ID for session tracking
	UserAgent     string
	IP            string
}

type Service interface {
	Signup(ctx context.Context, in SignupInput) (AccessTokens, error)
	Login(ctx context.Context, in LoginInput) (AccessTokens, error)
	Refresh(ctx context.Context, in RefreshInput) (AccessTokens, error)
	Logout(ctx context.Context, refreshToken string) error
	// IssueTokensForSSO issues access and refresh tokens for SSO-authenticated users
	IssueTokensForSSO(ctx context.Context, in SSOTokenInput) (AccessTokens, error)
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
	// SetUserEmailVerified sets the email_verified flag for a user.
	SetUserEmailVerified(ctx context.Context, userID uuid.UUID, verified bool) error
	// ListUserSessions lists refresh tokens (sessions) for a user within a tenant.
	ListUserSessions(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) ([]RefreshToken, error)
	// RevokeSession revokes a specific session (refresh token) by ID for the given user and tenant.
	RevokeSession(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID, sessionID uuid.UUID) error
	// RevokeUserSessions revokes all active refresh tokens for a user within a tenant.
	// Returns the number of tokens revoked.
	RevokeUserSessions(ctx context.Context, userID, tenantID uuid.UUID) (int64, error)
	// UnlockAccount clears lockout and resets failed attempts for a user (admin action).
	UnlockAccount(ctx context.Context, userID uuid.UUID) error

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
	ListUserRoles(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) ([]Role, error)
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

	// SSO provider discovery for login options
	ListSSOProvidersPublic(ctx context.Context, tenantID uuid.UUID) ([]PublicSSOProvider, error)

	// Password reset
	// RequestPasswordReset sends a password reset email to the user.
	RequestPasswordReset(ctx context.Context, in PasswordResetRequestInput) error
	// ConfirmPasswordReset verifies the token and sets the new password.
	ConfirmPasswordReset(ctx context.Context, in PasswordResetConfirmInput) error
	// ChangePassword changes the password for a logged-in user.
	ChangePassword(ctx context.Context, in PasswordChangeInput) error

	// Email verification
	// SendEmailVerification creates a token and optionally sends a verification email.
	SendEmailVerification(ctx context.Context, userID, tenantID uuid.UUID, email string) error
	// VerifyEmail validates a verification token and marks the user's email as verified.
	VerifyEmail(ctx context.Context, rawToken string) error
	// UpdateProfile updates the user's profile (first name, last name).
	UpdateProfile(ctx context.Context, userID uuid.UUID, firstName, lastName string) error

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

	// GetOrCreateAdminRole returns the admin role for a tenant, creating it if it doesn't exist.
	GetOrCreateAdminRole(ctx context.Context, tenantID uuid.UUID) (Role, error)
	// SeedDefaultRoles creates the standard set of roles (admin, member) for a tenant. Idempotent.
	SeedDefaultRoles(ctx context.Context, tenantID uuid.UUID) error
	// ParseAccessToken parses and validates an access token, returning the claims.
	// It validates the JWT signature using the tenant-specific signing key (resolved from
	// the token's tenant claim), verifies standard claims (exp, iss, aud), and returns
	// an error if the signature is invalid or the token is expired.
	// The returned AccessTokenClaims includes UserID, TenantID, Email, and Roles populated
	// directly from the JWT claims (not from a database lookup). Email and Roles are read
	// from the "email" and "roles" claim keys respectively.
	ParseAccessToken(token string) (AccessTokenClaims, error)

	// --- Invitations ---
	// InviteUser creates an invitation for a user to join a tenant.
	// Returns the invitation and the raw token (for sending via email).
	InviteUser(ctx context.Context, in InviteUserInput) (Invitation, string, error)
	// GetInvitationByToken retrieves an invitation by its raw token.
	GetInvitationByToken(ctx context.Context, token string) (Invitation, error)
	// ListInvitations returns all invitations for a tenant.
	ListInvitations(ctx context.Context, tenantID uuid.UUID) ([]Invitation, error)
	// ListPendingInvitations returns only pending (non-expired) invitations for a tenant.
	ListPendingInvitations(ctx context.Context, tenantID uuid.UUID) ([]Invitation, error)
	// AcceptInvitation accepts an invitation and creates the user account.
	AcceptInvitation(ctx context.Context, in AcceptInvitationInput) (AccessTokens, error)
	// RevokeInvitation revokes a pending invitation.
	RevokeInvitation(ctx context.Context, invitationID, tenantID uuid.UUID) error
	// DeleteInvitation deletes an invitation.
	DeleteInvitation(ctx context.Context, invitationID, tenantID uuid.UUID) error

	// --- Admin User Creation ---
	// AdminCreateUser creates a user directly in a tenant (admin operation).
	AdminCreateUser(ctx context.Context, in AdminCreateUserInput) (User, error)

	// --- API Keys ---
	// CreateAPIKey creates a new API key for service-to-service authentication.
	// Returns the APIKey metadata and the raw key (shown only once).
	CreateAPIKey(ctx context.Context, tenantID uuid.UUID, name string, scopes []string, createdBy uuid.UUID, expiresAt *time.Time) (APIKey, string, error)
	// ValidateAPIKey validates a raw API key and returns the associated metadata.
	ValidateAPIKey(ctx context.Context, rawKey string) (APIKey, error)
	// ListAPIKeys returns all API keys for a tenant.
	ListAPIKeys(ctx context.Context, tenantID uuid.UUID) ([]APIKey, error)
	// RevokeAPIKey revokes an API key.
	RevokeAPIKey(ctx context.Context, keyID, tenantID uuid.UUID) error

	// --- Self-Service ---
	RevokeTokenChain(ctx context.Context, tokenID uuid.UUID) error
	IsMFAEnrolled(ctx context.Context, userID, tenantID uuid.UUID) (bool, error)

	// --- Platform Admin ---
	ListAllTenantsWithStats(ctx context.Context, limit, offset int) ([]TenantStats, error)
	SearchUsersGlobal(ctx context.Context, query string) ([]UserSearchResult, error)
	QueryAuditLogs(ctx context.Context, tenantID *uuid.UUID, userID *uuid.UUID, action string, limit, offset int) ([]AuditLogEntry, int, error)
	PlatformStats(ctx context.Context) (PlatformStatsResult, error)

	// --- Bulk ---
	ListUsersByTenant(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]UserExport, error)
}

// AccessTokenClaims represents the claims in an access token.
type AccessTokenClaims struct {
	UserID   uuid.UUID
	TenantID uuid.UUID
	Email    string
	Roles    []string
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
	Provider       string
	TenantID       uuid.UUID
	RedirectURL    string
	State          string
	ConnectionID   string
	OrganizationID string
}

type SSOCallbackInput struct {
	Provider  string
	Query     map[string][]string
	UserAgent string
	IP        string
}

type SSOOrganizationPortalLinkGeneratorInput struct {
	Provider       string
	TenantID       uuid.UUID
	Intent         string
	OrganizationID string
	CreatedBy      uuid.UUID
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

	InsertRefreshToken(ctx context.Context, id uuid.UUID, userID uuid.UUID, tenantID uuid.UUID, tokenHash string, parentID *uuid.UUID, userAgent, ip string, expiresAt time.Time, authMethod string, ssoProviderID *uuid.UUID, metadata *RefreshTokenMetadata) error
	InsertRefreshTokenWithFamily(ctx context.Context, id uuid.UUID, userID uuid.UUID, tenantID uuid.UUID, tokenHash string, parentID *uuid.UUID, userAgent, ip string, expiresAt time.Time, authMethod string, ssoProviderID *uuid.UUID, metadata *RefreshTokenMetadata, familyID uuid.UUID) error
	GetRefreshTokenByHash(ctx context.Context, tokenHash string) (RefreshToken, error)
	RevokeTokenChain(ctx context.Context, id uuid.UUID) error
	RevokeTokenFamily(ctx context.Context, familyID uuid.UUID) error

	// Magic link operations
	CreateMagicLink(ctx context.Context, id uuid.UUID, userID *uuid.UUID, tenantID uuid.UUID, email, tokenHash, redirectURL string, expiresAt time.Time) error
	GetMagicLinkByHash(ctx context.Context, tokenHash string) (MagicLink, error)
	ConsumeMagicLink(ctx context.Context, tokenHash string) error

	// SSO portal tokens
	CreateSSOPortalToken(ctx context.Context, tenantID uuid.UUID, ssoProviderID *uuid.UUID, providerSlug, tokenHash, intent string, createdBy uuid.UUID, expiresAt time.Time, maxUses int32) (SSOPortalToken, error)

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
	// SetUserEmailVerified sets the email_verified flag for a user.
	SetUserEmailVerified(ctx context.Context, userID uuid.UUID, verified bool) error
	// UpdateUserNames updates only first and last name for a user, preserving roles.
	UpdateUserNames(ctx context.Context, userID uuid.UUID, firstName, lastName string) error
	// ListUserSessions lists refresh tokens (sessions) for a user within a tenant.
	ListUserSessions(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) ([]RefreshToken, error)
	// RevokeUserSessions revokes all active refresh tokens for a user within a tenant.
	// Returns the number of tokens revoked.
	RevokeUserSessions(ctx context.Context, userID, tenantID uuid.UUID) (int64, error)
	// RevokeRefreshTokenByHash revokes a specific refresh token by its hash.
	// Returns the number of tokens revoked (0 or 1).
	RevokeRefreshTokenByHash(ctx context.Context, tokenHash string) (int64, error)
	// RevokeAllUserSessions revokes all active refresh tokens for a user across all tenants.
	// Returns the number of tokens revoked.
	RevokeAllUserSessions(ctx context.Context, userID uuid.UUID) (int64, error)
	// UpdateRefreshTokenLastUsed updates the last_used_at timestamp for a refresh token.
	UpdateRefreshTokenLastUsed(ctx context.Context, tokenHash string) error

	// --- Account lockout ---
	// IncrementFailedAttempts increments the failed login counter and returns the new count.
	IncrementFailedAttempts(ctx context.Context, tenantID uuid.UUID, email string) (int32, error)
	// ResetFailedAttempts resets the failed login counter and clears any lockout.
	ResetFailedAttempts(ctx context.Context, tenantID uuid.UUID, email string) error
	// LockAccount sets the locked_until timestamp for an account.
	LockAccount(ctx context.Context, tenantID uuid.UUID, email string, lockedUntil time.Time) error
	// UnlockAccount clears lockout and resets failed attempts for a user (admin action).
	UnlockAccount(ctx context.Context, userID uuid.UUID) error
	// GetLockoutStatus returns the current failed attempts count and locked_until timestamp.
	GetLockoutStatus(ctx context.Context, tenantID uuid.UUID, email string) (failedAttempts int32, lockedUntil *time.Time, err error)

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
	ListUserRoleNames(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) ([]string, error)
	ListUserRoles(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) ([]Role, error)
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

	// Tenant lookups
	GetTenantByID(ctx context.Context, tenantID uuid.UUID) (Tenant, error)

	// SSO provider lookups for login options
	ListEnabledSSOProviders(ctx context.Context, tenantID uuid.UUID) ([]PublicSSOProvider, error)

	// Password reset tokens
	CreatePasswordResetToken(ctx context.Context, id uuid.UUID, userID uuid.UUID, tenantID uuid.UUID, email, tokenHash string, expiresAt time.Time) error
	GetPasswordResetTokenByHash(ctx context.Context, tokenHash string) (PasswordResetToken, error)
	ConsumePasswordResetToken(ctx context.Context, tokenHash string) (int64, error)

	// Email verification tokens
	CreateEmailVerificationToken(ctx context.Context, id, userID, tenantID uuid.UUID, email, tokenHash string, expiresAt time.Time) error
	GetEmailVerificationTokenByHash(ctx context.Context, tokenHash string) (EmailVerificationToken, error)
	ConsumeEmailVerificationToken(ctx context.Context, tokenHash string) error
	// UpdateAuthIdentityPassword updates the password hash for an auth identity.
	// Returns the number of rows affected.
	UpdateAuthIdentityPassword(ctx context.Context, tenantID uuid.UUID, email, passwordHash string) (int64, error)

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

	// --- Invitations ---
	CreateInvitation(ctx context.Context, id uuid.UUID, tenantID *uuid.UUID, email, tokenHash, role string, invitedBy *uuid.UUID, expiresAt time.Time) (Invitation, error)
	GetInvitationByHash(ctx context.Context, tokenHash string) (Invitation, error)
	GetInvitationByID(ctx context.Context, id uuid.UUID) (Invitation, error)
	ListInvitationsByTenant(ctx context.Context, tenantID uuid.UUID) ([]Invitation, error)
	ListPendingInvitationsByTenant(ctx context.Context, tenantID uuid.UUID) ([]Invitation, error)
	AcceptInvitation(ctx context.Context, tokenHash string) (uuid.UUID, error)
	RevokeInvitation(ctx context.Context, id uuid.UUID, tenantID uuid.UUID) error
	DeleteInvitation(ctx context.Context, id uuid.UUID, tenantID uuid.UUID) error

	// --- API Keys ---
	CreateAPIKey(ctx context.Context, id uuid.UUID, tenantID uuid.UUID, name, keyHash, keyPrefix string, scopes []string, createdBy uuid.UUID, expiresAt *time.Time) (APIKey, error)
	GetAPIKeyByHash(ctx context.Context, keyHash string) (APIKey, error)
	ListAPIKeysByTenant(ctx context.Context, tenantID uuid.UUID) ([]APIKey, error)
	RevokeAPIKey(ctx context.Context, keyID, tenantID uuid.UUID) error
	UpdateAPIKeyLastUsed(ctx context.Context, keyID uuid.UUID) error

	// --- Self-Service ---
	IsMFAEnrolled(ctx context.Context, userID, tenantID uuid.UUID) (bool, error)

	// --- Platform Admin ---
	ListAllTenantsWithStats(ctx context.Context, limit, offset int) ([]TenantStats, error)
	SearchUsersGlobal(ctx context.Context, query string) ([]UserSearchResult, error)
	QueryAuditLogs(ctx context.Context, tenantID *uuid.UUID, userID *uuid.UUID, action string, limit, offset int) ([]AuditLogEntry, int, error)
	PlatformStats(ctx context.Context) (PlatformStatsResult, error)

	// --- Bulk ---
	ListUsersByTenant(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]UserExport, error)
}

type AuthIdentity struct {
	ID           uuid.UUID
	UserID       uuid.UUID
	TenantID     uuid.UUID
	Email        string
	PasswordHash string
}

type Tenant struct {
	ID        uuid.UUID
	Name      string
	IsActive  bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// RefreshTokenMetadata contains additional context about how a refresh token was created.
// This metadata is stored as JSON in the database and can be used for debugging,
// auditing, and analytics purposes.
type RefreshTokenMetadata struct {
	AuthMethod    string `json:"auth_method,omitempty"`    // "password", "sso", "magic_link"
	SSOProvider   string `json:"sso_provider,omitempty"`   // Provider slug when auth_method is "sso"
	MFAVerified   bool   `json:"mfa_verified,omitempty"`   // Whether MFA was verified during authentication
	CreatedVia    string `json:"created_via,omitempty"`    // "login", "refresh", "sso_callback"
	ClientVersion string `json:"client_version,omitempty"` // SDK/client version from X-Guard-Client header
}

type RefreshToken struct {
	ID              uuid.UUID
	UserID          uuid.UUID
	TenantID        uuid.UUID
	FamilyID        uuid.UUID // All tokens in a rotation chain share the same family_id
	Revoked         bool
	ExpiresAt       time.Time
	CreatedAt       time.Time
	LastUsedAt      *time.Time // Tracks last usage for session idle timeout
	UserAgent       string
	IP              string
	AuthMethod      string     // "password", "sso", "magic_link"
	SSOProviderID   *uuid.UUID // Set when auth_method is "sso"
	SSOProviderName string     // Provider name (from join)
	SSOProviderSlug string     // Provider slug (from join)
	Metadata        *RefreshTokenMetadata
}

type MagicLink struct {
	ID          uuid.UUID
	UserID      *uuid.UUID
	TenantID    uuid.UUID
	Email       string
	TokenHash   string
	RedirectURL string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	ConsumedAt  *time.Time
}

// PasswordResetToken represents a password reset token record.
type PasswordResetToken struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	TenantID   uuid.UUID
	Email      string
	TokenHash  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	ConsumedAt *time.Time
}

// EmailVerificationToken represents an email verification token record.
type EmailVerificationToken struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	TenantID   uuid.UUID
	Email      string
	TokenHash  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	ConsumedAt *time.Time
}

// PasswordResetRequestInput is the input for requesting a password reset.
type PasswordResetRequestInput struct {
	TenantID *uuid.UUID // Optional - if nil, will look up by email across all tenants
	Email    string
}

// TenantSelectionRequiredError is returned when an email exists in multiple tenants.
// For password reset flows, this triggers sending separate reset emails to each tenant
// rather than exposing tenant options in the API response.
// Deprecated: This type is retained for backwards compatibility but the service now
// handles multi-tenant emails by sending per-tenant reset emails internally.
type TenantSelectionRequiredError struct {
	Tenants []TenantOption
}

func (e *TenantSelectionRequiredError) Error() string {
	return "tenant_selection_required"
}

// TenantOption represents a tenant the user can select from.
type TenantOption struct {
	TenantID   uuid.UUID `json:"tenant_id"`
	TenantName string    `json:"tenant_name"`
}

// PasswordResetConfirmInput is the input for confirming a password reset.
type PasswordResetConfirmInput struct {
	TenantID    *uuid.UUID // Optional - tenant is derived from token
	Token       string
	NewPassword string
}

// PasswordChangeInput is the input for changing password while logged in.
type PasswordChangeInput struct {
	UserID          uuid.UUID
	TenantID        uuid.UUID
	CurrentPassword string
	NewPassword     string
}

type SSOPortalToken struct {
	ID            uuid.UUID
	TenantID      uuid.UUID
	SSOProviderID *uuid.UUID
	ProviderSlug  string
	TokenHash     string
	Intent        string
	CreatedBy     uuid.UUID
	ExpiresAt     time.Time
	RevokedAt     *time.Time
	MaxUses       int32
	UseCount      int32
	LastUsedAt    *time.Time
	CreatedAt     time.Time
}

// User reflects the users table record.
type User struct {
	ID            uuid.UUID
	Email         string
	EmailVerified bool
	IsActive      bool
	FirstName     string
	LastName      string
	Roles         []string
	CreatedAt     time.Time
	UpdatedAt     time.Time
	LastLoginAt   *time.Time
}

// UserProfile is returned by the Me endpoint.
type UserProfile struct {
	ID            uuid.UUID  `json:"id"`
	TenantID      uuid.UUID  `json:"tenant_id"`
	Email         string     `json:"email"`
	FirstName     string     `json:"first_name"`
	LastName      string     `json:"last_name"`
	Roles         []string   `json:"roles"`
	MFAEnabled    bool       `json:"mfa_enabled"`
	EmailVerified bool       `json:"email_verified"`
	LastLoginAt   *time.Time `json:"last_login_at,omitempty"`
}

// Introspection is the response for /auth/introspect.
type Introspection struct {
	Active        bool      `json:"active"`
	UserID        uuid.UUID `json:"user_id"`
	TenantID      uuid.UUID `json:"tenant_id"`
	Email         string    `json:"email"`
	Roles         []string  `json:"roles"`
	MFAVerified   bool      `json:"mfa_verified"`
	EmailVerified bool      `json:"email_verified"`
	Exp           int64     `json:"exp"`
	Iat           int64     `json:"iat"`
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

// Invitation represents a user invitation to join a tenant or create a new tenant
type Invitation struct {
	ID         uuid.UUID
	TenantID   *uuid.UUID // nil if inviting to create a new tenant
	Email      string
	TokenHash  string
	Role       string // Optional role to assign upon acceptance
	InvitedBy  *uuid.UUID
	Status     string // "pending", "accepted", "expired", "revoked"
	ExpiresAt  time.Time
	AcceptedAt *time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// InviteUserInput is the input for creating an invitation
type InviteUserInput struct {
	TenantID  *uuid.UUID // nil to invite user to create a new tenant
	Email     string
	Role      string // Optional role to assign upon acceptance
	InvitedBy uuid.UUID
}

// AcceptInvitationInput is the input for accepting an invitation
type AcceptInvitationInput struct {
	Token     string
	Password  string
	FirstName string
	LastName  string
}

// AdminCreateUserInput is the input for admin creating a user directly
type AdminCreateUserInput struct {
	TenantID      uuid.UUID
	Email         string
	Password      string
	FirstName     string
	LastName      string
	Roles         []string
	EmailVerified bool
	SendWelcome   bool // If true, send welcome email to user
}

// --- API Keys ---

// APIKey represents a service-to-service API key.
type APIKey struct {
	ID         uuid.UUID
	TenantID   uuid.UUID
	Name       string
	KeyPrefix  string
	Scopes     []string
	CreatedBy  *uuid.UUID
	ExpiresAt  *time.Time
	RevokedAt  *time.Time
	LastUsedAt *time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// --- Platform Admin types ---

// TenantStats is a tenant with aggregate user count.
type TenantStats struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UserCount int       `json:"user_count"`
}

// UserSearchResult is a user returned from a global search.
type UserSearchResult struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	Tenants   []string  `json:"tenants"`
}

// AuditLogEntry represents a single audit log row.
type AuditLogEntry struct {
	ID        int64      `json:"id"`
	UserID    *uuid.UUID `json:"user_id,omitempty"`
	TenantID  *uuid.UUID `json:"tenant_id,omitempty"`
	Action    string     `json:"action"`
	Meta      string     `json:"meta"`
	IP        string     `json:"ip"`
	CreatedAt time.Time  `json:"created_at"`
}

// PlatformStatsResult holds aggregate platform statistics.
type PlatformStatsResult struct {
	TotalTenants   int `json:"total_tenants"`
	TotalUsers     int `json:"total_users"`
	ActiveSessions int `json:"active_sessions"`
	TotalAPIKeys   int `json:"total_api_keys"`
}

// UserExport represents a user row for bulk export.
type UserExport struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	Roles     []string  `json:"roles"`
	CreatedAt time.Time `json:"created_at"`
	Blocked   bool      `json:"blocked"`
}
