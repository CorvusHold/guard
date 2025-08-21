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
	"github.com/corvusHold/guard/internal/metrics"
	evdomain "github.com/corvusHold/guard/internal/events/domain"
	evsvc "github.com/corvusHold/guard/internal/events/service"
	sdomain "github.com/corvusHold/guard/internal/settings/domain"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"github.com/pquerna/otp/totp"
)

type Service struct {
	repo     domain.Repository
	cfg      config.Config
	settings sdomain.Service
	pub      evdomain.Publisher
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
    if n == "" { return domain.Role{}, errors.New("role name required") }
    return s.repo.CreateRole(ctx, uuid.New(), tenantID, n, description)
}

// UpdateRole updates a role in a tenant.
func (s *Service) UpdateRole(ctx context.Context, roleID uuid.UUID, tenantID uuid.UUID, name, description string) (domain.Role, error) {
    n := strings.ToLower(strings.TrimSpace(name))
    if n == "" { return domain.Role{}, errors.New("role name required") }
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
    if err != nil { return err }
    return s.repo.UpsertRolePermission(ctx, roleID, p.ID, scopeType, resourceType, resourceID)
}

func (s *Service) DeleteRolePermission(ctx context.Context, roleID uuid.UUID, permissionKey, scopeType string, resourceType, resourceID *string) error {
    p, err := s.repo.GetPermissionByKey(ctx, permissionKey)
    if err != nil { return err }
    return s.repo.DeleteRolePermission(ctx, roleID, p.ID, scopeType, resourceType, resourceID)
}

// ResolveUserPermissions aggregates permissions from roles, user ACL, and group ACL.
func (s *Service) ResolveUserPermissions(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) (domain.ResolvedPermissions, error) {
    // Role-derived grants
    roleIDs, err := s.repo.ListUserRoleIDs(ctx, userID, tenantID)
    if err != nil { return domain.ResolvedPermissions{}, err }
    rolePerms, err := s.repo.ListRolePermissionKeys(ctx, roleIDs)
    if err != nil { return domain.ResolvedPermissions{}, err }
    // Direct user ACL
    userACL, err := s.repo.ListACLPermissionKeysForUser(ctx, tenantID, userID)
    if err != nil { return domain.ResolvedPermissions{}, err }
    // Group ACL via memberships
    groups, err := s.repo.ListUserGroups(ctx, userID)
    if err != nil { return domain.ResolvedPermissions{}, err }
    groupACL, err := s.repo.ListACLPermissionKeysForGroups(ctx, tenantID, groups)
    if err != nil { return domain.ResolvedPermissions{}, err }

    // Merge and deduplicate
    dedup := make(map[string]struct{})
    appendGrant := func(gs *[]domain.PermissionGrant, g domain.PermissionGrant) {
        id := ""
        if g.ObjectID != nil { id = *g.ObjectID }
        k := g.Key + "|" + g.ObjectType + "|" + id
        if _, ok := dedup[k]; ok { return }
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
    for _, ua := range userACL { appendGrant(&grants, ua) }
    for _, ga := range groupACL { appendGrant(&grants, domain.PermissionGrant{Key: ga.Key, ObjectType: ga.ObjectType, ObjectID: ga.ObjectID}) }

    return domain.ResolvedPermissions{Grants: grants}, nil
}

// HasPermission checks whether user has a permission, optionally scoped to an object.
func (s *Service) HasPermission(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID, key, objectType string, objectID *string) (bool, error) {
    rp, err := s.ResolveUserPermissions(ctx, userID, tenantID)
    if err != nil { return false, err }
    for _, g := range rp.Grants {
        if g.Key != key { continue }
        if g.ObjectType == "*" { return true, nil }
        if objectID == nil {
            // Global check for a specific type requires an unscoped grant for that type
            if g.ObjectType == objectType && g.ObjectID == nil { return true, nil }
            continue
        }
        if g.ObjectType != objectType { continue }
        if g.ObjectID == nil || (g.ObjectID != nil && *g.ObjectID == *objectID) {
            return true, nil
        }
    }
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

// ListUserSessions lists refresh tokens (sessions) for a user within a tenant.
func (s *Service) ListUserSessions(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) ([]domain.RefreshToken, error) {
    return s.repo.ListUserSessions(ctx, userID, tenantID)
}

// RevokeSession revokes a specific session (refresh token) by ID for the given user and tenant.
func (s *Service) RevokeSession(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID, sessionID uuid.UUID) error {
    // Ensure the session belongs to this user and tenant
    sessions, err := s.repo.ListUserSessions(ctx, userID, tenantID)
    if err != nil { return err }
    ok := false
    for _, rt := range sessions {
        if rt.ID == sessionID { ok = true; break }
    }
    if !ok { return errors.New("session not found") }
    return s.repo.RevokeTokenChain(ctx, sessionID)
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
	if err != nil { return domain.AccessTokens{}, errors.New("invalid subject in challenge") }
	tid, err := uuid.Parse(tenStr)
	if err != nil { return domain.AccessTokens{}, errors.New("invalid tenant in challenge") }
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
		if err != nil { return domain.AccessTokens{}, err }
		if !ok { return domain.AccessTokens{}, errors.New("invalid backup code") }
	default:
		return domain.AccessTokens{}, errors.New("unsupported method")
	}
	// Issue tokens and publish login success audit event
	toks, err = s.issueTokens(ctx, uid, tid, in.UserAgent, in.IP, nil)
	if err != nil { return domain.AccessTokens{}, err }
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
	return &Service{repo: repo, cfg: cfg, settings: settings, pub: evsvc.NewLogger()}
}

// SetPublisher allows tests or callers to override the event publisher.
func (s *Service) SetPublisher(p evdomain.Publisher) { s.pub = p }

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
	return s.issueTokens(ctx, userID, in.TenantID, "", "", nil)
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
			"typ": "mfa_challenge",
			"sub": ai.UserID.String(),
			"ten": ai.TenantID.String(),
			"email": ai.Email,
			"amr": []string{"totp", "backup_code"},
			"exp": time.Now().Add(5 * time.Minute).Unix(),
			"iat": time.Now().Unix(),
		}
		t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		ch, err := t.SignedString([]byte(signingKey))
		if err != nil { return domain.AccessTokens{}, err }
		return domain.AccessTokens{}, domain.ErrMFARequired{ChallengeToken: ch, Methods: []string{"totp", "backup_code"}}
	}
	if err := s.repo.UpdateUserLoginAt(ctx, ai.UserID); err != nil {
		return domain.AccessTokens{}, err
	}
	toks, err := s.issueTokens(ctx, ai.UserID, ai.TenantID, in.UserAgent, in.IP, nil)
	if err != nil { return domain.AccessTokens{}, err }
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
	toks, err := s.issueTokens(ctx, rt.UserID, rt.TenantID, in.UserAgent, in.IP, &rt.ID)
	if err != nil { return domain.AccessTokens{}, err }
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
	if refreshToken == "" { return nil }
	h := sha256.Sum256([]byte(refreshToken))
	hashB64 := base64.RawURLEncoding.EncodeToString(h[:])
	rt, err := s.repo.GetRefreshTokenByHash(ctx, hashB64)
	if err != nil { return err }
	return s.repo.RevokeTokenChain(ctx, rt.ID)
}

func (s *Service) issueTokens(ctx context.Context, userID, tenantID uuid.UUID, userAgent, ip string, parent *uuid.UUID) (domain.AccessTokens, error) {
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
    if err != nil { return domain.AccessTokens{}, err }
    // Refresh token: random
    raw := make([]byte, 32)
    if _, err := rand.Read(raw); err != nil { return domain.AccessTokens{}, err }
    rt := base64.RawURLEncoding.EncodeToString(raw)
    h := sha256.Sum256([]byte(rt))
    hashB64 := base64.RawURLEncoding.EncodeToString(h[:])
    expiresAt := time.Now().Add(refreshTTL)
    if err := s.repo.InsertRefreshToken(ctx, uuid.New(), userID, tenantID, hashB64, parent, userAgent, ip, expiresAt); err != nil {
        return domain.AccessTokens{}, err
    }
    return domain.AccessTokens{AccessToken: access, RefreshToken: rt}, nil
}

// Me returns the current user's profile in a tenant context.
func (s *Service) Me(ctx context.Context, userID, tenantID uuid.UUID) (domain.UserProfile, error) {
    u, err := s.repo.GetUserByID(ctx, userID)
    if err != nil { return domain.UserProfile{}, err }
    ids, err := s.repo.GetAuthIdentitiesByUser(ctx, userID)
    if err != nil { return domain.UserProfile{}, err }
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
    // We don't know tenant a priori; parse without checking iss/aud first to extract tenant claim.
    // Use default signing key until tenant is known (settings lookup may rely on tenant id).
    signingDefault := s.cfg.JWTSigningKey
    parsed, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
        // HS256 only
        if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, errors.New("unexpected signing method")
        }
        return []byte(signingDefault), nil
    })
    if err != nil || !parsed.Valid {
        return domain.Introspection{Active: false}, errors.New("invalid token")
    }
    claims, ok := parsed.Claims.(jwt.MapClaims)
    if !ok {
        return domain.Introspection{Active: false}, errors.New("invalid claims")
    }
    // Extract basic claims
    subStr, _ := claims["sub"].(string)
    tenStr, _ := claims["ten"].(string)
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
    tid, err := uuid.Parse(tenStr)
    if err != nil {
        return domain.Introspection{Active: false}, errors.New("invalid ten")
    }
    // Validate against settings (issuer/audience/signing key may be overridden per tenant)
    issuer, _ := s.settings.GetString(ctx, sdomain.KeyJWTIssuer, &tid, s.cfg.PublicBaseURL)
    audience, _ := s.settings.GetString(ctx, sdomain.KeyJWTAudience, &tid, s.cfg.PublicBaseURL)
    signingKey, _ := s.settings.GetString(ctx, sdomain.KeyJWTSigning, &tid, s.cfg.JWTSigningKey)
    // Re-verify signature with possibly different signing key if default differed
    if signingKey != signingDefault {
        parsed2, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
            if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
                return nil, errors.New("unexpected signing method")
            }
            return []byte(signingKey), nil
        })
        if err != nil || !parsed2.Valid {
            return domain.Introspection{Active: false}, errors.New("invalid token")
        }
        // refresh claims from parsed2 to be safe
        if mc, ok := parsed2.Claims.(jwt.MapClaims); ok {
            claims = mc
        }
    }
    // Check issuer/audience if present
    if issStr != "" && issStr != issuer {
        return domain.Introspection{Active: false}, errors.New("issuer mismatch")
    }
    if audStr != "" && audStr != audience {
        return domain.Introspection{Active: false}, errors.New("audience mismatch")
    }
    // Exp validation
    if expInt != 0 && time.Now().Unix() > expInt {
        return domain.Introspection{Active: false}, errors.New("token expired")
    }
    // Load user context
    u, err := s.repo.GetUserByID(ctx, uid)
    if err != nil { return domain.Introspection{Active: false}, err }
    ids, err := s.repo.GetAuthIdentitiesByUser(ctx, uid)
    if err != nil { return domain.Introspection{Active: false}, err }
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
        if v == "" { continue }
        if _, ok := seen[v]; ok { continue }
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
    if err != nil { return "", "", err }
    secret := key.Secret()
    if err := s.repo.UpsertMFASecret(ctx, userID, secret, false); err != nil {
        return "", "", err
    }
    return secret, key.URL(), nil
}

// ActivateTOTP verifies a TOTP code for the stored secret and marks MFA as enabled.
func (s *Service) ActivateTOTP(ctx context.Context, userID uuid.UUID, code string) error {
    ms, err := s.repo.GetMFASecret(ctx, userID)
    if err != nil { return err }
    ok := totp.Validate(code, ms.Secret)
    if !ok { return errors.New("invalid TOTP code") }
    return s.repo.UpsertMFASecret(ctx, userID, ms.Secret, true)
}

// DisableTOTP disables TOTP for the user (keeps secret for potential reactivation).
func (s *Service) DisableTOTP(ctx context.Context, userID uuid.UUID) error {
    ms, err := s.repo.GetMFASecret(ctx, userID)
    if err != nil { return err }
    return s.repo.UpsertMFASecret(ctx, userID, ms.Secret, false)
}

// GenerateBackupCodes creates N backup codes, stores their hashes, and returns the plaintext codes.
func (s *Service) GenerateBackupCodes(ctx context.Context, userID uuid.UUID, count int) ([]string, error) {
    if count <= 0 { return nil, errors.New("count must be > 0") }
    out := make([]string, 0, count)
    for i := 0; i < count; i++ {
        code, err := generateBackupCode(10)
        if err != nil { return nil, err }
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
    if code == "" { return false, errors.New("code required") }
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
    if _, err := rand.Read(b); err != nil { return "", err }
    enc := base32.StdEncoding.WithPadding(base32.NoPadding)
    return enc.EncodeToString(b), nil
}
