package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/corvusHold/guard/internal/auth/domain"
	evdomain "github.com/corvusHold/guard/internal/events/domain"
	sdomain "github.com/corvusHold/guard/internal/settings/domain"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// InviteUser creates an invitation for a user to join a tenant or create a new tenant.
// If tenantID is nil, the invitation is for creating a new tenant.
// Returns the invitation with the raw token (not hashed) for sending via email.
func (s *Service) InviteUser(ctx context.Context, in domain.InviteUserInput) (domain.Invitation, string, error) {
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	if in.Email == "" {
		return domain.Invitation{}, "", errors.New("email is required")
	}

	// Generate a secure random token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return domain.Invitation{}, "", err
	}
	rawToken := base64.RawURLEncoding.EncodeToString(tokenBytes)

	// Hash the token for storage
	h := sha256.Sum256([]byte(rawToken))
	tokenHash := base64.RawURLEncoding.EncodeToString(h[:])

	// Get invitation TTL from settings (default 7 days)
	ttl, _ := s.settings.GetDuration(ctx, sdomain.KeyInvitationTTL, in.TenantID, 7*24*time.Hour)
	expiresAt := time.Now().Add(ttl)

	invID := uuid.New()
	inv, err := s.repo.CreateInvitation(ctx, invID, in.TenantID, in.Email, tokenHash, in.Role, &in.InvitedBy, expiresAt)
	if err != nil {
		return domain.Invitation{}, "", err
	}

	// Publish audit event
	meta := map[string]string{
		"email":      in.Email,
		"invited_by": in.InvitedBy.String(),
	}
	if in.TenantID != nil {
		meta["tenant_id"] = in.TenantID.String()
	}
	if in.Role != "" {
		meta["role"] = in.Role
	}
	tenantID := uuid.Nil
	if in.TenantID != nil {
		tenantID = *in.TenantID
	}
	_ = s.pub.Publish(ctx, evdomain.Event{
		Type:     "auth.invitation.created",
		TenantID: tenantID,
		UserID:   in.InvitedBy,
		Meta:     meta,
		Time:     time.Now(),
	})

	return inv, rawToken, nil
}

// GetInvitationByToken retrieves an invitation by its raw token.
func (s *Service) GetInvitationByToken(ctx context.Context, token string) (domain.Invitation, error) {
	h := sha256.Sum256([]byte(token))
	tokenHash := base64.RawURLEncoding.EncodeToString(h[:])
	return s.repo.GetInvitationByHash(ctx, tokenHash)
}

// ListInvitations returns all invitations for a tenant.
func (s *Service) ListInvitations(ctx context.Context, tenantID uuid.UUID) ([]domain.Invitation, error) {
	return s.repo.ListInvitationsByTenant(ctx, tenantID)
}

// ListPendingInvitations returns only pending (non-expired) invitations for a tenant.
func (s *Service) ListPendingInvitations(ctx context.Context, tenantID uuid.UUID) ([]domain.Invitation, error) {
	return s.repo.ListPendingInvitationsByTenant(ctx, tenantID)
}

// AcceptInvitation accepts an invitation and creates the user account.
// Returns access tokens for the newly created user.
func (s *Service) AcceptInvitation(ctx context.Context, in domain.AcceptInvitationInput) (domain.AccessTokens, error) {
	if in.Token == "" || in.Password == "" {
		return domain.AccessTokens{}, errors.New("token and password are required")
	}

	// Get invitation by token
	inv, err := s.GetInvitationByToken(ctx, in.Token)
	if err != nil {
		return domain.AccessTokens{}, errors.New("invalid or expired invitation")
	}

	// Check if invitation is still valid
	if inv.Status != "pending" {
		return domain.AccessTokens{}, errors.New("invitation has already been used or revoked")
	}
	if time.Now().After(inv.ExpiresAt) {
		return domain.AccessTokens{}, errors.New("invitation has expired")
	}

	// Invitation must have a tenant ID (for now, we don't support creating new tenants via invitation)
	if inv.TenantID == nil {
		return domain.AccessTokens{}, errors.New("invitation does not have a tenant")
	}

	// All mutations must happen inside a transaction to prevent partial failures
	userID := uuid.New()
	authID := uuid.New()

	// Determine initial roles
	var roles []string
	if inv.Role != "" {
		roles = []string{inv.Role}
	}

	// Hash password before starting the transaction
	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		return domain.AccessTokens{}, err
	}

	// Compute token hash for acceptance
	h := sha256.Sum256([]byte(in.Token))
	tokenHash := base64.RawURLEncoding.EncodeToString(h[:])

	// Execute all DB mutations in a transaction
	if err := s.acceptInvitationTx(ctx, userID, authID, inv, in, roles, string(hash), tokenHash); err != nil {
		return domain.AccessTokens{}, err
	}

	// Publish audit event only after successful commit
	_ = s.pub.Publish(ctx, evdomain.Event{
		Type:     "auth.invitation.accepted",
		TenantID: *inv.TenantID,
		UserID:   userID,
		Meta: map[string]string{
			"email":         inv.Email,
			"invitation_id": inv.ID.String(),
		},
		Time: time.Now(),
	})

	// Issue tokens only after successful commit
	return s.issueTokens(ctx, userID, *inv.TenantID, "", "", nil, "invitation", nil)
}

// acceptInvitationTx executes all AcceptInvitation DB mutations inside a single transaction.
// If the repo supports BeginTx (i.e. *repository.SQLCRepository), it uses a real DB transaction.
// Otherwise, it falls back to sequential calls (for test fakes).
func (s *Service) acceptInvitationTx(ctx context.Context, userID, authID uuid.UUID, inv domain.Invitation, in domain.AcceptInvitationInput, roles []string, passwordHash, tokenHash string) error {
	type txStarter interface {
		BeginTx(ctx context.Context) (interface {
			Rollback(context.Context) error
			Commit(context.Context) error
		}, domain.Repository, error)
	}

	// Try to use a real transaction if the repo supports it
	if txRepo, ok := s.repo.(txStarter); ok {
		tx, repo, err := txRepo.BeginTx(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(ctx) }()

		if err := s.runAcceptInvitationOps(ctx, repo, userID, authID, inv, in, roles, passwordHash, tokenHash); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}

	// Fallback: no transaction support (test fakes)
	return s.runAcceptInvitationOps(ctx, s.repo, userID, authID, inv, in, roles, passwordHash, tokenHash)
}

// runAcceptInvitationOps performs the actual DB operations for accepting an invitation.
func (s *Service) runAcceptInvitationOps(ctx context.Context, repo domain.Repository, userID, authID uuid.UUID, inv domain.Invitation, in domain.AcceptInvitationInput, roles []string, passwordHash, tokenHash string) error {
	if err := repo.CreateUser(ctx, userID, in.FirstName, in.LastName, roles); err != nil {
		return err
	}
	if err := repo.CreateAuthIdentity(ctx, authID, userID, *inv.TenantID, inv.Email, passwordHash); err != nil {
		return err
	}
	if err := repo.AddUserToTenant(ctx, userID, *inv.TenantID); err != nil {
		return err
	}

	// Mark invitation as accepted; returns the ID to confirm a row was updated
	acceptedID, err := repo.AcceptInvitation(ctx, tokenHash)
	if err != nil {
		return err
	}
	if acceptedID == uuid.Nil {
		return errors.New("invitation could not be accepted (already used or expired)")
	}

	// If a role was specified, assign it via RBAC
	if inv.Role != "" {
		role, err := repo.GetRoleByName(ctx, *inv.TenantID, inv.Role)
		if err == nil && role.ID != uuid.Nil {
			_ = repo.AddUserRole(ctx, userID, *inv.TenantID, role.ID)
		}
	}

	return nil
}

// RevokeInvitation revokes a pending invitation.
func (s *Service) RevokeInvitation(ctx context.Context, invitationID, tenantID uuid.UUID) error {
	if err := s.repo.RevokeInvitation(ctx, invitationID, tenantID); err != nil {
		return err
	}

	_ = s.pub.Publish(ctx, evdomain.Event{
		Type:     "auth.invitation.revoked",
		TenantID: tenantID,
		Meta: map[string]string{
			"invitation_id": invitationID.String(),
		},
		Time: time.Now(),
	})

	return nil
}

// DeleteInvitation deletes an invitation.
func (s *Service) DeleteInvitation(ctx context.Context, invitationID, tenantID uuid.UUID) error {
	return s.repo.DeleteInvitation(ctx, invitationID, tenantID)
}

// AdminCreateUser creates a user directly in a tenant (admin operation).
// This bypasses the invitation flow and creates the user immediately.
func (s *Service) AdminCreateUser(ctx context.Context, in domain.AdminCreateUserInput) (domain.User, error) {
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	if in.Email == "" || in.Password == "" {
		return domain.User{}, errors.New("email and password are required")
	}

	// Check if user already exists in this tenant
	_, err := s.repo.GetAuthIdentityByEmailTenant(ctx, in.TenantID, in.Email)
	if err == nil {
		return domain.User{}, errors.New("user with this email already exists in tenant")
	}

	userID := uuid.New()
	authID := uuid.New()

	// Normalize roles
	roles := make([]string, 0, len(in.Roles))
	seen := make(map[string]bool)
	for _, r := range in.Roles {
		r = strings.ToLower(strings.TrimSpace(r))
		if r != "" && !seen[r] {
			roles = append(roles, r)
			seen[r] = true
		}
	}

	// Create user
	if err := s.repo.CreateUser(ctx, userID, in.FirstName, in.LastName, roles); err != nil {
		return domain.User{}, err
	}

	// Set email verified if requested
	if in.EmailVerified {
		if err := s.repo.SetUserEmailVerified(ctx, userID, true); err != nil {
			return domain.User{}, err
		}
	}

	// Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		return domain.User{}, err
	}

	// Create auth identity
	if err := s.repo.CreateAuthIdentity(ctx, authID, userID, in.TenantID, in.Email, string(hash)); err != nil {
		return domain.User{}, err
	}

	// Add user to tenant
	if err := s.repo.AddUserToTenant(ctx, userID, in.TenantID); err != nil {
		return domain.User{}, err
	}

	// Assign roles via RBAC if specified
	for _, roleName := range roles {
		role, err := s.repo.GetRoleByName(ctx, in.TenantID, roleName)
		if err == nil && role.ID != uuid.Nil {
			_ = s.repo.AddUserRole(ctx, userID, in.TenantID, role.ID)
		}
	}

	// Publish audit event
	_ = s.pub.Publish(ctx, evdomain.Event{
		Type:     "auth.admin.user.created",
		TenantID: in.TenantID,
		Meta: map[string]string{
			"email":   in.Email,
			"user_id": userID.String(),
		},
		Time: time.Now(),
	})

	// Retrieve and return the created user
	return s.repo.GetUserByID(ctx, userID)
}
