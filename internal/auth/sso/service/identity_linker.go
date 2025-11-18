package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	authdomain "github.com/corvusHold/guard/internal/auth/domain"
	"github.com/corvusHold/guard/internal/auth/sso/domain"
	db "github.com/corvusHold/guard/internal/db/sqlc"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

// IdentityLinker handles linking SSO identities to user accounts.
type IdentityLinker struct {
	pool    *pgxpool.Pool
	queries *db.Queries
	log     zerolog.Logger
}

// NewIdentityLinker creates a new identity linker.
func NewIdentityLinker(pool *pgxpool.Pool, queries *db.Queries, log zerolog.Logger) *IdentityLinker {
	return &IdentityLinker{
		pool:    pool,
		queries: queries,
		log:     log,
	}
}

// LinkOrCreateUserRequest contains parameters for linking or creating a user.
type LinkOrCreateUserRequest struct {
	TenantID           uuid.UUID
	ProviderID         uuid.UUID
	Profile            *domain.Profile
	AllowSignup        bool
	TrustEmailVerified bool
}

// LinkOrCreateUserResult contains the result of linking or creating a user.
type LinkOrCreateUserResult struct {
	User       *authdomain.User
	IdentityID uuid.UUID
	IsNewUser  bool
}

// LinkOrCreateUser links an SSO identity to a user account or creates a new user.
func (l *IdentityLinker) LinkOrCreateUser(ctx context.Context, req LinkOrCreateUserRequest) (*LinkOrCreateUserResult, error) {
	if req.Profile == nil {
		return nil, fmt.Errorf("profile is required")
	}
	if req.Profile.Email == "" {
		return nil, fmt.Errorf("email is required in profile")
	}
	if req.Profile.Subject == "" {
		return nil, fmt.Errorf("subject is required in profile")
	}

	// Start a transaction
	tx, err := l.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to start transaction: %w", err)
	}
	// Ensure the transaction is rolled back on early returns; ignore ErrTxClosed
	// which is expected after a successful Commit.
	defer func() {
		if rbErr := tx.Rollback(ctx); rbErr != nil && rbErr != pgx.ErrTxClosed {
			l.log.Warn().Err(rbErr).Msg("failed to rollback transaction")
		}
	}()

	queries := l.queries.WithTx(tx)

	// 1. Look up existing identity by provider + subject
	existingIdentity, err := queries.GetSSOIdentity(ctx, db.GetSSOIdentityParams{
		TenantID:      toPgUUID(req.TenantID),
		SsoProviderID: toPgUUID(req.ProviderID),
		SsoSubject:    toPgText(req.Profile.Subject),
	})

	if err == nil {
		// Identity exists - load user and update identity
		user, err := queries.GetUserByID(ctx, existingIdentity.UserID)
		if err != nil {
			return nil, fmt.Errorf("failed to load linked user: %w", err)
		}

		// Update SSO attributes
		ssoAttributes, err := json.Marshal(req.Profile.RawAttributes)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal SSO attributes: %w", err)
		}

		if err := queries.UpdateSSOIdentity(ctx, db.UpdateSSOIdentityParams{
			ID:            existingIdentity.ID,
			SsoAttributes: ssoAttributes,
		}); err != nil {
			l.log.Warn().Err(err).Msg("failed to update SSO attributes")
		}

		// Update user last login
		if err := queries.UpdateUserLastLogin(ctx, existingIdentity.UserID); err != nil {
			l.log.Warn().Err(err).Msg("failed to update user last login")
		}

		if err := tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("failed to commit transaction: %w", err)
		}

		return &LinkOrCreateUserResult{
			User:       l.dbUserToDomain(user),
			IdentityID: toUUID(existingIdentity.ID),
			IsNewUser:  false,
		}, nil
	}

	if err != pgx.ErrNoRows {
		return nil, fmt.Errorf("failed to lookup SSO identity: %w", err)
	}

	// 2. Identity doesn't exist - check if user exists by email
	existingAuthIdentity, err := queries.GetAuthIdentityByEmailTenant(ctx, db.GetAuthIdentityByEmailTenantParams{
		TenantID: toPgUUID(req.TenantID),
		Email:    req.Profile.Email,
	})

	var userID uuid.UUID
	isNewUser := false

	switch err {
	case nil:
		// User exists with this email - link the identity
		userID = toUUID(existingAuthIdentity.UserID)
		l.log.Info().
			Str("user_id", userID.String()).
			Str("email", req.Profile.Email).
			Msg("linking SSO identity to existing user")
	case pgx.ErrNoRows:
		// User doesn't exist - check if signup is allowed
		if !req.AllowSignup {
			return nil, fmt.Errorf("user not found and signup is not allowed")
		}

		// Create new user
		userID = uuid.New()
		isNewUser = true

		emailVerified := false
		if req.TrustEmailVerified {
			emailVerified = req.Profile.EmailVerified
		}

		if err := queries.CreateUser(ctx, db.CreateUserParams{
			ID:            toPgUUID(userID),
			EmailVerified: emailVerified,
			IsActive:      true,
			FirstName:     toPgText(req.Profile.FirstName),
			LastName:      toPgText(req.Profile.LastName),
			Roles:         []string{}, // No roles by default
		}); err != nil {
			return nil, fmt.Errorf("failed to create user: %w", err)
		}

		// Add user to tenant
		if err := queries.AddUserToTenant(ctx, db.AddUserToTenantParams{
			UserID:   toPgUUID(userID),
			TenantID: toPgUUID(req.TenantID),
		}); err != nil {
			return nil, fmt.Errorf("failed to add user to tenant: %w", err)
		}

		l.log.Info().
			Str("user_id", userID.String()).
			Str("email", req.Profile.Email).
			Msg("created new user from SSO")
	default:
		return nil, fmt.Errorf("failed to lookup auth identity: %w", err)
	}

	// 3. Create SSO identity record
	identityID := uuid.New()
	ssoAttributes, err := json.Marshal(req.Profile.RawAttributes)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SSO attributes: %w", err)
	}

	_, err = queries.CreateSSOIdentity(ctx, db.CreateSSOIdentityParams{
		ID:            toPgUUID(identityID),
		UserID:        toPgUUID(userID),
		TenantID:      toPgUUID(req.TenantID),
		Email:         req.Profile.Email,
		SsoProviderID: toPgUUID(req.ProviderID),
		SsoSubject:    toPgText(req.Profile.Subject),
		SsoAttributes: ssoAttributes,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create SSO identity: %w", err)
	}

	// 4. Load user to return
	user, err := queries.GetUserByID(ctx, toPgUUID(userID))
	if err != nil {
		return nil, fmt.Errorf("failed to load user: %w", err)
	}

	// Update user last login
	if err := queries.UpdateUserLastLogin(ctx, toPgUUID(userID)); err != nil {
		l.log.Warn().Err(err).Msg("failed to update user last login")
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return &LinkOrCreateUserResult{
		User:       l.dbUserToDomain(user),
		IdentityID: identityID,
		IsNewUser:  isNewUser,
	}, nil
}

// UnlinkIdentity removes an SSO identity link from a user.
func (l *IdentityLinker) UnlinkIdentity(ctx context.Context, userID, providerID uuid.UUID) error {
	// Ensure the count check and delete happen atomically.
	tx, err := l.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer func() {
		if rbErr := tx.Rollback(ctx); rbErr != nil && rbErr != pgx.ErrTxClosed {
			l.log.Warn().Err(rbErr).Msg("failed to rollback transaction")
		}
	}()

	queries := l.queries.WithTx(tx)
	identities, err := queries.GetAuthIdentitiesByUserForUpdate(ctx, toPgUUID(userID))
	if err != nil {
		return fmt.Errorf("failed to check user identities: %w", err)
	}

	if len(identities) <= 1 {
		return fmt.Errorf("cannot unlink last authentication method")
	}

	var target *db.GetAuthIdentitiesByUserForUpdateRow
	for i := range identities {
		identity := identities[i]
		if identity.SsoProviderID.Valid && toUUID(identity.SsoProviderID) == providerID {
			target = &identity
			break
		}
	}

	if target == nil {
		return fmt.Errorf("SSO identity not found")
	}

	if err := queries.UnlinkSSOIdentity(ctx, db.UnlinkSSOIdentityParams{
		ID:       target.ID,
		TenantID: target.TenantID,
	}); err != nil {
		return fmt.Errorf("failed to unlink identity: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	l.log.Info().
		Str("user_id", userID.String()).
		Str("provider_id", providerID.String()).
		Msg("SSO identity unlinked")
	return nil
}

// ListIdentities returns all linked identities for a user.
func (l *IdentityLinker) ListIdentities(ctx context.Context, userID uuid.UUID) ([]db.ListUserSSOIdentitiesRow, error) {
	identities, err := l.queries.ListUserSSOIdentities(ctx, toPgUUID(userID))
	if err != nil {
		return nil, fmt.Errorf("failed to list identities: %w", err)
	}

	return identities, nil
}

// Helper to convert DB user to domain user
func (l *IdentityLinker) dbUserToDomain(u db.User) *authdomain.User {
	var lastLogin *time.Time
	if u.LastLoginAt.Valid {
		t := u.LastLoginAt.Time
		lastLogin = &t
	}

	return &authdomain.User{
		ID:            toUUID(u.ID),
		EmailVerified: u.EmailVerified,
		IsActive:      u.IsActive,
		FirstName:     u.FirstName.String,
		LastName:      u.LastName.String,
		Roles:         u.Roles,
		CreatedAt:     u.CreatedAt.Time,
		UpdatedAt:     u.UpdatedAt.Time,
		LastLoginAt:   lastLogin,
	}
}
