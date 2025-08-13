package repository

import (
	"context"
	"time"

	db "github.com/corvusHold/guard/internal/db/sqlc"
	domain "github.com/corvusHold/guard/internal/auth/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SQLCRepository struct{ q *db.Queries }

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

func New(pg *pgxpool.Pool) *SQLCRepository { return &SQLCRepository{q: db.New(pg)} }

func toPgUUID(u uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: u, Valid: true} }
func toPgText(s string) pgtype.Text   { return pgtype.Text{String: s, Valid: s != ""} }
func toPgTime(t time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: t, Valid: true} }
func toPgUUIDNullable(u *uuid.UUID) pgtype.UUID {
	if u == nil { return pgtype.UUID{} }
	return toPgUUID(*u)
}
func toPgTextNullable(s *string) pgtype.Text {
	if s == nil { return pgtype.Text{} }
	return toPgText(*s)
}

func toUUID(u pgtype.UUID) uuid.UUID { return uuid.UUID(u.Bytes) }

func mapAuthIdentity(ai db.AuthIdentity) domain.AuthIdentity {
	return domain.AuthIdentity{
		ID:          toUUID(ai.ID),
		UserID:      toUUID(ai.UserID),
		TenantID:    toUUID(ai.TenantID),
		Email:       ai.Email,
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
		ID:         toUUID(ml.ID),
		UserID:     uid,
		TenantID:   toUUID(ml.TenantID),
		Email:      ml.Email.String,
		TokenHash:  ml.TokenHash,
		RedirectURL: ml.RedirectUrl.String,
		CreatedAt:  ml.CreatedAt.Time,
		ExpiresAt:  ml.ExpiresAt.Time,
		ConsumedAt: consumed,
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
	if err != nil { return domain.AuthIdentity{}, err }
	return mapAuthIdentity(ai), nil
}

func (r *SQLCRepository) UpdateUserLoginAt(ctx context.Context, userID uuid.UUID) error {
	return r.q.UpdateUserLoginAt(ctx, toPgUUID(userID))
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
	if err != nil { return domain.RefreshToken{}, err }
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
	if err != nil { return domain.MagicLink{}, err }
	return mapMagicLink(ml), nil
}

func (r *SQLCRepository) ConsumeMagicLink(ctx context.Context, tokenHash string) error {
    return r.q.ConsumeMagicLink(ctx, tokenHash)
}

// Additional lookups for profile/introspection
func (r *SQLCRepository) GetUserByID(ctx context.Context, userID uuid.UUID) (domain.User, error) {
    u, err := r.q.GetUserByID(ctx, toPgUUID(userID))
    if err != nil { return domain.User{}, err }
    return mapUser(u), nil
}

func (r *SQLCRepository) GetAuthIdentitiesByUser(ctx context.Context, userID uuid.UUID) ([]domain.AuthIdentity, error) {
    items, err := r.q.GetAuthIdentitiesByUser(ctx, toPgUUID(userID))
    if err != nil { return nil, err }
    out := make([]domain.AuthIdentity, 0, len(items))
    for _, ai := range items {
        out = append(out, mapAuthIdentity(ai))
    }
    return out, nil
}

// MFA persistence
func (r *SQLCRepository) UpsertMFASecret(ctx context.Context, userID uuid.UUID, secret string, enabled bool) error {
    return r.q.UpsertMFASecret(ctx, db.UpsertMFASecretParams{
        UserID: toPgUUID(userID),
        Secret: secret,
        Enabled: enabled,
    })
}

func (r *SQLCRepository) GetMFASecret(ctx context.Context, userID uuid.UUID) (domain.MFASecret, error) {
    ms, err := r.q.GetMFASecret(ctx, toPgUUID(userID))
    if err != nil { return domain.MFASecret{}, err }
    return mapMFASecret(ms), nil
}

func (r *SQLCRepository) InsertMFABackupCode(ctx context.Context, id uuid.UUID, userID uuid.UUID, codeHash string) error {
    return r.q.InsertMFABackupCode(ctx, db.InsertMFABackupCodeParams{
        ID: toPgUUID(id),
        UserID: toPgUUID(userID),
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
