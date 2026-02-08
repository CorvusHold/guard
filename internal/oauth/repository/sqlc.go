package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	db "github.com/corvusHold/guard/internal/db/sqlc"
	"github.com/corvusHold/guard/internal/oauth/domain"
)

// SQLCRepository implements domain.Repository using sqlc-generated queries.
type SQLCRepository struct {
	q *db.Queries
}

// New creates a new SQLCRepository.
func New(pg *pgxpool.Pool) *SQLCRepository {
	return &SQLCRepository{q: db.New(pg)}
}

func (r *SQLCRepository) CreateOAuthClient(ctx context.Context, client domain.OAuthClient) (domain.OAuthClient, error) {
	row, err := r.q.CreateOAuthClient(ctx, db.CreateOAuthClientParams{
		ID:               uuidToPG(client.ID),
		TenantID:         uuidToPG(client.TenantID),
		ClientID:         client.ClientID,
		ClientSecretHash: textToPG(client.ClientSecretHash),
		ClientType:       client.ClientType,
		Name:             client.Name,
		RedirectUris:     client.RedirectURIs,
		Scopes:           client.Scopes,
		GrantTypes:       client.GrantTypes,
		LogoUri:          textToPG(client.LogoURI),
		CreatedBy:        uuidToPGNullable(client.CreatedBy),
	})
	if err != nil {
		return domain.OAuthClient{}, err
	}
	return mapClient(row), nil
}

func (r *SQLCRepository) GetOAuthClientByClientID(ctx context.Context, clientID string) (domain.OAuthClient, error) {
	row, err := r.q.GetOAuthClientByClientID(ctx, clientID)
	if err != nil {
		return domain.OAuthClient{}, err
	}
	return mapClient(row), nil
}

func (r *SQLCRepository) GetOAuthClientByID(ctx context.Context, id, tenantID uuid.UUID) (domain.OAuthClient, error) {
	row, err := r.q.GetOAuthClientByID(ctx, db.GetOAuthClientByIDParams{
		ID:       uuidToPG(id),
		TenantID: uuidToPG(tenantID),
	})
	if err != nil {
		return domain.OAuthClient{}, err
	}
	return mapClient(row), nil
}

func (r *SQLCRepository) ListOAuthClientsByTenant(ctx context.Context, tenantID uuid.UUID) ([]domain.OAuthClient, error) {
	rows, err := r.q.ListOAuthClientsByTenant(ctx, uuidToPG(tenantID))
	if err != nil {
		return nil, err
	}
	out := make([]domain.OAuthClient, len(rows))
	for i, row := range rows {
		out[i] = mapClient(row)
	}
	return out, nil
}

func (r *SQLCRepository) UpdateOAuthClient(ctx context.Context, id, tenantID uuid.UUID, in domain.UpdateOAuthClientInput) error {
	name := ""
	if in.Name != nil {
		name = *in.Name
	}
	// When IsActive is nil, preserve the existing value by fetching current state.
	if in.IsActive == nil {
		existing, fetchErr := r.q.GetOAuthClientByID(ctx, db.GetOAuthClientByIDParams{
			ID:       uuidToPG(id),
			TenantID: uuidToPG(tenantID),
		})
		if fetchErr != nil {
			return fetchErr
		}
		return r.q.UpdateOAuthClient(ctx, db.UpdateOAuthClientParams{
			ID:           uuidToPG(id),
			TenantID:     uuidToPG(tenantID),
			Column3:      name,
			RedirectUris: in.RedirectURIs,
			Scopes:       in.Scopes,
			GrantTypes:   in.GrantTypes,
			LogoUri:      textToPGPtr(in.LogoURI),
			IsActive:     existing.IsActive,
		})
	}
	return r.q.UpdateOAuthClient(ctx, db.UpdateOAuthClientParams{
		ID:           uuidToPG(id),
		TenantID:     uuidToPG(tenantID),
		Column3:      name,
		RedirectUris: in.RedirectURIs,
		Scopes:       in.Scopes,
		GrantTypes:   in.GrantTypes,
		LogoUri:      textToPGPtr(in.LogoURI),
		IsActive:     *in.IsActive,
	})
}

func (r *SQLCRepository) DeleteOAuthClient(ctx context.Context, id, tenantID uuid.UUID) error {
	return r.q.DeleteOAuthClient(ctx, db.DeleteOAuthClientParams{
		ID:       uuidToPG(id),
		TenantID: uuidToPG(tenantID),
	})
}

func (r *SQLCRepository) CreateAuthorizationCode(ctx context.Context, code domain.AuthorizationCode) (domain.AuthorizationCode, error) {
	row, err := r.q.CreateOAuthAuthorizationCode(ctx, db.CreateOAuthAuthorizationCodeParams{
		ID:                  uuidToPG(code.ID),
		ClientID:            code.ClientID,
		UserID:              uuidToPG(code.UserID),
		TenantID:            uuidToPG(code.TenantID),
		CodeHash:            code.CodeHash,
		RedirectUri:         code.RedirectURI,
		Scopes:              code.Scopes,
		Nonce:               textToPG(code.Nonce),
		CodeChallenge:       textToPG(code.CodeChallenge),
		CodeChallengeMethod: textToPG(code.CodeChallengeMethod),
		ExpiresAt:           timestampToPG(code.ExpiresAt),
	})
	if err != nil {
		return domain.AuthorizationCode{}, err
	}
	return mapCode(row), nil
}

func (r *SQLCRepository) GetAuthorizationCodeByHash(ctx context.Context, codeHash string) (domain.AuthorizationCode, error) {
	row, err := r.q.GetOAuthAuthorizationCodeByHash(ctx, codeHash)
	if err != nil {
		return domain.AuthorizationCode{}, err
	}
	return mapCode(row), nil
}

func (r *SQLCRepository) ConsumeAuthorizationCode(ctx context.Context, codeHash string) error {
	return r.q.ConsumeOAuthAuthorizationCode(ctx, codeHash)
}

func (r *SQLCRepository) UpsertConsentGrant(ctx context.Context, userID, tenantID uuid.UUID, clientID string, scopes []string) (domain.ConsentGrant, error) {
	row, err := r.q.UpsertOAuthConsentGrant(ctx, db.UpsertOAuthConsentGrantParams{
		UserID:   uuidToPG(userID),
		TenantID: uuidToPG(tenantID),
		ClientID: clientID,
		Scopes:   scopes,
	})
	if err != nil {
		return domain.ConsentGrant{}, err
	}
	return mapConsentGrant(row), nil
}

func (r *SQLCRepository) GetConsentGrant(ctx context.Context, userID, tenantID uuid.UUID, clientID string) (domain.ConsentGrant, error) {
	row, err := r.q.GetOAuthConsentGrant(ctx, db.GetOAuthConsentGrantParams{
		UserID:   uuidToPG(userID),
		ClientID: clientID,
		TenantID: uuidToPG(tenantID),
	})
	if err != nil {
		return domain.ConsentGrant{}, err
	}
	return mapConsentGrant(row), nil
}

func (r *SQLCRepository) RevokeConsentGrant(ctx context.Context, userID uuid.UUID, clientID string) error {
	return r.q.RevokeOAuthConsentGrant(ctx, db.RevokeOAuthConsentGrantParams{
		UserID:   uuidToPG(userID),
		ClientID: clientID,
	})
}

// --- Mapping helpers ---

func mapClient(row db.OauthClient) domain.OAuthClient {
	c := domain.OAuthClient{
		ClientID:         row.ClientID,
		ClientSecretHash: pgToText(row.ClientSecretHash),
		ClientType:       row.ClientType,
		Name:             row.Name,
		RedirectURIs:     row.RedirectUris,
		Scopes:           row.Scopes,
		GrantTypes:       row.GrantTypes,
		LogoURI:          pgToText(row.LogoUri),
		IsActive:         row.IsActive,
	}
	if row.ID.Valid {
		c.ID = row.ID.Bytes
	}
	if row.TenantID.Valid {
		c.TenantID = row.TenantID.Bytes
	}
	if row.CreatedBy.Valid {
		c.CreatedBy = row.CreatedBy.Bytes
	}
	if row.CreatedAt.Valid {
		c.CreatedAt = row.CreatedAt.Time
	}
	if row.UpdatedAt.Valid {
		c.UpdatedAt = row.UpdatedAt.Time
	}
	return c
}

func mapCode(row db.OauthAuthorizationCode) domain.AuthorizationCode {
	c := domain.AuthorizationCode{
		ClientID:            row.ClientID,
		CodeHash:            row.CodeHash,
		RedirectURI:         row.RedirectUri,
		Scopes:              row.Scopes,
		Nonce:               pgToText(row.Nonce),
		CodeChallenge:       pgToText(row.CodeChallenge),
		CodeChallengeMethod: pgToText(row.CodeChallengeMethod),
	}
	if row.ID.Valid {
		c.ID = row.ID.Bytes
	}
	if row.UserID.Valid {
		c.UserID = row.UserID.Bytes
	}
	if row.TenantID.Valid {
		c.TenantID = row.TenantID.Bytes
	}
	if row.ExpiresAt.Valid {
		c.ExpiresAt = row.ExpiresAt.Time
	}
	if row.ConsumedAt.Valid {
		t := row.ConsumedAt.Time
		c.ConsumedAt = &t
	}
	if row.CreatedAt.Valid {
		c.CreatedAt = row.CreatedAt.Time
	}
	return c
}

// --- pgtype conversion helpers ---

func uuidToPG(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: id, Valid: true}
}

func uuidToPGNullable(id uuid.UUID) pgtype.UUID {
	if id == uuid.Nil {
		return pgtype.UUID{Valid: false}
	}
	return pgtype.UUID{Bytes: id, Valid: true}
}

func textToPG(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{Valid: false}
	}
	return pgtype.Text{String: s, Valid: true}
}

func textToPGPtr(s *string) pgtype.Text {
	if s == nil || *s == "" {
		return pgtype.Text{Valid: false}
	}
	return pgtype.Text{String: *s, Valid: true}
}

func pgToText(t pgtype.Text) string {
	if t.Valid {
		return t.String
	}
	return ""
}

func timestampToPG(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}

func mapConsentGrant(row db.OauthConsentGrant) domain.ConsentGrant {
	g := domain.ConsentGrant{
		ClientID: row.ClientID,
		Scopes:   row.Scopes,
	}
	if row.ID.Valid {
		g.ID = row.ID.Bytes
	}
	if row.UserID.Valid {
		g.UserID = row.UserID.Bytes
	}
	if row.TenantID.Valid {
		g.TenantID = row.TenantID.Bytes
	}
	if row.GrantedAt.Valid {
		g.GrantedAt = row.GrantedAt.Time
	}
	if row.RevokedAt.Valid {
		t := row.RevokedAt.Time
		g.RevokedAt = &t
	}
	return g
}
