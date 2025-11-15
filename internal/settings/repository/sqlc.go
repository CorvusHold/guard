package repository

import (
	"context"

	db "github.com/corvusHold/guard/internal/db/sqlc"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SQLCRepository struct{ q *db.Queries }

func New(pg *pgxpool.Pool) *SQLCRepository { return &SQLCRepository{q: db.New(pg)} }

func toPgUUIDPtr(u *uuid.UUID) pgtype.UUID {
	if u == nil {
		return pgtype.UUID{}
	}
	return pgtype.UUID{Bytes: *u, Valid: true}
}

func (r *SQLCRepository) Get(ctx context.Context, key string, tenantID *uuid.UUID) (string, bool, error) {
	if tenantID != nil {
		row, err := r.q.GetAppSettingByKeyTenant(ctx, db.GetAppSettingByKeyTenantParams{Key: key, TenantID: toPgUUIDPtr(tenantID)})
		if err == nil {
			return row.Value, true, nil
		}
	}
	row, err := r.q.GetAppSettingGlobal(ctx, key)
	if err != nil {
		return "", false, nil
	}
	return row.Value, true, nil
}

func (r *SQLCRepository) Upsert(ctx context.Context, key string, tenantID *uuid.UUID, value string, secret bool) error {
	id := uuid.New()
	return r.q.UpsertAppSetting(ctx, db.UpsertAppSettingParams{
		ID:       pgtype.UUID{Bytes: id, Valid: true},
		TenantID: toPgUUIDPtr(tenantID),
		Key:      key,
		Value:    value,
		IsSecret: secret,
	})
}
