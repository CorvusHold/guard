package repository

import (
	"context"

	db "github.com/corvusHold/guard/internal/db/sqlc"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SQLCRepository struct {
	q *db.Queries
}

func New(pg *pgxpool.Pool) *SQLCRepository {
	return &SQLCRepository{q: db.New(pg)}
}

func toPgUUID(u uuid.UUID) pgtype.UUID {
	var id pgtype.UUID
	id.Bytes = u
	id.Valid = true
	return id
}

func toPgUUIDPtr(u *uuid.UUID) pgtype.UUID {
	if u == nil {
		return pgtype.UUID{Valid: false}
	}
	return toPgUUID(*u)
}

func (r *SQLCRepository) Create(ctx context.Context, id uuid.UUID, name string, parentTenantID *uuid.UUID) error {
	return r.q.CreateTenant(ctx, db.CreateTenantParams{
		ID:             toPgUUID(id),
		Name:           name,
		ParentTenantID: toPgUUIDPtr(parentTenantID),
	})
}

func (r *SQLCRepository) GetByID(ctx context.Context, id uuid.UUID) (db.Tenant, error) {
	return r.q.GetTenantByID(ctx, toPgUUID(id))
}

func (r *SQLCRepository) GetByName(ctx context.Context, name string) (db.Tenant, error) {
	return r.q.GetTenantByName(ctx, name)
}

func (r *SQLCRepository) Deactivate(ctx context.Context, id uuid.UUID) error {
	return r.q.DeactivateTenant(ctx, toPgUUID(id))
}

func (r *SQLCRepository) List(ctx context.Context, query string, active int, limit, offset int32) ([]db.Tenant, int64, error) {
	items, err := r.q.ListTenants(ctx, db.ListTenantsParams{
		Column1: query,
		Column2: int32(active),
		Limit:   limit,
		Offset:  offset,
	})
	if err != nil {
		return nil, 0, err
	}
	total, err := r.q.CountTenants(ctx, db.CountTenantsParams{
		Column1: query,
		Column2: int32(active),
	})
	if err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (r *SQLCRepository) ListChildTenants(ctx context.Context, parentID uuid.UUID) ([]db.Tenant, error) {
	return r.q.ListChildTenants(ctx, toPgUUID(parentID))
}

func (r *SQLCRepository) GetTenantAncestors(ctx context.Context, tenantID uuid.UUID) ([]db.Tenant, error) {
	rows, err := r.q.GetTenantAncestors(ctx, toPgUUID(tenantID))
	if err != nil {
		return nil, err
	}
	out := make([]db.Tenant, len(rows))
	for i, row := range rows {
		out[i] = db.Tenant(row)
	}
	return out, nil
}

func (r *SQLCRepository) UpdateParent(ctx context.Context, id uuid.UUID, parentID *uuid.UUID) error {
	return r.q.UpdateTenantParent(ctx, db.UpdateTenantParentParams{
		ID:             toPgUUID(id),
		ParentTenantID: toPgUUIDPtr(parentID),
	})
}
