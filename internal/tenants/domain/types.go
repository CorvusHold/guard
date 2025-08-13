package domain

import (
	"context"

	db "github.com/corvusHold/guard/internal/db/sqlc"
	"github.com/google/uuid"
)

// ListOptions for tenant listing
type ListOptions struct {
	Query    string
	Active   int // -1 any, 1 active, 0 inactive
	Page     int
	PageSize int
}

// ListResult holds items and pagination metadata
type ListResult struct {
	Items     []db.Tenant
	Total     int64
	Page      int
	PageSize  int
	TotalPages int
}

// Repository abstracts persistence for tenants.
type Repository interface {
	Create(ctx context.Context, id uuid.UUID, name string) error
	GetByID(ctx context.Context, id uuid.UUID) (db.Tenant, error)
	GetByName(ctx context.Context, name string) (db.Tenant, error)
	Deactivate(ctx context.Context, id uuid.UUID) error
	List(ctx context.Context, query string, active int, limit, offset int32) ([]db.Tenant, int64, error)
}

// Service encapsulates business logic for tenants.
type Service interface {
	Create(ctx context.Context, name string) (db.Tenant, error)
	GetByID(ctx context.Context, id uuid.UUID) (db.Tenant, error)
	GetByName(ctx context.Context, name string) (db.Tenant, error)
	Deactivate(ctx context.Context, id uuid.UUID) error
	List(ctx context.Context, opts ListOptions) (ListResult, error)
}
