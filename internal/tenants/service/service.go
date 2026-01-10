package service

import (
	"context"
	"errors"

	db "github.com/corvusHold/guard/internal/db/sqlc"
	domain "github.com/corvusHold/guard/internal/tenants/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type service struct {
	repo domain.Repository
}

func New(repo domain.Repository) domain.Service {
	return &service{repo: repo}
}

func (s *service) Create(ctx context.Context, name string, parentTenantID *uuid.UUID) (db.Tenant, error) {
	if name == "" {
		return db.Tenant{}, errors.New("tenant name is required")
	}
	// Optionally enforce uniqueness by name
	if _, err := s.repo.GetByName(ctx, name); err == nil {
		return db.Tenant{}, errors.New("tenant name already exists")
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return db.Tenant{}, err
	}

	// Validate parent tenant exists if specified
	if parentTenantID != nil {
		if _, err := s.repo.GetByID(ctx, *parentTenantID); err != nil {
			return db.Tenant{}, errors.New("parent tenant not found")
		}
	}

	id := uuid.New()

	// Prevent circular parent references: check if parent is a descendant of this new tenant
	if parentTenantID != nil {
		isDescendant, err := s.IsAncestorOf(ctx, *parentTenantID, id)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return db.Tenant{}, err
		}
		if isDescendant {
			return db.Tenant{}, errors.New("cannot set parent to a descendant tenant")
		}
	}

	if err := s.repo.Create(ctx, id, name, parentTenantID); err != nil {
		return db.Tenant{}, err
	}
	return s.repo.GetByID(ctx, id)
}

func (s *service) ListChildTenants(ctx context.Context, parentID uuid.UUID) ([]db.Tenant, error) {
	return s.repo.ListChildTenants(ctx, parentID)
}

func (s *service) GetTenantAncestors(ctx context.Context, tenantID uuid.UUID) ([]db.Tenant, error) {
	return s.repo.GetTenantAncestors(ctx, tenantID)
}

func (s *service) IsAncestorOf(ctx context.Context, ancestorID, descendantID uuid.UUID) (bool, error) {
	ancestors, err := s.repo.GetTenantAncestors(ctx, descendantID)
	if err != nil {
		return false, err
	}
	for _, a := range ancestors {
		if a.ID.Valid && uuid.UUID(a.ID.Bytes) == ancestorID {
			return true, nil
		}
	}
	return false, nil
}

func (s *service) GetByID(ctx context.Context, id uuid.UUID) (db.Tenant, error) {
	return s.repo.GetByID(ctx, id)
}

func (s *service) GetByName(ctx context.Context, name string) (db.Tenant, error) {
	return s.repo.GetByName(ctx, name)
}

func (s *service) Deactivate(ctx context.Context, id uuid.UUID) error {
	return s.repo.Deactivate(ctx, id)
}

func (s *service) List(ctx context.Context, opts domain.ListOptions) (domain.ListResult, error) {
	if opts.PageSize <= 0 || opts.PageSize > 100 {
		opts.PageSize = 20
	}
	if opts.Page <= 0 {
		opts.Page = 1
	}
	if opts.Active != -1 && opts.Active != 0 && opts.Active != 1 {
		opts.Active = -1
	}
	limit := int32(opts.PageSize)
	offset := int32((opts.Page - 1) * opts.PageSize)

	items, total, err := s.repo.List(ctx, opts.Query, opts.Active, limit, offset)
	if err != nil {
		return domain.ListResult{}, err
	}
	totalPages := int(total) / opts.PageSize
	if int(total)%opts.PageSize != 0 {
		totalPages++
	}
	return domain.ListResult{
		Items:      items,
		Total:      total,
		Page:       opts.Page,
		PageSize:   opts.PageSize,
		TotalPages: totalPages,
	}, nil
}
