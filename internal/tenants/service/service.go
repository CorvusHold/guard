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

func (s *service) Create(ctx context.Context, name string) (db.Tenant, error) {
	if name == "" {
		return db.Tenant{}, errors.New("tenant name is required")
	}
	// Optionally enforce uniqueness by name
	if _, err := s.repo.GetByName(ctx, name); err == nil {
		return db.Tenant{}, errors.New("tenant name already exists")
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return db.Tenant{}, err
	}

	id := uuid.New()
	if err := s.repo.Create(ctx, id, name); err != nil {
		return db.Tenant{}, err
	}
	return s.repo.GetByID(ctx, id)
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
