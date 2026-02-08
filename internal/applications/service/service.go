package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/corvusHold/guard/internal/applications/domain"
	"github.com/google/uuid"
)

// Service implements domain.Service.
type Service struct {
	repo domain.Repository
}

// New creates a new application service.
func New(repo domain.Repository) *Service {
	return &Service{repo: repo}
}

func (s *Service) Create(ctx context.Context, input domain.CreateInput) (domain.Application, error) {
	name := strings.TrimSpace(input.Name)
	if name == "" {
		return domain.Application{}, errors.New("application name is required")
	}
	app := domain.Application{
		ID:          uuid.New(),
		TenantID:    input.TenantID,
		Name:        name,
		Description: strings.TrimSpace(input.Description),
		LogoURI:     strings.TrimSpace(input.LogoURI),
		HomepageURL: strings.TrimSpace(input.HomepageURL),
		CreatedBy:   &input.CreatedBy,
		IsActive:    true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	return s.repo.Create(ctx, app)
}

func (s *Service) GetByID(ctx context.Context, id uuid.UUID) (domain.Application, error) {
	return s.repo.GetByID(ctx, id)
}

func (s *Service) List(ctx context.Context, tenantID uuid.UUID, opts domain.ListOptions) ([]domain.Application, int, error) {
	return s.repo.List(ctx, tenantID, opts)
}

func (s *Service) Update(ctx context.Context, id uuid.UUID, input domain.UpdateInput) (domain.Application, error) {
	return s.repo.Update(ctx, id, input)
}

func (s *Service) Delete(ctx context.Context, id uuid.UUID) error {
	return s.repo.Delete(ctx, id)
}
