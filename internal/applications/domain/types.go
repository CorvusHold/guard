package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Application represents a registered application within a tenant.
type Application struct {
	ID          uuid.UUID  `json:"id"`
	TenantID    uuid.UUID  `json:"tenant_id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	LogoURI     string     `json:"logo_uri,omitempty"`
	HomepageURL string     `json:"homepage_url,omitempty"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty"`
	IsActive    bool       `json:"is_active"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// CreateInput is the input for creating an application.
type CreateInput struct {
	TenantID    uuid.UUID
	Name        string
	Description string
	LogoURI     string
	HomepageURL string
	CreatedBy   uuid.UUID
}

// UpdateInput is the input for updating an application.
type UpdateInput struct {
	Name        *string
	Description *string
	LogoURI     *string
	HomepageURL *string
	IsActive    *bool
}

// ListOptions defines pagination for listing applications.
type ListOptions struct {
	Limit  int
	Offset int
}

// Repository abstracts data access for applications.
type Repository interface {
	Create(ctx context.Context, app Application) (Application, error)
	GetByID(ctx context.Context, id uuid.UUID) (Application, error)
	List(ctx context.Context, tenantID uuid.UUID, opts ListOptions) ([]Application, int, error)
	Update(ctx context.Context, id uuid.UUID, input UpdateInput) (Application, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

// Service defines business logic for applications.
type Service interface {
	Create(ctx context.Context, input CreateInput) (Application, error)
	GetByID(ctx context.Context, id uuid.UUID) (Application, error)
	List(ctx context.Context, tenantID uuid.UUID, opts ListOptions) ([]Application, int, error)
	Update(ctx context.Context, id uuid.UUID, input UpdateInput) (Application, error)
	Delete(ctx context.Context, id uuid.UUID) error
}
