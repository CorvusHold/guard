package repository

import (
	"context"
	"time"

	"github.com/corvusHold/guard/internal/applications/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Repository implements domain.Repository using pgxpool.
type Repository struct {
	pool *pgxpool.Pool
}

// New creates a new application repository.
func New(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

func (r *Repository) Create(ctx context.Context, app domain.Application) (domain.Application, error) {
	row := r.pool.QueryRow(ctx,
		`INSERT INTO applications (id, tenant_id, name, description, logo_uri, homepage_url, created_by, is_active, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		 RETURNING id, tenant_id, name, description, logo_uri, homepage_url, created_by, is_active, created_at, updated_at`,
		app.ID, app.TenantID, app.Name, app.Description, app.LogoURI, app.HomepageURL, app.CreatedBy, app.IsActive, app.CreatedAt, app.UpdatedAt,
	)
	return scanApp(row)
}

func (r *Repository) GetByID(ctx context.Context, id uuid.UUID) (domain.Application, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT id, tenant_id, name, description, logo_uri, homepage_url, created_by, is_active, created_at, updated_at
		 FROM applications WHERE id = $1`, id,
	)
	return scanApp(row)
}

func (r *Repository) List(ctx context.Context, tenantID uuid.UUID, opts domain.ListOptions) ([]domain.Application, int, error) {
	if opts.Limit <= 0 {
		opts.Limit = 50
	}
	var total int
	if err := r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM applications WHERE tenant_id = $1`, tenantID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.pool.Query(ctx,
		`SELECT id, tenant_id, name, description, logo_uri, homepage_url, created_by, is_active, created_at, updated_at
		 FROM applications WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
		tenantID, opts.Limit, opts.Offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var apps []domain.Application
	for rows.Next() {
		app, err := scanAppRows(rows)
		if err != nil {
			return nil, 0, err
		}
		apps = append(apps, app)
	}
	return apps, total, rows.Err()
}

func (r *Repository) Update(ctx context.Context, id uuid.UUID, input domain.UpdateInput) (domain.Application, error) {
	// Fetch current
	current, err := r.GetByID(ctx, id)
	if err != nil {
		return domain.Application{}, err
	}
	if input.Name != nil {
		current.Name = *input.Name
	}
	if input.Description != nil {
		current.Description = *input.Description
	}
	if input.LogoURI != nil {
		current.LogoURI = *input.LogoURI
	}
	if input.HomepageURL != nil {
		current.HomepageURL = *input.HomepageURL
	}
	if input.IsActive != nil {
		current.IsActive = *input.IsActive
	}
	current.UpdatedAt = time.Now()

	row := r.pool.QueryRow(ctx,
		`UPDATE applications SET name=$1, description=$2, logo_uri=$3, homepage_url=$4, is_active=$5, updated_at=$6
		 WHERE id=$7
		 RETURNING id, tenant_id, name, description, logo_uri, homepage_url, created_by, is_active, created_at, updated_at`,
		current.Name, current.Description, current.LogoURI, current.HomepageURL, current.IsActive, current.UpdatedAt, id,
	)
	return scanApp(row)
}

func (r *Repository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM applications WHERE id = $1`, id)
	return err
}

func scanApp(row pgx.Row) (domain.Application, error) {
	var app domain.Application
	err := row.Scan(&app.ID, &app.TenantID, &app.Name, &app.Description, &app.LogoURI, &app.HomepageURL, &app.CreatedBy, &app.IsActive, &app.CreatedAt, &app.UpdatedAt)
	return app, err
}

func scanAppRows(rows pgx.Rows) (domain.Application, error) {
	var app domain.Application
	err := rows.Scan(&app.ID, &app.TenantID, &app.Name, &app.Description, &app.LogoURI, &app.HomepageURL, &app.CreatedBy, &app.IsActive, &app.CreatedAt, &app.UpdatedAt)
	return app, err
}
