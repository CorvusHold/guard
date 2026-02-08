package service

import (
	"context"
	"encoding/json"

	"github.com/corvusHold/guard/internal/events/domain"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DB is a Publisher that persists events to the audit_logs table.
type DB struct {
	pg *pgxpool.Pool
}

// NewDB creates a DB-backed event publisher.
func NewDB(pg *pgxpool.Pool) *DB { return &DB{pg: pg} }

func (d *DB) Publish(ctx context.Context, e domain.Event) error {
	meta, _ := json.Marshal(e.Meta)
	_, err := d.pg.Exec(ctx,
		`INSERT INTO audit_logs (user_id, tenant_id, action, meta, ip, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		e.UserID, e.TenantID, e.Type, string(meta), e.Meta["ip"], e.Time,
	)
	return err
}
