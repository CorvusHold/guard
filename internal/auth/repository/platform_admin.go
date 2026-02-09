package repository

import (
	"context"
	"fmt"
	"strings"

	domain "github.com/corvusHold/guard/internal/auth/domain"
	"github.com/google/uuid"
)

func (r *SQLCRepository) ListAllTenantsWithStats(ctx context.Context, limit, offset int) ([]domain.TenantStats, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT t.id, t.name, t.is_active, t.created_at, COUNT(ut.user_id) AS user_count
		 FROM tenants t
		 LEFT JOIN user_tenants ut ON ut.tenant_id = t.id
		 GROUP BY t.id, t.name, t.is_active, t.created_at
		 ORDER BY t.created_at DESC
		 LIMIT $1 OFFSET $2`, limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []domain.TenantStats
	for rows.Next() {
		var ts domain.TenantStats
		if err := rows.Scan(&ts.ID, &ts.Name, &ts.IsActive, &ts.CreatedAt, &ts.UserCount); err != nil {
			return nil, err
		}
		result = append(result, ts)
	}
	return result, rows.Err()
}

// escapeILIKE escapes SQL ILIKE special characters (% and _) in user input
// to prevent wildcard injection.
func escapeILIKE(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

func (r *SQLCRepository) SearchUsersGlobal(ctx context.Context, query string) ([]domain.UserSearchResult, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT u.id, ai.email, u.first_name, u.last_name
		 FROM users u
		 JOIN auth_identities ai ON ai.user_id = u.id
		 WHERE ai.email ILIKE $1
		 ORDER BY ai.email ASC
		 LIMIT 50`,
		"%"+escapeILIKE(query)+"%",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []domain.UserSearchResult
	for rows.Next() {
		var usr domain.UserSearchResult
		if err := rows.Scan(&usr.ID, &usr.Email, &usr.FirstName, &usr.LastName); err != nil {
			return nil, err
		}
		result = append(result, usr)
	}
	return result, rows.Err()
}

func (r *SQLCRepository) QueryAuditLogs(ctx context.Context, tenantID *uuid.UUID, userID *uuid.UUID, action string, limit, offset int) ([]domain.AuditLogEntry, int, error) {
	// Build dynamic WHERE clause
	conditions := []string{}
	args := []interface{}{}
	argIdx := 1

	if tenantID != nil {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIdx))
		args = append(args, *tenantID)
		argIdx++
	}
	if userID != nil {
		conditions = append(conditions, fmt.Sprintf("user_id = $%d", argIdx))
		args = append(args, *userID)
		argIdx++
	}
	if action != "" {
		conditions = append(conditions, fmt.Sprintf("action = $%d", argIdx))
		args = append(args, action)
		argIdx++
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count
	var total int
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM audit_logs %s", where)
	if err := r.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	// Fetch
	dataQuery := fmt.Sprintf(
		`SELECT id, user_id, tenant_id, action, meta, ip, created_at FROM audit_logs %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d`,
		where, argIdx, argIdx+1,
	)
	args = append(args, limit, offset)

	rows, err := r.pool.Query(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var result []domain.AuditLogEntry
	for rows.Next() {
		var entry domain.AuditLogEntry
		if err := rows.Scan(&entry.ID, &entry.UserID, &entry.TenantID, &entry.Action, &entry.Meta, &entry.IP, &entry.CreatedAt); err != nil {
			return nil, 0, err
		}
		result = append(result, entry)
	}
	return result, total, rows.Err()
}

func (r *SQLCRepository) IsMFAEnrolled(ctx context.Context, userID, tenantID uuid.UUID) (bool, error) {
	var count int
	// mfa_secrets is keyed by user_id only (no tenant_id column); column is 'enabled' not 'verified'
	err := r.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM mfa_secrets WHERE user_id = $1 AND enabled = TRUE`,
		userID,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (r *SQLCRepository) ListUsersByTenant(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]domain.UserExport, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT u.id, ai.email, u.first_name, u.last_name, u.created_at, u.blocked,
		        COALESCE(array_agg(r.name) FILTER (WHERE r.name IS NOT NULL), '{}') AS roles
		 FROM users u
		 JOIN user_tenants ut ON ut.user_id = u.id AND ut.tenant_id = $1
		 JOIN auth_identities ai ON ai.user_id = u.id AND ai.tenant_id = $1
		 LEFT JOIN user_roles ur ON ur.user_id = u.id AND ur.tenant_id = $1
		 LEFT JOIN roles r ON r.id = ur.role_id
		 GROUP BY u.id, ai.email, u.first_name, u.last_name, u.created_at, u.blocked
		 ORDER BY u.created_at DESC
		 LIMIT $2 OFFSET $3`,
		tenantID, limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []domain.UserExport
	for rows.Next() {
		var ue domain.UserExport
		if err := rows.Scan(&ue.ID, &ue.Email, &ue.FirstName, &ue.LastName, &ue.CreatedAt, &ue.Blocked, &ue.Roles); err != nil {
			return nil, err
		}
		result = append(result, ue)
	}
	return result, rows.Err()
}

func (r *SQLCRepository) PlatformStats(ctx context.Context) (domain.PlatformStatsResult, error) {
	var stats domain.PlatformStatsResult
	err := r.pool.QueryRow(ctx,
		`SELECT
			(SELECT COUNT(*) FROM tenants) AS total_tenants,
			(SELECT COUNT(*) FROM users) AS total_users,
			(SELECT COUNT(*) FROM refresh_tokens WHERE revoked = FALSE AND expires_at > now()) AS active_sessions,
			(SELECT COUNT(*) FROM api_keys WHERE revoked_at IS NULL) AS total_api_keys`,
	).Scan(&stats.TotalTenants, &stats.TotalUsers, &stats.ActiveSessions, &stats.TotalAPIKeys)
	return stats, err
}
