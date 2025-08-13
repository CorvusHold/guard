-- name: InsertAuditLog :exec
INSERT INTO audit_logs (user_id, tenant_id, action, metadata, ip)
VALUES ($1, $2, $3, $4, $5);

-- name: ListAuditLogsByTenant :many
SELECT id, user_id, tenant_id, action, metadata, ip, created_at
FROM audit_logs
WHERE tenant_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;
