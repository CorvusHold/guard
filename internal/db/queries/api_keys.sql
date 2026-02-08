-- name: CreateAPIKey :one
INSERT INTO api_keys (id, tenant_id, name, key_hash, key_prefix, scopes, created_by, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING id, tenant_id, name, key_hash, key_prefix, scopes, created_by, expires_at, revoked_at, last_used_at, created_at, updated_at;

-- name: GetAPIKeyByHash :one
SELECT id, tenant_id, name, key_hash, key_prefix, scopes, created_by, expires_at, revoked_at, last_used_at, created_at, updated_at
FROM api_keys
WHERE key_hash = $1 AND revoked_at IS NULL;

-- name: ListAPIKeysByTenant :many
SELECT id, tenant_id, name, key_prefix, scopes, created_by, expires_at, revoked_at, last_used_at, created_at, updated_at
FROM api_keys
WHERE tenant_id = $1
ORDER BY created_at DESC;

-- name: RevokeAPIKey :exec
UPDATE api_keys SET revoked_at = now(), updated_at = now()
WHERE id = $1 AND tenant_id = $2 AND revoked_at IS NULL;

-- name: UpdateAPIKeyLastUsed :exec
UPDATE api_keys SET last_used_at = now() WHERE id = $1;

-- name: DeleteAPIKey :exec
DELETE FROM api_keys WHERE id = $1 AND tenant_id = $2;
