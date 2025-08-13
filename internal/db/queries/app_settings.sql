-- name: GetAppSettingByKeyTenant :one
SELECT id, tenant_id, key, value, is_secret, created_at, updated_at
FROM app_settings
WHERE key = $1 AND tenant_id = $2
LIMIT 1;

-- name: GetAppSettingGlobal :one
SELECT id, tenant_id, key, value, is_secret, created_at, updated_at
FROM app_settings
WHERE key = $1 AND tenant_id IS NULL
LIMIT 1;

-- name: UpsertAppSetting :exec
INSERT INTO app_settings (id, tenant_id, key, value, is_secret)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (key, tenant_id)
DO UPDATE SET value = EXCLUDED.value, is_secret = EXCLUDED.is_secret, updated_at = now();
