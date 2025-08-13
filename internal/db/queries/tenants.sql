-- name: CreateTenant :exec
INSERT INTO tenants (id, name)
VALUES ($1, $2);

-- name: GetTenantByID :one
SELECT id, name, is_active, created_at, updated_at
FROM tenants
WHERE id = $1;

-- name: GetTenantByName :one
SELECT id, name, is_active, created_at, updated_at
FROM tenants
WHERE name = $1;

-- name: DeactivateTenant :exec
UPDATE tenants SET is_active = FALSE, updated_at = now()
WHERE id = $1;

-- name: ListTenants :many
SELECT id, name, is_active, created_at, updated_at
FROM tenants
WHERE ($1::text = '' OR name ILIKE '%' || $1::text || '%')
  AND (
    $2::int = -1 OR
    ($2::int = 1 AND is_active = TRUE) OR
    ($2::int = 0 AND is_active = FALSE)
  )
ORDER BY created_at DESC
LIMIT $3 OFFSET $4;

-- name: CountTenants :one
SELECT COUNT(*)
FROM tenants
WHERE ($1::text = '' OR name ILIKE '%' || $1::text || '%')
  AND (
    $2::int = -1 OR
    ($2::int = 1 AND is_active = TRUE) OR
    ($2::int = 0 AND is_active = FALSE)
  );
