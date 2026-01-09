-- name: CreateTenant :exec
INSERT INTO tenants (id, name, parent_tenant_id)
VALUES ($1, $2, $3);

-- name: GetTenantByID :one
SELECT id, name, is_active, created_at, updated_at, parent_tenant_id
FROM tenants
WHERE id = $1;

-- name: GetTenantByName :one
SELECT id, name, is_active, created_at, updated_at, parent_tenant_id
FROM tenants
WHERE name = $1;

-- name: DeactivateTenant :exec
UPDATE tenants SET is_active = FALSE, updated_at = now()
WHERE id = $1;

-- name: ListTenants :many
SELECT id, name, is_active, created_at, updated_at, parent_tenant_id
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

-- name: ListChildTenants :many
SELECT id, name, is_active, created_at, updated_at, parent_tenant_id
FROM tenants
WHERE parent_tenant_id = $1
ORDER BY created_at DESC;

-- name: GetTenantAncestors :many
WITH RECURSIVE ancestors AS (
  SELECT t.id, t.name, t.is_active, t.created_at, t.updated_at, t.parent_tenant_id, 0 AS depth
  FROM tenants t
  WHERE t.id = $1
  UNION ALL
  SELECT t2.id, t2.name, t2.is_active, t2.created_at, t2.updated_at, t2.parent_tenant_id, a.depth + 1
  FROM tenants t2
  INNER JOIN ancestors a ON t2.id = a.parent_tenant_id
)
SELECT ancestors.id, ancestors.name, ancestors.is_active, ancestors.created_at, ancestors.updated_at, ancestors.parent_tenant_id
FROM ancestors
WHERE ancestors.depth > 0
ORDER BY ancestors.depth ASC;

-- name: UpdateTenantParent :exec
UPDATE tenants SET parent_tenant_id = $2, updated_at = now()
WHERE id = $1;
