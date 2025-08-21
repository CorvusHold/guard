-- RBAC v2 queries: roles, permissions, role_permissions, user_roles, groups, acl tuples

-- name: ListPermissions :many
SELECT id, key, description, created_at, updated_at
FROM permissions
ORDER BY key;

-- name: GetPermissionByKey :one
SELECT id, key, description, created_at, updated_at
FROM permissions
WHERE key = $1;

-- name: ListRolesByTenant :many
SELECT id, tenant_id, name, description, created_at, updated_at
FROM roles
WHERE tenant_id = $1
ORDER BY name;

-- name: GetRoleByName :one
SELECT id, tenant_id, name, description, created_at, updated_at
FROM roles
WHERE tenant_id = $1 AND name = $2;

-- name: CreateRole :one
INSERT INTO roles (id, tenant_id, name, description)
VALUES ($1, $2, $3, $4)
RETURNING id, tenant_id, name, description, created_at, updated_at;

-- name: UpdateRole :one
UPDATE roles
SET name = $3, description = $4, updated_at = now()
WHERE id = $1 AND tenant_id = $2
RETURNING id, tenant_id, name, description, created_at, updated_at;

-- name: DeleteRole :exec
DELETE FROM roles WHERE id = $1 AND tenant_id = $2;

-- name: UpsertRolePermission :exec
INSERT INTO role_permissions (role_id, permission_id, scope_type, resource_type, resource_id)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (role_id, permission_id, scope_type, resource_type, resource_id) DO NOTHING;

-- name: DeleteRolePermission :exec
DELETE FROM role_permissions
WHERE role_id = $1 AND permission_id = $2 AND scope_type = $3
  AND (resource_type IS NOT DISTINCT FROM $4)
  AND (resource_id IS NOT DISTINCT FROM $5);

-- name: ListRolePermissionKeys :many
SELECT rp.role_id, p.key, rp.scope_type, rp.resource_type, rp.resource_id
FROM role_permissions rp
JOIN permissions p ON p.id = rp.permission_id
WHERE rp.role_id = ANY($1::uuid[])
ORDER BY rp.role_id, p.key;

-- name: ListUserRoleIDs :many
SELECT role_id
FROM user_roles
WHERE user_id = $1 AND tenant_id = $2;

-- name: AddUserRole :exec
INSERT INTO user_roles (user_id, tenant_id, role_id)
VALUES ($1, $2, $3)
ON CONFLICT DO NOTHING;

-- name: RemoveUserRole :exec
DELETE FROM user_roles WHERE user_id = $1 AND tenant_id = $2 AND role_id = $3;

-- name: ListUserGroups :many
SELECT group_id
FROM group_members
WHERE user_id = $1;

-- name: ListACLPermissionKeysForUser :many
SELECT p.key, a.object_type, a.object_id
FROM acl_tuples a
JOIN permissions p ON p.id = a.permission_id
WHERE a.tenant_id = $1 AND a.subject_type = 'user' AND a.subject_id = $2;

-- name: ListACLPermissionKeysForGroups :many
SELECT a.subject_id AS group_id, p.key, a.object_type, a.object_id
FROM acl_tuples a
JOIN permissions p ON p.id = a.permission_id
WHERE a.tenant_id = $1 AND a.subject_type = 'group' AND a.subject_id = ANY($2::uuid[]);
