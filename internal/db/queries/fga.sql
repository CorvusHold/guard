-- FGA queries: groups, group_members, acl_tuples

-- name: CreateGroup :one
INSERT INTO groups (id, tenant_id, name, description)
VALUES ($1, $2, $3, $4)
RETURNING id, tenant_id, name, description, created_at, updated_at;

-- name: ListGroups :many
SELECT id, tenant_id, name, description, created_at, updated_at
FROM groups
WHERE tenant_id = $1
ORDER BY name;

-- name: DeleteGroup :exec
DELETE FROM groups
WHERE id = $1 AND tenant_id = $2;

-- name: AddGroupMember :exec
INSERT INTO group_members (group_id, user_id)
VALUES ($1, $2)
ON CONFLICT DO NOTHING;

-- name: RemoveGroupMember :exec
DELETE FROM group_members
WHERE group_id = $1 AND user_id = $2;

-- name: CreateACLTuple :one
INSERT INTO acl_tuples (id, tenant_id, subject_type, subject_id, permission_id, object_type, object_id, created_by)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING id, tenant_id, subject_type, subject_id, permission_id, object_type, object_id, created_by, created_at;

-- name: DeleteACLTuple :exec
DELETE FROM acl_tuples
WHERE tenant_id = $1
  AND subject_type = $2
  AND subject_id = $3
  AND permission_id = $4
  AND object_type = $5
  AND (object_id IS NOT DISTINCT FROM $6);
