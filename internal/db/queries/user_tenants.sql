-- name: AddUserToTenant :exec
INSERT INTO user_tenants (user_id, tenant_id)
VALUES ($1, $2)
ON CONFLICT DO NOTHING;

-- name: RemoveUserFromTenant :exec
DELETE FROM user_tenants WHERE user_id = $1 AND tenant_id = $2;

-- name: ListUserTenants :many
SELECT t.id, t.name, t.is_active, t.created_at, t.updated_at
FROM user_tenants ut
JOIN tenants t ON t.id = ut.tenant_id
WHERE ut.user_id = $1;

-- name: ListTenantUsers :many
SELECT u.id, u.email_verified, u.is_active, u.first_name, u.last_name, u.roles, u.created_at, u.updated_at, u.last_login_at
FROM user_tenants ut
JOIN users u ON u.id = ut.user_id
WHERE ut.tenant_id = $1;
