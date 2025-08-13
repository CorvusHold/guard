-- name: CreateAuthIdentity :exec
INSERT INTO auth_identities (id, user_id, tenant_id, email, password_hash)
VALUES ($1, $2, $3, $4, $5);

-- name: GetAuthIdentityByEmailTenant :one
SELECT id, user_id, tenant_id, email, password_hash, created_at, updated_at
FROM auth_identities
WHERE tenant_id = $1 AND email = $2;

-- name: GetAuthIdentitiesByUser :many
SELECT id, user_id, tenant_id, email, password_hash, created_at, updated_at
FROM auth_identities
WHERE user_id = $1;

-- name: UpdateAuthIdentityPassword :exec
UPDATE auth_identities
SET password_hash = $2, updated_at = now()
WHERE id = $1;
