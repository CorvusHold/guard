-- name: CreateAuthIdentity :exec
INSERT INTO auth_identities (id, user_id, tenant_id, email, password_hash)
VALUES ($1, $2, $3, $4, $5);

-- name: GetAuthIdentityByEmailTenant :one
SELECT id, user_id, tenant_id, email, password_hash, sso_provider_id, sso_subject, sso_attributes, created_at, updated_at
FROM auth_identities
WHERE tenant_id = $1 AND email = $2;

-- name: GetAuthIdentitiesByUser :many
SELECT id, user_id, tenant_id, email, password_hash, sso_provider_id, sso_subject, sso_attributes, created_at, updated_at
FROM auth_identities
WHERE user_id = $1;

-- name: UpdateAuthIdentityPassword :exec
UPDATE auth_identities
SET password_hash = $2, updated_at = now()
WHERE id = $1;

-- SSO Identity Management

-- name: CreateSSOIdentity :one
INSERT INTO auth_identities (id, user_id, tenant_id, email, sso_provider_id, sso_subject, sso_attributes)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id, user_id, tenant_id, email, password_hash, sso_provider_id, sso_subject, sso_attributes, created_at, updated_at;

-- name: GetSSOIdentity :one
SELECT id, user_id, tenant_id, email, password_hash, sso_provider_id, sso_subject, sso_attributes, created_at, updated_at
FROM auth_identities
WHERE tenant_id = $1 AND sso_provider_id = $2 AND sso_subject = $3;

-- name: UpdateSSOIdentity :exec
UPDATE auth_identities
SET sso_attributes = $2, updated_at = now()
WHERE id = $1;

-- name: ListUserSSOIdentities :many
SELECT id, user_id, tenant_id, email, password_hash, sso_provider_id, sso_subject, sso_attributes, created_at, updated_at
FROM auth_identities
WHERE user_id = $1 AND sso_provider_id IS NOT NULL;

-- name: UnlinkSSOIdentity :exec
DELETE FROM auth_identities
WHERE id = $1 AND tenant_id = $2;