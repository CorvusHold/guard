-- name: CreateOAuthClient :one
INSERT INTO oauth_clients (
    id, tenant_id, client_id, client_secret_hash, client_type,
    name, redirect_uris, scopes, grant_types, logo_uri, created_by
) VALUES (
    $1, $2, $3, $4, $5,
    $6, $7, $8, $9, $10, $11
) RETURNING *;

-- name: GetOAuthClientByClientID :one
SELECT * FROM oauth_clients
WHERE client_id = $1 AND is_active = TRUE;

-- name: GetOAuthClientByID :one
SELECT * FROM oauth_clients
WHERE id = $1 AND tenant_id = $2;

-- name: ListOAuthClientsByTenant :many
SELECT * FROM oauth_clients
WHERE tenant_id = $1
ORDER BY created_at DESC;

-- name: UpdateOAuthClient :exec
UPDATE oauth_clients
SET name = COALESCE(NULLIF(sqlc.arg(name)::text, ''), name),
    redirect_uris = COALESCE(sqlc.arg(redirect_uris), redirect_uris),
    scopes = COALESCE(sqlc.arg(scopes), scopes),
    grant_types = COALESCE(sqlc.arg(grant_types), grant_types),
    logo_uri = COALESCE(sqlc.arg(logo_uri), logo_uri),
    is_active = COALESCE(sqlc.narg(is_active), is_active),
    updated_at = now()
WHERE id = sqlc.arg(id) AND tenant_id = sqlc.arg(tenant_id);

-- name: DeleteOAuthClient :exec
DELETE FROM oauth_clients
WHERE id = $1 AND tenant_id = $2;

-- name: CreateOAuthAuthorizationCode :one
INSERT INTO oauth_authorization_codes (
    id, client_id, user_id, tenant_id, code_hash,
    redirect_uri, scopes, nonce, code_challenge, code_challenge_method,
    expires_at
) VALUES (
    $1, $2, $3, $4, $5,
    $6, $7, $8, $9, $10,
    $11
) RETURNING *;

-- name: GetOAuthAuthorizationCodeByHash :one
SELECT * FROM oauth_authorization_codes
WHERE code_hash = $1 AND consumed_at IS NULL AND expires_at > now();

-- name: ConsumeOAuthAuthorizationCode :exec
UPDATE oauth_authorization_codes
SET consumed_at = now()
WHERE code_hash = $1 AND consumed_at IS NULL;

-- name: CleanupExpiredOAuthCodes :exec
DELETE FROM oauth_authorization_codes
WHERE expires_at < now() - INTERVAL '1 hour';

-- name: UpsertOAuthConsentGrant :one
INSERT INTO oauth_consent_grants (user_id, tenant_id, client_id, scopes)
VALUES ($1, $2, $3, $4)
ON CONFLICT (user_id, client_id, tenant_id) DO UPDATE
SET scopes = EXCLUDED.scopes, granted_at = now(), revoked_at = NULL
RETURNING *;

-- name: GetOAuthConsentGrant :one
SELECT * FROM oauth_consent_grants
WHERE user_id = $1 AND client_id = $2 AND tenant_id = $3 AND revoked_at IS NULL;

-- name: RevokeOAuthConsentGrant :exec
UPDATE oauth_consent_grants
SET revoked_at = now()
WHERE user_id = $1 AND client_id = $2 AND tenant_id = $3 AND revoked_at IS NULL;
