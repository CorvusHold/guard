-- name: InsertRefreshToken :exec
INSERT INTO refresh_tokens (id, user_id, tenant_id, token_hash, parent_id, user_agent, ip, expires_at, auth_method, sso_provider_id, metadata)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens SET revoked = TRUE WHERE id = $1;

-- name: GetRefreshTokenByHash :one
SELECT id, user_id, tenant_id, token_hash, parent_id, revoked, user_agent, ip, created_at, expires_at, auth_method, sso_provider_id, metadata
FROM refresh_tokens
WHERE token_hash = $1;

-- name: RevokeTokenChain :exec
WITH RECURSIVE chain AS (
  SELECT rt.id, rt.parent_id FROM refresh_tokens rt WHERE rt.id = $1
  UNION ALL
  SELECT rt.id, rt.parent_id FROM refresh_tokens rt
  JOIN chain c ON rt.parent_id = c.id
)
UPDATE refresh_tokens rt SET revoked = TRUE WHERE rt.id IN (SELECT c.id FROM chain c);

-- name: ListUserSessions :many
SELECT rt.id, rt.user_id, rt.tenant_id, rt.token_hash, rt.parent_id, rt.revoked, rt.user_agent, rt.ip, rt.created_at, rt.expires_at, rt.auth_method, rt.sso_provider_id, rt.metadata, sp.name as sso_provider_name, sp.slug as sso_provider_slug
FROM refresh_tokens rt
LEFT JOIN sso_providers sp ON rt.sso_provider_id = sp.id
WHERE rt.user_id = $1 AND rt.tenant_id = $2
ORDER BY rt.created_at DESC;
