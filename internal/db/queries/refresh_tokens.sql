-- name: InsertRefreshToken :exec
INSERT INTO refresh_tokens (id, user_id, tenant_id, token_hash, parent_id, user_agent, ip, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens SET revoked = TRUE WHERE id = $1;

-- name: GetRefreshTokenByHash :one
SELECT id, user_id, tenant_id, token_hash, parent_id, revoked, user_agent, ip, created_at, expires_at
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
