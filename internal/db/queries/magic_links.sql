-- name: CreateMagicLink :exec
INSERT INTO magic_links (id, user_id, tenant_id, email, token_hash, redirect_url, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: ConsumeMagicLink :exec
UPDATE magic_links
SET consumed_at = now()
WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now();

-- name: GetMagicLinkByHash :one
SELECT id, user_id, tenant_id, email, token_hash, redirect_url, created_at, expires_at, consumed_at
FROM magic_links
WHERE token_hash = $1;
