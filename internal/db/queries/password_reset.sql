-- name: CreatePasswordResetToken :exec
INSERT INTO password_reset_tokens (id, user_id, tenant_id, email, token_hash, expires_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: ConsumePasswordResetToken :exec
UPDATE password_reset_tokens
SET consumed_at = now()
WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now();

-- name: GetPasswordResetTokenByHash :one
SELECT id, user_id, tenant_id, email, token_hash, created_at, expires_at, consumed_at
FROM password_reset_tokens
WHERE token_hash = $1;

-- name: UpdateAuthIdentityPasswordByTenantEmail :exec
UPDATE auth_identities
SET password_hash = $3, updated_at = now()
WHERE tenant_id = $1 AND email = $2;
