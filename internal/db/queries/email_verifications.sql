-- name: CreateEmailVerification :exec
INSERT INTO email_verifications (id, user_id, tenant_id, token_hash, expires_at)
VALUES ($1, $2, $3, $4, $5);

-- name: ConsumeEmailVerification :exec
UPDATE email_verifications
SET consumed_at = now()
WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now();

-- name: GetEmailVerificationByHash :one
SELECT id, user_id, tenant_id, token_hash, created_at, expires_at, consumed_at
FROM email_verifications
WHERE token_hash = $1;
