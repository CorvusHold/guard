-- name: UpsertMFASecret :exec
INSERT INTO mfa_secrets (user_id, secret, enabled)
VALUES ($1, $2, $3)
ON CONFLICT (user_id) DO UPDATE SET secret = EXCLUDED.secret, enabled = EXCLUDED.enabled;

-- name: GetMFASecret :one
SELECT user_id, secret, enabled, created_at FROM mfa_secrets WHERE user_id = $1;

-- name: InsertMFABackupCode :exec
INSERT INTO mfa_backup_codes (id, user_id, code_hash)
VALUES ($1, $2, $3);

-- name: ConsumeMFABackupCode :one
UPDATE mfa_backup_codes SET consumed_at = now()
WHERE user_id = $1 AND code_hash = $2 AND consumed_at IS NULL
RETURNING id;

-- name: CountRemainingMFABackupCodes :one
SELECT COUNT(*) FROM mfa_backup_codes WHERE user_id = $1 AND consumed_at IS NULL;
