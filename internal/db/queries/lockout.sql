-- name: IncrementFailedAttempts :one
UPDATE auth_identities
SET failed_attempts = failed_attempts + 1
WHERE tenant_id = $1 AND email = $2
RETURNING failed_attempts;

-- name: ResetFailedAttempts :exec
UPDATE auth_identities
SET failed_attempts = 0, locked_until = NULL
WHERE tenant_id = $1 AND email = $2;

-- name: LockAccount :exec
UPDATE auth_identities
SET locked_until = $3
WHERE tenant_id = $1 AND email = $2;

-- name: UnlockAccount :exec
UPDATE auth_identities
SET failed_attempts = 0, locked_until = NULL
WHERE user_id = $1;

-- name: GetLockoutStatus :one
SELECT failed_attempts, locked_until
FROM auth_identities
WHERE tenant_id = $1 AND email = $2;
