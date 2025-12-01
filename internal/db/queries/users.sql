-- name: CreateUser :exec
INSERT INTO users (id, email_verified, is_active, first_name, last_name, roles)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: GetUserByID :one
SELECT id, email_verified, is_active, first_name, last_name, roles, created_at, updated_at, last_login_at
FROM users
WHERE id = $1;

-- name: UpdateUserProfile :exec
UPDATE users SET first_name = $2, last_name = $3, roles = $4, updated_at = now()
WHERE id = $1;

-- name: UpdateUserLastLogin :exec
UPDATE users SET last_login_at = now(), updated_at = now()
WHERE id = $1;

-- name: SetUserActive :exec
UPDATE users SET is_active = $2, updated_at = now() WHERE id = $1;

-- name: SetUserEmailVerified :exec
UPDATE users SET email_verified = $2, updated_at = now() WHERE id = $1;
