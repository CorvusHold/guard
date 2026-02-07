-- name: CreateInvitation :one
INSERT INTO invitations (id, tenant_id, email, token_hash, role, invited_by, status, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7)
RETURNING *;

-- name: GetInvitationByHash :one
SELECT * FROM invitations WHERE token_hash = $1;

-- name: GetInvitationByID :one
SELECT * FROM invitations WHERE id = $1;

-- name: GetPendingInvitationByEmail :one
SELECT * FROM invitations 
WHERE email = $1 AND tenant_id = $2 AND status = 'pending' AND expires_at > now()
LIMIT 1;

-- name: ListPendingInvitationsByTenant :many
SELECT * FROM invitations 
WHERE tenant_id = $1 AND status = 'pending' AND expires_at > now()
ORDER BY created_at DESC;

-- name: ListInvitationsByTenant :many
SELECT * FROM invitations 
WHERE tenant_id = $1
ORDER BY created_at DESC;

-- name: AcceptInvitation :one
UPDATE invitations 
SET status = 'accepted', accepted_at = now(), updated_at = now()
WHERE token_hash = $1 AND status = 'pending' AND expires_at > now()
RETURNING id;

-- name: RevokeInvitation :exec
UPDATE invitations 
SET status = 'revoked', updated_at = now()
WHERE id = $1 AND tenant_id = $2 AND status = 'pending';

-- name: ExpireOldInvitations :exec
UPDATE invitations 
SET status = 'expired', updated_at = now()
WHERE status = 'pending' AND expires_at <= now();

-- name: DeleteInvitation :exec
DELETE FROM invitations WHERE id = $1 AND tenant_id = $2;
