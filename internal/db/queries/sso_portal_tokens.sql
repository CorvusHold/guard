-- SSO Portal Tokens

-- name: CreateSSOPortalToken :one
INSERT INTO sso_portal_tokens (
    tenant_id,
    sso_provider_id,
    provider_slug,
    token_hash,
    intent,
    created_by,
    expires_at,
    max_uses
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8
) RETURNING *;

-- name: ConsumeSSOPortalTokenByHash :one
UPDATE sso_portal_tokens
SET use_count = use_count + 1,
    last_used_at = NOW()
WHERE token_hash = $1
  AND expires_at > NOW()
  AND revoked_at IS NULL
  AND (max_uses = 0 OR use_count < max_uses)
RETURNING *;

-- name: RevokeSSOPortalToken :exec
UPDATE sso_portal_tokens
SET revoked_at = NOW()
WHERE id = $1;

-- name: GetSSOPortalTokenByHash :one
SELECT * FROM sso_portal_tokens
WHERE token_hash = $1
  AND expires_at > NOW()
  AND revoked_at IS NULL;
