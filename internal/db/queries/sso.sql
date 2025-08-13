-- name: UpsertSSOProvider :exec
INSERT INTO sso_providers (id, tenant_id, provider, client_id, config)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (tenant_id, provider) DO UPDATE SET client_id = EXCLUDED.client_id, config = EXCLUDED.config;

-- name: GetSSOProvider :one
SELECT id, tenant_id, provider, client_id, config, created_at
FROM sso_providers
WHERE tenant_id = $1 AND provider = $2;

-- name: CreateSSOIdentity :exec
INSERT INTO sso_identities (id, provider_id, user_id, external_id)
VALUES ($1, $2, $3, $4);

-- name: GetSSOIdentity :one
SELECT id, provider_id, user_id, external_id, created_at
FROM sso_identities
WHERE provider_id = $1 AND external_id = $2;
