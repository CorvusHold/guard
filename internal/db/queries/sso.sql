-- SSO Provider Management

-- name: CreateSSOProvider :one
INSERT INTO sso_providers (
    tenant_id,
    name,
    slug,
    provider_type,
    -- OIDC fields
    issuer,
    authorization_endpoint,
    token_endpoint,
    userinfo_endpoint,
    jwks_uri,
    client_id,
    client_secret,
    scopes,
    response_type,
    response_mode,
    -- SAML fields
    entity_id,
    acs_url,
    slo_url,
    idp_metadata_url,
    idp_metadata_xml,
    idp_entity_id,
    idp_sso_url,
    idp_slo_url,
    idp_certificate,
    sp_certificate,
    sp_private_key,
    sp_certificate_expires_at,
    want_assertions_signed,
    want_response_signed,
    sign_requests,
    force_authn,
    -- Common fields
    attribute_mapping,
    enabled,
    allow_signup,
    trust_email_verified,
    domains,
    created_by,
    updated_by
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
    $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26,
    $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37
) RETURNING *;

-- name: GetSSOProvider :one
SELECT * FROM sso_providers
WHERE id = $1 AND tenant_id = $2;

-- name: GetSSOProviderBySlug :one
SELECT * FROM sso_providers
WHERE tenant_id = $1 AND slug = $2;

-- name: ListSSOProviders :many
SELECT * FROM sso_providers
WHERE tenant_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: UpdateSSOProvider :exec
UPDATE sso_providers
SET
    name = COALESCE(sqlc.narg('name'), name),
    enabled = COALESCE(sqlc.narg('enabled'), enabled),
    -- OIDC fields
    issuer = COALESCE(sqlc.narg('issuer'), issuer),
    authorization_endpoint = COALESCE(sqlc.narg('authorization_endpoint'), authorization_endpoint),
    token_endpoint = COALESCE(sqlc.narg('token_endpoint'), token_endpoint),
    userinfo_endpoint = COALESCE(sqlc.narg('userinfo_endpoint'), userinfo_endpoint),
    jwks_uri = COALESCE(sqlc.narg('jwks_uri'), jwks_uri),
    client_id = COALESCE(sqlc.narg('client_id'), client_id),
    client_secret = COALESCE(sqlc.narg('client_secret'), client_secret),
    scopes = COALESCE(sqlc.narg('scopes'), scopes),
    response_type = COALESCE(sqlc.narg('response_type'), response_type),
    response_mode = COALESCE(sqlc.narg('response_mode'), response_mode),
    -- SAML fields
    entity_id = COALESCE(sqlc.narg('entity_id'), entity_id),
    acs_url = COALESCE(sqlc.narg('acs_url'), acs_url),
    slo_url = COALESCE(sqlc.narg('slo_url'), slo_url),
    idp_metadata_url = COALESCE(sqlc.narg('idp_metadata_url'), idp_metadata_url),
    idp_metadata_xml = COALESCE(sqlc.narg('idp_metadata_xml'), idp_metadata_xml),
    idp_entity_id = COALESCE(sqlc.narg('idp_entity_id'), idp_entity_id),
    idp_sso_url = COALESCE(sqlc.narg('idp_sso_url'), idp_sso_url),
    idp_slo_url = COALESCE(sqlc.narg('idp_slo_url'), idp_slo_url),
    idp_certificate = COALESCE(sqlc.narg('idp_certificate'), idp_certificate),
    sp_certificate = COALESCE(sqlc.narg('sp_certificate'), sp_certificate),
    sp_private_key = COALESCE(sqlc.narg('sp_private_key'), sp_private_key),
    sp_certificate_expires_at = COALESCE(sqlc.narg('sp_certificate_expires_at'), sp_certificate_expires_at),
    want_assertions_signed = COALESCE(sqlc.narg('want_assertions_signed'), want_assertions_signed),
    want_response_signed = COALESCE(sqlc.narg('want_response_signed'), want_response_signed),
    sign_requests = COALESCE(sqlc.narg('sign_requests'), sign_requests),
    force_authn = COALESCE(sqlc.narg('force_authn'), force_authn),
    -- Common fields
    attribute_mapping = COALESCE(sqlc.narg('attribute_mapping'), attribute_mapping),
    allow_signup = COALESCE(sqlc.narg('allow_signup'), allow_signup),
    trust_email_verified = COALESCE(sqlc.narg('trust_email_verified'), trust_email_verified),
    domains = COALESCE(sqlc.narg('domains'), domains),
    updated_by = sqlc.narg('updated_by'),
    updated_at = NOW()
WHERE id = sqlc.arg('id') AND tenant_id = sqlc.arg('tenant_id');

-- name: DeleteSSOProvider :exec
DELETE FROM sso_providers
WHERE id = $1 AND tenant_id = $2;

-- name: FindSSOProviderByDomain :one
SELECT * FROM sso_providers
WHERE tenant_id = $1
  AND enabled = TRUE
  AND $2 = ANY(domains)
ORDER BY created_at DESC
LIMIT 1;

-- SSO Authentication Attempts

-- name: CreateSSOAuthAttempt :one
INSERT INTO sso_auth_attempts (
    tenant_id,
    provider_id,
    user_id,
    state,
    status,
    error_code,
    error_message,
    ip_address,
    user_agent
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9
) RETURNING *;

-- name: UpdateSSOAuthAttempt :exec
UPDATE sso_auth_attempts
SET
    status = $1,
    error_code = $2,
    error_message = $3,
    user_id = $4,
    completed_at = NOW()
WHERE id = $5;

-- name: GetSSOAuthAttemptByState :one
SELECT * FROM sso_auth_attempts
WHERE state = $1 AND status = 'initiated'
ORDER BY initiated_at DESC
LIMIT 1;

-- name: ListSSOAuthAttemptsByProvider :many
SELECT * FROM sso_auth_attempts
WHERE provider_id = $1
ORDER BY initiated_at DESC
LIMIT $2 OFFSET $3;

-- name: ListSSOAuthAttemptsByTenant :many
SELECT * FROM sso_auth_attempts
WHERE tenant_id = $1
ORDER BY initiated_at DESC
LIMIT $2 OFFSET $3;

-- SSO Sessions

-- name: CreateSSOSession :one
INSERT INTO sso_sessions (
    tenant_id,
    provider_id,
    user_id,
    session_index,
    name_id,
    id_token_hint,
    expires_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7
) RETURNING *;

-- name: GetActiveSSOSessions :many
SELECT * FROM sso_sessions
WHERE user_id = $1
  AND terminated_at IS NULL
  AND (expires_at IS NULL OR expires_at > NOW())
ORDER BY created_at DESC;

-- name: TerminateSSOSession :exec
UPDATE sso_sessions
SET terminated_at = NOW()
WHERE id = $1;

-- name: TerminateAllUserSSOSessions :exec
UPDATE sso_sessions
SET terminated_at = NOW()
WHERE user_id = $1
  AND terminated_at IS NULL;

-- name: GetSSOSessionByIndex :one
SELECT * FROM sso_sessions
WHERE provider_id = $1
  AND session_index = $2
  AND terminated_at IS NULL
LIMIT 1;
