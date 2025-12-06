-- +goose Up
-- +goose StatementBegin

-- SSO Portal Tokens: used to grant temporary SSO configuration access to IdP admins
CREATE TABLE sso_portal_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    sso_provider_id UUID NULL REFERENCES sso_providers(id) ON DELETE CASCADE,
    provider_slug   TEXT NOT NULL,

    token_hash      TEXT NOT NULL UNIQUE,
    intent          TEXT NOT NULL DEFAULT 'sso',

    created_by      UUID NOT NULL REFERENCES users(id),

    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ NULL,
    max_uses        INT NOT NULL DEFAULT 0,  -- 0 = unlimited until expiry
    use_count       INT NOT NULL DEFAULT 0,
    last_used_at    TIMESTAMPTZ NULL,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sso_portal_tokens_lookup
  ON sso_portal_tokens (tenant_id, provider_slug, expires_at);

CREATE INDEX idx_sso_portal_tokens_token_hash
  ON sso_portal_tokens (token_hash);

CREATE INDEX idx_sso_portal_tokens_not_expired
  ON sso_portal_tokens (expires_at)
  WHERE revoked_at IS NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_sso_portal_tokens_not_expired;
DROP INDEX IF EXISTS idx_sso_portal_tokens_token_hash;
DROP INDEX IF EXISTS idx_sso_portal_tokens_lookup;
DROP TABLE IF EXISTS sso_portal_tokens;

-- +goose StatementEnd
