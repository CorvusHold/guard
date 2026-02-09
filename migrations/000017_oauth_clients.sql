-- +goose Up
-- +goose StatementBegin

-- OAuth 2.0 Client Registry (per-tenant)
CREATE TABLE oauth_clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id VARCHAR(64) NOT NULL UNIQUE,
    client_secret_hash VARCHAR(255),
    client_type VARCHAR(20) NOT NULL DEFAULT 'confidential',
    name VARCHAR(255) NOT NULL,
    redirect_uris TEXT[] NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT '{openid,profile,email}',
    grant_types TEXT[] NOT NULL DEFAULT '{authorization_code,refresh_token}',
    logo_uri TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (client_type IN ('confidential', 'public'))
);

CREATE INDEX idx_oauth_clients_tenant ON oauth_clients(tenant_id);
CREATE INDEX idx_oauth_clients_client_id ON oauth_clients(client_id) WHERE is_active = TRUE;

-- OAuth 2.0 Authorization Codes (short-lived, single-use)
CREATE TABLE oauth_authorization_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(64) NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    code_hash VARCHAR(255) NOT NULL UNIQUE,
    redirect_uri TEXT NOT NULL,
    scopes TEXT[] NOT NULL,
    nonce TEXT,
    code_challenge TEXT,
    code_challenge_method VARCHAR(10),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_oauth_codes_hash ON oauth_authorization_codes(code_hash) WHERE consumed_at IS NULL;
CREATE INDEX idx_oauth_codes_expires ON oauth_authorization_codes(expires_at);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS oauth_authorization_codes;
DROP TABLE IF EXISTS oauth_clients;
-- +goose StatementEnd
