-- +goose Up
-- +goose StatementBegin

-- Signing key versions for JWT key rotation.
-- Supports per-tenant keys (tenant_id NULL = global).
CREATE TABLE IF NOT EXISTS signing_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    algorithm TEXT NOT NULL DEFAULT 'ES256',
    key_pem TEXT NOT NULL,
    kid TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at TIMESTAMPTZ
);

CREATE INDEX idx_signing_keys_tenant_active ON signing_keys(tenant_id, active);
CREATE UNIQUE INDEX idx_signing_keys_kid ON signing_keys(kid);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS signing_keys;
-- +goose StatementEnd
