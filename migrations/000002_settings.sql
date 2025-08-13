-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS app_settings (
    id UUID PRIMARY KEY,
    tenant_id UUID NULL REFERENCES tenants(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    is_secret BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (key, tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_app_settings_tenant ON app_settings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_app_settings_key ON app_settings(key);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS app_settings;
-- +goose StatementEnd
