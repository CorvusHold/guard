-- +goose Up
-- +goose StatementBegin

-- Application registry: first-class entities grouping OAuth clients + API keys.
CREATE TABLE IF NOT EXISTS applications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    logo_uri TEXT NOT NULL DEFAULT '',
    homepage_url TEXT NOT NULL DEFAULT '',
    created_by UUID REFERENCES users(id),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_applications_tenant ON applications(tenant_id);
CREATE UNIQUE INDEX idx_applications_tenant_name ON applications(tenant_id, name);

-- Link API keys to applications (optional FK)
ALTER TABLE api_keys ADD COLUMN application_id UUID REFERENCES applications(id) ON DELETE SET NULL;
CREATE INDEX idx_api_keys_application ON api_keys(application_id);

-- Link OAuth clients to applications (optional FK)
ALTER TABLE oauth_clients ADD COLUMN application_id UUID REFERENCES applications(id) ON DELETE SET NULL;
CREATE INDEX idx_oauth_clients_application ON oauth_clients(application_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS application_id;
ALTER TABLE api_keys DROP COLUMN IF EXISTS application_id;
DROP TABLE IF EXISTS applications;
-- +goose StatementEnd
