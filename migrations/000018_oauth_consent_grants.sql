-- +goose Up
-- +goose StatementBegin

-- OAuth 2.0 Consent Grants (persisted user approvals to skip re-consent)
CREATE TABLE oauth_consent_grants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id VARCHAR(64) NOT NULL,
    scopes TEXT[] NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    UNIQUE (user_id, client_id) -- one active grant per user+client
);

CREATE INDEX idx_oauth_consent_grants_user ON oauth_consent_grants(user_id, client_id) WHERE revoked_at IS NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS oauth_consent_grants;
-- +goose StatementEnd
