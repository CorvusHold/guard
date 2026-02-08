-- +goose Up
-- +goose StatementBegin

-- Fix: consent grant unique constraint must include tenant_id for multi-tenant isolation.
-- Previously UNIQUE(user_id, client_id) allowed cross-tenant conflicts.
ALTER TABLE oauth_consent_grants DROP CONSTRAINT IF EXISTS oauth_consent_grants_user_id_client_id_key;
ALTER TABLE oauth_consent_grants ADD CONSTRAINT oauth_consent_grants_user_tenant_client_key UNIQUE (user_id, client_id, tenant_id);

-- Recreate partial index to match new constraint
DROP INDEX IF EXISTS idx_oauth_consent_grants_user;
CREATE INDEX idx_oauth_consent_grants_user ON oauth_consent_grants(user_id, client_id, tenant_id) WHERE revoked_at IS NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE oauth_consent_grants DROP CONSTRAINT IF EXISTS oauth_consent_grants_user_tenant_client_key;
ALTER TABLE oauth_consent_grants ADD CONSTRAINT oauth_consent_grants_user_id_client_id_key UNIQUE (user_id, client_id);
DROP INDEX IF EXISTS idx_oauth_consent_grants_user;
CREATE INDEX idx_oauth_consent_grants_user ON oauth_consent_grants(user_id, client_id) WHERE revoked_at IS NULL;
-- +goose StatementEnd
