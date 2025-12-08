-- +goose Up
-- Add auth_method and metadata columns to refresh_tokens for session tracking
ALTER TABLE refresh_tokens
    ADD COLUMN auth_method VARCHAR(32) DEFAULT 'password',
    ADD COLUMN sso_provider_id UUID REFERENCES sso_providers(id) ON DELETE SET NULL,
    ADD COLUMN metadata JSONB DEFAULT '{}';

-- Add index for querying by auth method
CREATE INDEX idx_refresh_tokens_auth_method ON refresh_tokens(auth_method);

-- +goose Down
DROP INDEX IF EXISTS idx_refresh_tokens_auth_method;
ALTER TABLE refresh_tokens
    DROP COLUMN IF EXISTS metadata,
    DROP COLUMN IF EXISTS sso_provider_id,
    DROP COLUMN IF EXISTS auth_method;
