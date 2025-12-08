-- +goose Up
-- +goose StatementBegin

-- Add linking_policy column to sso_providers table
-- This controls how SSO accounts link to existing users with matching email
-- Default is 'verified_email' which is the safest balance between security and UX
ALTER TABLE sso_providers
    ADD COLUMN IF NOT EXISTS linking_policy VARCHAR(20) DEFAULT 'verified_email'
    CHECK (linking_policy IN ('never', 'verified_email', 'always'));

COMMENT ON COLUMN sso_providers.linking_policy IS 
    'Account linking policy: never (no linking), verified_email (link if both emails verified), always (always link - less secure)';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE sso_providers
    DROP COLUMN IF EXISTS linking_policy;

-- +goose StatementEnd
