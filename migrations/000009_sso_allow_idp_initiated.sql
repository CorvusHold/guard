-- +goose Up
-- +goose StatementBegin

-- Add allow_idp_initiated column to sso_providers table
-- This allows IdP-initiated SSO flows (e.g., Azure AD "Test" button)
-- Default is FALSE for security (SP-initiated is more secure)
ALTER TABLE sso_providers
    ADD COLUMN IF NOT EXISTS allow_idp_initiated BOOLEAN DEFAULT FALSE;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE sso_providers
    DROP COLUMN IF EXISTS allow_idp_initiated;

-- +goose StatementEnd
