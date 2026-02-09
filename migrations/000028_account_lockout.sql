-- +goose Up
-- +goose StatementBegin

-- Add account lockout columns to auth_identities
ALTER TABLE auth_identities ADD COLUMN failed_attempts INT NOT NULL DEFAULT 0;
ALTER TABLE auth_identities ADD COLUMN locked_until TIMESTAMPTZ NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE auth_identities DROP COLUMN IF EXISTS locked_until;
ALTER TABLE auth_identities DROP COLUMN IF EXISTS failed_attempts;
-- +goose StatementEnd
