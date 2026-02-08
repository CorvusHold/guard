-- +goose Up
-- +goose StatementBegin

-- Add fingerprint_hash column to refresh_tokens for session binding.
ALTER TABLE refresh_tokens ADD COLUMN fingerprint_hash TEXT;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS fingerprint_hash;
-- +goose StatementEnd
