-- +goose Up
-- +goose StatementBegin

-- Add last_used_at to refresh_tokens for session idle timeout tracking
ALTER TABLE refresh_tokens ADD COLUMN last_used_at TIMESTAMPTZ NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS last_used_at;
-- +goose StatementEnd
