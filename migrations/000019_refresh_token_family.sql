-- +goose Up
-- +goose StatementBegin

-- Add family_id for refresh token reuse detection.
-- All tokens in a rotation chain share the same family_id.
-- When a revoked token is reused, the entire family is revoked.
ALTER TABLE refresh_tokens ADD COLUMN family_id UUID;

-- Backfill: each existing token becomes its own family root
UPDATE refresh_tokens SET family_id = id WHERE family_id IS NULL;

ALTER TABLE refresh_tokens ALTER COLUMN family_id SET NOT NULL;

CREATE INDEX idx_refresh_tokens_family ON refresh_tokens(family_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_refresh_tokens_family;
ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS family_id;
-- +goose StatementEnd
