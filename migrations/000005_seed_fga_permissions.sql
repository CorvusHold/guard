-- +goose Up
-- +goose StatementBegin
-- Seed additional permissions used by FGA integration tests
INSERT INTO permissions (key, description)
VALUES
  ('docs:read', 'Read access to documents'),
  ('files:read', 'Read access to files'),
  ('reports:read', 'Read access to reports')
ON CONFLICT (key) DO UPDATE SET updated_at = now();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DELETE FROM permissions WHERE key IN ('docs:read','files:read','reports:read');
-- +goose StatementEnd
