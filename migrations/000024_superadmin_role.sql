-- +goose Up
-- +goose StatementBegin

-- Seed superadmin permission for cross-tenant management.
INSERT INTO permissions (id, key, description)
VALUES (gen_random_uuid(), 'platform:admin', 'Full platform administration across all tenants')
ON CONFLICT (key) DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DELETE FROM permissions WHERE key = 'platform:admin';
-- +goose StatementEnd
