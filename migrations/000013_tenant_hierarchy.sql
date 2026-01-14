-- +goose Up
-- +goose StatementBegin

-- Add parent_tenant_id for hierarchical tenant support
ALTER TABLE tenants ADD COLUMN parent_tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL;

-- Index for efficient child tenant lookups
CREATE INDEX IF NOT EXISTS idx_tenants_parent ON tenants(parent_tenant_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_tenants_parent;
ALTER TABLE tenants DROP COLUMN IF EXISTS parent_tenant_id;
-- +goose StatementEnd
