-- +goose Up
-- +goose StatementBegin

-- User invitations table for inviting users to join a tenant or create a new tenant
CREATE TABLE IF NOT EXISTS invitations (
    id UUID PRIMARY KEY,
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,  -- NULL if inviting to create a new tenant
    email TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    role TEXT,  -- Optional role to assign upon acceptance (e.g., 'admin', 'member')
    invited_by UUID REFERENCES users(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'pending',  -- 'pending', 'accepted', 'expired', 'revoked'
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (token_hash)
);

-- Index for looking up invitations by email within a tenant
CREATE INDEX IF NOT EXISTS idx_invitations_tenant_email ON invitations(tenant_id, email);
-- Index for looking up pending invitations by email (for new tenant invites)
CREATE INDEX IF NOT EXISTS idx_invitations_email_status ON invitations(email, status);
-- Index for expiration cleanup
CREATE INDEX IF NOT EXISTS idx_invitations_expires ON invitations(expires_at) WHERE status = 'pending';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_invitations_expires;
DROP INDEX IF EXISTS idx_invitations_email_status;
DROP INDEX IF EXISTS idx_invitations_tenant_email;
DROP TABLE IF EXISTS invitations;
-- +goose StatementEnd
