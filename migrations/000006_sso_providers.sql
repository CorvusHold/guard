-- +goose Up
-- +goose StatementBegin

-- Drop old simple sso_providers table if it exists (from migration 000001)
DROP TABLE IF EXISTS sso_identities CASCADE;
DROP TABLE IF EXISTS sso_providers CASCADE;

-- Shared trigger helper for maintaining updated_at columns
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- SSO Provider Configuration (multi-tenant, multi-provider)
CREATE TABLE sso_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Provider identity
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) NOT NULL,
    provider_type VARCHAR(50) NOT NULL,

    -- OIDC Configuration
    issuer TEXT,
    authorization_endpoint TEXT,
    token_endpoint TEXT,
    userinfo_endpoint TEXT,
    jwks_uri TEXT,

    -- OAuth 2.0 Credentials
    client_id TEXT,
    client_secret TEXT,

    -- OIDC Specifics
    scopes TEXT[] DEFAULT ARRAY['openid', 'profile', 'email'],
    response_type VARCHAR(50) DEFAULT 'code',
    response_mode VARCHAR(50),

    -- SAML Configuration
    entity_id TEXT,
    acs_url TEXT,
    slo_url TEXT,
    idp_metadata_url TEXT,
    idp_metadata_xml TEXT,
    idp_entity_id TEXT,
    idp_sso_url TEXT,
    idp_slo_url TEXT,
    idp_certificate TEXT,

    -- SAML SP Configuration
    sp_certificate TEXT,
    sp_private_key TEXT,
    sp_certificate_expires_at TIMESTAMPTZ,

    -- SAML Options
    want_assertions_signed BOOLEAN DEFAULT TRUE,
    want_response_signed BOOLEAN DEFAULT FALSE,
    sign_requests BOOLEAN DEFAULT FALSE,
    force_authn BOOLEAN DEFAULT FALSE,

    -- Attribute Mapping (JSON for flexibility)
    attribute_mapping JSONB DEFAULT '{
        "email": ["email", "mail", "emailAddress"],
        "first_name": ["firstName", "givenName", "given_name"],
        "last_name": ["lastName", "surname", "sn", "family_name"],
        "display_name": ["displayName", "name", "cn"]
    }'::jsonb,

    -- Provider Options
    enabled BOOLEAN DEFAULT TRUE,
    allow_signup BOOLEAN DEFAULT TRUE,
    trust_email_verified BOOLEAN DEFAULT TRUE,

    -- Domain-based routing
    domains TEXT[],

    -- Metadata
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES users(id),
    updated_by UUID REFERENCES users(id),

    -- Constraints
    UNIQUE(tenant_id, slug),
    CHECK (provider_type IN ('oidc', 'saml', 'oauth2', 'workos', 'dev')),
    CHECK (
        (provider_type = 'oidc' AND issuer IS NOT NULL AND client_id IS NOT NULL) OR
        (provider_type = 'saml' AND entity_id IS NOT NULL AND idp_entity_id IS NOT NULL) OR
        (provider_type IN ('oauth2', 'workos', 'dev'))
    )
);

-- Indexes for performance
CREATE INDEX idx_sso_providers_tenant ON sso_providers(tenant_id) WHERE enabled = TRUE;
CREATE INDEX idx_sso_providers_slug ON sso_providers(tenant_id, slug);
CREATE INDEX idx_sso_providers_domains ON sso_providers USING GIN(domains) WHERE enabled = TRUE;
CREATE INDEX idx_sso_providers_type ON sso_providers(provider_type) WHERE enabled = TRUE;

-- Update trigger for updated_at
CREATE TRIGGER update_sso_providers_updated_at
    BEFORE UPDATE ON sso_providers
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- SSO Authentication Attempts (Audit Trail)
CREATE TABLE sso_auth_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider_id UUID NOT NULL REFERENCES sso_providers(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id),

    -- Attempt details
    state VARCHAR(255),
    status VARCHAR(50) NOT NULL,
    error_code VARCHAR(100),
    error_message TEXT,

    -- Request metadata
    ip_address INET,
    user_agent TEXT,

    -- Timing
    initiated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,

    -- Constraints
    CHECK (status IN ('initiated', 'success', 'failed'))
);

CREATE INDEX idx_sso_auth_attempts_tenant ON sso_auth_attempts(tenant_id, initiated_at DESC);
CREATE INDEX idx_sso_auth_attempts_provider ON sso_auth_attempts(provider_id, initiated_at DESC);
CREATE INDEX idx_sso_auth_attempts_user ON sso_auth_attempts(user_id, initiated_at DESC) WHERE user_id IS NOT NULL;
CREATE INDEX idx_sso_auth_attempts_state ON sso_auth_attempts(state) WHERE status = 'initiated';

-- SSO Sessions (for Single Logout)
CREATE TABLE sso_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider_id UUID NOT NULL REFERENCES sso_providers(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Session identifiers
    session_index VARCHAR(255),
    name_id VARCHAR(255),

    -- Tokens (for OIDC RP-initiated logout)
    id_token_hint TEXT,

    -- Session lifecycle
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    terminated_at TIMESTAMPTZ,

    -- Constraints
    UNIQUE(provider_id, session_index)
);

CREATE INDEX idx_sso_sessions_user ON sso_sessions(user_id) WHERE terminated_at IS NULL;
CREATE INDEX idx_sso_sessions_expiry ON sso_sessions(expires_at) WHERE terminated_at IS NULL;

-- Extend auth_identities to support SSO providers
ALTER TABLE auth_identities
    ADD COLUMN IF NOT EXISTS sso_provider_id UUID REFERENCES sso_providers(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS sso_subject TEXT,
    ADD COLUMN IF NOT EXISTS sso_attributes JSONB;

CREATE INDEX idx_auth_identities_sso_provider ON auth_identities(sso_provider_id, sso_subject) WHERE sso_provider_id IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Drop indexes
DROP INDEX IF EXISTS idx_auth_identities_sso_provider;

-- Revert auth_identities changes
ALTER TABLE auth_identities
    DROP COLUMN IF EXISTS sso_attributes,
    DROP COLUMN IF EXISTS sso_subject,
    DROP COLUMN IF EXISTS sso_provider_id;

-- Drop tables in reverse order
DROP TABLE IF EXISTS sso_sessions;
DROP TABLE IF EXISTS sso_auth_attempts;
DROP TABLE IF EXISTS sso_providers;

DROP FUNCTION IF EXISTS update_updated_at_column();

-- +goose StatementEnd
