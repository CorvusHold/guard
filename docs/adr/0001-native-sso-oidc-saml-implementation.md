# ADR-0001: Native SSO/OIDC/SAML Implementation

**Status**: Proposed
**Date**: 2025-11-11
**Authors**: Guard Team
**Deciders**: Engineering Team, Product Team

---

## Context and Problem Statement

Guard currently integrates with WorkOS for enterprise SSO support, providing seamless integration with SAML, OIDC, and OAuth 2.0 providers. However, this comes at a significant cost:

- **€150/month per tenant** (€1,800/year per tenant)
- **Vendor lock-in**: Dependency on external service availability and pricing
- **Limited customization**: Cannot modify SSO flows or add custom providers
- **Data sovereignty**: Third-party processes authentication data

As an **open-source authentication platform**, these constraints are problematic:
1. High costs limit adoption for small teams and open-source deployments
2. Closed-source dependency conflicts with open-source ethos
3. Self-hosted deployments still require external service

**Key Question**: Should we implement native OIDC and SAML 2.0 support to replace WorkOS?

---

## Decision Drivers

### Business Drivers
- **Cost Reduction**: Eliminate €1,800/year per tenant operational cost
- **Open Source Alignment**: Remove proprietary dependencies
- **Competitive Position**: Match competitors like Better Auth with native SSO
- **Market Expansion**: Enable enterprise features for self-hosted deployments

### Technical Drivers
- **Control**: Full ownership of authentication flows
- **Customization**: Add custom providers and protocols
- **Performance**: Eliminate external API latency
- **Security**: Keep authentication data on-premises
- **Reliability**: Remove external service dependency

### Risk Factors
- **Development Effort**: 6-8 weeks initial implementation
- **Maintenance Burden**: Ongoing security updates and protocol compliance
- **Complexity**: SAML is notoriously difficult to implement correctly
- **Testing**: Requires integration testing with multiple IdPs
- **Support**: Becomes first-line support for SSO configuration issues

---

## Decision Outcome

**Chosen Option**: ✅ **Implement Native OIDC and SAML 2.0 Support**

We will build native SSO capabilities using established Go libraries while maintaining the existing WorkOS integration during a transition period.

### Implementation Strategy
1. **Phase 1 (Weeks 1-3)**: OIDC implementation using `go-oidc`
2. **Phase 2 (Weeks 4-5)**: SAML 2.0 implementation using `crewjam/saml`
3. **Phase 3 (Weeks 6-8)**: Management UI, testing, and migration tooling
4. **Phase 4 (Months 3-6)**: Gradual WorkOS deprecation with feature flag

### Success Criteria
- ✅ Support top 5 IdPs (Google Workspace, Microsoft Entra ID, Okta, OneLogin, Auth0)
- ✅ Feature parity with WorkOS for core SSO flows
- ✅ 99.9% uptime for authentication flows
- ✅ <500ms p95 latency for authentication requests
- ✅ Zero-downtime migration for existing WorkOS tenants
- ✅ Comprehensive documentation for IdP configuration

---

## Considered Options

### Option 1: Keep WorkOS (Status Quo)
**Pros:**
- ✅ No development effort required
- ✅ Battle-tested and reliable
- ✅ Includes admin portal and audit logs
- ✅ Handles IdP complexity

**Cons:**
- ❌ €150/month per tenant ongoing cost
- ❌ Vendor lock-in
- ❌ Limited customization
- ❌ Conflicts with open-source mission
- ❌ External dependency and latency

**Decision:** ❌ Rejected - High cost and vendor lock-in unacceptable for open-source project

---

### Option 2: Use Auth0 or Okta
**Pros:**
- ✅ Enterprise-grade infrastructure
- ✅ Extensive protocol support
- ✅ Good developer experience

**Cons:**
- ❌ Still vendor lock-in (replaces one vendor with another)
- ❌ Similar or higher pricing (€100-200/month per tenant)
- ❌ Doesn't solve core problem

**Decision:** ❌ Rejected - Doesn't address vendor dependency issue

---

### Option 3: Use SuperTokens or Keycloak
**Pros:**
- ✅ Open-source solutions
- ✅ Self-hostable
- ✅ Native OIDC/SAML support

**Cons:**
- ❌ Still external dependency (another service to deploy)
- ❌ Different architecture (Java for Keycloak, Node.js for SuperTokens)
- ❌ Less control than native implementation
- ❌ Additional operational complexity

**Decision:** ❌ Rejected - Adds complexity rather than solving it

---

### Option 4: Native OIDC Only (No SAML)
**Pros:**
- ✅ Simpler implementation (OIDC is easier than SAML)
- ✅ Covers 70% of modern enterprise use cases
- ✅ Lower maintenance burden

**Cons:**
- ❌ Excludes legacy enterprises that require SAML
- ❌ Incomplete enterprise offering
- ❌ Competitive disadvantage

**Decision:** ❌ Rejected - SAML required for "Enterprise-Ready" positioning

---

### Option 5: Native OIDC + SAML (Chosen)
**Pros:**
- ✅ Complete enterprise SSO support
- ✅ Zero ongoing vendor costs
- ✅ Full control and customization
- ✅ Open-source aligned
- ✅ Battle-tested libraries available (go-oidc, crewjam/saml)
- ✅ Performance improvement (no external API calls)
- ✅ Data sovereignty

**Cons:**
- ❌ 6-8 weeks development effort
- ❌ Ongoing maintenance responsibility
- ❌ SAML complexity

**Risk Mitigation:**
- Use established libraries (`coreos/go-oidc`, `crewjam/saml`)
- Incremental rollout with feature flags
- Maintain WorkOS support during transition
- Comprehensive integration testing with sandbox IdPs
- Security audits before GA release

**Decision:** ✅ **Accepted** - Benefits outweigh costs, especially for open-source positioning

---

## Technical Design

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         Guard API (Echo)                         │
├─────────────────────────────────────────────────────────────────┤
│  HTTP Controllers                                                │
│  • /v1/auth/sso/{provider}/start     (OAuth start)              │
│  • /v1/auth/sso/{provider}/callback  (OAuth callback)           │
│  • /v1/tenants/{id}/sso-providers    (CRUD API)                 │
│  • /v1/auth/sso/saml/metadata        (SAML SP metadata)         │
│  • /v1/auth/sso/saml/acs             (SAML assertion consumer)  │
├─────────────────────────────────────────────────────────────────┤
│  Service Layer                                                   │
│  • SSOService: Orchestrates authentication flows                │
│  • ProviderRegistry: Factory for provider instances             │
│  • ProviderConfigService: Manages provider configuration        │
├─────────────────────────────────────────────────────────────────┤
│  Provider Interface (Pluggable Architecture)                    │
│  • OIDCProvider: OpenID Connect implementation                  │
│  • SAMLProvider: SAML 2.0 SP implementation                     │
│  • WorkOSProvider: Legacy WorkOS (migration period)             │
│  • DevProvider: Local testing adapter                           │
├─────────────────────────────────────────────────────────────────┤
│  Repository Layer (sqlc)                                         │
│  • SSOProviderRepository: Provider configuration persistence    │
│  • UserRepository: User and identity management                 │
├─────────────────────────────────────────────────────────────────┤
│  Infrastructure                                                  │
│  • PostgreSQL: Provider configs, user identities                │
│  • Redis: OAuth state, SAML assertions (temporary)              │
│  • go-oidc: OIDC client library (CoreOS)                        │
│  • crewjam/saml: SAML SP library                                │
└─────────────────────────────────────────────────────────────────┘
```

### Database Schema

#### New Tables

```sql
-- SSO Provider Configuration (multi-tenant, multi-provider)
CREATE TABLE sso_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Provider identity
    name VARCHAR(255) NOT NULL,                    -- "Google Workspace", "Azure AD", etc.
    slug VARCHAR(255) NOT NULL,                    -- "google", "azure", "okta-prod"
    provider_type VARCHAR(50) NOT NULL,            -- "oidc", "saml", "oauth2", "workos", "dev"

    -- OIDC Configuration
    issuer TEXT,                                    -- OIDC issuer URL
    authorization_endpoint TEXT,                    -- Override discovery
    token_endpoint TEXT,                            -- Override discovery
    userinfo_endpoint TEXT,                         -- Override discovery
    jwks_uri TEXT,                                  -- Override discovery

    -- OAuth 2.0 Credentials
    client_id TEXT,
    client_secret TEXT,                             -- Encrypted at application layer

    -- OIDC Specifics
    scopes TEXT[] DEFAULT ARRAY['openid', 'profile', 'email'],
    response_type VARCHAR(50) DEFAULT 'code',       -- 'code', 'id_token', 'code id_token'
    response_mode VARCHAR(50),                      -- 'query', 'fragment', 'form_post'

    -- SAML Configuration
    entity_id TEXT,                                 -- SP Entity ID
    acs_url TEXT,                                   -- Assertion Consumer Service URL
    slo_url TEXT,                                   -- Single Logout URL
    idp_metadata_url TEXT,                          -- IdP metadata URL (for refresh)
    idp_metadata_xml TEXT,                          -- Cached IdP metadata
    idp_entity_id TEXT,                             -- IdP Entity ID
    idp_sso_url TEXT,                               -- IdP SSO URL
    idp_slo_url TEXT,                               -- IdP SLO URL
    idp_certificate TEXT,                           -- IdP X.509 cert (PEM)

    -- SAML SP Configuration
    sp_certificate TEXT,                            -- SP X.509 cert (PEM)
    sp_private_key TEXT,                            -- SP private key (encrypted)
    sp_certificate_expires_at TIMESTAMPTZ,          -- For renewal alerts

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
    allow_signup BOOLEAN DEFAULT TRUE,              -- Allow new user creation
    trust_email_verified BOOLEAN DEFAULT TRUE,      -- Trust IdP email verification

    -- Domain-based routing
    domains TEXT[],                                 -- Auto-route users from these domains

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

-- Indexes
CREATE INDEX idx_sso_providers_tenant ON sso_providers(tenant_id) WHERE enabled = TRUE;
CREATE INDEX idx_sso_providers_slug ON sso_providers(tenant_id, slug);
CREATE INDEX idx_sso_providers_domains ON sso_providers USING GIN(domains) WHERE enabled = TRUE;
CREATE INDEX idx_sso_providers_type ON sso_providers(provider_type) WHERE enabled = TRUE;

-- Update trigger
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
    state VARCHAR(255),                             -- OAuth state or SAML request ID
    status VARCHAR(50) NOT NULL,                    -- 'initiated', 'success', 'failed'
    error_code VARCHAR(100),                        -- Error classification
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
CREATE INDEX idx_sso_auth_attempts_user ON sso_auth_attempts(user_id, initiated_at DESC);
CREATE INDEX idx_sso_auth_attempts_state ON sso_auth_attempts(state) WHERE status = 'initiated';
```

#### Modified Tables

```sql
-- Extend existing auth_identities table to support SSO providers
ALTER TABLE auth_identities
    ADD COLUMN IF NOT EXISTS sso_provider_id UUID REFERENCES sso_providers(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS sso_subject TEXT,     -- IdP's unique user identifier
    ADD COLUMN IF NOT EXISTS sso_attributes JSONB; -- Additional attributes from IdP

CREATE INDEX idx_auth_identities_sso_provider ON auth_identities(sso_provider_id, sso_subject);

-- Optional: Track SSO sessions for SLO (Single Logout)
CREATE TABLE sso_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider_id UUID NOT NULL REFERENCES sso_providers(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Session identifiers
    session_index VARCHAR(255),                     -- SAML SessionIndex
    name_id VARCHAR(255),                           -- SAML NameID

    -- Tokens (for OIDC RP-initiated logout)
    id_token_hint TEXT,                             -- OIDC ID token for logout

    -- Session lifecycle
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    terminated_at TIMESTAMPTZ,

    -- Constraints
    UNIQUE(provider_id, session_index)
);

CREATE INDEX idx_sso_sessions_user ON sso_sessions(user_id) WHERE terminated_at IS NULL;
CREATE INDEX idx_sso_sessions_expiry ON sso_sessions(expires_at) WHERE terminated_at IS NULL;
```

### Migration Files

**Migration: `000010_sso_providers.sql`**

```sql
-- +goose Up
-- +goose StatementBegin

-- SSO Provider Configuration
CREATE TABLE sso_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) NOT NULL,
    provider_type VARCHAR(50) NOT NULL,
    issuer TEXT,
    authorization_endpoint TEXT,
    token_endpoint TEXT,
    userinfo_endpoint TEXT,
    jwks_uri TEXT,
    client_id TEXT,
    client_secret TEXT,
    scopes TEXT[] DEFAULT ARRAY['openid', 'profile', 'email'],
    response_type VARCHAR(50) DEFAULT 'code',
    response_mode VARCHAR(50),
    entity_id TEXT,
    acs_url TEXT,
    slo_url TEXT,
    idp_metadata_url TEXT,
    idp_metadata_xml TEXT,
    idp_entity_id TEXT,
    idp_sso_url TEXT,
    idp_slo_url TEXT,
    idp_certificate TEXT,
    sp_certificate TEXT,
    sp_private_key TEXT,
    sp_certificate_expires_at TIMESTAMPTZ,
    want_assertions_signed BOOLEAN DEFAULT TRUE,
    want_response_signed BOOLEAN DEFAULT FALSE,
    sign_requests BOOLEAN DEFAULT FALSE,
    force_authn BOOLEAN DEFAULT FALSE,
    attribute_mapping JSONB DEFAULT '{
        "email": ["email", "mail", "emailAddress"],
        "first_name": ["firstName", "givenName", "given_name"],
        "last_name": ["lastName", "surname", "sn", "family_name"],
        "display_name": ["displayName", "name", "cn"]
    }'::jsonb,
    enabled BOOLEAN DEFAULT TRUE,
    allow_signup BOOLEAN DEFAULT TRUE,
    trust_email_verified BOOLEAN DEFAULT TRUE,
    domains TEXT[],
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES users(id),
    updated_by UUID REFERENCES users(id),
    UNIQUE(tenant_id, slug),
    CHECK (provider_type IN ('oidc', 'saml', 'oauth2', 'workos', 'dev'))
);

CREATE INDEX idx_sso_providers_tenant ON sso_providers(tenant_id) WHERE enabled = TRUE;
CREATE INDEX idx_sso_providers_slug ON sso_providers(tenant_id, slug);
CREATE INDEX idx_sso_providers_domains ON sso_providers USING GIN(domains) WHERE enabled = TRUE;
CREATE INDEX idx_sso_providers_type ON sso_providers(provider_type) WHERE enabled = TRUE;

CREATE TRIGGER update_sso_providers_updated_at
    BEFORE UPDATE ON sso_providers
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- SSO Authentication Attempts
CREATE TABLE sso_auth_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider_id UUID NOT NULL REFERENCES sso_providers(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id),
    state VARCHAR(255),
    status VARCHAR(50) NOT NULL,
    error_code VARCHAR(100),
    error_message TEXT,
    ip_address INET,
    user_agent TEXT,
    initiated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    CHECK (status IN ('initiated', 'success', 'failed'))
);

CREATE INDEX idx_sso_auth_attempts_tenant ON sso_auth_attempts(tenant_id, initiated_at DESC);
CREATE INDEX idx_sso_auth_attempts_provider ON sso_auth_attempts(provider_id, initiated_at DESC);
CREATE INDEX idx_sso_auth_attempts_user ON sso_auth_attempts(user_id, initiated_at DESC);
CREATE INDEX idx_sso_auth_attempts_state ON sso_auth_attempts(state) WHERE status = 'initiated';

-- SSO Sessions (for Single Logout)
CREATE TABLE sso_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider_id UUID NOT NULL REFERENCES sso_providers(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_index VARCHAR(255),
    name_id VARCHAR(255),
    id_token_hint TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    terminated_at TIMESTAMPTZ,
    UNIQUE(provider_id, session_index)
);

CREATE INDEX idx_sso_sessions_user ON sso_sessions(user_id) WHERE terminated_at IS NULL;
CREATE INDEX idx_sso_sessions_expiry ON sso_sessions(expires_at) WHERE terminated_at IS NULL;

-- Extend auth_identities
ALTER TABLE auth_identities
    ADD COLUMN IF NOT EXISTS sso_provider_id UUID REFERENCES sso_providers(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS sso_subject TEXT,
    ADD COLUMN IF NOT EXISTS sso_attributes JSONB;

CREATE INDEX idx_auth_identities_sso_provider ON auth_identities(sso_provider_id, sso_subject);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_auth_identities_sso_provider;
ALTER TABLE auth_identities
    DROP COLUMN IF EXISTS sso_attributes,
    DROP COLUMN IF EXISTS sso_subject,
    DROP COLUMN IF EXISTS sso_provider_id;

DROP TABLE IF EXISTS sso_sessions;
DROP TABLE IF EXISTS sso_auth_attempts;
DROP TABLE IF EXISTS sso_providers;

-- +goose StatementEnd
```

### sqlc Queries

**File: `internal/db/queries/sso_providers.sql`**

```sql
-- name: CreateSSOProvider :one
INSERT INTO sso_providers (
    id, tenant_id, name, slug, provider_type,
    issuer, client_id, client_secret, scopes,
    attribute_mapping, enabled, allow_signup, trust_email_verified,
    domains, created_by
) VALUES (
    $1, $2, $3, $4, $5,
    $6, $7, $8, $9,
    $10, $11, $12, $13,
    $14, $15
) RETURNING *;

-- name: GetSSOProvider :one
SELECT * FROM sso_providers
WHERE id = $1 AND tenant_id = $2;

-- name: GetSSOProviderBySlug :one
SELECT * FROM sso_providers
WHERE tenant_id = $1 AND slug = $2;

-- name: ListSSOProviders :many
SELECT * FROM sso_providers
WHERE tenant_id = $1
  AND ($2::text = '' OR name ILIKE '%' || $2::text || '%')
  AND ($3::boolean IS NULL OR enabled = $3)
  AND ($4::text IS NULL OR provider_type = $4)
ORDER BY created_at DESC
LIMIT $5 OFFSET $6;

-- name: UpdateSSOProvider :exec
UPDATE sso_providers
SET name = COALESCE($3, name),
    issuer = COALESCE($4, issuer),
    client_id = COALESCE($5, client_id),
    client_secret = CASE WHEN $6::text != '' THEN $6 ELSE client_secret END,
    scopes = COALESCE($7, scopes),
    attribute_mapping = COALESCE($8, attribute_mapping),
    enabled = COALESCE($9, enabled),
    allow_signup = COALESCE($10, allow_signup),
    trust_email_verified = COALESCE($11, trust_email_verified),
    domains = COALESCE($12, domains),
    updated_by = $13,
    updated_at = NOW()
WHERE id = $1 AND tenant_id = $2;

-- name: DeleteSSOProvider :exec
DELETE FROM sso_providers
WHERE id = $1 AND tenant_id = $2;

-- name: FindSSOProviderByDomain :one
SELECT * FROM sso_providers
WHERE tenant_id = $1
  AND enabled = TRUE
  AND $2 = ANY(domains)
ORDER BY array_length(domains, 1) ASC
LIMIT 1;

-- name: CreateSSOAuthAttempt :one
INSERT INTO sso_auth_attempts (
    tenant_id, provider_id, state, status, ip_address, user_agent
) VALUES (
    $1, $2, $3, $4, $5, $6
) RETURNING *;

-- name: UpdateSSOAuthAttempt :exec
UPDATE sso_auth_attempts
SET status = $2,
    user_id = $3,
    error_code = $4,
    error_message = $5,
    completed_at = NOW()
WHERE id = $1;

-- name: GetSSOAuthAttemptByState :one
SELECT * FROM sso_auth_attempts
WHERE state = $1 AND status = 'initiated'
ORDER BY initiated_at DESC
LIMIT 1;

-- name: CreateSSOSession :one
INSERT INTO sso_sessions (
    tenant_id, provider_id, user_id, session_index, name_id, id_token_hint, expires_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7
) RETURNING *;

-- name: GetActiveSSOSessions :many
SELECT * FROM sso_sessions
WHERE user_id = $1 AND terminated_at IS NULL AND expires_at > NOW()
ORDER BY created_at DESC;

-- name: TerminateSSOSession :exec
UPDATE sso_sessions
SET terminated_at = NOW()
WHERE id = $1;
```

---

## Provider Interface Design

**File: `internal/auth/sso/domain/types.go`**

```go
package domain

import (
    "context"
    "time"

    "github.com/google/uuid"
)

// SSOProvider defines the interface all SSO providers must implement
type SSOProvider interface {
    // Start initiates the SSO flow and returns the authorization URL
    Start(ctx context.Context, opts StartOptions) (*StartResult, error)

    // Callback handles the IdP response and returns user profile
    Callback(ctx context.Context, req CallbackRequest) (*Profile, error)

    // GetMetadata returns provider-specific metadata (for SAML SP metadata, OIDC config)
    GetMetadata(ctx context.Context) (*Metadata, error)

    // ValidateConfig checks if the provider configuration is valid
    ValidateConfig() error

    // Type returns the provider type
    Type() ProviderType
}

type ProviderType string

const (
    ProviderTypeOIDC    ProviderType = "oidc"
    ProviderTypeSAML    ProviderType = "saml"
    ProviderTypeOAuth2  ProviderType = "oauth2"
    ProviderTypeWorkOS  ProviderType = "workos"
    ProviderTypeDev     ProviderType = "dev"
)

// StartOptions contains parameters for initiating SSO flow
type StartOptions struct {
    TenantID     uuid.UUID
    ProviderID   uuid.UUID
    RedirectURI  string
    State        string
    Nonce        string // For OIDC
    RelayState   string // For SAML
}

// StartResult contains the authorization URL and metadata
type StartResult struct {
    AuthorizationURL string
    State            string
    Nonce            string // Stored in Redis for verification
}

// CallbackRequest contains IdP response data
type CallbackRequest struct {
    // OAuth/OIDC
    Code  string
    State string

    // SAML
    SAMLResponse string
    RelayState   string

    // Context
    TenantID   uuid.UUID
    ProviderID uuid.UUID
}

// Profile represents the user profile extracted from IdP
type Profile struct {
    Subject       string                 // Unique user ID from IdP
    Email         string                 `json:"email"`
    EmailVerified bool                   `json:"email_verified"`
    FirstName     string                 `json:"first_name"`
    LastName      string                 `json:"last_name"`
    DisplayName   string                 `json:"display_name"`
    Attributes    map[string]interface{} `json:"attributes"` // Additional claims

    // Session info (for SAML SLO)
    SessionIndex string `json:"session_index,omitempty"`
    NameID       string `json:"name_id,omitempty"`

    // Token (for OIDC logout)
    IDToken string `json:"-"`
}

// Metadata represents provider-specific metadata
type Metadata struct {
    Type         ProviderType
    EntityID     string // SAML SP Entity ID
    ACSURL       string // SAML Assertion Consumer Service URL
    SLOURL       string // SAML Single Logout URL
    MetadataXML  string // SAML SP Metadata XML
    Issuer       string // OIDC Issuer
    RedirectURIs []string
}

// Config represents provider configuration loaded from database
type Config struct {
    ID         uuid.UUID
    TenantID   uuid.UUID
    Name       string
    Slug       string
    Type       ProviderType
    Enabled    bool
    AllowSignup bool
    TrustEmailVerified bool
    Domains    []string

    // OIDC Configuration
    Issuer                string
    AuthorizationEndpoint string
    TokenEndpoint         string
    UserinfoEndpoint      string
    JWKSURI               string
    ClientID              string
    ClientSecret          string
    Scopes                []string
    ResponseType          string
    ResponseMode          string

    // SAML Configuration
    EntityID          string
    ACSURL            string
    SLOURL            string
    IdPMetadataURL    string
    IdPMetadataXML    string
    IdPEntityID       string
    IdPSSOURL         string
    IdPSLOURL         string
    IdPCertificate    string
    SPCertificate     string
    SPPrivateKey      string
    SPCertExpiry      time.Time
    WantAssertionsSigned bool
    WantResponseSigned   bool
    SignRequests         bool
    ForceAuthn           bool

    // Attribute Mapping
    AttributeMapping map[string][]string

    CreatedAt time.Time
    UpdatedAt time.Time
}
```

---

## OIDC Provider Implementation

**File: `internal/auth/sso/provider/oidc.go`**

```go
package provider

import (
    "context"
    "crypto/rand"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "time"

    "github.com/coreos/go-oidc/v3/oidc"
    "github.com/google/uuid"
    "golang.org/x/oauth2"

    "github.com/CorvusHold/guard/internal/auth/sso/domain"
)

// OIDCProvider implements SSO for OpenID Connect providers
type OIDCProvider struct {
    config   *domain.Config
    provider *oidc.Provider
    oauth2   *oauth2.Config
    verifier *oidc.IDTokenVerifier
}

// NewOIDCProvider creates a new OIDC provider instance
func NewOIDCProvider(ctx context.Context, config *domain.Config) (*OIDCProvider, error) {
    if config.Type != domain.ProviderTypeOIDC {
        return nil, fmt.Errorf("invalid provider type: %s", config.Type)
    }

    // Discover OIDC configuration from issuer
    provider, err := oidc.NewProvider(ctx, config.Issuer)
    if err != nil {
        return nil, fmt.Errorf("OIDC discovery failed: %w", err)
    }

    // Build OAuth2 configuration
    oauth2Config := &oauth2.Config{
        ClientID:     config.ClientID,
        ClientSecret: config.ClientSecret,
        RedirectURL:  config.ACSURL, // Reuse ACSURL field for OAuth redirect
        Endpoint:     provider.Endpoint(),
        Scopes:       config.Scopes,
    }

    // Override endpoints if specified (manual configuration)
    if config.AuthorizationEndpoint != "" {
        oauth2Config.Endpoint.AuthURL = config.AuthorizationEndpoint
    }
    if config.TokenEndpoint != "" {
        oauth2Config.Endpoint.TokenURL = config.TokenEndpoint
    }

    // Create ID token verifier
    verifier := provider.Verifier(&oidc.Config{
        ClientID: config.ClientID,
    })

    return &OIDCProvider{
        config:   config,
        provider: provider,
        oauth2:   oauth2Config,
        verifier: verifier,
    }, nil
}

// Start initiates the OIDC authorization flow
func (p *OIDCProvider) Start(ctx context.Context, opts domain.StartOptions) (*domain.StartResult, error) {
    // Generate secure nonce
    nonce, err := generateNonce()
    if err != nil {
        return nil, fmt.Errorf("nonce generation failed: %w", err)
    }

    // Build authorization URL with PKCE and nonce
    authURL := p.oauth2.AuthCodeURL(
        opts.State,
        oauth2.AccessTypeOnline,
        oidc.Nonce(nonce),
    )

    return &domain.StartResult{
        AuthorizationURL: authURL,
        State:            opts.State,
        Nonce:            nonce,
    }, nil
}

// Callback handles the OIDC callback and extracts user profile
func (p *OIDCProvider) Callback(ctx context.Context, req domain.CallbackRequest) (*domain.Profile, error) {
    // Exchange authorization code for token
    oauth2Token, err := p.oauth2.Exchange(ctx, req.Code)
    if err != nil {
        return nil, fmt.Errorf("token exchange failed: %w", err)
    }

    // Extract ID token
    rawIDToken, ok := oauth2Token.Extra("id_token").(string)
    if !ok {
        return nil, fmt.Errorf("no id_token in token response")
    }

    // Verify ID token signature and claims
    idToken, err := p.verifier.Verify(ctx, rawIDToken)
    if err != nil {
        return nil, fmt.Errorf("ID token verification failed: %w", err)
    }

    // Parse claims
    var claims struct {
        Subject       string `json:"sub"`
        Email         string `json:"email"`
        EmailVerified bool   `json:"email_verified"`
        GivenName     string `json:"given_name"`
        FamilyName    string `json:"family_name"`
        Name          string `json:"name"`
        Picture       string `json:"picture"`
        Nonce         string `json:"nonce"`
    }

    if err := idToken.Claims(&claims); err != nil {
        return nil, fmt.Errorf("failed to parse claims: %w", err)
    }

    // Extract all claims for attribute mapping
    var allClaims map[string]interface{}
    if err := idToken.Claims(&allClaims); err != nil {
        return nil, fmt.Errorf("failed to parse all claims: %w", err)
    }

    // Apply attribute mapping
    profile := &domain.Profile{
        Subject:       claims.Subject,
        Email:         claims.Email,
        EmailVerified: claims.EmailVerified,
        FirstName:     claims.GivenName,
        LastName:      claims.FamilyName,
        DisplayName:   claims.Name,
        Attributes:    allClaims,
        IDToken:       rawIDToken,
    }

    // Apply custom attribute mapping if configured
    if p.config.AttributeMapping != nil {
        applyAttributeMapping(profile, allClaims, p.config.AttributeMapping)
    }

    // Override email verification if trust_email_verified is true
    if p.config.TrustEmailVerified {
        profile.EmailVerified = true
    }

    return profile, nil
}

// GetMetadata returns OIDC provider metadata
func (p *OIDCProvider) GetMetadata(ctx context.Context) (*domain.Metadata, error) {
    return &domain.Metadata{
        Type:         domain.ProviderTypeOIDC,
        Issuer:       p.config.Issuer,
        RedirectURIs: []string{p.oauth2.RedirectURL},
    }, nil
}

// ValidateConfig checks if OIDC configuration is valid
func (p *OIDCProvider) ValidateConfig() error {
    if p.config.Issuer == "" {
        return fmt.Errorf("issuer is required")
    }
    if p.config.ClientID == "" {
        return fmt.Errorf("client_id is required")
    }
    if p.config.ClientSecret == "" {
        return fmt.Errorf("client_secret is required")
    }
    return nil
}

// Type returns the provider type
func (p *OIDCProvider) Type() domain.ProviderType {
    return domain.ProviderTypeOIDC
}

// Helper: Generate cryptographically secure nonce
func generateNonce() (string, error) {
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil {
        return "", err
    }
    return base64.RawURLEncoding.EncodeToString(b), nil
}

// Helper: Apply custom attribute mapping
func applyAttributeMapping(profile *domain.Profile, claims map[string]interface{}, mapping map[string][]string) {
    // Map email
    if emailKeys, ok := mapping["email"]; ok {
        for _, key := range emailKeys {
            if val, exists := claims[key]; exists {
                if email, ok := val.(string); ok && email != "" {
                    profile.Email = email
                    break
                }
            }
        }
    }

    // Map first_name
    if fnKeys, ok := mapping["first_name"]; ok {
        for _, key := range fnKeys {
            if val, exists := claims[key]; exists {
                if fn, ok := val.(string); ok && fn != "" {
                    profile.FirstName = fn
                    break
                }
            }
        }
    }

    // Map last_name
    if lnKeys, ok := mapping["last_name"]; ok {
        for _, key := range lnKeys {
            if val, exists := claims[key]; exists {
                if ln, ok := val.(string); ok && ln != "" {
                    profile.LastName = ln
                    break
                }
            }
        }
    }

    // Map display_name
    if dnKeys, ok := mapping["display_name"]; ok {
        for _, key := range dnKeys {
            if val, exists := claims[key]; exists {
                if dn, ok := val.(string); ok && dn != "" {
                    profile.DisplayName = dn
                    break
                }
            }
        }
    }
}
```

---

## SAML Provider Implementation

**File: `internal/auth/sso/provider/saml.go`**

```go
package provider

import (
    "context"
    "crypto/rsa"
    "crypto/tls"
    "crypto/x509"
    "encoding/pem"
    "encoding/xml"
    "fmt"
    "net/http"
    "net/url"

    "github.com/crewjam/saml"
    "github.com/crewjam/saml/samlsp"

    "github.com/CorvusHold/guard/internal/auth/sso/domain"
)

// SAMLProvider implements SSO for SAML 2.0 providers
type SAMLProvider struct {
    config *domain.Config
    sp     *saml.ServiceProvider
}

// NewSAMLProvider creates a new SAML provider instance
func NewSAMLProvider(ctx context.Context, config *domain.Config) (*SAMLProvider, error) {
    if config.Type != domain.ProviderTypeSAML {
        return nil, fmt.Errorf("invalid provider type: %s", config.Type)
    }

    // Parse SP certificate and private key
    cert, err := parseCertificate(config.SPCertificate)
    if err != nil {
        return nil, fmt.Errorf("failed to parse SP certificate: %w", err)
    }

    key, err := parsePrivateKey(config.SPPrivateKey)
    if err != nil {
        return nil, fmt.Errorf("failed to parse SP private key: %w", err)
    }

    // Build SP metadata URL
    metadataURL, err := url.Parse(config.EntityID)
    if err != nil {
        return nil, fmt.Errorf("invalid entity_id: %w", err)
    }

    // Build ACS URL
    acsURL, err := url.Parse(config.ACSURL)
    if err != nil {
        return nil, fmt.Errorf("invalid acs_url: %w", err)
    }

    // Parse IdP metadata
    var idpMetadata *saml.EntityDescriptor
    if config.IdPMetadataXML != "" {
        idpMetadata = &saml.EntityDescriptor{}
        if err := xml.Unmarshal([]byte(config.IdPMetadataXML), idpMetadata); err != nil {
            return nil, fmt.Errorf("failed to parse IdP metadata: %w", err)
        }
    } else if config.IdPMetadataURL != "" {
        // Fetch IdP metadata from URL
        resp, err := http.Get(config.IdPMetadataURL)
        if err != nil {
            return nil, fmt.Errorf("failed to fetch IdP metadata: %w", err)
        }
        defer resp.Body.Close()

        idpMetadata = &saml.EntityDescriptor{}
        if err := xml.NewDecoder(resp.Body).Decode(idpMetadata); err != nil {
            return nil, fmt.Errorf("failed to decode IdP metadata: %w", err)
        }
    } else {
        return nil, fmt.Errorf("either idp_metadata_url or idp_metadata_xml is required")
    }

    // Create Service Provider
    sp := &saml.ServiceProvider{
        Key:         key,
        Certificate: cert,
        MetadataURL: *metadataURL,
        AcsURL:      *acsURL,
        IDPMetadata: idpMetadata,
    }

    // Configure SAML options
    if config.SLOURL != "" {
        sloURL, _ := url.Parse(config.SLOURL)
        sp.SloURL = *sloURL
    }

    sp.AuthnNameIDFormat = saml.EmailAddressNameIDFormat // Default to email
    sp.ForceAuthn = &config.ForceAuthn

    return &SAMLProvider{
        config: config,
        sp:     sp,
    }, nil
}

// Start initiates the SAML authentication flow
func (p *SAMLProvider) Start(ctx context.Context, opts domain.StartOptions) (*domain.StartResult, error) {
    // Build authentication request
    binding := saml.HTTPRedirectBinding
    bindingLocation := p.sp.GetSSOBindingLocation(binding)

    req, err := p.sp.MakeAuthenticationRequest(bindingLocation, binding, saml.HTTPPostBinding)
    if err != nil {
        return nil, fmt.Errorf("failed to create SAML AuthnRequest: %w", err)
    }

    // Sign request if configured
    if p.config.SignRequests {
        if err := req.SignRequest(p.sp.Key, p.sp.Certificate); err != nil {
            return nil, fmt.Errorf("failed to sign SAML request: %w", err)
        }
    }

    // Build redirect URL
    redirectURL, err := req.Redirect(opts.RelayState, p.sp)
    if err != nil {
        return nil, fmt.Errorf("failed to build SAML redirect URL: %w", err)
    }

    return &domain.StartResult{
        AuthorizationURL: redirectURL.String(),
        State:            req.ID, // Use SAML request ID as state
        Nonce:            "",
    }, nil
}

// Callback handles SAML response and extracts user profile
func (p *SAMLProvider) Callback(ctx context.Context, req domain.CallbackRequest) (*domain.Profile, error) {
    // Parse SAML response
    assertionInfo, err := p.sp.ParseResponse(
        &http.Request{
            Method: "POST",
            Header: http.Header{"Content-Type": []string{"application/x-www-form-urlencoded"}},
            PostForm: url.Values{
                "SAMLResponse": []string{req.SAMLResponse},
                "RelayState":   []string{req.RelayState},
            },
        },
        []string{req.State}, // Possible request IDs
    )
    if err != nil {
        return nil, fmt.Errorf("SAML response parse failed: %w", err)
    }

    // Extract subject (NameID)
    subject := assertionInfo.NameID

    // Extract attributes
    attributes := make(map[string]interface{})
    for _, stmt := range assertionInfo.Assertions[0].AttributeStatements {
        for _, attr := range stmt.Attributes {
            if len(attr.Values) == 1 {
                attributes[attr.Name] = attr.Values[0].Value
            } else {
                values := make([]string, len(attr.Values))
                for i, v := range attr.Values {
                    values[i] = v.Value
                }
                attributes[attr.Name] = values
            }
        }
    }

    // Build profile
    profile := &domain.Profile{
        Subject:       subject,
        EmailVerified: p.config.TrustEmailVerified,
        Attributes:    attributes,
    }

    // Apply attribute mapping
    if p.config.AttributeMapping != nil {
        applyAttributeMapping(profile, attributes, p.config.AttributeMapping)
    }

    // Extract session info for SLO
    if len(assertionInfo.Assertions) > 0 {
        if authnStmt := assertionInfo.Assertions[0].AuthnStatements; len(authnStmt) > 0 {
            profile.SessionIndex = authnStmt[0].SessionIndex
        }
        profile.NameID = subject
    }

    return profile, nil
}

// GetMetadata returns SAML SP metadata
func (p *SAMLProvider) GetMetadata(ctx context.Context) (*domain.Metadata, error) {
    metadata := p.sp.Metadata()
    xmlBytes, err := xml.MarshalIndent(metadata, "", "  ")
    if err != nil {
        return nil, fmt.Errorf("failed to marshal SP metadata: %w", err)
    }

    return &domain.Metadata{
        Type:        domain.ProviderTypeSAML,
        EntityID:    p.config.EntityID,
        ACSURL:      p.config.ACSURL,
        SLOURL:      p.config.SLOURL,
        MetadataXML: string(xmlBytes),
    }, nil
}

// ValidateConfig checks if SAML configuration is valid
func (p *SAMLProvider) ValidateConfig() error {
    if p.config.EntityID == "" {
        return fmt.Errorf("entity_id is required")
    }
    if p.config.ACSURL == "" {
        return fmt.Errorf("acs_url is required")
    }
    if p.config.IdPEntityID == "" && p.config.IdPMetadataXML == "" && p.config.IdPMetadataURL == "" {
        return fmt.Errorf("IdP metadata is required (idp_metadata_url or idp_metadata_xml)")
    }
    if p.config.SPCertificate == "" {
        return fmt.Errorf("sp_certificate is required")
    }
    if p.config.SPPrivateKey == "" {
        return fmt.Errorf("sp_private_key is required")
    }
    return nil
}

// Type returns the provider type
func (p *SAMLProvider) Type() domain.ProviderType {
    return domain.ProviderTypeSAML
}

// Helper: Parse X.509 certificate from PEM
func parseCertificate(pemData string) (*x509.Certificate, error) {
    block, _ := pem.Decode([]byte(pemData))
    if block == nil {
        return nil, fmt.Errorf("failed to decode PEM block")
    }
    return x509.ParseCertificate(block.Bytes)
}

// Helper: Parse RSA private key from PEM
func parsePrivateKey(pemData string) (*rsa.PrivateKey, error) {
    block, _ := pem.Decode([]byte(pemData))
    if block == nil {
        return nil, fmt.Errorf("failed to decode PEM block")
    }

    key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
    if err != nil {
        // Try PKCS1 format
        return x509.ParsePKCS1PrivateKey(block.Bytes)
    }

    rsaKey, ok := key.(*rsa.PrivateKey)
    if !ok {
        return nil, fmt.Errorf("not an RSA private key")
    }

    return rsaKey, nil
}
```

---

## Provider Registry

**File: `internal/auth/sso/service/registry.go`**

```go
package service

import (
    "context"
    "fmt"
    "sync"

    "github.com/CorvusHold/guard/internal/auth/sso/domain"
    "github.com/CorvusHold/guard/internal/auth/sso/provider"
)

// ProviderFactory is a function that creates a provider instance
type ProviderFactory func(ctx context.Context, config *domain.Config) (domain.SSOProvider, error)

// ProviderRegistry manages provider types and instances
type ProviderRegistry struct {
    factories map[domain.ProviderType]ProviderFactory
    mu        sync.RWMutex
}

// NewProviderRegistry creates a new provider registry with built-in providers
func NewProviderRegistry() *ProviderRegistry {
    r := &ProviderRegistry{
        factories: make(map[domain.ProviderType]ProviderFactory),
    }

    // Register built-in providers
    r.Register(domain.ProviderTypeOIDC, func(ctx context.Context, config *domain.Config) (domain.SSOProvider, error) {
        return provider.NewOIDCProvider(ctx, config)
    })

    r.Register(domain.ProviderTypeSAML, func(ctx context.Context, config *domain.Config) (domain.SSOProvider, error) {
        return provider.NewSAMLProvider(ctx, config)
    })

    // Keep legacy providers during migration
    // r.Register(domain.ProviderTypeWorkOS, func(ctx context.Context, config *domain.Config) (domain.SSOProvider, error) {
    //     return provider.NewWorkOSProvider(ctx, config)
    // })

    r.Register(domain.ProviderTypeDev, func(ctx context.Context, config *domain.Config) (domain.SSOProvider, error) {
        return provider.NewDevProvider(ctx, config)
    })

    return r
}

// Register adds a provider factory to the registry
func (r *ProviderRegistry) Register(providerType domain.ProviderType, factory ProviderFactory) {
    r.mu.Lock()
    defer r.mu.Unlock()
    r.factories[providerType] = factory
}

// Create instantiates a provider from configuration
func (r *ProviderRegistry) Create(ctx context.Context, config *domain.Config) (domain.SSOProvider, error) {
    r.mu.RLock()
    factory, ok := r.factories[config.Type]
    r.mu.RUnlock()

    if !ok {
        return nil, fmt.Errorf("unsupported provider type: %s", config.Type)
    }

    provider, err := factory(ctx, config)
    if err != nil {
        return nil, fmt.Errorf("failed to create provider: %w", err)
    }

    // Validate configuration
    if err := provider.ValidateConfig(); err != nil {
        return nil, fmt.Errorf("invalid provider configuration: %w", err)
    }

    return provider, nil
}

// SupportedTypes returns all registered provider types
func (r *ProviderRegistry) SupportedTypes() []domain.ProviderType {
    r.mu.RLock()
    defer r.mu.RUnlock()

    types := make([]domain.ProviderType, 0, len(r.factories))
    for t := range r.factories {
        types = append(types, t)
    }
    return types
}
```

---

## Repository Layer

**File: `internal/auth/sso/domain/repository.go`**

```go
package domain

import (
    "context"

    "github.com/google/uuid"
    "github.com/CorvusHold/guard/internal/db/sqlc"
)

// Repository defines persistence operations for SSO providers
type Repository interface {
    // Provider CRUD
    Create(ctx context.Context, config *Config) error
    GetByID(ctx context.Context, tenantID, providerID uuid.UUID) (*Config, error)
    GetBySlug(ctx context.Context, tenantID uuid.UUID, slug string) (*Config, error)
    List(ctx context.Context, tenantID uuid.UUID, filters ListFilters) ([]*Config, int64, error)
    Update(ctx context.Context, config *Config) error
    Delete(ctx context.Context, tenantID, providerID uuid.UUID) error

    // Domain-based routing
    FindByDomain(ctx context.Context, tenantID uuid.UUID, domain string) (*Config, error)

    // Auth attempts (audit trail)
    CreateAuthAttempt(ctx context.Context, attempt *AuthAttempt) error
    GetAuthAttemptByState(ctx context.Context, state string) (*AuthAttempt, error)
    UpdateAuthAttempt(ctx context.Context, attemptID uuid.UUID, status, errorCode, errorMessage string, userID *uuid.UUID) error

    // Sessions (for SLO)
    CreateSession(ctx context.Context, session *Session) error
    GetActiveSessions(ctx context.Context, userID uuid.UUID) ([]*Session, error)
    TerminateSession(ctx context.Context, sessionID uuid.UUID) error
}

type ListFilters struct {
    Query        string
    Enabled      *bool
    ProviderType *ProviderType
    Limit        int32
    Offset       int32
}

type AuthAttempt struct {
    ID         uuid.UUID
    TenantID   uuid.UUID
    ProviderID uuid.UUID
    UserID     *uuid.UUID
    State      string
    Status     string // 'initiated', 'success', 'failed'
    ErrorCode  string
    ErrorMsg   string
    IPAddress  string
    UserAgent  string
}

type Session struct {
    ID           uuid.UUID
    TenantID     uuid.UUID
    ProviderID   uuid.UUID
    UserID       uuid.UUID
    SessionIndex string
    NameID       string
    IDTokenHint  string
    ExpiresAt    time.Time
}
```

**File: `internal/auth/sso/repository/sqlc.go`**

```go
package repository

import (
    "context"
    "encoding/json"
    "fmt"

    "github.com/google/uuid"
    "github.com/jackc/pgx/v5/pgtype"
    "github.com/jackc/pgx/v5/pgxpool"

    "github.com/CorvusHold/guard/internal/auth/sso/domain"
    "github.com/CorvusHold/guard/internal/db/sqlc"
)

type sqlcRepository struct {
    q *db.Queries
}

func New(pool *pgxpool.Pool) domain.Repository {
    return &sqlcRepository{q: db.New(pool)}
}

// Create creates a new SSO provider
func (r *sqlcRepository) Create(ctx context.Context, config *domain.Config) error {
    // Convert attribute_mapping to JSON
    attrMappingJSON, err := json.Marshal(config.AttributeMapping)
    if err != nil {
        return fmt.Errorf("failed to marshal attribute mapping: %w", err)
    }

    params := db.CreateSSOProviderParams{
        ID:                   toPgUUID(config.ID),
        TenantID:             toPgUUID(config.TenantID),
        Name:                 config.Name,
        Slug:                 config.Slug,
        ProviderType:         string(config.Type),
        Issuer:               toTextPtr(config.Issuer),
        ClientID:             toTextPtr(config.ClientID),
        ClientSecret:         toTextPtr(config.ClientSecret),
        Scopes:               config.Scopes,
        AttributeMapping:     attrMappingJSON,
        Enabled:              config.Enabled,
        AllowSignup:          config.AllowSignup,
        TrustEmailVerified:   config.TrustEmailVerified,
        Domains:              config.Domains,
        CreatedBy:            toPgUUIDPtr(nil), // Set from auth context
    }

    _, err = r.q.CreateSSOProvider(ctx, params)
    return err
}

// GetByID retrieves a provider by ID
func (r *sqlcRepository) GetByID(ctx context.Context, tenantID, providerID uuid.UUID) (*domain.Config, error) {
    row, err := r.q.GetSSOProvider(ctx, db.GetSSOProviderParams{
        ID:       toPgUUID(providerID),
        TenantID: toPgUUID(tenantID),
    })
    if err != nil {
        return nil, err
    }

    return rowToConfig(row)
}

// GetBySlug retrieves a provider by slug
func (r *sqlcRepository) GetBySlug(ctx context.Context, tenantID uuid.UUID, slug string) (*domain.Config, error) {
    row, err := r.q.GetSSOProviderBySlug(ctx, db.GetSSOProviderBySlugParams{
        TenantID: toPgUUID(tenantID),
        Slug:     slug,
    })
    if err != nil {
        return nil, err
    }

    return rowToConfig(row)
}

// FindByDomain finds a provider by email domain
func (r *sqlcRepository) FindByDomain(ctx context.Context, tenantID uuid.UUID, domain string) (*domain.Config, error) {
    row, err := r.q.FindSSOProviderByDomain(ctx, db.FindSSOProviderByDomainParams{
        TenantID: toPgUUID(tenantID),
        Domain:   domain,
    })
    if err != nil {
        return nil, err
    }

    return rowToConfig(row)
}

// Helper: Convert DB row to domain Config
func rowToConfig(row db.SsoProvider) (*domain.Config, error) {
    var attrMapping map[string][]string
    if err := json.Unmarshal(row.AttributeMapping, &attrMapping); err != nil {
        return nil, fmt.Errorf("failed to unmarshal attribute mapping: %w", err)
    }

    config := &domain.Config{
        ID:                 toUUID(row.ID),
        TenantID:           toUUID(row.TenantID),
        Name:               row.Name,
        Slug:               row.Slug,
        Type:               domain.ProviderType(row.ProviderType),
        Enabled:            row.Enabled,
        AllowSignup:        row.AllowSignup,
        TrustEmailVerified: row.TrustEmailVerified,
        Domains:            row.Domains,
        Scopes:             row.Scopes,
        AttributeMapping:   attrMapping,
        CreatedAt:          row.CreatedAt.Time,
        UpdatedAt:          row.UpdatedAt.Time,
    }

    // OIDC fields
    if row.Issuer.Valid {
        config.Issuer = row.Issuer.String
    }
    if row.ClientID.Valid {
        config.ClientID = row.ClientID.String
    }
    if row.ClientSecret.Valid {
        config.ClientSecret = row.ClientSecret.String
    }

    // SAML fields
    if row.EntityID.Valid {
        config.EntityID = row.EntityID.String
    }
    if row.AcsUrl.Valid {
        config.ACSURL = row.AcsUrl.String
    }

    return config, nil
}

// Type conversion helpers
func toPgUUID(id uuid.UUID) pgtype.UUID {
    return pgtype.UUID{Bytes: id, Valid: true}
}

func toPgUUIDPtr(id *uuid.UUID) pgtype.UUID {
    if id == nil {
        return pgtype.UUID{Valid: false}
    }
    return pgtype.UUID{Bytes: *id, Valid: true}
}

func toUUID(pg pgtype.UUID) uuid.UUID {
    return pg.Bytes
}

func toTextPtr(s string) pgtype.Text {
    if s == "" {
        return pgtype.Text{Valid: false}
    }
    return pgtype.Text{String: s, Valid: true}
}
```

---

## SSO Service

**File: `internal/auth/sso/service/service.go`**

```go
package service

import (
    "context"
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "strings"
    "time"

    "github.com/google/uuid"
    "github.com/redis/go-redis/v9"
    "github.com/rs/zerolog"

    "github.com/CorvusHold/guard/internal/auth/domain"
    "github.com/CorvusHold/guard/internal/auth/sso/ssodomain"
    "github.com/CorvusHold/guard/internal/config"
    "github.com/CorvusHold/guard/internal/events/evdomain"
)

// Service orchestrates SSO authentication flows
type Service struct {
    repo         ssodomain.Repository
    userRepo     domain.Repository
    registry     *ProviderRegistry
    redis        *redis.Client
    eventPub     evdomain.Publisher
    cfg          config.Config
    log          zerolog.Logger
}

// New creates a new SSO service
func New(
    repo ssodomain.Repository,
    userRepo domain.Repository,
    registry *ProviderRegistry,
    redisClient *redis.Client,
    eventPub evdomain.Publisher,
    cfg config.Config,
) *Service {
    return &Service{
        repo:     repo,
        userRepo: userRepo,
        registry: registry,
        redis:    redisClient,
        eventPub: eventPub,
        cfg:      cfg,
        log:      zerolog.Nop(),
    }
}

func (s *Service) SetLogger(log zerolog.Logger) {
    s.log = log
}

// Start initiates SSO authentication flow
func (s *Service) Start(ctx context.Context, tenantID uuid.UUID, providerSlug, redirectURI, ipAddress, userAgent string) (*StartResult, error) {
    s.log.Debug().
        Str("tenant_id", tenantID.String()).
        Str("provider", providerSlug).
        Msg("sso:start")

    // Load provider configuration
    providerConfig, err := s.repo.GetBySlug(ctx, tenantID, providerSlug)
    if err != nil {
        return nil, fmt.Errorf("provider not found: %w", err)
    }

    if !providerConfig.Enabled {
        return nil, fmt.Errorf("provider is disabled")
    }

    // Create provider instance
    provider, err := s.registry.Create(ctx, providerConfig)
    if err != nil {
        return nil, fmt.Errorf("failed to create provider: %w", err)
    }

    // Generate secure state
    state, err := generateSecureState()
    if err != nil {
        return nil, fmt.Errorf("state generation failed: %w", err)
    }

    // Generate nonce for OIDC
    nonce, err := generateSecureState()
    if err != nil {
        return nil, fmt.Errorf("nonce generation failed: %w", err)
    }

    // Create auth attempt (audit trail)
    attempt := &ssodomain.AuthAttempt{
        ID:         uuid.New(),
        TenantID:   tenantID,
        ProviderID: providerConfig.ID,
        State:      state,
        Status:     "initiated",
        IPAddress:  ipAddress,
        UserAgent:  userAgent,
    }

    if err := s.repo.CreateAuthAttempt(ctx, attempt); err != nil {
        s.log.Warn().Err(err).Msg("failed to create auth attempt")
    }

    // Start provider flow
    result, err := provider.Start(ctx, ssodomain.StartOptions{
        TenantID:    tenantID,
        ProviderID:  providerConfig.ID,
        RedirectURI: redirectURI,
        State:       state,
        Nonce:       nonce,
    })
    if err != nil {
        return nil, fmt.Errorf("provider start failed: %w", err)
    }

    // Store state in Redis with TTL (10 minutes)
    stateKey := fmt.Sprintf("sso:state:%s", state)
    stateData := map[string]interface{}{
        "tenant_id":   tenantID.String(),
        "provider_id": providerConfig.ID.String(),
        "nonce":       nonce,
        "attempt_id":  attempt.ID.String(),
    }

    if err := s.redis.HSet(ctx, stateKey, stateData).Err(); err != nil {
        return nil, fmt.Errorf("failed to store state: %w", err)
    }

    if err := s.redis.Expire(ctx, stateKey, 10*time.Minute).Err(); err != nil {
        s.log.Warn().Err(err).Msg("failed to set state TTL")
    }

    return &StartResult{
        AuthorizationURL: result.AuthorizationURL,
        State:            result.State,
    }, nil
}

// Callback handles SSO callback and creates/updates user
func (s *Service) Callback(ctx context.Context, tenantID uuid.UUID, providerSlug, code, state, samlResponse, ipAddress, userAgent string) (*CallbackResult, error) {
    s.log.Debug().
        Str("tenant_id", tenantID.String()).
        Str("provider", providerSlug).
        Msg("sso:callback")

    // Validate and consume state (atomic get-and-delete)
    stateKey := fmt.Sprintf("sso:state:%s", state)
    stateData, err := s.redis.HGetAll(ctx, stateKey).Result()
    if err != nil || len(stateData) == 0 {
        s.log.Warn().Str("state", state).Msg("invalid or expired state")
        return nil, fmt.Errorf("invalid or expired state")
    }

    // Delete state immediately (prevent replay)
    if err := s.redis.Del(ctx, stateKey).Err(); err != nil {
        s.log.Warn().Err(err).Msg("failed to delete state")
    }

    // Verify tenant and provider match
    if stateData["tenant_id"] != tenantID.String() {
        return nil, fmt.Errorf("tenant mismatch")
    }

    providerID, err := uuid.Parse(stateData["provider_id"])
    if err != nil {
        return nil, fmt.Errorf("invalid provider_id in state")
    }

    // Load provider configuration
    providerConfig, err := s.repo.GetByID(ctx, tenantID, providerID)
    if err != nil {
        return nil, fmt.Errorf("provider not found: %w", err)
    }

    // Create provider instance
    provider, err := s.registry.Create(ctx, providerConfig)
    if err != nil {
        return nil, fmt.Errorf("failed to create provider: %w", err)
    }

    // Handle provider callback
    profile, err := provider.Callback(ctx, ssodomain.CallbackRequest{
        Code:         code,
        State:        state,
        SAMLResponse: samlResponse,
        TenantID:     tenantID,
        ProviderID:   providerID,
    })
    if err != nil {
        // Update auth attempt with failure
        attemptID, _ := uuid.Parse(stateData["attempt_id"])
        _ = s.repo.UpdateAuthAttempt(ctx, attemptID, "failed", "callback_error", err.Error(), nil)

        // Publish event
        _ = s.eventPub.Publish(ctx, evdomain.Event{
            Type:     "auth.sso.login.failure",
            TenantID: tenantID,
            Meta:     map[string]string{"provider": providerSlug, "error": err.Error()},
            Time:     time.Now(),
        })

        return nil, fmt.Errorf("callback failed: %w", err)
    }

    // Validate email
    if profile.Email == "" {
        return nil, fmt.Errorf("email not provided by identity provider")
    }

    // Check email verification
    if !profile.EmailVerified && !providerConfig.TrustEmailVerified {
        return nil, fmt.Errorf("email not verified by identity provider")
    }

    // Find or create user
    user, err := s.userRepo.GetByEmailAndTenant(ctx, profile.Email, tenantID)
    if err != nil {
        // User doesn't exist - create if allowed
        if !providerConfig.AllowSignup {
            return nil, fmt.Errorf("signup not allowed for this provider")
        }

        userID := uuid.New()
        if err := s.userRepo.Create(ctx, userID, profile.Email, profile.FirstName, profile.LastName); err != nil {
            return nil, fmt.Errorf("failed to create user: %w", err)
        }

        if err := s.userRepo.AddUserToTenant(ctx, userID, tenantID); err != nil {
            return nil, fmt.Errorf("failed to add user to tenant: %w", err)
        }

        user, err = s.userRepo.GetByID(ctx, userID)
        if err != nil {
            return nil, fmt.Errorf("failed to retrieve created user: %w", err)
        }
    }

    // Create or update auth identity
    identityID := uuid.New()
    if err := s.userRepo.CreateAuthIdentity(ctx, identityID, user.ID, tenantID, "sso", providerSlug, profile.Subject); err != nil {
        // Identity might already exist - that's okay
        s.log.Debug().Err(err).Msg("identity already exists")
    }

    // Update auth attempt with success
    attemptID, _ := uuid.Parse(stateData["attempt_id"])
    _ = s.repo.UpdateAuthAttempt(ctx, attemptID, "success", "", "", &user.ID)

    // Publish success event
    _ = s.eventPub.Publish(ctx, evdomain.Event{
        Type:     "auth.sso.login.success",
        TenantID: tenantID,
        UserID:   user.ID,
        Meta:     map[string]string{"provider": providerSlug, "email": profile.Email},
        Time:     time.Now(),
    })

    return &CallbackResult{
        UserID:   user.ID,
        TenantID: tenantID,
        Email:    profile.Email,
    }, nil
}

// Helper: Generate cryptographically secure state
func generateSecureState() (string, error) {
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil {
        return "", err
    }
    return base64.RawURLEncoding.EncodeToString(b), nil
}

type StartResult struct {
    AuthorizationURL string
    State            string
}

type CallbackResult struct {
    UserID   uuid.UUID
    TenantID uuid.UUID
    Email    string
}
```

---

## HTTP Controllers

**File: `internal/auth/sso/controller/http.go`**

```go
package controller

import (
    "net/http"

    "github.com/labstack/echo/v4"
    "github.com/google/uuid"

    "github.com/CorvusHold/guard/internal/auth/sso/service"
    authmw "github.com/CorvusHold/guard/internal/auth/middleware"
)

type Controller struct {
    svc *service.Service
}

func New(svc *service.Service) *Controller {
    return &Controller{svc: svc}
}

// Register mounts SSO routes
func (c *Controller) Register(e *echo.Echo) {
    // Public SSO endpoints
    ssoGroup := e.Group("/v1/auth/sso")
    ssoGroup.GET("/:provider/start", c.start)
    ssoGroup.GET("/:provider/callback", c.callback)
    ssoGroup.POST("/:provider/callback", c.callback) // For SAML POST binding

    // Admin endpoints (JWT required)
    adminGroup := e.Group("/v1/tenants/:tenant_id/sso-providers", authmw.NewJWT())
    adminGroup.POST("", c.createProvider)
    adminGroup.GET("", c.listProviders)
    adminGroup.GET("/:id", c.getProvider)
    adminGroup.PUT("/:id", c.updateProvider)
    adminGroup.DELETE("/:id", c.deleteProvider)
}

// @Summary Start SSO Flow
// @Tags SSO
// @Param provider path string true "Provider slug"
// @Param tenant_id query string true "Tenant ID"
// @Param redirect_uri query string false "Redirect URI"
// @Success 302
// @Router /v1/auth/sso/{provider}/start [get]
func (c *Controller) start(ctx echo.Context) error {
    providerSlug := ctx.Param("provider")
    tenantIDStr := ctx.QueryParam("tenant_id")
    redirectURI := ctx.QueryParam("redirect_uri")

    tenantID, err := uuid.Parse(tenantIDStr)
    if err != nil {
        return ctx.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
    }

    result, err := c.svc.Start(
        ctx.Request().Context(),
        tenantID,
        providerSlug,
        redirectURI,
        ctx.RealIP(),
        ctx.Request().UserAgent(),
    )
    if err != nil {
        return ctx.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
    }

    // Redirect to IdP
    return ctx.Redirect(http.StatusFound, result.AuthorizationURL)
}

// @Summary SSO Callback
// @Tags SSO
// @Param provider path string true "Provider slug"
// @Param code query string false "OAuth code"
// @Param state query string true "State"
// @Param SAMLResponse formData string false "SAML response"
// @Success 200 {object} map[string]interface{}
// @Router /v1/auth/sso/{provider}/callback [get]
func (c *Controller) callback(ctx echo.Context) error {
    providerSlug := ctx.Param("provider")

    // OAuth/OIDC parameters
    code := ctx.QueryParam("code")
    state := ctx.QueryParam("state")

    // SAML parameters
    samlResponse := ctx.FormValue("SAMLResponse")

    // Extract tenant_id from state (stored in Redis during start)
    // For now, require it as query param
    tenantIDStr := ctx.QueryParam("tenant_id")
    tenantID, err := uuid.Parse(tenantIDStr)
    if err != nil {
        return ctx.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
    }

    result, err := c.svc.Callback(
        ctx.Request().Context(),
        tenantID,
        providerSlug,
        code,
        state,
        samlResponse,
        ctx.RealIP(),
        ctx.Request().UserAgent(),
    )
    if err != nil {
        return ctx.JSON(http.StatusUnauthorized, map[string]string{"error": err.Error()})
    }

    // Return tokens (reuse existing token generation logic)
    return ctx.JSON(http.StatusOK, map[string]interface{}{
        "user_id":   result.UserID,
        "tenant_id": result.TenantID,
        "email":     result.Email,
    })
}

// Additional CRUD handlers for provider management...
func (c *Controller) createProvider(ctx echo.Context) error {
    // Implementation...
    return nil
}

func (c *Controller) listProviders(ctx echo.Context) error {
    // Implementation...
    return nil
}

func (c *Controller) getProvider(ctx echo.Context) error {
    // Implementation...
    return nil
}

func (c *Controller) updateProvider(ctx echo.Context) error {
    // Implementation...
    return nil
}

func (c *Controller) deleteProvider(ctx echo.Context) error {
    // Implementation...
    return nil
}
```

---

## Testing Strategy

### Unit Tests

**File: `internal/auth/sso/provider/oidc_test.go`**

```go
package provider_test

import (
    "context"
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/CorvusHold/guard/internal/auth/sso/domain"
    "github.com/CorvusHold/guard/internal/auth/sso/provider"
)

func TestOIDCProvider_Start(t *testing.T) {
    config := &domain.Config{
        Type:         domain.ProviderTypeOIDC,
        Issuer:       "https://accounts.google.com",
        ClientID:     "test-client-id",
        ClientSecret: "test-client-secret",
        Scopes:       []string{"openid", "profile", "email"},
    }

    p, err := provider.NewOIDCProvider(context.Background(), config)
    assert.NoError(t, err)

    result, err := p.Start(context.Background(), domain.StartOptions{
        State:       "test-state",
        RedirectURI: "http://localhost:8080/callback",
    })

    assert.NoError(t, err)
    assert.NotEmpty(t, result.AuthorizationURL)
    assert.Contains(t, result.AuthorizationURL, "accounts.google.com")
    assert.Contains(t, result.AuthorizationURL, "test-client-id")
}

func TestOIDCProvider_ValidateConfig(t *testing.T) {
    tests := []struct {
        name    string
        config  *domain.Config
        wantErr bool
    }{
        {
            name: "valid config",
            config: &domain.Config{
                Type:         domain.ProviderTypeOIDC,
                Issuer:       "https://example.com",
                ClientID:     "client-id",
                ClientSecret: "client-secret",
            },
            wantErr: false,
        },
        {
            name: "missing issuer",
            config: &domain.Config{
                Type:         domain.ProviderTypeOIDC,
                ClientID:     "client-id",
                ClientSecret: "client-secret",
            },
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            p, _ := provider.NewOIDCProvider(context.Background(), tt.config)
            err := p.ValidateConfig()
            if tt.wantErr {
                assert.Error(t, err)
            } else {
                assert.NoError(t, err)
            }
        })
    }
}
```

### Integration Tests

**File: `internal/auth/sso/integration_test.go`**

```go
package sso_test

import (
    "context"
    "testing"

    "github.com/google/uuid"
    "github.com/stretchr/testify/assert"
    "github.com/jarcoal/httpmock"

    "github.com/CorvusHold/guard/internal/auth/sso/service"
    "github.com/CorvusHold/guard/internal/auth/sso/domain"
)

func TestSSOService_StartOIDC(t *testing.T) {
    // Setup test database and Redis
    ctx := context.Background()
    repo := setupTestRepo(t)
    redis := setupTestRedis(t)
    registry := service.NewProviderRegistry()

    svc := service.New(repo, nil, registry, redis, nil, testConfig())

    // Create test provider
    providerID := uuid.New()
    tenantID := uuid.New()

    err := repo.Create(ctx, &domain.Config{
        ID:           providerID,
        TenantID:     tenantID,
        Name:         "Google",
        Slug:         "google",
        Type:         domain.ProviderTypeOIDC,
        Issuer:       "https://accounts.google.com",
        ClientID:     "test-client",
        ClientSecret: "test-secret",
        Enabled:      true,
    })
    assert.NoError(t, err)

    // Mock OIDC discovery
    httpmock.Activate()
    defer httpmock.DeactivateAndReset()

    httpmock.RegisterResponder("GET", "https://accounts.google.com/.well-known/openid-configuration",
        httpmock.NewJsonResponderOrPanic(200, map[string]interface{}{
            "issuer":                 "https://accounts.google.com",
            "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_endpoint":         "https://oauth2.googleapis.com/token",
            "jwks_uri":               "https://www.googleapis.com/oauth2/v3/certs",
        }))

    // Test Start
    result, err := svc.Start(ctx, tenantID, "google", "http://localhost/callback", "127.0.0.1", "test-agent")
    assert.NoError(t, err)
    assert.NotEmpty(t, result.AuthorizationURL)
    assert.NotEmpty(t, result.State)

    // Verify state stored in Redis
    stateKey := "sso:state:" + result.State
    exists, _ := redis.Exists(ctx, stateKey).Result()
    assert.Equal(t, int64(1), exists)
}
```

---

## Implementation Timeline

### Week 1: Foundation & OIDC Core
- ✅ Create database schema and migrations
- ✅ Generate sqlc queries
- ✅ Implement provider interface and registry
- ✅ Implement OIDC provider (go-oidc)
- ✅ Implement repository layer
- ✅ Write unit tests for OIDC provider

### Week 2: OIDC Service & Controllers
- ✅ Implement SSO service with Start/Callback
- ✅ Implement HTTP controllers
- ✅ Add Redis state management
- ✅ Implement auth attempt tracking
- ✅ Write integration tests
- ✅ Test with Google, Microsoft, Okta sandboxes

### Week 3: OIDC Polish & Testing
- ✅ Error handling and validation
- ✅ Attribute mapping
- ✅ Domain-based routing
- ✅ Rate limiting
- ✅ Comprehensive integration tests
- ✅ Security audit (OWASP review)

### Week 4: SAML Implementation
- ✅ Implement SAML provider (crewjam/saml)
- ✅ Certificate generation/management
- ✅ Metadata endpoints (SP metadata, ACS, SLO)
- ✅ SAML request/response handling
- ✅ Write unit tests for SAML provider

### Week 5: SAML Integration & Testing
- ✅ SAML integration tests
- ✅ Test with Azure AD, Okta SAML
- ✅ Assertion parsing and validation
- ✅ Single Logout (SLO) implementation
- ✅ Certificate expiry monitoring

### Week 6: Management UI (Optional Phase 1)
- ✅ Provider list/create/edit UI
- ✅ Test connection functionality
- ✅ Import IdP metadata
- ✅ Domain configuration
- ✅ Certificate upload/generation

### Week 7: Migration & Documentation
- ✅ WorkOS migration tooling
- ✅ Feature flag implementation
- ✅ Migration guide for existing tenants
- ✅ IdP-specific setup guides (Google, Microsoft, Okta, etc.)
- ✅ API documentation (Swagger)

### Week 8: Launch Preparation
- ✅ Security penetration testing
- ✅ Load testing
- ✅ Monitoring and alerting
- ✅ Production deployment plan
- ✅ Rollback procedures
- ✅ Beta launch with opt-in tenants

---

## Consequences

### Positive

✅ **Cost Elimination**: €150/month per tenant → €0 (infrastructure only)
✅ **Full Control**: Complete ownership of authentication flows
✅ **Customization**: Add custom providers, protocols, and workflows
✅ **Open Source Alignment**: No proprietary dependencies
✅ **Performance**: Eliminate external API latency
✅ **Data Sovereignty**: All authentication data on-premises
✅ **Competitive Advantage**: Enterprise features in open-source offering
✅ **Community Value**: Enable self-hosted enterprise deployments

### Negative

❌ **Development Cost**: 6-8 weeks engineering effort
❌ **Maintenance**: Ongoing security updates and protocol compliance
❌ **Support Burden**: First-line support for SSO configuration
❌ **Testing Complexity**: Need sandbox accounts for multiple IdPs
❌ **Certificate Management**: SSL/TLS cert rotation and monitoring
❌ **Feature Gap**: No built-in directory sync (SCIM) initially

### Risks & Mitigation

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| **Security vulnerability** | Critical | Medium | Use battle-tested libraries, security audits, penetration testing |
| **IdP compatibility issues** | High | Medium | Comprehensive integration testing with top 5 IdPs |
| **Migration failures** | High | Low | Parallel WorkOS support, gradual rollout, rollback plan |
| **Performance degradation** | Medium | Low | Load testing, monitoring, Redis optimization |
| **SAML complexity** | High | High | Use crewjam/saml library, comprehensive testing, expert review |
| **Certificate expiry** | High | Medium | Automated monitoring, renewal alerts, self-service renewal |
| **Support tickets spike** | Medium | High | Comprehensive documentation, IdP-specific guides, troubleshooting tools |

---

## References

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [SAML 2.0 Technical Overview](http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0.html)
- [go-oidc Library](https://github.com/coreos/go-oidc)
- [crewjam/saml Library](https://github.com/crewjam/saml)
- [Better Auth SSO Plugin](https://www.better-auth.com/docs/plugins/sso)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

---

## Appendix A: Provider Configuration Examples

### Google Workspace (OIDC)

```json
{
  "name": "Google Workspace",
  "slug": "google",
  "provider_type": "oidc",
  "issuer": "https://accounts.google.com",
  "client_id": "YOUR_CLIENT_ID.apps.googleusercontent.com",
  "client_secret": "YOUR_CLIENT_SECRET",
  "scopes": ["openid", "profile", "email"],
  "domains": ["example.com"],
  "allow_signup": true,
  "trust_email_verified": true
}
```

### Microsoft Entra ID (OIDC)

```json
{
  "name": "Microsoft Entra ID",
  "slug": "microsoft",
  "provider_type": "oidc",
  "issuer": "https://login.microsoftonline.com/{tenant_id}/v2.0",
  "client_id": "YOUR_CLIENT_ID",
  "client_secret": "YOUR_CLIENT_SECRET",
  "scopes": ["openid", "profile", "email"],
  "domains": ["example.com"],
  "allow_signup": true,
  "trust_email_verified": true
}
```

### Okta (SAML)

```json
{
  "name": "Okta SAML",
  "slug": "okta",
  "provider_type": "saml",
  "entity_id": "https://guard.example.com/saml/metadata",
  "acs_url": "https://guard.example.com/v1/auth/sso/saml/acs",
  "idp_metadata_url": "https://example.okta.com/app/YOUR_APP_ID/sso/saml/metadata",
  "want_assertions_signed": true,
  "domains": ["example.com"],
  "allow_signup": true,
  "trust_email_verified": true,
  "attribute_mapping": {
    "email": ["email", "mail"],
    "first_name": ["firstName", "given_name"],
    "last_name": ["lastName", "family_name"]
  }
}
```

---

## Appendix B: Migration from WorkOS

### Migration Script

```go
// POST /v1/tenants/{tenant_id}/sso-providers/migrate-from-workos
func (s *Service) MigrateFromWorkOS(ctx context.Context, tenantID uuid.UUID) error {
    // 1. Fetch current WorkOS settings
    workosClientID, _ := s.settingsRepo.Get(ctx, tenantID, "sso.workos.client_id")
    workosClientSecret, _ := s.settingsRepo.Get(ctx, tenantID, "sso.workos.client_secret")
    workosConnectionID, _ := s.settingsRepo.Get(ctx, tenantID, "sso.workos.default_connection_id")

    // 2. Query WorkOS API for connection metadata
    connection := fetchWorkOSConnection(workosConnectionID)

    // 3. Determine provider type
    var providerType domain.ProviderType
    var config *domain.Config

    switch connection.Type {
    case "OIDC":
        providerType = domain.ProviderTypeOIDC
        config = &domain.Config{
            Type:         providerType,
            Issuer:       connection.Issuer,
            ClientID:     connection.ClientID,
            ClientSecret: connection.ClientSecret,
        }
    case "SAML":
        providerType = domain.ProviderTypeSAML
        config = &domain.Config{
            Type:            providerType,
            EntityID:        connection.EntityID,
            IdPMetadataXML:  connection.IdPMetadata,
        }
    }

    // 4. Create native provider
    config.ID = uuid.New()
    config.TenantID = tenantID
    config.Name = "Migrated from WorkOS"
    config.Slug = "workos-migrated"
    config.Enabled = false // Start disabled

    if err := s.repo.Create(ctx, config); err != nil {
        return fmt.Errorf("failed to create provider: %w", err)
    }

    // 5. Test new provider
    if err := s.testProvider(ctx, config); err != nil {
        return fmt.Errorf("migration test failed: %w", err)
    }

    // 6. Enable native provider
    config.Enabled = true
    if err := s.repo.Update(ctx, config); err != nil {
        return fmt.Errorf("failed to enable provider: %w", err)
    }

    // 7. Update tenant settings to use native provider
    _ = s.settingsRepo.Set(ctx, tenantID, "sso.provider", "native")

    return nil
}
```

---

## Team Decisions (2025-11-11)

Following questions were answered:

1. **Implementation Approach**: ✅ AI agents handle implementation, humans do code review
2. **Priorities**: ✅ OIDC + SAML together (not staged)
3. **WorkOS**: ✅ Keep as "enterprise tier" for edge cases we don't want to handle
4. **Directory Sync (SCIM)**: ✅ **v1 requirement** (see implementation below)
5. **Management UI**: ✅ API-only first with clear specs for AI-driven UI implementation
6. **Testing**: ✅ Prioritize **Azure AD** (potential customer interest)
7. **Security**: ✅ Internal audit first, external later

---

## Appendix C: Directory Sync (SCIM 2.0) - v1 Requirement

### Overview

SCIM (System for Cross-domain Identity Management) 2.0 enables automatic user and group provisioning from Identity Providers (IdPs) to Guard.

**Benefits**:
- Automatic user creation/deactivation when added/removed from IdP
- Group synchronization for RBAC
- Reduced manual user management
- Real-time updates (webhooks) or periodic sync

### Database Schema

```sql
-- SCIM Directory Connections
CREATE TABLE scim_directories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    sso_provider_id UUID REFERENCES sso_providers(id) ON DELETE SET NULL,

    -- Directory configuration
    name VARCHAR(255) NOT NULL,
    directory_type VARCHAR(50) NOT NULL, -- 'azure_ad', 'okta', 'google', 'onelogin', 'generic'

    -- SCIM authentication
    bearer_token TEXT NOT NULL, -- Generated token for IdP to authenticate
    endpoint_url TEXT NOT NULL, -- Our SCIM endpoint URL

    -- Sync configuration
    sync_users BOOLEAN DEFAULT TRUE,
    sync_groups BOOLEAN DEFAULT TRUE,
    auto_activate_users BOOLEAN DEFAULT TRUE,
    auto_deactivate_users BOOLEAN DEFAULT TRUE,
    default_role VARCHAR(50) DEFAULT 'member',

    -- Sync state
    last_sync_at TIMESTAMPTZ,
    last_sync_status VARCHAR(50), -- 'success', 'failed', 'partial'
    last_sync_error TEXT,

    -- Metadata
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(tenant_id, name),
    CHECK (directory_type IN ('azure_ad', 'okta', 'google', 'onelogin', 'generic'))
);

CREATE INDEX idx_scim_directories_tenant ON scim_directories(tenant_id) WHERE enabled = TRUE;
CREATE INDEX idx_scim_directories_provider ON scim_directories(sso_provider_id) WHERE sso_provider_id IS NOT NULL;

-- SCIM Sync Events (audit trail)
CREATE TABLE scim_sync_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    directory_id UUID NOT NULL REFERENCES scim_directories(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Event details
    event_type VARCHAR(50) NOT NULL, -- 'user_created', 'user_updated', 'user_deactivated', 'group_created', etc.
    resource_type VARCHAR(50) NOT NULL, -- 'user', 'group'
    resource_id TEXT, -- External ID from IdP
    user_id UUID REFERENCES users(id),

    -- Request/response
    request_payload JSONB,
    response_status INTEGER,
    error_message TEXT,

    -- Timing
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CHECK (event_type IN ('user_created', 'user_updated', 'user_deactivated', 'user_deleted', 'group_created', 'group_updated', 'group_deleted', 'group_membership_updated')),
    CHECK (resource_type IN ('user', 'group'))
);

CREATE INDEX idx_scim_sync_events_directory ON scim_sync_events(directory_id, created_at DESC);
CREATE INDEX idx_scim_sync_events_tenant ON scim_sync_events(tenant_id, created_at DESC);
CREATE INDEX idx_scim_sync_events_type ON scim_sync_events(event_type, created_at DESC);

-- External ID mapping (IdP user ID → Guard user ID)
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS scim_external_id TEXT,
    ADD COLUMN IF NOT EXISTS scim_directory_id UUID REFERENCES scim_directories(id) ON DELETE SET NULL;

CREATE INDEX idx_users_scim_external ON users(scim_directory_id, scim_external_id) WHERE scim_directory_id IS NOT NULL;

-- Group sync
CREATE TABLE scim_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    directory_id UUID NOT NULL REFERENCES scim_directories(id) ON DELETE CASCADE,

    -- Group identity
    external_id TEXT NOT NULL, -- IdP group ID
    display_name VARCHAR(255) NOT NULL,

    -- Mapping to Guard RBAC
    guard_role VARCHAR(50), -- Maps to Guard role (admin, member, viewer, etc.)

    -- Metadata
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(directory_id, external_id)
);

CREATE INDEX idx_scim_groups_directory ON scim_groups(directory_id);
CREATE INDEX idx_scim_groups_tenant ON scim_groups(tenant_id);
```

### SCIM Endpoints

Guard will expose SCIM 2.0 endpoints:

```
# Service Provider Config (metadata)
GET  /scim/v2/ServiceProviderConfig
GET  /scim/v2/Schemas
GET  /scim/v2/ResourceTypes

# Users
GET    /scim/v2/Users              # List users
GET    /scim/v2/Users/:id          # Get user
POST   /scim/v2/Users              # Create user
PUT    /scim/v2/Users/:id          # Replace user
PATCH  /scim/v2/Users/:id          # Update user
DELETE /scim/v2/Users/:id          # Deactivate user

# Groups
GET    /scim/v2/Groups             # List groups
GET    /scim/v2/Groups/:id         # Get group
POST   /scim/v2/Groups             # Create group
PUT    /scim/v2/Groups/:id         # Replace group
PATCH  /scim/v2/Groups/:id         # Update group
DELETE /scim/v2/Groups/:id         # Delete group

# Bulk operations (optional)
POST   /scim/v2/Bulk               # Bulk operations
```

### SCIM Implementation

**File: `internal/scim/domain/types.go`**

```go
package domain

import (
    "time"
    "github.com/google/uuid"
)

// User represents a SCIM user resource
type User struct {
    Schemas  []string `json:"schemas"`
    ID       string   `json:"id"`
    ExternalID string `json:"externalId,omitempty"`
    UserName string   `json:"userName"`
    Name     Name     `json:"name"`
    Emails   []Email  `json:"emails"`
    Active   bool     `json:"active"`
    Groups   []Group  `json:"groups,omitempty"`
    Meta     Meta     `json:"meta"`
}

type Name struct {
    GivenName  string `json:"givenName"`
    FamilyName string `json:"familyName"`
    Formatted  string `json:"formatted,omitempty"`
}

type Email struct {
    Value   string `json:"value"`
    Primary bool   `json:"primary"`
    Type    string `json:"type,omitempty"`
}

type Group struct {
    Value   string `json:"value"`
    Ref     string `json:"$ref,omitempty"`
    Display string `json:"display,omitempty"`
}

type Meta struct {
    ResourceType string    `json:"resourceType"`
    Created      time.Time `json:"created"`
    LastModified time.Time `json:"lastModified"`
    Location     string    `json:"location"`
}

// ListResponse represents a SCIM list response
type ListResponse struct {
    Schemas      []string    `json:"schemas"`
    TotalResults int         `json:"totalResults"`
    StartIndex   int         `json:"startIndex"`
    ItemsPerPage int         `json:"itemsPerPage"`
    Resources    interface{} `json:"Resources"`
}
```

**File: `internal/scim/service/service.go`**

```go
package service

import (
    "context"
    "fmt"
    "time"

    "github.com/google/uuid"
    "github.com/rs/zerolog"

    "github.com/CorvusHold/guard/internal/scim/domain"
    authdomain "github.com/CorvusHold/guard/internal/auth/domain"
)

type Service struct {
    userRepo     authdomain.Repository
    directoryRepo domain.Repository
    log          zerolog.Logger
}

func New(userRepo authdomain.Repository, directoryRepo domain.Repository) *Service {
    return &Service{
        userRepo:     userRepo,
        directoryRepo: directoryRepo,
        log:          zerolog.Nop(),
    }
}

// GetUsers returns SCIM users for directory
func (s *Service) GetUsers(ctx context.Context, tenantID, directoryID uuid.UUID, filter string, startIndex, count int) (*domain.ListResponse, error) {
    users, total, err := s.userRepo.ListByDirectory(ctx, tenantID, directoryID, filter, int32(count), int32(startIndex-1))
    if err != nil {
        return nil, err
    }

    scimUsers := make([]domain.User, len(users))
    for i, u := range users {
        scimUsers[i] = s.toSCIMUser(u)
    }

    return &domain.ListResponse{
        Schemas:      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
        TotalResults: int(total),
        StartIndex:   startIndex,
        ItemsPerPage: len(scimUsers),
        Resources:    scimUsers,
    }, nil
}

// CreateUser creates a user from SCIM request
func (s *Service) CreateUser(ctx context.Context, tenantID, directoryID uuid.UUID, scimUser *domain.User) (*domain.User, error) {
    // Validate required fields
    if scimUser.UserName == "" || len(scimUser.Emails) == 0 {
        return nil, fmt.Errorf("userName and emails are required")
    }

    // Create Guard user
    userID := uuid.New()
    email := scimUser.Emails[0].Value

    if err := s.userRepo.Create(ctx, userID, email, scimUser.Name.GivenName, scimUser.Name.FamilyName); err != nil {
        return nil, fmt.Errorf("failed to create user: %w", err)
    }

    // Link to directory
    if err := s.userRepo.SetSCIMExternalID(ctx, userID, scimUser.ExternalID, directoryID); err != nil {
        return nil, fmt.Errorf("failed to link SCIM user: %w", err)
    }

    // Add to tenant
    if err := s.userRepo.AddUserToTenant(ctx, userID, tenantID); err != nil {
        return nil, fmt.Errorf("failed to add user to tenant: %w", err)
    }

    // Log event
    _ = s.directoryRepo.LogEvent(ctx, directoryID, tenantID, "user_created", "user", scimUser.ExternalID, &userID, nil)

    // Return created user
    user, _ := s.userRepo.GetByID(ctx, userID)
    result := s.toSCIMUser(user)
    return &result, nil
}

// UpdateUser updates a user from SCIM request
func (s *Service) UpdateUser(ctx context.Context, tenantID, directoryID uuid.UUID, userID string, scimUser *domain.User) (*domain.User, error) {
    // Find user by SCIM ID
    user, err := s.userRepo.GetBySCIMExternalID(ctx, directoryID, userID)
    if err != nil {
        return nil, fmt.Errorf("user not found: %w", err)
    }

    // Update user fields
    if err := s.userRepo.Update(ctx, user.ID, scimUser.Emails[0].Value, scimUser.Name.GivenName, scimUser.Name.FamilyName); err != nil {
        return nil, fmt.Errorf("failed to update user: %w", err)
    }

    // Handle activation/deactivation
    if !scimUser.Active {
        if err := s.userRepo.Deactivate(ctx, user.ID); err != nil {
            return nil, fmt.Errorf("failed to deactivate user: %w", err)
        }
    }

    // Log event
    _ = s.directoryRepo.LogEvent(ctx, directoryID, tenantID, "user_updated", "user", userID, &user.ID, nil)

    // Return updated user
    updated, _ := s.userRepo.GetByID(ctx, user.ID)
    result := s.toSCIMUser(updated)
    return &result, nil
}

// Helper: Convert Guard user to SCIM user
func (s *Service) toSCIMUser(user authdomain.User) domain.User {
    return domain.User{
        Schemas:    []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
        ID:         user.SCIMExternalID,
        ExternalID: user.SCIMExternalID,
        UserName:   user.Email,
        Name: domain.Name{
            GivenName:  user.FirstName,
            FamilyName: user.LastName,
            Formatted:  user.FirstName + " " + user.LastName,
        },
        Emails: []domain.Email{
            {Value: user.Email, Primary: true, Type: "work"},
        },
        Active: user.IsActive,
        Meta: domain.Meta{
            ResourceType: "User",
            Created:      user.CreatedAt,
            LastModified: user.UpdatedAt,
            Location:     fmt.Sprintf("/scim/v2/Users/%s", user.SCIMExternalID),
        },
    }
}
```

**File: `internal/scim/controller/http.go`**

```go
package controller

import (
    "net/http"

    "github.com/labstack/echo/v4"
    "github.com/google/uuid"

    "github.com/CorvusHold/guard/internal/scim/service"
    "github.com/CorvusHold/guard/internal/scim/domain"
)

type Controller struct {
    svc *service.Service
}

func New(svc *service.Service) *Controller {
    return &Controller{svc: svc}
}

// Register mounts SCIM routes
func (c *Controller) Register(e *echo.Echo) {
    // SCIM endpoints require bearer token authentication
    scim := e.Group("/scim/v2", c.authenticateSCIM)

    // Service Provider Config
    scim.GET("/ServiceProviderConfig", c.getServiceProviderConfig)
    scim.GET("/Schemas", c.getSchemas)
    scim.GET("/ResourceTypes", c.getResourceTypes)

    // Users
    scim.GET("/Users", c.listUsers)
    scim.GET("/Users/:id", c.getUser)
    scim.POST("/Users", c.createUser)
    scim.PUT("/Users/:id", c.replaceUser)
    scim.PATCH("/Users/:id", c.updateUser)
    scim.DELETE("/Users/:id", c.deleteUser)

    // Groups
    scim.GET("/Groups", c.listGroups)
    scim.GET("/Groups/:id", c.getGroup)
    scim.POST("/Groups", c.createGroup)
    scim.PATCH("/Groups/:id", c.updateGroup)
    scim.DELETE("/Groups/:id", c.deleteGroup)
}

// Middleware: Authenticate SCIM requests with bearer token
func (c *Controller) authenticateSCIM(next echo.HandlerFunc) echo.HandlerFunc {
    return func(ctx echo.Context) error {
        authHeader := ctx.Request().Header.Get("Authorization")
        if authHeader == "" || len(authHeader) < 7 || authHeader[:7] != "Bearer " {
            return ctx.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
        }

        bearerToken := authHeader[7:]

        // Validate token and get directory
        directory, err := c.svc.ValidateBearerToken(ctx.Request().Context(), bearerToken)
        if err != nil {
            return ctx.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
        }

        // Store in context
        ctx.Set("scim_tenant_id", directory.TenantID)
        ctx.Set("scim_directory_id", directory.ID)

        return next(ctx)
    }
}

// GET /scim/v2/Users
func (c *Controller) listUsers(ctx echo.Context) error {
    tenantID := ctx.Get("scim_tenant_id").(uuid.UUID)
    directoryID := ctx.Get("scim_directory_id").(uuid.UUID)

    filter := ctx.QueryParam("filter")
    startIndex := 1
    count := 100

    if si := ctx.QueryParam("startIndex"); si != "" {
        fmt.Sscanf(si, "%d", &startIndex)
    }
    if c := ctx.QueryParam("count"); c != "" {
        fmt.Sscanf(c, "%d", &count)
    }

    result, err := c.svc.GetUsers(ctx.Request().Context(), tenantID, directoryID, filter, startIndex, count)
    if err != nil {
        return ctx.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
    }

    return ctx.JSON(http.StatusOK, result)
}

// POST /scim/v2/Users
func (c *Controller) createUser(ctx echo.Context) error {
    tenantID := ctx.Get("scim_tenant_id").(uuid.UUID)
    directoryID := ctx.Get("scim_directory_id").(uuid.UUID)

    var user domain.User
    if err := ctx.Bind(&user); err != nil {
        return ctx.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request"})
    }

    result, err := c.svc.CreateUser(ctx.Request().Context(), tenantID, directoryID, &user)
    if err != nil {
        return ctx.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
    }

    return ctx.JSON(http.StatusCreated, result)
}

// PATCH /scim/v2/Users/:id
func (c *Controller) updateUser(ctx echo.Context) error {
    tenantID := ctx.Get("scim_tenant_id").(uuid.UUID)
    directoryID := ctx.Get("scim_directory_id").(uuid.UUID)
    userID := ctx.Param("id")

    var user domain.User
    if err := ctx.Bind(&user); err != nil {
        return ctx.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request"})
    }

    result, err := c.svc.UpdateUser(ctx.Request().Context(), tenantID, directoryID, userID, &user)
    if err != nil {
        return ctx.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
    }

    return ctx.JSON(http.StatusOK, result)
}

// Additional handlers for groups, delete, etc...
```

### API Specifications for AI-Driven UI

**Management API Endpoints**:

```yaml
# Directory Management
POST   /v1/tenants/{tenant_id}/scim-directories
  Request:
    name: string (required)
    directory_type: enum [azure_ad, okta, google, onelogin, generic]
    sso_provider_id: uuid (optional, link to SSO provider)
    sync_users: boolean (default: true)
    sync_groups: boolean (default: true)
    auto_activate_users: boolean (default: true)
    default_role: string (default: "member")
  Response:
    id: uuid
    bearer_token: string (show once, store securely)
    endpoint_url: string (SCIM endpoint URL)
    ...

GET    /v1/tenants/{tenant_id}/scim-directories
  Response:
    directories: [
      {
        id: uuid
        name: string
        directory_type: string
        enabled: boolean
        last_sync_at: timestamp
        last_sync_status: enum [success, failed, partial]
        user_count: integer
        group_count: integer
      }
    ]

GET    /v1/tenants/{tenant_id}/scim-directories/{id}
PUT    /v1/tenants/{tenant_id}/scim-directories/{id}
DELETE /v1/tenants/{tenant_id}/scim-directories/{id}

# Sync Status & Events
GET    /v1/tenants/{tenant_id}/scim-directories/{id}/events
  Query params:
    event_type: string (optional filter)
    start_date: timestamp
    end_date: timestamp
    limit: integer (default: 50)
    offset: integer (default: 0)
  Response:
    events: [
      {
        id: uuid
        event_type: string
        resource_type: string
        resource_id: string
        user_id: uuid (nullable)
        error_message: string (nullable)
        created_at: timestamp
      }
    ]
    total: integer

POST   /v1/tenants/{tenant_id}/scim-directories/{id}/sync
  Description: Trigger manual sync
  Response:
    sync_id: uuid
    status: "initiated"

GET    /v1/tenants/{tenant_id}/scim-directories/{id}/test
  Description: Test connection to IdP
  Response:
    status: enum [success, failed]
    message: string
```

### Updated Implementation Timeline

**Week 1-2: Foundation & OIDC**
- Database schema + OIDC provider
- Repository & service layers
- Unit tests

**Week 3-4: SAML Implementation**
- SAML provider (crewjam/saml)
- Certificate management
- Integration tests with **Azure AD** (priority)

**Week 5-6: SCIM/Directory Sync (v1)**
- SCIM 2.0 endpoints (Users, Groups)
- Directory configuration API
- User/group sync logic
- Event audit trail
- Test with Azure AD SCIM provisioning

**Week 7-8: Testing & Security**
- Integration testing (Azure AD priority)
- Security audit (internal)
- Performance testing
- API documentation
- Rate limiting

**Week 9-10: Migration & Launch**
- WorkOS → Native migration tooling
- Feature flags
- Beta launch
- Monitor & iterate

---

## Appendix D: Azure AD Priority Testing

### Azure AD OIDC Configuration

```json
{
  "name": "Azure AD",
  "slug": "azure-ad",
  "provider_type": "oidc",
  "issuer": "https://login.microsoftonline.com/{tenant_id}/v2.0",
  "client_id": "{application_id}",
  "client_secret": "{client_secret}",
  "scopes": ["openid", "profile", "email", "User.Read"],
  "domains": ["customer-domain.com"]
}
```

### Azure AD SAML Configuration

```json
{
  "name": "Azure AD SAML",
  "slug": "azure-ad-saml",
  "provider_type": "saml",
  "entity_id": "https://guard.yourdomain.com/saml/metadata",
  "acs_url": "https://guard.yourdomain.com/v1/auth/sso/saml/acs",
  "idp_metadata_url": "https://login.microsoftonline.com/{tenant_id}/federationmetadata/2007-06/federationmetadata.xml",
  "want_assertions_signed": true,
  "sign_requests": true,
  "domains": ["customer-domain.com"]
}
```

### Azure AD SCIM Configuration

**Provisioning Endpoint**: `https://guard.yourdomain.com/scim/v2`
**Authentication**: Bearer Token (generated by Guard)
**Supported Operations**:
- Create/Update/Deactivate Users
- Create/Update/Delete Groups
- Group Membership Management

**Test Plan**:
1. Create Azure AD Enterprise Application
2. Configure OIDC/SAML for SSO
3. Enable provisioning with SCIM endpoint
4. Test user creation from Azure AD
5. Test group sync and role mapping
6. Test user deactivation
7. Test automatic provisioning on login

---

## Revised Success Criteria

✅ Support Azure AD (OIDC, SAML, SCIM) - **Priority 1**
✅ Support Google Workspace, Okta, OneLogin - **Priority 2**
✅ SCIM 2.0 user/group provisioning - **v1 requirement**
✅ Feature parity with WorkOS for core SSO + directory sync
✅ 99.9% uptime, <500ms p95 latency
✅ Zero-downtime migration with WorkOS as enterprise tier fallback
✅ API specifications ready for AI agent UI implementation
✅ Internal security audit completed

---

---

## Appendix E: Azure AD Testing Infrastructure

### Overview

Azure AD provides the best free testing infrastructure for SSO/SCIM development:
- **Free unlimited test tenants**
- **25 pre-populated test users** (M365 Developer Program)
- **Full Azure AD Premium P2** features (90-day renewable)
- **Comprehensive debugging** (sign-in logs, provisioning logs, audit logs)
- **All protocols**: OIDC, SAML, SCIM in one platform
- **API automation**: Microsoft Graph for CI/CD

### Free Resources

#### 1. Microsoft 365 Developer Program (Recommended)

**What You Get**:
- Instant Microsoft 365 E5 subscription (90-day renewable)
- Azure AD Premium P2 included
- 25 test user accounts with real licenses
- SCIM provisioning capability
- Advanced sign-in and audit logs
- Conditional Access policies
- Multi-factor authentication

**Sign Up**:
1. Visit: https://developer.microsoft.com/microsoft-365/dev-program
2. Sign in with Microsoft account
3. Complete developer profile
4. Get instant sandbox tenant (e.g., `guarddev.onmicrosoft.com`)
5. 25 sample users auto-populated with data

**Renewal**: Automatic if you use the tenant regularly (90-day cycles)

#### 2. Azure Free Account

**What You Get**:
- Free Azure AD tenant (unlimited duration)
- 50,000 monthly active users on free tier
- Basic OIDC and SAML support
- SCIM requires Azure AD Premium (use M365 Dev Program instead)
- Create/destroy tenants easily

**Sign Up**:
1. Visit: https://azure.microsoft.com/free
2. No credit card required for Azure AD features
3. Create tenants via Azure Portal → Azure Active Directory → Create tenant

### Recommended Testing Setup

#### Three-Tenant Strategy

**1. Development Tenant**
```yaml
Name: guard-dev.onmicrosoft.com
Source: M365 Developer Program
Purpose: Daily development and unit testing
Users: 5-10 test users
Configuration:
  - Simple OIDC setup
  - Basic SCIM provisioning
  - No MFA or Conditional Access
  - Fast iteration
```

**2. Staging Tenant**
```yaml
Name: guard-staging.onmicrosoft.com
Source: M365 Developer Program
Purpose: Pre-production validation and integration testing
Users: 25 users (full M365 Developer allocation)
Configuration:
  - OIDC + SAML + SCIM
  - MFA enabled
  - Conditional Access policies
  - Custom domain (optional: guard-staging.yourdomain.com)
  - Matches production configuration
```

**3. Demo/Customer Preview Tenant**
```yaml
Name: guard-demo.onmicrosoft.com
Source: M365 Developer Program
Purpose: Customer demos, sales presentations, training
Users: 10-15 users with realistic names/roles
Configuration:
  - Full production-like setup
  - Custom branding
  - Sample data
  - Stable configuration (don't break during demos)
```

### Initial Setup Guide

#### Step 1: Create M365 Developer Tenant (15 minutes)

```bash
1. Join M365 Developer Program
   - https://developer.microsoft.com/microsoft-365/dev-program
   - Sign in with Microsoft account
   - Complete profile

2. Provision sandbox
   - Choose "Instant sandbox"
   - Tenant name: guard-dev
   - Admin username: admin@guard-dev.onmicrosoft.com
   - Set admin password (save securely!)

3. Access tenant
   - Azure Portal: https://portal.azure.com
   - Sign in with admin@guard-dev.onmicrosoft.com
   - Navigate to: Azure Active Directory
```

#### Step 2: Configure OIDC (10 minutes)

```bash
1. Azure Portal → Azure Active Directory → App registrations
2. Click "New registration"
   - Name: "Guard Development"
   - Supported account types: "Accounts in this organizational directory only"
   - Redirect URI:
     - Platform: Web
     - URL: https://dev.guard.yourdomain.com/v1/auth/sso/azure-ad/callback
3. Click "Register"

4. Note the following (save these):
   - Application (client) ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
   - Directory (tenant) ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

5. Configure authentication:
   - Click "Authentication"
   - Under "Implicit grant and hybrid flows":
     - ✅ ID tokens (for OIDC)
   - Click "Save"

6. Create client secret:
   - Click "Certificates & secrets"
   - Click "New client secret"
   - Description: "Guard Dev"
   - Expires: 24 months
   - Click "Add"
   - Copy the secret VALUE (shown once!) and save securely

7. Configure API permissions:
   - Click "API permissions"
   - Click "Add a permission"
   - Choose "Microsoft Graph"
   - Choose "Delegated permissions"
   - Select: openid, profile, email, User.Read
   - Click "Add permissions"
   - Click "Grant admin consent for [tenant]" (admin only)

8. Test endpoint:
   - Issuer: https://login.microsoftonline.com/{tenant_id}/v2.0
   - Discovery: https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration
```

**Guard Configuration**:
```json
{
  "name": "Azure AD Dev",
  "slug": "azure-ad",
  "provider_type": "oidc",
  "issuer": "https://login.microsoftonline.com/{tenant_id}/v2.0",
  "client_id": "{application_client_id}",
  "client_secret": "{client_secret_value}",
  "scopes": ["openid", "profile", "email", "User.Read"],
  "enabled": true,
  "allow_signup": true,
  "trust_email_verified": true
}
```

#### Step 3: Configure SAML (15 minutes)

```bash
1. Azure Portal → Azure Active Directory → Enterprise applications
2. Click "New application"
3. Click "Create your own application"
   - Name: "Guard SAML Development"
   - Choose: "Integrate any other application you don't find in the gallery (Non-gallery)"
   - Click "Create"

4. Set up single sign-on:
   - Click "Single sign-on"
   - Choose "SAML"
   - Click "Edit" on Basic SAML Configuration:
     - Identifier (Entity ID): https://dev.guard.yourdomain.com/saml/metadata
     - Reply URL (ACS): https://dev.guard.yourdomain.com/v1/auth/sso/saml/acs
     - Sign on URL: https://dev.guard.yourdomain.com
     - Click "Save"

5. Download metadata:
   - Section 3: "SAML Signing Certificate"
   - Click "Download" next to "Federation Metadata XML"
   - Save file: azure-ad-metadata.xml

6. Configure attributes (optional):
   - Section 2: "Attributes & Claims"
   - Default mappings work (email, givenname, surname)
   - Customize if needed

7. Assign users:
   - Click "Users and groups"
   - Click "Add user/group"
   - Select test users
   - Click "Assign"
```

**Guard Configuration**:
```json
{
  "name": "Azure AD SAML Dev",
  "slug": "azure-ad-saml",
  "provider_type": "saml",
  "entity_id": "https://dev.guard.yourdomain.com/saml/metadata",
  "acs_url": "https://dev.guard.yourdomain.com/v1/auth/sso/saml/acs",
  "idp_metadata_xml": "<paste contents of azure-ad-metadata.xml>",
  "want_assertions_signed": true,
  "enabled": true,
  "allow_signup": true,
  "trust_email_verified": true
}
```

#### Step 4: Configure SCIM Provisioning (20 minutes)

```bash
1. Azure Portal → Azure Active Directory → Enterprise applications
2. Find your SAML app: "Guard SAML Development"
3. Click "Provisioning"
4. Click "Get started"
5. Set Provisioning Mode: "Automatic"

6. Configure Admin Credentials:
   - Tenant URL: https://dev.guard.yourdomain.com/scim/v2
   - Secret Token: [Bearer token from Guard - see below]
   - Click "Test Connection" (should succeed)
   - Click "Save"

7. Configure Mappings:
   - Click "Mappings"
   - Review "Provision Azure Active Directory Users"
   - Default mappings:
     - userPrincipalName → userName
     - Switch([IsSoftDeleted], , "False", "True", "True", "False") → active
     - mail → emails[type eq "work"].value
     - givenName → name.givenName
     - surname → name.familyName
   - Customize as needed
   - Click "Save"

8. Enable provisioning:
   - Provisioning Status: On
   - Click "Save"
   - Click "Start provisioning"

9. Monitor provisioning:
   - Click "Provisioning logs" (wait 5-10 minutes)
   - View user creation events
   - Check for errors
```

**Generate Guard SCIM Bearer Token**:
```bash
# Via Guard API
curl -X POST https://dev.guard.yourdomain.com/v1/tenants/{tenant_id}/scim-directories \
  -H "Authorization: Bearer {guard_admin_token}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Azure AD Dev Directory",
    "directory_type": "azure_ad",
    "sync_users": true,
    "sync_groups": true
  }'

# Response includes:
{
  "id": "...",
  "bearer_token": "guard_scim_xxxxxxxxxxxxxxxx",  # Use this in Azure AD
  "endpoint_url": "https://dev.guard.yourdomain.com/scim/v2"
}
```

### E2E Testing Strategy

#### Week 1-2: OIDC Testing

```typescript
// e2e/azure-ad-oidc.spec.ts
import { test, expect } from '@playwright/test';

test.describe('Azure AD OIDC Integration', () => {
  test('should complete full login flow', async ({ page }) => {
    // Start SSO flow
    await page.goto('https://dev.guard.yourdomain.com/auth/sso/azure-ad/start?tenant_id=...');

    // Azure AD login page
    await expect(page).toHaveURL(/login.microsoftonline.com/);
    await page.fill('input[type=email]', 'test@guard-dev.onmicrosoft.com');
    await page.click('input[type=submit]');
    await page.fill('input[type=password]', process.env.AZURE_TEST_PASSWORD);
    await page.click('input[type=submit]');

    // Handle "Stay signed in?" prompt
    await page.click('input[value="No"]');

    // Should redirect back to Guard
    await expect(page).toHaveURL(/dev.guard.yourdomain.com/);

    // Verify token response
    const response = await page.waitForResponse(/\/callback/);
    const data = await response.json();
    expect(data.access_token).toBeDefined();
    expect(data.user_id).toBeDefined();
  });

  test('should extract correct user claims', async ({ page }) => {
    // ... login flow ...

    // Verify user profile
    const user = await guardAPI.getCurrentUser();
    expect(user.email).toBe('test@guard-dev.onmicrosoft.com');
    expect(user.first_name).toBeDefined();
    expect(user.last_name).toBeDefined();
  });

  test('should handle invalid state', async ({ page }) => {
    await page.goto('https://dev.guard.yourdomain.com/auth/sso/azure-ad/callback?state=invalid&code=xyz');
    await expect(page).toHaveText(/invalid or expired state/i);
  });
});
```

#### Week 3-4: SAML Testing

```typescript
// e2e/azure-ad-saml.spec.ts
test.describe('Azure AD SAML Integration', () => {
  test('should login via SAML', async ({ page }) => {
    await page.goto('https://dev.guard.yourdomain.com/auth/sso/azure-ad-saml/start?tenant_id=...');

    // Azure AD SAML login
    await expect(page).toHaveURL(/login.microsoftonline.com/);
    await page.fill('input[type=email]', 'test@guard-dev.onmicrosoft.com');
    await page.click('input[type=submit]');
    await page.fill('input[type=password]', process.env.AZURE_TEST_PASSWORD);
    await page.click('input[type=submit]');

    // SAML POST back to Guard
    await expect(page).toHaveURL(/dev.guard.yourdomain.com/);
  });

  test('should parse SAML assertions correctly', async ({ page }) => {
    // ... login flow ...

    // Verify assertion attributes mapped correctly
    const user = await guardAPI.getCurrentUser();
    expect(user.email).toMatch(/@guard-dev.onmicrosoft.com$/);
  });
});
```

#### Week 5-6: SCIM Testing

```typescript
// e2e/azure-ad-scim.spec.ts
import { GraphClient } from '@microsoft/microsoft-graph-client';

const graphClient = GraphClient.initWithMiddleware({
  authProvider: azureAuthProvider
});

test.describe('Azure AD SCIM Provisioning', () => {
  test('should create user via SCIM', async () => {
    // Create user in Azure AD
    const azureUser = await graphClient.api('/users').post({
      accountEnabled: true,
      displayName: 'SCIM Test User',
      mailNickname: 'scimtest',
      userPrincipalName: 'scimtest@guard-dev.onmicrosoft.com',
      passwordProfile: {
        forceChangePasswordNextSignIn: false,
        password: 'Test@1234'
      }
    });

    // Wait for SCIM sync (Azure AD polls every 40 minutes, or trigger manual sync)
    await triggerAzureADProvisioning();
    await new Promise(resolve => setTimeout(resolve, 60000)); // Wait 1 minute

    // Verify user created in Guard
    const guardUser = await guardAPI.getUserBySCIMExternalID(azureUser.id);
    expect(guardUser).toBeDefined();
    expect(guardUser.email).toBe('scimtest@guard-dev.onmicrosoft.com');
  });

  test('should deactivate user via SCIM', async () => {
    const azureUser = await createTestUser();
    await waitForSCIMSync();

    // Disable user in Azure AD
    await graphClient.api(`/users/${azureUser.id}`).patch({
      accountEnabled: false
    });

    await triggerAzureADProvisioning();
    await waitForSCIMSync();

    // Verify user deactivated in Guard
    const guardUser = await guardAPI.getUserBySCIMExternalID(azureUser.id);
    expect(guardUser.is_active).toBe(false);
  });

  test('should sync group membership', async () => {
    // Create group in Azure AD
    const group = await graphClient.api('/groups').post({
      displayName: 'Guard Admins',
      mailEnabled: false,
      mailNickname: 'guardadmins',
      securityEnabled: true
    });

    // Add user to group
    await graphClient.api(`/groups/${group.id}/members/$ref`).post({
      '@odata.id': `https://graph.microsoft.com/v1.0/users/${azureUser.id}`
    });

    await triggerAzureADProvisioning();
    await waitForSCIMSync();

    // Verify group membership in Guard
    const guardUser = await guardAPI.getUserBySCIMExternalID(azureUser.id);
    expect(guardUser.groups).toContainEqual(expect.objectContaining({
      name: 'Guard Admins'
    }));
  });
});

async function triggerAzureADProvisioning() {
  // Trigger on-demand provisioning via Graph API
  await graphClient.api('/servicePrincipals/{servicePrincipalId}/synchronization/jobs/{jobId}/provision')
    .post({});
}
```

### CI/CD Integration

#### GitHub Actions Example

```yaml
# .github/workflows/e2e-azure-ad.yml
name: E2E Azure AD SSO Tests

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 2 * * *' # Daily at 2 AM

env:
  AZURE_TENANT_ID: ${{ secrets.AZURE_TEST_TENANT_ID }}
  AZURE_CLIENT_ID: ${{ secrets.AZURE_TEST_CLIENT_ID }}
  AZURE_CLIENT_SECRET: ${{ secrets.AZURE_TEST_CLIENT_SECRET }}
  AZURE_TEST_USER: test@guard-dev.onmicrosoft.com
  AZURE_TEST_PASSWORD: ${{ secrets.AZURE_TEST_PASSWORD }}
  GUARD_API_URL: https://dev.guard.yourdomain.com

jobs:
  test-oidc:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'

      - name: Install dependencies
        run: npm ci

      - name: Install Playwright
        run: npx playwright install --with-deps

      - name: Run OIDC E2E tests
        run: npm run test:e2e:azure-oidc

      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: playwright-report-oidc
          path: playwright-report/

  test-saml:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Setup Node.js
        uses: actions/setup-node@v3
      - name: Install dependencies
        run: npm ci
      - name: Run SAML E2E tests
        run: npm run test:e2e:azure-saml

  test-scim:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Node.js
        uses: actions/setup-node@v3

      - name: Install Microsoft Graph SDK
        run: npm install @microsoft/microsoft-graph-client

      - name: Create test user in Azure AD
        run: |
          node scripts/azure-create-test-user.js

      - name: Trigger SCIM provisioning
        run: |
          node scripts/azure-trigger-provisioning.js

      - name: Wait for sync
        run: sleep 120

      - name: Verify user in Guard
        run: |
          node scripts/verify-scim-sync.js

      - name: Cleanup test user
        if: always()
        run: |
          node scripts/azure-delete-test-user.js
```

### Debugging & Monitoring

#### Sign-In Logs

```bash
# Access sign-in logs
Azure Portal → Azure Active Directory → Monitoring → Sign-ins

# Filter to your app
- Application: "Guard Development"
- Status: All / Success / Failure
- Date range: Last 24 hours

# View details
- Click on any sign-in event
- See: User, IP, Location, Device, Authentication details
- Error codes with explanations
- Token claims issued
```

**Common Error Codes**:
- `AADSTS50105`: User not assigned to application
- `AADSTS50011`: Reply URL mismatch
- `AADSTS7000215`: Invalid client secret
- `AADSTS650052`: The app needs access to a service

#### Provisioning Logs

```bash
# Access provisioning logs
Azure Portal → Enterprise Applications → Guard SAML Development → Provisioning logs

# View events
- User created
- User updated
- User disabled
- Group membership changed

# Troubleshoot errors
- Click on failed event
- See: Error details, Retry count, Attribute mappings
- Fix issue in Guard SCIM endpoint
- Azure AD auto-retries
```

#### Microsoft Graph API

```bash
# Install Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Login
az login

# Get sign-in logs (last 24 hours)
az rest --method get \
  --url "https://graph.microsoft.com/v1.0/auditLogs/signIns?\$filter=appId eq '{app_id}'" \
  --headers "Content-Type=application/json"

# Get provisioning logs
az rest --method get \
  --url "https://graph.microsoft.com/beta/auditLogs/provisioning" \
  --headers "Content-Type=application/json"

# Get user details
az ad user show --id test@guard-dev.onmicrosoft.com
```

### Cost Analysis

#### Free Tier Limits

**M365 Developer Program**:
- ✅ 25 users included
- ✅ All Azure AD Premium P2 features
- ✅ Unlimited SCIM provisioning
- ✅ 90-day renewal (auto if active)
- ✅ No credit card required

**Azure AD Free Tier**:
- ✅ 50,000 MAU (monthly active users)
- ✅ Basic OIDC/SAML
- ❌ No SCIM (requires Premium)
- ❌ No advanced sign-in logs
- ❌ No Conditional Access

**Recommendation**: Use M365 Developer Program for full feature testing

### Troubleshooting Guide

#### Issue: "AADSTS50011: The reply URL specified does not match"

```bash
Fix:
1. Azure Portal → App registrations → Guard Development → Authentication
2. Verify redirect URI exactly matches:
   - OIDC: https://dev.guard.yourdomain.com/v1/auth/sso/azure-ad/callback
   - SAML: https://dev.guard.yourdomain.com/v1/auth/sso/saml/acs
3. No trailing slash
4. HTTPS required (unless localhost)
5. Click "Save"
```

#### Issue: "AADSTS7000215: Invalid client secret"

```bash
Fix:
1. Azure Portal → App registrations → Guard Development → Certificates & secrets
2. Check expiry date of client secret
3. Create new secret if expired
4. Update Guard configuration with new secret
```

#### Issue: SCIM provisioning fails with 401 Unauthorized

```bash
Fix:
1. Verify Guard SCIM endpoint is accessible:
   curl https://dev.guard.yourdomain.com/scim/v2/ServiceProviderConfig
2. Check bearer token is correct (regenerate if needed)
3. Azure Portal → Enterprise Applications → Provisioning → Edit Provisioning
4. Update Secret Token with new bearer token
5. Click "Test Connection" → should succeed
```

#### Issue: Users not syncing via SCIM

```bash
Debug:
1. Azure Portal → Provisioning logs
2. Check for errors (red X icon)
3. Common issues:
   - Attribute mapping mismatch (email field name)
   - Guard SCIM endpoint returning 400/500 errors
   - User already exists (external ID conflict)
4. Fix issue in Guard
5. Azure AD auto-retries failed events
6. Or manually trigger: Provisioning → Provision on demand
```

---

**Status**: ✅ **Approved with Decisions**
**Next Steps**:
1. ✅ **Set up M365 Developer Program** (15 min) - Priority #1
2. ✅ **Create guard-dev.onmicrosoft.com** test tenant
3. ✅ **Configure OIDC app registration** (10 min)
4. Begin Week 1 implementation (AI agents + human code review)
5. Run E2E tests against Azure AD throughout development
