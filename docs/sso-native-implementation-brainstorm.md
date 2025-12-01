# Native SSO/OIDC Implementation Brainstorm

## Executive Summary

**Current State**: Guard uses WorkOS for SSO integration, supporting all enterprise SSO providers (SAML, OIDC, etc.) at €150/month per tenant.

**Goal**: Implement native OIDC and SAML support to eliminate per-tenant costs while maintaining enterprise-grade SSO capabilities for the open-source Guard project.

**Estimated Savings**: €1,800/year per tenant (€150 × 12 months)

---

## 1. Current WorkOS Integration Analysis

### What We're Using WorkOS For

Based on the codebase analysis, Guard currently uses WorkOS for:

1. **OAuth 2.0 Authorization Flow**
   - Authorization endpoint: `/sso/authorize`
   - Token exchange: `/sso/token`
   - State management with Redis (CSRF protection)

2. **Enterprise SSO Support**
   - Connection-based SSO (specific SAML/OIDC providers)
   - Organization-based SSO (multi-org setups)
   - Profile extraction (email, first_name, last_name)

3. **Admin Portal**
   - Portal link generation: `/portal/generate_link`
   - Supports: SSO, Directory Sync, Audit Logs, Log Streams, Domain Verification, Certificate Renewal

4. **Multi-Tenant Configuration**
   - Per-tenant WorkOS credentials (client_id, client_secret, api_key)
   - Per-tenant connection/organization defaults
   - Tenant-scoped settings at `/v1/tenants/{id}/settings`

### Key Files
- Backend: `internal/auth/service/sso_workos.go` (507 lines)
- Orchestration: `internal/auth/service/sso.go` (315 lines)
- Settings: `internal/settings/domain/domain.go`
- Frontend: `ui/src/components/auth/Login.tsx`, `ui/src/components/auth/Callback.tsx`

---

## 2. Cost-Benefit Analysis

### Current Costs (WorkOS)
- **€150/month per tenant** = €1,800/year per tenant
- **Hidden costs**: Vendor lock-in, limited customization, external dependency

### Native Implementation Costs
- **One-time**: Development effort (estimated 2-4 weeks)
- **Ongoing**: Maintenance, security updates, protocol compliance
- **Infrastructure**: Certificate management, metadata hosting

### Break-Even Analysis
- **1 tenant**: Break-even after ~1-2 months of development
- **10 tenants**: €18,000/year savings
- **100 tenants**: €180,000/year savings

**For an open-source project, native implementation is clearly cost-effective.**

---

## 3. Better Auth's Approach (Reference Implementation)

### Architecture Highlights

Better Auth uses a **plugin-based architecture** with native OIDC and SAML 2.0 support:

```typescript
// Unified SSO plugin approach
import { sso } from "@better-auth/sso"

export const auth = betterAuth({
  plugins: [
    sso({
      organizationProvisioning: true,
      provisionUser: async (user, provider) => {
        // Custom user provisioning logic
      }
    })
  ]
})
```

### Key Features
1. **Protocol Support**: Both OIDC and SAML 2.0 in same package
2. **Multi-Tenant**: Organization-based provider configuration
3. **Domain Routing**: Automatic org detection via email domain
4. **Database-Driven**: Providers stored in `ssoProvider` table
5. **Dynamic Registration**: Runtime provider registration via API

### What Makes It Work
- **No third-party service**: Direct OIDC/SAML implementation
- **Standard libraries**: Protocol-specific libraries for SAML parsing, OIDC token validation
- **Configuration storage**: JSON blobs for provider-specific settings
- **Flexible provisioning**: Custom hooks for user/organization setup

---

## 4. Native Implementation Strategy for Guard

### Phase 1: OIDC Implementation (High Priority)

**Why OIDC First?**
- Simpler protocol (OAuth 2.0 + identity layer)
- Modern standard (JWT-based)
- Most SaaS providers support it (Google Workspace, Microsoft Entra ID, Okta)
- Better API/developer experience

**Technical Approach**:

```go
// New provider architecture
type SSOProvider interface {
    Start(ctx context.Context, opts StartOptions) (string, error)      // Generate auth URL
    Callback(ctx context.Context, code string) (*Profile, error)        // Exchange token
    ValidateConfig(config map[string]interface{}) error                 // Validate settings
}

// OIDC implementation
type OIDCProvider struct {
    issuer       string
    clientID     string
    clientSecret string
    redirectURI  string
    scopes       []string
}
```

**Dependencies** (Go ecosystem):
- `github.com/coreos/go-oidc/v3/oidc` - OIDC client library (by CoreOS)
- `golang.org/x/oauth2` - OAuth 2.0 client
- Built-in `encoding/json`, `crypto/rand` for state management

**Database Schema**:
```sql
CREATE TABLE sso_providers (
    id                UUID PRIMARY KEY,
    tenant_id         UUID NOT NULL REFERENCES tenants(id),
    name              VARCHAR(255) NOT NULL,
    provider_type     VARCHAR(50) NOT NULL, -- 'oidc', 'saml', 'oauth2'
    issuer            TEXT NOT NULL,
    client_id         TEXT NOT NULL,
    client_secret     TEXT, -- encrypted
    scopes            TEXT[], -- JSON array for OIDC
    metadata_url      TEXT, -- OIDC discovery URL
    config            JSONB, -- Protocol-specific config
    enabled           BOOLEAN DEFAULT true,
    created_at        TIMESTAMP DEFAULT NOW(),
    updated_at        TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_sso_providers_tenant ON sso_providers(tenant_id);
CREATE INDEX idx_sso_providers_issuer ON sso_providers(issuer);
```

**Configuration API**:
```
POST   /v1/tenants/{id}/sso-providers          # Create provider
GET    /v1/tenants/{id}/sso-providers          # List providers
PUT    /v1/tenants/{id}/sso-providers/{pid}    # Update provider
DELETE /v1/tenants/{id}/sso-providers/{pid}    # Delete provider
GET    /v1/tenants/{id}/sso-providers/{pid}/test # Test connection
```

**OIDC Flow Implementation**:

1. **Discovery** (automatic configuration):
   ```go
   // Fetch .well-known/openid-configuration
   provider, err := oidc.NewProvider(ctx, issuerURL)
   oauth2Config := oauth2.Config{
       ClientID:     clientID,
       ClientSecret: clientSecret,
       Endpoint:     provider.Endpoint(),
       Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
   }
   ```

2. **Authorization** (Start):
   ```go
   func (p *OIDCProvider) Start(ctx context.Context) (string, error) {
       state := generateSecureState()
       nonce := generateSecureNonce()

       // Store state in Redis with TTL
       storeState(ctx, state, nonce, 10*time.Minute)

       return oauth2Config.AuthCodeURL(state,
           oidc.Nonce(nonce),
           oauth2.AccessTypeOnline,
       ), nil
   }
   ```

3. **Callback** (Token Exchange):
   ```go
   func (p *OIDCProvider) Callback(ctx context.Context, code, state string) (*Profile, error) {
       // Validate state (atomic get-and-delete from Redis)
       storedNonce, err := validateAndConsumeState(ctx, state)
       if err != nil {
           return nil, ErrInvalidState
       }

       // Exchange code for token
       oauth2Token, err := oauth2Config.Exchange(ctx, code)
       if err != nil {
           return nil, fmt.Errorf("token exchange failed: %w", err)
       }

       // Extract ID token and verify
       rawIDToken, ok := oauth2Token.Extra("id_token").(string)
       if !ok {
           return nil, ErrNoIDToken
       }

       idToken, err := provider.Verifier(&oidc.Config{ClientID: clientID}).Verify(ctx, rawIDToken)
       if err != nil {
           return nil, fmt.Errorf("ID token verification failed: %w", err)
       }

       // Verify nonce
       if idToken.Nonce != storedNonce {
           return nil, ErrInvalidNonce
       }

       // Parse claims
       var claims struct {
           Email         string `json:"email"`
           EmailVerified bool   `json:"email_verified"`
           FirstName     string `json:"given_name"`
           LastName      string `json:"family_name"`
           Name          string `json:"name"`
       }
       if err := idToken.Claims(&claims); err != nil {
           return nil, err
       }

       return &Profile{
           Email:     claims.Email,
           FirstName: claims.FirstName,
           LastName:  claims.LastName,
           Verified:  claims.EmailVerified,
       }, nil
   }
   ```

### Phase 2: SAML 2.0 Implementation (Medium Priority)

**Why SAML?**
- Legacy enterprise requirement (banks, government, large corps)
- Okta, Azure AD, OneLogin still widely use SAML
- Required for "Enterprise-ready" badge

**Technical Approach**:

**Dependencies**:
- `github.com/crewjam/saml` - Pure Go SAML library
- `crypto/x509`, `crypto/rsa` for certificate handling

**Additional Schema**:
```sql
ALTER TABLE sso_providers ADD COLUMN certificate TEXT; -- X.509 cert for SAML
ALTER TABLE sso_providers ADD COLUMN private_key TEXT; -- Encrypted private key
ALTER TABLE sso_providers ADD COLUMN idp_metadata_url TEXT; -- IdP metadata
ALTER TABLE sso_providers ADD COLUMN acs_url TEXT; -- Assertion Consumer Service URL
ALTER TABLE sso_providers ADD COLUMN entity_id TEXT; -- Service Provider Entity ID
```

**SAML Endpoints**:
```
GET  /v1/auth/sso/saml/metadata                    # SP metadata XML
POST /v1/auth/sso/saml/acs                         # Assertion Consumer Service
GET  /v1/auth/sso/saml/slo                         # Single Logout
```

**SAML Flow**:

1. **Metadata Generation** (Service Provider):
   ```go
   func (p *SAMLProvider) Metadata() ([]byte, error) {
       sp := saml.ServiceProvider{
           Key:         privateKey,
           Certificate: certificate,
           MetadataURL: url.URL{Scheme: "https", Host: "guard.example.com", Path: "/v1/auth/sso/saml/metadata"},
           AcsURL:      url.URL{Scheme: "https", Host: "guard.example.com", Path: "/v1/auth/sso/saml/acs"},
           IDPMetadata: idpMetadata,
       }
       return xml.Marshal(sp.Metadata())
   }
   ```

2. **Authentication Request**:
   ```go
   func (p *SAMLProvider) Start(ctx context.Context) (string, error) {
       authReq, err := sp.MakeAuthenticationRequest(binding)
       if err != nil {
           return "", err
       }

       // Store RelayState
       relayState := generateSecureState()
       storeState(ctx, relayState, authReq.ID, 10*time.Minute)

       return authReq.Redirect(relayState), nil
   }
   ```

3. **Assertion Parsing**:
   ```go
   func (p *SAMLProvider) Callback(ctx context.Context, samlResponse string) (*Profile, error) {
       assertion, err := sp.ParseResponse(req, []string{possibleRequestID})
       if err != nil {
           return nil, fmt.Errorf("SAML assertion parse failed: %w", err)
       }

       // Extract attributes
       email := assertion.AttributeStatements[0].Attributes["email"].Values[0]
       firstName := assertion.AttributeStatements[0].Attributes["firstName"].Values[0]
       lastName := assertion.AttributeStatements[0].Attributes["lastName"].Values[0]

       return &Profile{
           Email:     email,
           FirstName: firstName,
           LastName:  lastName,
           Verified:  true, // Trust IdP verification
       }, nil
   }
   ```

### Phase 3: Management Portal (Low Priority)

**Replace WorkOS Admin Portal**:

Since WorkOS portal provides SSO connection management, we'd need:

1. **UI for SSO Provider Configuration**:
   ```
   /admin/tenants/{id}/sso-providers
   ```
   - List providers (Google, Microsoft, Okta, Custom OIDC, Custom SAML)
   - Add/Edit provider configuration
   - Test connection button
   - Import IdP metadata (for SAML)

2. **Certificate Management**:
   - Generate self-signed certs for SAML
   - Upload custom certificates
   - Certificate expiry warnings
   - Renewal workflows

3. **Domain Verification**:
   - DNS TXT record verification
   - Automatic domain → provider routing

**Tech Stack**:
- Extend existing React UI (`ui/src/`)
- New routes: `ui/src/pages/sso-providers/`
- Form library: React Hook Form + Zod validation

---

## 5. Recommended Architecture

### Pluggable Provider System

```go
// internal/auth/service/sso_provider.go
type SSOProvider interface {
    // Core flow
    Start(ctx context.Context, opts StartOptions) (*StartResult, error)
    Callback(ctx context.Context, req CallbackRequest) (*Profile, error)

    // Validation
    ValidateConfig(config ProviderConfig) error

    // Metadata
    GetMetadata() (*ProviderMetadata, error)
}

type StartOptions struct {
    TenantID    uuid.UUID
    ProviderID  uuid.UUID
    RedirectURI string
    State       string
}

type CallbackRequest struct {
    Code        string // For OIDC/OAuth
    SAMLResponse string // For SAML
    State       string
}

type Profile struct {
    ProviderID    string
    Email         string
    EmailVerified bool
    FirstName     string
    LastName      string
    Attributes    map[string]interface{} // Additional claims/attributes
}
```

### Provider Registry

```go
// internal/auth/service/sso_registry.go
type ProviderRegistry struct {
    providers map[string]func(config ProviderConfig) (SSOProvider, error)
}

func NewProviderRegistry() *ProviderRegistry {
    r := &ProviderRegistry{providers: make(map[string]func(config ProviderConfig) (SSOProvider, error))}

    // Register built-in providers
    r.Register("oidc", NewOIDCProvider)
    r.Register("saml", NewSAMLProvider)
    r.Register("workos", NewWorkOSProvider) // Keep for migration
    r.Register("dev", NewDevProvider)

    return r
}

func (r *ProviderRegistry) Create(ctx context.Context, tenantID, providerID uuid.UUID) (SSOProvider, error) {
    // Load provider config from database
    config, err := r.loadProviderConfig(ctx, tenantID, providerID)
    if err != nil {
        return nil, err
    }

    // Create provider instance
    factory, ok := r.providers[config.Type]
    if !ok {
        return nil, fmt.Errorf("unknown provider type: %s", config.Type)
    }

    return factory(config)
}
```

### Modified SSO Service

```go
// internal/auth/service/sso.go - Updated
type SSOService struct {
    registry *ProviderRegistry
    repo     *SSOProviderRepository
    // ... existing fields
}

func (s *SSOService) Start(ctx context.Context, tenantID uuid.UUID, providerIdentifier string) (*StartResult, error) {
    // Look up provider by ID or name
    providerID, err := s.repo.ResolveProvider(ctx, tenantID, providerIdentifier)
    if err != nil {
        return nil, err
    }

    // Create provider instance
    provider, err := s.registry.Create(ctx, tenantID, providerID)
    if err != nil {
        return nil, err
    }

    // Generate state
    state := generateSecureState()

    // Execute provider start
    result, err := provider.Start(ctx, StartOptions{
        TenantID:    tenantID,
        ProviderID:  providerID,
        State:       state,
        RedirectURI: s.buildRedirectURI(tenantID, providerID),
    })
    if err != nil {
        return nil, err
    }

    // Store state in Redis
    s.stateStore.Set(ctx, state, StateData{
        TenantID:   tenantID,
        ProviderID: providerID,
        Nonce:      result.Nonce,
    }, 10*time.Minute)

    return result, nil
}
```

### Database Layer

```go
// internal/auth/repository/sso_provider.go
type SSOProviderRepository struct {
    db *sqlx.DB
}

func (r *SSOProviderRepository) Create(ctx context.Context, provider *SSOProvider) error
func (r *SSOProviderRepository) Update(ctx context.Context, provider *SSOProvider) error
func (r *SSOProviderRepository) Delete(ctx context.Context, tenantID, providerID uuid.UUID) error
func (r *SSOProviderRepository) GetByID(ctx context.Context, tenantID, providerID uuid.UUID) (*SSOProvider, error)
func (r *SSOProviderRepository) ListByTenant(ctx context.Context, tenantID uuid.UUID) ([]*SSOProvider, error)
func (r *SSOProviderRepository) ResolveProvider(ctx context.Context, tenantID uuid.UUID, identifier string) (uuid.UUID, error)
```

---

## 6. Implementation Roadmap

### Week 1-2: OIDC Foundation
- [ ] Design database schema
- [ ] Create provider interface and registry
- [ ] Implement OIDC provider (go-oidc)
- [ ] Add CRUD APIs for provider management
- [ ] Update SSO service to use registry
- [ ] Write unit tests

### Week 3: OIDC Integration & Testing
- [ ] Update frontend to support multiple providers
- [ ] Add provider selection UI
- [ ] Implement provider configuration form
- [ ] Write integration tests
- [ ] Test with Google, Microsoft, Okta
- [ ] Security audit (OWASP review)

### Week 4: SAML Implementation
- [ ] Implement SAML provider (crewjam/saml)
- [ ] Certificate generation/management
- [ ] Metadata endpoints
- [ ] SAML integration tests
- [ ] Test with Azure AD, Okta SAML

### Week 5-6: Management Portal & Polish
- [ ] Admin UI for provider management
- [ ] Certificate management UI
- [ ] Provider testing/validation tools
- [ ] Migration guide from WorkOS
- [ ] Documentation

### Week 7: Migration & Deprecation
- [ ] Add deprecation warnings for WorkOS
- [ ] Migration script for existing tenants
- [ ] Feature flag for WorkOS vs native
- [ ] Parallel testing period

### Week 8: Launch
- [ ] Remove WorkOS dependency (optional)
- [ ] Update documentation
- [ ] Announce native SSO support
- [ ] Celebrate cost savings! 🎉

---

## 7. Technical Trade-offs

### Pros of Native Implementation

✅ **Cost Savings**: €150/month/tenant → €0 (infrastructure only)
✅ **Control**: Full customization and debugging
✅ **Open Source Friendly**: No proprietary dependencies
✅ **Flexibility**: Add custom protocols (LDAP, CAS, etc.)
✅ **Data Sovereignty**: No third-party data sharing
✅ **Offline Capable**: No external API dependencies
✅ **Performance**: No network hops to WorkOS
✅ **Branding**: White-label experience

### Cons of Native Implementation

❌ **Development Time**: 6-8 weeks initial implementation
❌ **Maintenance Burden**: Security updates, protocol changes
❌ **Complexity**: SAML is notoriously difficult
❌ **Testing**: Need access to multiple IdPs
❌ **Certificate Management**: Rotation, expiry monitoring
❌ **Support**: You become first-line support for SSO issues
❌ **Compliance**: Self-certification for SOC2, ISO27001
❌ **Feature Gap**: No directory sync, audit logs (yet)

### Risk Mitigation

1. **Security Audits**: Regular OWASP testing, penetration testing
2. **Library Selection**: Use battle-tested libraries (go-oidc, crewjam/saml)
3. **Incremental Rollout**: Feature flag, parallel WorkOS support
4. **Testing Strategy**:
   - Unit tests for crypto/validation
   - Integration tests with IdP sandboxes
   - E2E tests with real providers
5. **Documentation**: Comprehensive setup guides for each IdP
6. **Community Support**: Leverage open-source community for edge cases

---

## 8. Migration Strategy

### Option A: Hard Cut-Over (Aggressive)

```
Week 1-6: Build native SSO
Week 7:   Migrate all tenants
Week 8:   Remove WorkOS
```

**Pros**: Fast, clean codebase
**Cons**: Risky, requires downtime

### Option B: Feature Flag (Conservative)

```
Week 1-6: Build native SSO
Week 7:   Enable for new tenants only
Week 8+:  Gradual migration of existing tenants
Month 3:  Deprecate WorkOS
Month 6:  Remove WorkOS
```

**Pros**: Safe, reversible
**Cons**: Maintain both codepaths

### Option C: Hybrid (Recommended)

```
Week 1-6: Build native SSO with OIDC + SAML
Week 7:   Release as "beta" with opt-in
Week 8-12: Collect feedback, fix bugs
Month 4:  Announce GA, auto-migrate new tenants
Month 6:  Migrate existing tenants with consent
Month 9:  Mark WorkOS deprecated
Month 12: Remove WorkOS (optional - keep for enterprise)
```

**Pros**: Balanced risk, user choice
**Cons**: Longer timeline

### Migration API

```go
// POST /v1/tenants/{id}/sso-providers/migrate-from-workos
func MigrateFromWorkOS(ctx context.Context, tenantID uuid.UUID) error {
    // 1. Fetch WorkOS configuration
    workosConfig := getWorkOSConfig(ctx, tenantID)

    // 2. Determine provider type from connection metadata
    providerType := detectProviderType(workosConfig.ConnectionID)

    // 3. Create native provider
    provider := &SSOProvider{
        TenantID: tenantID,
        Type:     providerType,
        Name:     "Migrated from WorkOS",
        // Map WorkOS fields to native fields
    }

    // 4. Test new provider
    if err := testProvider(ctx, provider); err != nil {
        return fmt.Errorf("migration test failed: %w", err)
    }

    // 5. Activate native provider
    if err := createProvider(ctx, provider); err != nil {
        return err
    }

    // 6. Disable WorkOS (keep config for rollback)
    disableWorkOS(ctx, tenantID)

    return nil
}
```

---

## 9. Additional Features to Consider

### Directory Sync (SCIM)
- WorkOS provides User Provisioning (SCIM 2.0)
- **Native Implementation**: `github.com/elimity-com/scim` (Go SCIM server)
- **Endpoints**: `/scim/v2/Users`, `/scim/v2/Groups`
- **Value**: Automatic user/group sync from IdP
- **Priority**: Medium (enterprise feature)

### Audit Logs
- WorkOS provides centralized audit logs
- **Native Implementation**: Already have events system (`auth.sso.login.success`)
- **Enhancement**: Export to Elasticsearch, Splunk, Datadog
- **Priority**: Low (already have basic logging)

### Magic Links / Passwordless
- WorkOS supports magic links
- **Native Implementation**: Already feasible with current JWT system
- **Priority**: Low (not SSO-specific)

### Multi-Factor Authentication (MFA)
- WorkOS MFA separate from SSO
- **Native Implementation**: TOTP (RFC 6238), WebAuthn
- **Libraries**: `github.com/pquerna/otp`, `github.com/go-webauthn/webauthn`
- **Priority**: High (security feature)

---

## 10. Comparison Matrix

| Feature | WorkOS | Native OIDC/SAML | Better Auth |
|---------|--------|------------------|-------------|
| **Cost** | €150/mo/tenant | €0 (infra only) | €0 (self-hosted) |
| **OIDC Support** | ✅ | ✅ | ✅ |
| **SAML Support** | ✅ | ✅ | ✅ |
| **Directory Sync** | ✅ | ❌ (future) | ❌ |
| **Admin Portal** | ✅ | 🟡 (build required) | 🟡 (build required) |
| **Audit Logs** | ✅ | 🟡 (export required) | ❌ |
| **Setup Complexity** | Low | Medium | Medium |
| **Maintenance** | Low | High | Medium |
| **Customization** | Low | High | High |
| **Open Source** | ❌ | ✅ | ✅ |
| **Data Privacy** | ❌ (3rd party) | ✅ (self-hosted) | ✅ (self-hosted) |
| **Vendor Lock-in** | ❌ | ✅ | ✅ |

---

## 11. Recommended Next Steps

### Immediate (This Week)
1. ✅ Review this brainstorm document with team
2. ✅ Decide: Native implementation vs. keep WorkOS
3. ✅ If native: Choose migration strategy (A/B/C)
4. ✅ Assign engineering resources

### Short-term (Weeks 1-2)
1. Spike: Prototype OIDC provider with go-oidc
2. Test with Google Workspace + Azure AD
3. Design database schema
4. Create project board with tasks

### Medium-term (Weeks 3-8)
1. Implement full OIDC + SAML support
2. Build management UI
3. Write comprehensive tests
4. Security audit

### Long-term (Months 3-6)
1. Migrate existing WorkOS tenants
2. Add SCIM directory sync
3. Build advanced features (domain verification, cert management)
4. Open-source documentation and guides

---

## 12. Final Recommendation

**✅ Proceed with native OIDC/SAML implementation using Option C (Hybrid Migration)**

### Why?

1. **Cost**: Massive savings for open-source project (€1,800/year per tenant)
2. **Alignment**: Better Auth proves this is feasible and production-ready
3. **Control**: Full customization for open-source community
4. **Feasibility**: Go has excellent OIDC/SAML libraries (go-oidc, crewjam/saml)
5. **Risk**: Mitigated by hybrid rollout and parallel WorkOS support

### Success Criteria

- ✅ 99.9% uptime for SSO flows
- ✅ <500ms p95 latency for auth requests
- ✅ Support top 5 IdPs (Google, Microsoft, Okta, OneLogin, Azure AD)
- ✅ 100% feature parity with WorkOS for core SSO
- ✅ Zero-downtime migration for existing tenants
- ✅ Comprehensive documentation + setup guides

### Expected Outcomes

- **6 months**: Native SSO production-ready
- **12 months**: WorkOS fully deprecated (optional to keep)
- **Cost savings**: €150-€15,000/month depending on tenant count
- **Community impact**: Major feature for open-source Guard adoption

---

## Questions for Discussion

1. **Timeline**: Is 8-week implementation realistic with current team capacity?
2. **Priorities**: OIDC-only first, or OIDC+SAML together?
3. **WorkOS**: Keep as "enterprise tier" option or fully remove?
4. **Directory Sync**: Required for v1 or can be v2 feature?
5. **UI/UX**: Build admin portal in v1 or use API-only approach?
6. **Testing**: Which IdPs should we prioritize for integration testing?
7. **Security**: Internal audit sufficient or hire external firm?
8. **Documentation**: Who owns the IdP-specific setup guides?

---

**Document Version**: 1.0
**Date**: 2025-11-11
**Author**: Claude (AI Assistant)
**Status**: Draft for Review
