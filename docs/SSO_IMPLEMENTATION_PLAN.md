# SSO Native Implementation Plan (ADR-0001)

**Project**: Native OIDC & SAML 2.0 Implementation to replace WorkOS  
**Timeline**: 6-8 weeks  
**Status**: Ready for Implementation  

---

## Executive Summary

Replace WorkOS (€150/month per tenant) with native OIDC and SAML 2.0 support using established Go libraries:
- **OIDC**: `coreos/go-oidc` 
- **SAML**: `crewjam/saml`

**Success Criteria**:
- Support top 5 IdPs (Google, Azure AD, Okta, OneLogin, Auth0)
- <500ms p95 latency
- 99.9% uptime
- Zero-downtime migration from WorkOS
- Full test coverage (80%+)

---

## Phase 0: Database Schema & Migration Setup

**Duration**: 2-3 days  
**Dependencies**: None  
**Goal**: Create database foundation for SSO providers

### Tasks

#### 0.1 Create Migration File
**File**: `migrations/000010_sso_providers.sql`

**Content**:
- `sso_providers` table (multi-tenant provider configuration)
- `sso_auth_attempts` table (audit trail)
- `sso_sessions` table (for Single Logout support)
- Extend `auth_identities` table with SSO columns
- Indexes for performance

**Key Constraints**:
```sql
-- Provider type validation
CHECK (provider_type IN ('oidc', 'saml', 'oauth2', 'workos', 'dev'))

-- OIDC requires issuer + client_id
-- SAML requires entity_id + idp_entity_id
```

#### 0.2 Create sqlc Queries
**File**: `internal/db/queries/sso_providers.sql`

**Required Queries**:
```sql
-- name: CreateSSOProvider :one
-- name: GetSSOProvider :one
-- name: GetSSOProviderBySlug :one
-- name: ListSSOProviders :many
-- name: UpdateSSOProvider :exec
-- name: DeleteSSOProvider :exec
-- name: FindSSOProviderByDomain :one
-- name: CreateSSOAuthAttempt :one
-- name: UpdateSSOAuthAttempt :exec
-- name: GetSSOAuthAttemptByState :one
-- name: CreateSSOSession :one
-- name: GetActiveSSOSessions :many
-- name: TerminateSSOSession :exec
```

#### 0.3 Generate sqlc Code
```bash
sqlc generate
go build ./...
```

### Tests

**File**: `internal/db/sqlc/sso_providers_test.go`

```go
func TestCreateSSOProvider(t *testing.T)
func TestGetSSOProviderBySlug(t *testing.T)
func TestFindSSOProviderByDomain(t *testing.T)
func TestSSOAuthAttempts(t *testing.T)
```

**Migration Test**: 
```bash
# Run up migration
goose -dir migrations postgres "..." up

# Run down migration
goose -dir migrations postgres "..." down

# Verify clean state
```

### Documentation

**File**: `docs/sso/DATABASE_SCHEMA.md`

- ER diagram (tables and relationships)
- Column descriptions
- Index strategy
- Query patterns
- Performance considerations

### Acceptance Criteria
- ✅ Migration runs up/down cleanly
- ✅ All indexes created
- ✅ sqlc generates without errors
- ✅ Code compiles
- ✅ Basic CRUD tests pass

---

## Phase 1: OIDC Core Implementation

**Duration**: 4-5 days  
**Dependencies**: Phase 0  
**Goal**: Implement OpenID Connect provider support

### Tasks

#### 1.1 Create Domain Types
**File**: `internal/auth/sso/domain/types.go`

**Interfaces**:
```go
type SSOProvider interface {
    Start(ctx context.Context, opts StartOptions) (*StartResult, error)
    Callback(ctx context.Context, req CallbackRequest) (*Profile, error)
    GetMetadata(ctx context.Context) (*Metadata, error)
    ValidateConfig() error
    Type() ProviderType
}
```

**Types**:
- `ProviderType` enum (oidc, saml, oauth2, workos, dev)
- `StartOptions` / `StartResult`
- `CallbackRequest` / `Profile`
- `Config` (provider configuration)
- `Metadata`

#### 1.2 Implement OIDC Provider
**File**: `internal/auth/sso/provider/oidc.go`

**Dependencies**:
```go
import (
    "github.com/coreos/go-oidc/v3/oidc"
    "golang.org/x/oauth2"
)
```

**Key Methods**:

```go
func NewOIDCProvider(ctx context.Context, config *domain.Config) (*OIDCProvider, error)
    // - Discover OIDC configuration from issuer
    // - Build OAuth2 config
    // - Create ID token verifier

func (p *OIDCProvider) Start(ctx context.Context, opts domain.StartOptions) (*domain.StartResult, error)
    // - Generate secure nonce
    // - Build authorization URL with PKCE

func (p *OIDCProvider) Callback(ctx context.Context, req domain.CallbackRequest) (*domain.Profile, error)
    // - Exchange code for token
    // - Verify ID token signature
    // - Parse claims
    // - Apply attribute mapping
    // - Return user profile
```

**Utilities**:
```go
func generateNonce() (string, error)
func applyAttributeMapping(profile *domain.Profile, claims map[string]interface{}, mapping map[string][]string)
```

#### 1.3 Add Dependencies
```bash
go get github.com/coreos/go-oidc/v3/oidc
go get golang.org/x/oauth2
```

### Tests

**File**: `internal/auth/sso/provider/oidc_test.go`

```go
func TestOIDCProvider_Start(t *testing.T)
    // Test authorization URL generation
    // Verify nonce generation
    // Check state inclusion

func TestOIDCProvider_Callback_Success(t *testing.T)
    // Mock token exchange
    // Mock ID token verification
    // Verify profile extraction

func TestOIDCProvider_Callback_InvalidToken(t *testing.T)
    // Test expired token
    // Test invalid signature
    // Test missing claims

func TestOIDCProvider_AttributeMapping(t *testing.T)
    // Test custom attribute mapping
    // Test fallback attributes
    // Test missing attributes

func TestOIDCProvider_ValidateConfig(t *testing.T)
    // Test missing issuer
    // Test missing client_id
    // Test missing client_secret
```

**Integration Test**: `internal/auth/sso/provider/oidc_integration_test.go`

```go
func TestOIDCProvider_RealFlow(t *testing.T)
    // Use mock OIDC server (testify/http)
    // Complete full auth flow
    // Verify end-to-end
```

### Documentation

**File**: `docs/sso/OIDC_IMPLEMENTATION.md`

- OIDC flow diagram
- Configuration parameters
- Supported OIDC features
- Attribute mapping examples
- Common errors and solutions

**File**: `docs/sso/providers/GOOGLE_WORKSPACE.md`

- Setup instructions for Google Workspace
- OAuth consent screen configuration
- Redirect URI setup
- Testing guide

**File**: `docs/sso/providers/AZURE_AD.md`

- Setup instructions for Azure AD
- App registration
- API permissions
- Testing guide

### Acceptance Criteria
- ✅ OIDC provider implements SSOProvider interface
- ✅ Start flow generates valid authorization URL
- ✅ Callback flow validates tokens correctly
- ✅ Attribute mapping works
- ✅ All tests pass (80%+ coverage)
- ✅ Code compiles and lints clean

---

## Phase 2: SAML Core Implementation

**Duration**: 5-7 days  
**Dependencies**: Phase 1  
**Goal**: Implement SAML 2.0 Service Provider support

### Tasks

#### 2.1 Implement SAML Provider
**File**: `internal/auth/sso/provider/saml.go`

**Dependencies**:
```go
import (
    "github.com/crewjam/saml"
    "github.com/crewjam/saml/samlsp"
)
```

**Key Methods**:

```go
func NewSAMLProvider(ctx context.Context, config *domain.Config) (*SAMLProvider, error)
    // - Parse SP certificate and private key
    // - Parse IdP metadata (XML or URL)
    // - Create ServiceProvider instance
    // - Configure SAML options

func (p *SAMLProvider) Start(ctx context.Context, opts domain.StartOptions) (*domain.StartResult, error)
    // - Build AuthnRequest
    // - Sign request (if configured)
    // - Generate redirect URL
    // - Return authorization URL

func (p *SAMLProvider) Callback(ctx context.Context, req domain.CallbackRequest) (*domain.Profile, error)
    // - Parse SAML response
    // - Validate signature
    // - Extract assertions
    // - Apply attribute mapping
    // - Extract session info (for SLO)
    // - Return user profile

func (p *SAMLProvider) GetMetadata(ctx context.Context) (*domain.Metadata, error)
    // - Generate SP metadata XML
    // - Include ACS URL, Entity ID, SLO URL
```

**Utilities**:
```go
func parseCertificate(pemData string) (*x509.Certificate, error)
func parsePrivateKey(pemData string) (*rsa.PrivateKey, error)
```

#### 2.2 Add Certificate Management
**File**: `internal/auth/sso/provider/certs.go`

```go
func GenerateSelfSignedCert(commonName string, validDays int) (certPEM, keyPEM string, err error)
func ValidateCertExpiry(certPEM string) (time.Time, error)
```

#### 2.3 Add Dependencies
```bash
go get github.com/crewjam/saml
```

### Tests

**File**: `internal/auth/sso/provider/saml_test.go`

```go
func TestSAMLProvider_Start(t *testing.T)
    // Test AuthnRequest generation
    // Verify request signing (if enabled)
    // Check redirect URL format

func TestSAMLProvider_Callback_Success(t *testing.T)
    // Mock SAML response
    // Mock signature verification
    // Verify assertion parsing
    // Test attribute extraction

func TestSAMLProvider_Callback_InvalidSignature(t *testing.T)
    // Test tampered response
    // Test expired assertion
    // Test replay attack prevention

func TestSAMLProvider_GetMetadata(t *testing.T)
    // Verify SP metadata generation
    // Check XML validity
    // Verify ACS URL, Entity ID

func TestSAMLProvider_AttributeMapping(t *testing.T)
    // Test SAML attribute mapping
    // Test multi-value attributes
    // Test missing attributes

func TestCertificateManagement(t *testing.T)
    // Test certificate parsing
    // Test key parsing
    // Test self-signed cert generation
```

**Integration Test**: `internal/auth/sso/provider/saml_integration_test.go`

```go
func TestSAMLProvider_RealFlow(t *testing.T)
    // Use mock SAML IdP
    // Complete full auth flow
    // Test POST binding
```

### Documentation

**File**: `docs/sso/SAML_IMPLEMENTATION.md`

- SAML 2.0 flow diagram (SP-initiated)
- Configuration parameters
- Certificate management
- Attribute mapping
- Common errors and solutions

**File**: `docs/sso/providers/OKTA_SAML.md`

- Setup instructions for Okta
- SAML app creation
- Attribute statements
- Certificate upload
- Testing guide

**File**: `docs/sso/providers/ONELOGIN_SAML.md`

- Setup instructions for OneLogin
- SAML connector configuration
- Parameter mapping
- Testing guide

**File**: `docs/sso/CERTIFICATE_MANAGEMENT.md`

- Generate self-signed certificates
- Certificate renewal process
- Key storage security
- Expiry monitoring

### Acceptance Criteria
- ✅ SAML provider implements SSOProvider interface
- ✅ Start flow generates valid AuthnRequest
- ✅ Callback flow validates SAML responses
- ✅ Signature verification works
- ✅ SP metadata generation works
- ✅ All tests pass (80%+ coverage)
- ✅ Code compiles and lints clean

---

## Phase 3: Service Layer & Business Logic

**Duration**: 3-4 days  
**Dependencies**: Phase 1, Phase 2  
**Goal**: Orchestrate SSO flows and manage providers

### Tasks

#### 3.1 Create Provider Registry
**File**: `internal/auth/sso/service/registry.go`

```go
type ProviderRegistry struct {
    factories map[domain.ProviderType]ProviderFactory
}

func NewProviderRegistry() *ProviderRegistry
    // Register OIDC provider
    // Register SAML provider
    // Register Dev provider (for testing)

func (r *ProviderRegistry) Register(providerType domain.ProviderType, factory ProviderFactory)
func (r *ProviderRegistry) Create(ctx context.Context, config *domain.Config) (domain.SSOProvider, error)
```

#### 3.2 Create Repository Layer
**File**: `internal/auth/sso/domain/repository.go` (interface)

```go
type Repository interface {
    Create(ctx context.Context, config *Config) error
    GetByID(ctx context.Context, tenantID, providerID uuid.UUID) (*Config, error)
    GetBySlug(ctx context.Context, tenantID uuid.UUID, slug string) (*Config, error)
    List(ctx context.Context, tenantID uuid.UUID, filters ListFilters) ([]*Config, int64, error)
    Update(ctx context.Context, config *Config) error
    Delete(ctx context.Context, tenantID, providerID uuid.UUID) error
    FindByDomain(ctx context.Context, tenantID uuid.UUID, domain string) (*Config, error)
    // Auth attempts
    CreateAuthAttempt(ctx context.Context, attempt *AuthAttempt) error
    GetAuthAttemptByState(ctx context.Context, state string) (*AuthAttempt, error)
    UpdateAuthAttempt(ctx context.Context, attemptID uuid.UUID, status, errorCode, errorMessage string, userID *uuid.UUID) error
    // Sessions
    CreateSession(ctx context.Context, session *Session) error
    GetActiveSessions(ctx context.Context, userID uuid.UUID) ([]*Session, error)
    TerminateSession(ctx context.Context, sessionID uuid.UUID) error
}
```

**File**: `internal/auth/sso/repository/sqlc.go` (implementation)

```go
func New(pool *pgxpool.Pool) domain.Repository
func (r *sqlcRepository) Create(ctx context.Context, config *domain.Config) error
// Implement all repository methods using sqlc queries
```

#### 3.3 Implement SSO Service
**File**: `internal/auth/sso/service/service.go`

```go
type Service struct {
    repo         domain.Repository
    userRepo     authdomain.Repository
    registry     *ProviderRegistry
    redis        *redis.Client
    eventPub     evdomain.Publisher
    cfg          config.Config
    log          zerolog.Logger
}

func New(...) *Service

func (s *Service) Start(ctx context.Context, tenantID uuid.UUID, providerSlug, redirectURI, ipAddress, userAgent string) (*StartResult, error)
    // 1. Load provider configuration from DB
    // 2. Create provider instance from registry
    // 3. Generate secure state
    // 4. Create auth attempt (audit)
    // 5. Call provider.Start()
    // 6. Store state in Redis (10min TTL)
    // 7. Return authorization URL

func (s *Service) Callback(ctx context.Context, tenantID uuid.UUID, providerSlug, code, state, samlResponse, ipAddress, userAgent string) (*CallbackResult, error)
    // 1. Validate state from Redis (atomic get-delete)
    // 2. Load provider configuration
    // 3. Create provider instance
    // 4. Call provider.Callback()
    // 5. Validate email
    // 6. Find or create user
    // 7. Create/update auth identity
    // 8. Update auth attempt (success)
    // 9. Publish success event
    // 10. Return user info

func (s *Service) GetProviderByDomain(ctx context.Context, tenantID uuid.UUID, email string) (*domain.Config, error)
    // Extract domain from email
    // Query DB for provider with matching domain
```

**Utilities**:
```go
func generateSecureState() (string, error)
func extractDomain(email string) string
```

#### 3.4 Add Factory
**File**: `internal/auth/sso/factory.go`

```go
func NewSSOService(
    db *pgxpool.Pool,
    userRepo authdomain.Repository,
    redisClient *redis.Client,
    eventPub evdomain.Publisher,
    cfg config.Config,
) *service.Service
    // Wire up all dependencies
```

### Tests

**File**: `internal/auth/sso/service/service_test.go`

```go
func TestService_Start_OIDC(t *testing.T)
func TestService_Start_SAML(t *testing.T)
func TestService_Start_DisabledProvider(t *testing.T)
func TestService_Callback_NewUser(t *testing.T)
func TestService_Callback_ExistingUser(t *testing.T)
func TestService_Callback_InvalidState(t *testing.T)
func TestService_Callback_ExpiredState(t *testing.T)
func TestService_GetProviderByDomain(t *testing.T)
```

**File**: `internal/auth/sso/repository/sqlc_test.go`

```go
func TestRepository_Create(t *testing.T)
func TestRepository_GetBySlug(t *testing.T)
func TestRepository_FindByDomain(t *testing.T)
func TestRepository_List(t *testing.T)
func TestRepository_Update(t *testing.T)
func TestRepository_Delete(t *testing.T)
```

### Documentation

**File**: `docs/sso/SERVICE_ARCHITECTURE.md`

- Service layer architecture
- State management (Redis)
- User provisioning flow
- Event publishing
- Error handling strategy

### Acceptance Criteria
- ✅ Service orchestrates full SSO flow
- ✅ State management works (Redis)
- ✅ User creation/linking works
- ✅ Domain-based routing works
- ✅ All tests pass (80%+ coverage)
- ✅ Code compiles and lints clean

---

## Phase 4: HTTP Controllers & API Endpoints

**Duration**: 3-4 days  
**Dependencies**: Phase 3  
**Goal**: Expose REST API for SSO flows

### Tasks

#### 4.1 Create SSO Controller
**File**: `internal/auth/sso/controller/http.go`

**Endpoints**:

```go
// Public endpoints (no auth required)
GET  /api/v1/auth/sso/:provider/start
    Query params: tenant_id, redirect_uri
    Response: HTTP 302 redirect to IdP

GET  /api/v1/auth/sso/:provider/callback
POST /api/v1/auth/sso/:provider/callback
    Query params: code, state (OIDC)
    Form params: SAMLResponse, RelayState (SAML)
    Response: Redirect or JSON with session token

GET  /api/v1/auth/sso/saml/:provider/metadata
    Response: SP metadata XML
```

**Implementation**:
```go
func (c *Controller) start(ctx echo.Context) error
func (c *Controller) callback(ctx echo.Context) error
func (c *Controller) samlMetadata(ctx echo.Context) error
```

#### 4.2 Create Admin Controller
**File**: `internal/auth/sso/controller/admin.go`

**Endpoints** (require JWT auth):

```go
POST   /api/v1/tenants/:tenant_id/sso-providers
GET    /api/v1/tenants/:tenant_id/sso-providers
GET    /api/v1/tenants/:tenant_id/sso-providers/:id
PUT    /api/v1/tenants/:tenant_id/sso-providers/:id
DELETE /api/v1/tenants/:tenant_id/sso-providers/:id

GET    /api/v1/tenants/:tenant_id/sso-providers/:id/auth-attempts
```

**DTOs**:
```go
type CreateProviderRequest struct {
    Name         string   `json:"name" validate:"required"`
    Slug         string   `json:"slug" validate:"required,alphanum"`
    ProviderType string   `json:"provider_type" validate:"required,oneof=oidc saml"`
    Issuer       string   `json:"issuer,omitempty"`
    ClientID     string   `json:"client_id,omitempty"`
    ClientSecret string   `json:"client_secret,omitempty"`
    Domains      []string `json:"domains,omitempty"`
    // ... SAML fields
}

type ProviderResponse struct {
    ID           uuid.UUID `json:"id"`
    TenantID     uuid.UUID `json:"tenant_id"`
    Name         string    `json:"name"`
    Slug         string    `json:"slug"`
    ProviderType string    `json:"provider_type"`
    Enabled      bool      `json:"enabled"`
    Domains      []string  `json:"domains"`
    CreatedAt    time.Time `json:"created_at"`
    UpdatedAt    time.Time `json:"updated_at"`
}
```

#### 4.3 Update OpenAPI Spec
**File**: `docs/swagger.yaml`

Add specifications for:
- SSO start endpoint
- SSO callback endpoint
- SAML metadata endpoint
- Admin CRUD endpoints
- Request/response schemas

#### 4.4 Register Routes
**File**: `cmd/api/main.go`

```go
// Register SSO routes
ssoController := sso_controller.New(ssoService)
ssoController.Register(e)
```

### Tests

**File**: `internal/auth/sso/controller/http_test.go`

```go
func TestController_Start_OIDC(t *testing.T)
    // Test redirect to IdP
    // Verify state generation
    // Check authorization URL

func TestController_Start_InvalidProvider(t *testing.T)
func TestController_Start_MissingTenantID(t *testing.T)

func TestController_Callback_OIDC_Success(t *testing.T)
    // Mock successful callback
    // Verify session creation

func TestController_Callback_SAML_Success(t *testing.T)
    // Test POST binding
    // Verify SAMLResponse parsing

func TestController_Callback_InvalidState(t *testing.T)
func TestController_SAMLMetadata(t *testing.T)
```

**File**: `internal/auth/sso/controller/admin_test.go`

```go
func TestAdminController_CreateProvider(t *testing.T)
func TestAdminController_CreateProvider_InvalidInput(t *testing.T)
func TestAdminController_ListProviders(t *testing.T)
func TestAdminController_GetProvider(t *testing.T)
func TestAdminController_UpdateProvider(t *testing.T)
func TestAdminController_DeleteProvider(t *testing.T)
func TestAdminController_Unauthorized(t *testing.T)
```

**E2E Tests**: `e2e/sso_test.go`

```go
func TestSSO_OIDC_FullFlow(t *testing.T)
func TestSSO_SAML_FullFlow(t *testing.T)
func TestSSO_DomainRouting(t *testing.T)
```

### Documentation

**File**: `docs/sso/API_REFERENCE.md`

- Endpoint documentation
- Request/response examples
- cURL examples
- Error codes

**File**: `docs/sso/API_EXAMPLES.md`

- Complete flow examples
- Postman collection
- SDK usage examples

### Acceptance Criteria
- ✅ All endpoints implemented
- ✅ Input validation works
- ✅ Authentication/authorization works
- ✅ Error responses are consistent
- ✅ OpenAPI spec updated
- ✅ All tests pass
- ✅ E2E flows work

---

## Phase 5: Testing & Quality Assurance

**Duration**: 5-6 days  
**Dependencies**: Phase 4  
**Goal**: Comprehensive test coverage and quality assurance

### Tasks

#### 5.1 Unit Tests (Target: 80%+ coverage)

**Files to test**:
- `internal/auth/sso/provider/*.go`
- `internal/auth/sso/service/*.go`
- `internal/auth/sso/repository/*.go`
- `internal/auth/sso/controller/*.go`

**Generate coverage report**:
```bash
go test -coverprofile=coverage.out ./internal/auth/sso/...
go tool cover -html=coverage.out -o coverage.html
```

#### 5.2 Integration Tests

**File**: `internal/auth/sso/integration_test.go`

```go
func TestIntegration_OIDC_FullFlow(t *testing.T)
    // Setup: DB, Redis, mock OIDC server
    // Execute: Complete auth flow
    // Verify: User created, session established

func TestIntegration_SAML_FullFlow(t *testing.T)
    // Setup: DB, Redis, mock SAML IdP
    // Execute: Complete auth flow
    // Verify: User created, session established

func TestIntegration_ConcurrentAuthentications(t *testing.T)
    // Test concurrent SSO flows
    // Verify no race conditions
```

#### 5.3 E2E Tests (Playwright)

**File**: `ui/e2e/sso-oidc.spec.ts`

```typescript
test('SSO login with OIDC provider', async ({ page }) => {
  // Navigate to login
  // Click "Login with Google"
  // Complete OAuth flow (mock)
  // Verify redirect to dashboard
});

test('SSO domain-based routing', async ({ page }) => {
  // Enter email with domain
  // Verify auto-detection of provider
  // Complete SSO flow
});
```

**File**: `ui/e2e/sso-saml.spec.ts`

```typescript
test('SSO login with SAML provider', async ({ page }) => {
  // Navigate to login
  // Click "Login with Okta"
  // Complete SAML flow (mock)
  // Verify redirect to dashboard
});
```

**File**: `ui/e2e/sso-admin.spec.ts`

```typescript
test('Admin creates SSO provider', async ({ page }) => {
  // Login as admin
  // Navigate to SSO settings
  // Create new OIDC provider
  // Verify provider appears in list
});

test('Admin updates SSO provider', async ({ page }) => {
  // Edit existing provider
  // Update configuration
  // Save changes
  // Verify updates persisted
});
```

#### 5.4 Security Tests

**File**: `internal/auth/sso/security_test.go`

```go
func TestSecurity_StateTampering(t *testing.T)
    // Attempt callback with modified state
    // Verify rejection

func TestSecurity_StateReplay(t *testing.T)
    // Use same state twice
    // Verify second attempt fails

func TestSecurity_ExpiredState(t *testing.T)
    // Wait for state to expire
    // Attempt callback
    // Verify rejection

func TestSecurity_CSRFProtection(t *testing.T)
    // Test CSRF token validation

func TestSecurity_SQLInjection(t *testing.T)
    // Test malicious inputs
    // Verify parameterized queries
```

**Run gosec**:
```bash
gosec -exclude=G104 ./internal/auth/sso/...
```

#### 5.5 Performance Tests

**File**: `ops/k6/sso_load.js`

```javascript
export default function() {
  // Simulate SSO login
  // Measure latency
  // Track success rate
}

export let options = {
  stages: [
    { duration: '1m', target: 50 },  // Ramp-up
    { duration: '3m', target: 50 },  // Steady
    { duration: '1m', target: 100 }, // Peak
    { duration: '1m', target: 0 },   // Ramp-down
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'], // 95% under 500ms
    http_req_failed: ['rate<0.01'],   // <1% errors
  },
};
```

**Run load test**:
```bash
k6 run ops/k6/sso_load.js
```

#### 5.6 Database Performance Tests

**File**: `internal/auth/sso/benchmark_test.go`

```go
func BenchmarkRepository_GetBySlug(b *testing.B)
func BenchmarkRepository_FindByDomain(b *testing.B)
func BenchmarkService_Start(b *testing.B)
func BenchmarkService_Callback(b *testing.B)
```

### Tests Checklist

- [ ] Unit tests: 80%+ coverage
- [ ] Integration tests: All flows covered
- [ ] E2E tests: User journeys covered
- [ ] Security tests: All attack vectors tested
- [ ] Performance tests: Meet SLA (<500ms p95)
- [ ] gosec scan: No critical issues
- [ ] golangci-lint: No errors
- [ ] Race detector: `go test -race`

### Documentation

**File**: `docs/sso/TESTING_STRATEGY.md`

- Test pyramid approach
- Coverage requirements
- CI/CD integration
- Performance benchmarks

**File**: `docs/sso/SECURITY_AUDIT.md`

- Security test results
- Vulnerability scan results
- Remediation plans

### Acceptance Criteria
- ✅ 80%+ test coverage
- ✅ All tests pass
- ✅ No security vulnerabilities
- ✅ Performance meets SLA
- ✅ No race conditions
- ✅ CI/CD pipeline green

---

## Phase 6: Documentation & Examples

**Duration**: 3-4 days  
**Dependencies**: Phase 5  
**Goal**: Comprehensive documentation for users and developers

### Tasks

#### 6.1 User Documentation

**File**: `docs/sso/USER_GUIDE.md`

Contents:
- What is SSO?
- Benefits of SSO
- Supported providers
- Getting started
- Domain-based routing
- Troubleshooting

**File**: `docs/sso/SETUP_GOOGLE.md`

Step-by-step guide:
1. Create OAuth 2.0 credentials in Google Cloud Console
2. Configure OAuth consent screen
3. Set redirect URIs
4. Create SSO provider in Guard
5. Test login flow

**File**: `docs/sso/SETUP_AZURE.md`

Step-by-step guide:
1. Register app in Azure AD
2. Configure API permissions
3. Create client secret
4. Set redirect URIs
5. Create SSO provider in Guard
6. Test login flow

**File**: `docs/sso/SETUP_OKTA.md`

Step-by-step guide (SAML):
1. Create SAML app in Okta
2. Configure SAML settings
3. Download IdP metadata
4. Create SSO provider in Guard
5. Upload SP metadata to Okta
6. Test login flow

**File**: `docs/sso/SETUP_ONELOGIN.md`

Step-by-step guide (SAML):
1. Create SAML connector in OneLogin
2. Configure SAML settings
3. Map attributes
4. Download IdP certificate
5. Create SSO provider in Guard
6. Test login flow

**File**: `docs/sso/SETUP_AUTH0.md`

Step-by-step guide (OIDC):
1. Create application in Auth0
2. Configure callback URLs
3. Get client credentials
4. Create SSO provider in Guard
5. Test login flow

**File**: `docs/sso/DOMAIN_ROUTING.md`

- How domain-based routing works
- Configuration examples
- Multi-provider scenarios
- Priority rules

**File**: `docs/sso/TROUBLESHOOTING.md`

Common issues:
- "Invalid state" error
- "Email not verified" error
- "Provider not found" error
- Certificate errors (SAML)
- Token validation errors (OIDC)
- Redirect URI mismatch

#### 6.2 Developer Documentation

**File**: `docs/sso/DEVELOPER_GUIDE.md`

Contents:
- Architecture overview
- Provider interface
- Adding custom providers
- State management
- Event system
- Error handling

**File**: `docs/sso/API_INTEGRATION.md`

- API authentication
- SSO flow integration
- Session management
- Error handling
- SDK examples

**File**: `docs/sso/CUSTOM_PROVIDER.md`

How to implement a custom provider:
```go
type CustomProvider struct {
    config *domain.Config
}

func (p *CustomProvider) Start(ctx context.Context, opts domain.StartOptions) (*domain.StartResult, error)
func (p *CustomProvider) Callback(ctx context.Context, req domain.CallbackRequest) (*domain.Profile, error)
// ... implement interface
```

**File**: `docs/sso/MIGRATION_FROM_WORKOS.md`

Migration guide:
1. Audit current WorkOS usage
2. Create equivalent providers in Guard
3. Test in staging
4. Gradual rollout
5. Monitor metrics
6. Decommission WorkOS

**File**: `docs/sso/ATTRIBUTE_MAPPING.md`

- Default attribute mappings
- Custom attribute mappings
- Provider-specific attributes
- JSON configuration examples

#### 6.3 Admin Documentation

**File**: `docs/sso/ADMIN_GUIDE.md`

- Provider configuration
- User provisioning settings
- Security best practices
- Monitoring and alerts
- Certificate renewal

**File**: `docs/sso/CERTIFICATE_MANAGEMENT.md`

- Generate certificates
- Upload certificates
- Renew certificates
- Monitor expiry
- Automate renewal

**File**: `docs/sso/SECURITY_BEST_PRACTICES.md`

- Enforce email verification
- Limit allowed domains
- Enable audit logging
- Monitor failed attempts
- Certificate security

#### 6.4 SDK Examples

**File**: `sdk/go/examples/sso/main.go`

```go
package main

import (
    "github.com/CorvusHold/guard/sdk/go"
)

func main() {
    client := guard.NewClient("https://api.guard.example.com", "api-key")
    
    // Start SSO flow
    result, err := client.SSO.Start(ctx, guard.SSOStartRequest{
        TenantID:    tenantID,
        Provider:    "google",
        RedirectURI: "https://app.example.com/callback",
    })
    
    // Redirect user to result.AuthorizationURL
}
```

**File**: `sdk/ts/examples/sso.ts`

```typescript
import { GuardClient } from '@corvus/guard-sdk';

const client = new GuardClient({
  apiUrl: 'https://api.guard.example.com',
  apiKey: 'api-key',
});

// Start SSO flow
const result = await client.sso.start({
  tenantId: tenantId,
  provider: 'google',
  redirectUri: 'https://app.example.com/callback',
});

// Redirect user
window.location.href = result.authorizationUrl;
```

#### 6.5 Example Applications

**Directory**: `examples/sso-demo/`

Simple demo app:
- Login page with SSO buttons
- Callback handler
- Protected dashboard
- README with setup instructions

**Technologies**:
- Backend: Go (Echo)
- Frontend: React
- Auth: Guard SSO

### Documentation Checklist

- [ ] User guides for all supported providers
- [ ] Developer integration guide
- [ ] API reference documentation
- [ ] SDK examples (Go, TypeScript)
- [ ] Troubleshooting guide
- [ ] Migration guide from WorkOS
- [ ] Admin guide
- [ ] Security best practices
- [ ] Example application

### Acceptance Criteria
- ✅ All provider setup guides complete
- ✅ API documentation complete
- ✅ SDK examples work
- ✅ Example app runs
- ✅ Troubleshooting guide covers common issues
- ✅ Documentation reviewed for clarity

---

## Phase 7: Integration Testing with Real IdPs

**Duration**: 2-3 days  
**Dependencies**: Phase 6  
**Goal**: Verify compatibility with real identity providers

### Tasks

#### 7.1 Setup Test IdP Accounts

**Accounts needed**:
- [ ] Google Workspace test tenant
- [ ] Azure AD test tenant
- [ ] Okta developer account
- [ ] OneLogin developer account
- [ ] Auth0 developer account

#### 7.2 Test OIDC Providers

**Test cases**:

**Google Workspace**:
- [ ] Create OAuth app
- [ ] Configure provider in Guard
- [ ] Test login flow
- [ ] Verify attribute mapping
- [ ] Test error scenarios

**Azure AD**:
- [ ] Register app
- [ ] Configure API permissions
- [ ] Test login flow
- [ ] Verify attribute mapping
- [ ] Test multi-tenant scenarios

**Auth0**:
- [ ] Create application
- [ ] Test login flow
- [ ] Verify attribute mapping
- [ ] Test custom domains

#### 7.3 Test SAML Providers

**Okta**:
- [ ] Create SAML app
- [ ] Upload SP metadata
- [ ] Test login flow
- [ ] Verify attribute statements
- [ ] Test Single Logout

**OneLogin**:
- [ ] Create SAML connector
- [ ] Configure mappings
- [ ] Test login flow
- [ ] Verify attributes
- [ ] Test different NameID formats

#### 7.4 Create Compatibility Matrix

**File**: `docs/sso/COMPATIBILITY_MATRIX.md`

| Provider | Protocol | Status | Known Issues | Notes |
|----------|----------|--------|--------------|-------|
| Google Workspace | OIDC | ✅ Supported | None | Recommended |
| Azure AD | OIDC | ✅ Supported | Multi-tenant requires admin consent | |
| Okta | SAML | ✅ Supported | None | Recommended |
| Okta | OIDC | ✅ Supported | None | |
| OneLogin | SAML | ✅ Supported | Requires SHA-256 signing | |
| Auth0 | OIDC | ✅ Supported | None | |

#### 7.5 Document Provider-Specific Quirks

**File**: `docs/sso/PROVIDER_NOTES.md`

- Azure AD: Multi-tenant apps require admin consent
- Okta: Default NameID format is `emailAddress`
- OneLogin: Requires SHA-256 (not SHA-1)
- Google: Requires verified redirect URIs

### Tests

**File**: `internal/auth/sso/provider_integration_test.go`

```go
// +build integration

func TestGoogleWorkspace_RealFlow(t *testing.T)
    // Skip if no credentials
    // Use real Google OAuth flow
    // Verify success

func TestAzureAD_RealFlow(t *testing.T)
func TestOkta_RealFlow(t *testing.T)
func TestOneLogin_RealFlow(t *testing.T)
func TestAuth0_RealFlow(t *testing.T)
```

**Run with**:
```bash
go test -tags=integration ./internal/auth/sso/...
```

### Documentation

**File**: `docs/sso/INTEGRATION_TEST_RESULTS.md`

- Test results for each provider
- Performance metrics
- Known limitations
- Recommendations

### Acceptance Criteria
- ✅ All providers tested with real accounts
- ✅ Compatibility matrix complete
- ✅ Known issues documented
- ✅ Provider-specific notes captured
- ✅ Integration test suite passes

---

## Phase 8: Monitoring & Observability

**Duration**: 2-3 days  
**Dependencies**: Phase 7  
**Goal**: Production-ready monitoring and alerting

### Tasks

#### 8.1 Add Metrics

**File**: `internal/metrics/sso.go`

```go
package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
    SSOAuthAttempts = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "guard_sso_auth_attempts_total",
            Help: "Total SSO authentication attempts",
        },
        []string{"tenant_id", "provider", "status"}, // status: success, failed
    )

    SSOAuthDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "guard_sso_auth_duration_seconds",
            Help:    "SSO authentication duration",
            Buckets: prometheus.DefBuckets,
        },
        []string{"tenant_id", "provider", "flow"}, // flow: start, callback
    )

    SSOProviderErrors = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "guard_sso_provider_errors_total",
            Help: "Total SSO provider errors",
        },
        []string{"tenant_id", "provider", "error_type"},
    )

    SSOActiveProviders = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "guard_sso_active_providers",
            Help: "Number of active SSO providers",
        },
        []string{"tenant_id", "provider_type"},
    )

    SSOCertificateExpiry = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "guard_sso_certificate_expiry_days",
            Help: "Days until SSO certificate expiry",
        },
        []string{"tenant_id", "provider"},
    )
)

func init() {
    prometheus.MustRegister(
        SSOAuthAttempts,
        SSOAuthDuration,
        SSOProviderErrors,
        SSOActiveProviders,
        SSOCertificateExpiry,
    )
}
```

**Instrument service**:
```go
func (s *Service) Start(ctx context.Context, ...) (*StartResult, error) {
    timer := prometheus.NewTimer(metrics.SSOAuthDuration.WithLabelValues(tenantID.String(), providerSlug, "start"))
    defer timer.ObserveDuration()

    result, err := s.doStart(ctx, ...)
    
    status := "success"
    if err != nil {
        status = "failed"
        metrics.SSOProviderErrors.WithLabelValues(tenantID.String(), providerSlug, classifyError(err)).Inc()
    }
    metrics.SSOAuthAttempts.WithLabelValues(tenantID.String(), providerSlug, status).Inc()
    
    return result, err
}
```

#### 8.2 Add Structured Logging

**Update service logging**:
```go
func (s *Service) Start(ctx context.Context, tenantID uuid.UUID, providerSlug string, ...) (*StartResult, error) {
    log := s.log.With().
        Str("tenant_id", tenantID.String()).
        Str("provider", providerSlug).
        Str("flow", "start").
        Logger()

    log.Info().Msg("sso flow initiated")
    
    // ... business logic
    
    if err != nil {
        log.Error().Err(err).Msg("sso flow failed")
        return nil, err
    }
    
    log.Info().
        Str("state", result.State).
        Msg("sso flow started successfully")
    
    return result, nil
}
```

**PII Redaction**:
```go
func sanitizeEmail(email string) string {
    // user@example.com -> u***r@example.com
}
```

#### 8.3 Add Alerts

**File**: `ops/prometheus/alerts.yml`

```yaml
groups:
  - name: sso_alerts
    interval: 30s
    rules:
      # High failure rate
      - alert: SSOHighFailureRate
        expr: |
          rate(guard_sso_auth_attempts_total{status="failed"}[5m])
          /
          rate(guard_sso_auth_attempts_total[5m])
          > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High SSO failure rate ({{ $labels.provider }})"
          description: "SSO failure rate is {{ $value | humanizePercentage }} for provider {{ $labels.provider }}"

      # Provider unavailable
      - alert: SSOProviderUnavailable
        expr: |
          rate(guard_sso_provider_errors_total{error_type="provider_unavailable"}[5m]) > 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "SSO provider unavailable ({{ $labels.provider }})"
          description: "Provider {{ $labels.provider }} is unreachable"

      # Certificate expiring soon
      - alert: SSOCertificateExpiringSoon
        expr: guard_sso_certificate_expiry_days < 30
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "SSO certificate expiring soon ({{ $labels.provider }})"
          description: "Certificate for {{ $labels.provider }} expires in {{ $value }} days"

      # Certificate expired
      - alert: SSOCertificateExpired
        expr: guard_sso_certificate_expiry_days <= 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "SSO certificate expired ({{ $labels.provider }})"
          description: "Certificate for {{ $labels.provider }} has expired"

      # Slow authentication
      - alert: SSOSlowAuthentication
        expr: |
          histogram_quantile(0.95, rate(guard_sso_auth_duration_seconds_bucket[5m])) > 0.5
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Slow SSO authentication ({{ $labels.provider }})"
          description: "95th percentile auth duration is {{ $value }}s for {{ $labels.provider }}"

      # No SSO activity (might indicate issue)
      - alert: SSONoActivity
        expr: |
          rate(guard_sso_auth_attempts_total[15m]) == 0
        for: 1h
        labels:
          severity: info
        annotations:
          summary: "No SSO authentication activity"
          description: "No SSO authentications in the last hour"
```

#### 8.4 Create Dashboards

**File**: `ops/grafana/dashboards/sso.json`

**Panels**:
1. **SSO Authentication Overview**
   - Total attempts (counter)
   - Success rate (gauge)
   - Failure rate (gauge)

2. **Authentication Flow**
   - Auth attempts over time (graph)
   - Success vs failed (stacked graph)
   - By provider (pie chart)

3. **Performance**
   - Auth duration p50, p95, p99 (graph)
   - By provider (table)

4. **Errors**
   - Error rate over time (graph)
   - Error types (table)
   - By provider (bar chart)

5. **Providers**
   - Active providers (gauge)
   - Provider health (table)
   - Certificate expiry (table)

6. **User Activity**
   - New users created (counter)
   - Existing users logged in (counter)
   - By tenant (table)

#### 8.5 Add Health Checks

**File**: `internal/auth/sso/service/health.go`

```go
func (s *Service) HealthCheck(ctx context.Context) error {
    // Check database connectivity
    if err := s.repo.Ping(ctx); err != nil {
        return fmt.Errorf("database unhealthy: %w", err)
    }

    // Check Redis connectivity
    if err := s.redis.Ping(ctx).Err(); err != nil {
        return fmt.Errorf("redis unhealthy: %w", err)
    }

    return nil
}
```

**Add to health endpoint**:
```go
GET /health/sso
{
  "status": "healthy",
  "checks": {
    "database": "ok",
    "redis": "ok"
  }
}
```

### Tests

**File**: `internal/metrics/sso_test.go`

```go
func TestMetrics_SSOAuthAttempts(t *testing.T)
    // Increment metric
    // Verify counter value

func TestMetrics_SSOAuthDuration(t *testing.T)
    // Record duration
    // Verify histogram

func TestMetrics_SSOCertificateExpiry(t *testing.T)
    // Set expiry gauge
    // Verify value
```

### Documentation

**File**: `docs/sso/MONITORING.md`

- Available metrics
- Alert descriptions
- Dashboard usage
- Troubleshooting with metrics

**File**: `docs/sso/RUNBOOK.md`

Runbook for alerts:
- **SSOHighFailureRate**: Check provider configuration, check IdP status
- **SSOProviderUnavailable**: Verify network connectivity, check IdP status page
- **SSOCertificateExpiringSoon**: Renew certificate
- **SSOCertificateExpired**: Immediately renew certificate
- **SSOSlowAuthentication**: Check database performance, check network latency

### Acceptance Criteria
- ✅ All metrics implemented
- ✅ Structured logging added
- ✅ PII redacted from logs
- ✅ Alerts configured
- ✅ Dashboard created
- ✅ Health checks added
- ✅ Runbook documented

---

## Implementation Checklist

### Pre-Implementation
- [ ] Review ADR-0001
- [ ] Review this implementation plan
- [ ] Setup development environment
- [ ] Create feature branch: `feature/sso-native-implementation`

### Phase Completion
- [ ] Phase 0: Database Schema ✅
- [ ] Phase 1: OIDC Implementation ✅
- [ ] Phase 2: SAML Implementation ✅
- [ ] Phase 3: Service Layer ✅
- [ ] Phase 4: HTTP Controllers ✅
- [ ] Phase 5: Testing ✅
- [ ] Phase 6: Documentation ✅
- [ ] Phase 7: Real IdP Testing ✅
- [ ] Phase 8: Monitoring ✅

### Post-Implementation
- [ ] Code review
- [ ] Security audit
- [ ] Performance testing
- [ ] Documentation review
- [ ] Demo preparation
- [ ] Deployment plan
- [ ] Rollback plan
- [ ] Communication plan

---

## Dependencies

### Go Libraries
```bash
go get github.com/coreos/go-oidc/v3/oidc
go get golang.org/x/oauth2
go get github.com/crewjam/saml
```

### Existing Guard Components
- Database (PostgreSQL)
- Redis (state management)
- User repository
- Event publisher
- HTTP server (Echo)
- JWT middleware

---

## Success Metrics

### Performance
- ✅ <500ms p95 latency for SSO flows
- ✅ Support 100 concurrent authentications
- ✅ Database queries optimized (<50ms)

### Reliability
- ✅ 99.9% uptime
- ✅ <1% error rate
- ✅ Zero data loss

### Quality
- ✅ 80%+ test coverage
- ✅ Zero critical security issues
- ✅ All E2E tests passing

### Documentation
- ✅ Complete API documentation
- ✅ Setup guides for all providers
- ✅ Troubleshooting guide
- ✅ Migration guide

---

## Rollout Plan

### Phase 1: Alpha (Week 7)
- Deploy to staging
- Internal testing
- Fix critical bugs

### Phase 2: Beta (Week 8)
- Deploy to production (feature flag)
- Invite beta testers
- Monitor metrics
- Gather feedback

### Phase 3: GA (Week 9-10)
- Enable for all tenants
- Monitor metrics
- Support existing users

### Phase 4: WorkOS Deprecation (Week 11-24)
- Gradual migration
- Monitor metrics
- Decommission WorkOS

---

## Risk Mitigation

### Technical Risks
- **SAML complexity**: Use battle-tested library (`crewjam/saml`)
- **Token validation**: Use official OIDC library (`coreos/go-oidc`)
- **State management**: Use Redis with TTL
- **Certificate management**: Automated expiry monitoring

### Operational Risks
- **Migration issues**: Feature flag for gradual rollout
- **Provider incompatibility**: Extensive integration testing
- **Performance degradation**: Load testing before GA
- **Security vulnerabilities**: Security audit before GA

---

## Support Plan

### During Implementation
- Daily standup updates
- Slack channel: #sso-implementation
- Weekly demo to stakeholders

### Post-Launch
- Monitor error rates
- Respond to support tickets
- Maintain compatibility matrix
- Update documentation

---

## References

- ADR-0001: Native SSO/OIDC/SAML Implementation
- OpenID Connect Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
- SAML 2.0 Technical Overview: http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0.html
- `coreos/go-oidc` documentation: https://pkg.go.dev/github.com/coreos/go-oidc/v3/oidc
- `crewjam/saml` documentation: https://pkg.go.dev/github.com/crewjam/saml

---

**Document Version**: 1.0  
**Last Updated**: 2025-01-13  
**Owner**: Guard Engineering Team  
**Status**: Ready for Implementation
