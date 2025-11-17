# Guard

**A production-ready, multi-tenant Central Authentication Service (CAS)**

Guard is an identity and authentication platform that provides centralized authentication, authorization, and user management for multi-tenant applications. Built with Go and modern web standards, Guard offers OAuth 2.0 / OpenID Connect compliance, comprehensive security features, and flexible deployment options.

[![Go Version](https://img.shields.io/badge/Go-1.24.6-blue.svg)](https://golang.org)

---

## Features

### Authentication Methods
- **Password-based authentication** - Secure signup, login, and password reset flows
- **Magic links** - Passwordless email authentication
- **SSO integration** - Enterprise SSO via WorkOS (SAML, OAuth)
- **Social providers** - Google, GitHub, and other OAuth providers
- **Multi-factor authentication (MFA)** - TOTP with QR codes and backup codes
- **Cookie mode sessions** – First-party session cookies with automatic token storage

### Authorization
- **Role-Based Access Control (RBAC v2)** - Flexible role and permission system with custom roles
- **Fine-Grained Authorization (FGA)** - Groups, memberships, and ACL tuples for granular access control
- **Permission resolution** - Intelligent permission resolution across roles and groups

### Security & Compliance
- **JWT tokens** - Industry-standard access and refresh tokens
- **Session management** - Secure session tracking and revocation
- **Rate limiting** - Tenant-aware, Redis-backed rate limiting
- **Email verification** - Automated email verification workflows
- **Password policies** - Configurable password strength requirements
- **Audit logging** - Comprehensive audit trail for compliance
- **OAuth 2.0 / OIDC** - RFC 8414 compliant authorization server metadata

### Multi-tenancy
- **Complete tenant isolation** - Data separation at the database level
- **Per-tenant configuration** - Customizable settings for each tenant
- **Tenant-scoped rate limiting** - Independent rate limits per tenant
- **Custom CORS policies** - Per-tenant CORS configuration

### Developer Experience
- **RESTful API** - Clean, well-documented REST endpoints
- **OpenAPI/Swagger docs** - Auto-generated API documentation
- **Multi-language SDKs** - TypeScript (production-ready), Go, Rust (planned)
- **CLI tools** - Seeding and management utilities
- **Hot reload** - Fast development with Air
- **Comprehensive testing** - Unit, integration, E2E, and conformance tests

### Observability
- **Health checks** - Kubernetes-ready liveness and readiness probes
- **Prometheus metrics** - Built-in metrics for monitoring
- **Structured logging** - JSON logging with zerolog
- **Monitoring stack** - Optional Grafana dashboards and alerting

---

## Quick Start

### Prerequisites

- **Go** 1.24.6 or higher
- **Docker & Docker Compose**
- **PostgreSQL** 17 (or via Docker)
- **Redis/Valkey** 7.2 (or via Docker)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/corvusHold/guard.git
   cd guard
   ```

2. **Start infrastructure services**
   ```bash
   make compose-up
   ```

3. **Run database migrations**
   ```bash
   make migrate-up
   ```

4. **Start the development server**
   ```bash
   make dev
   ```

5. **Create a test tenant and user**
   ```bash
   make seed-test
   ```

The API will be available at `http://localhost:8080`

### Verify Installation

```bash
# Check health
curl http://localhost:8080/healthz

# View API documentation
open http://localhost:8080/swagger/index.html

# Get OAuth authorization server metadata (RFC 8414)
curl http://localhost:8080/.well-known/oauth-authorization-server
```

---

## Usage

### Creating Your First Tenant

#### Option 1: Using the CLI (Recommended)

```bash
go run ./cmd/guard-cli default \
  --tenant-name "my-company" \
  --email "admin@my-company.com" \
  --password "SecurePassword123!" \
  --enable-mfa
```

Output:
```
TENANT_ID=550e8400-e29b-41d4-a716-446655440000
EMAIL=admin@my-company.com
USER_ID=660f9500-f39c-52e5-b827-556766550111
TOTP_SECRET=JBSWY3DPEHPK3PXP
BACKUP_CODES=abc123,def456,ghi789
```

#### Option 2: Using the API

```bash
# 1. Create tenant
curl -X POST http://localhost:8080/tenants \
  -H "Content-Type: application/json" \
  -d '{"name": "my-company"}'

# 2. Create admin user
curl -X POST http://localhost:8080/v1/auth/password/signup \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "admin@my-company.com",
    "password": "SecurePassword123!",
    "first_name": "Admin",
    "last_name": "User"
  }'
```

### Authentication Examples

#### Password Login

```bash
curl -X POST http://localhost:8080/v1/auth/password/login \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "admin@my-company.com",
    "password": "SecurePassword123!"
  }'
```

#### Cookie Mode Sessions

Browser-based apps can ask Guard to manage access and refresh tokens as HTTP-only cookies instead of returning them in the JSON body:

```bash
curl -X POST http://localhost:8080/v1/auth/password/login \
  -H "Content-Type: application/json" \
  -H "X-Auth-Mode: cookie" \
  -d '{
    "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "admin@my-company.com",
    "password": "SecurePassword123!"
  }'
```

When `X-Auth-Mode: cookie` is present, Guard will:

1. Set `guard_access_token` and `guard_refresh_token` cookies (HttpOnly, SameSite=Strict, `Secure` when using HTTPS).
2. Return `{ "success": true }` in the HTTP body instead of the raw tokens.
3. Accept future refresh/logout calls by reading the `guard_refresh_token` cookie (omit it from the JSON body).

To refresh cookies, send `POST /v1/auth/refresh` with the same header and allow the server to rotate the cookies. To terminate the session, call `POST /v1/auth/logout` with `X-Auth-Mode: cookie`; Guard clears both cookies and revokes the refresh token.

Remember to enable `credentials: 'include'` (or the equivalent in your HTTP client) and configure CORS to allow credentials if you are making cross-origin requests.

#### Magic Link Authentication

```bash
# Send magic link
curl -X POST http://localhost:8080/v1/auth/magic/send \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@my-company.com"
  }'

# Verify magic link (from email)
curl -X POST http://localhost:8080/v1/auth/magic/verify \
  -H "Content-Type: application/json" \
  -d '{
    "token": "magic_token_from_email"
  }'
```

#### SSO Flow

```bash
# Start SSO authentication
curl -i "http://localhost:8080/v1/auth/sso/google/start?tenant_id=550e8400-e29b-41d4-a716-446655440000"

# Follow redirect to provider, complete authentication
# User will be redirected back with tokens
```

### Configuration

Configure tenant settings via the API:

```bash
curl -X PUT http://localhost:8080/v1/tenants/{tenant_id}/settings \
  -H "Authorization: Bearer {admin_token}" \
  -H "Content-Type: application/json" \
  -d '{
    "app_cors_allowed_origins": "https://app.my-company.com",
    "auth_access_token_ttl": "30m",
    "auth_refresh_token_ttl": "720h",
    "auth_ratelimit_login_limit": "10",
    "auth_ratelimit_login_window": "1m",
    "sso_provider": "workos",
    "sso_workos_client_id": "client_123",
    "sso_workos_client_secret": "wk_live_secret"
  }'
```

---

## Architecture

Guard follows Domain-Driven Design (DDD) principles with clear separation of concerns:

```
guard/
├── cmd/                    # Application entry points
│   ├── api/               # Main API server
│   └── guard-cli/         # CLI tools for seeding and management
├── internal/              # Core business logic
│   ├── auth/             # Authentication domain (main feature)
│   │   ├── controller/   # HTTP handlers
│   │   ├── service/      # Business logic
│   │   ├── repository/   # Data access layer
│   │   └── domain/       # Domain models
│   ├── tenants/          # Multi-tenancy management
│   ├── settings/         # Tenant configuration
│   ├── config/           # Application configuration
│   ├── db/               # Database utilities
│   ├── email/            # Email service
│   ├── events/           # Event publishing
│   ├── logger/           # Logging configuration
│   ├── metrics/          # Prometheus metrics
│   └── platform/         # Shared utilities
├── migrations/           # Database migrations
├── sdk/                  # Multi-language SDKs
│   ├── ts/              # TypeScript SDK
│   ├── go/              # Go SDK
│   ├── spec/            # OpenAPI specification
│   └── conformance/     # Cross-SDK test suite
├── ui/                   # Admin dashboard (React)
├── docs/                 # Documentation
└── ops/                  # Monitoring and load testing
```

### Technology Stack

**Backend:**
- Go 1.24.6
- Echo v4 (HTTP framework)
- PostgreSQL 17 (primary database)
- Redis/Valkey 7.2 (caching, sessions, rate limiting)
- JWT for token-based auth
- Prometheus for metrics

**Frontend:**
- React 19 with TypeScript
- Vite 7 (build tool)
- Radix UI components
- Tailwind CSS 4

**Infrastructure:**
- Docker & Docker Compose
- Prometheus, Grafana, AlertManager
- MailHog (development email testing)
- k6 (load testing)


## SDK Integration

Guard provides official SDKs for multiple languages:

### TypeScript SDK

```bash
npm install @corvus/guard-sdk
```

```typescript
import { GuardClient } from '@corvus/guard-sdk';

const client = new GuardClient({
  baseUrl: 'http://localhost:8080',
  tenantId: '550e8400-e29b-41d4-a716-446655440000'
});

// Password login
const { accessToken } = await client.auth.login({
  email: 'user@example.com',
  password: 'Password123!'
});

// Get current user
const user = await client.auth.me(accessToken);
```

### Go SDK

```go
import "github.com/corvusHold/guard/sdk/go"

client := guard.NewClient(guard.Config{
    BaseURL:  "http://localhost:8080",
    TenantID: "550e8400-e29b-41d4-a716-446655440000",
})

// Password login
resp, err := client.Auth.Login(ctx, guard.LoginRequest{
    Email:    "user@example.com",
    Password: "Password123!",
})
```

See [SDK Integration Guide](docs/SDK_INTEGRATION.md) for more details.

## Contributing

We welcome contributions! Please see our contributing guidelines (coming soon).

### Development Setup

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`make test`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Code Style

- Go code follows standard Go formatting (`gofmt`, `goimports`)
- Run `make lint` before committing
- Write tests for new features
- Update documentation as needed

---

## License

This project is licensed under the FSL-1.1-ALv2 License - see the [LICENSE](LICENSE) file for details.

---

## Roadmap

- [x] Additional SSO providers (Okta, Auth0, Azure AD)
- [ ] WebAuthn/Passkey support
- [ ] Advanced audit logging with filtering
- [ ] User import/export tools
- [ ] SAML 2.0 support
- [ ] Account linking across providers
- [ ] Advanced rate limiting policies
- [ ] Rust SDK completion
- [ ] Python SDK
- [ ] Java/Kotlin SDK
- [ ] Mobile SDKs (iOS, Android)
- [ ] Customizable email templates
- [ ] Admin UI enhancements
- [ ] Tenant analytics dashboard

---

## Support

- **Documentation**: See [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/corvusHold/guard/issues)
- **Discussions**: [GitHub Discussions](https://github.com/corvusHold/guard/discussions)
---

## Acknowledgments

Built with love by [Arnaud (Martient) Leherpeur](https://github.com/martient) and the Corvus team.

Guard is built on top of excellent open-source projects including:
- [Echo](https://echo.labstack.com/) - High performance HTTP framework
- [pgx](https://github.com/jackc/pgx) - PostgreSQL driver
- [go-redis](https://github.com/redis/go-redis) - Redis client
- [JWT](https://github.com/golang-jwt/jwt) - JSON Web Tokens
- [Prometheus](https://prometheus.io/) - Monitoring and alerting

