# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Guard CAS is a multi-tenant Central Authentication Service built with Go (Echo framework), PostgreSQL, Redis, and includes TypeScript/JavaScript SDKs, React admin UI, and Next.js examples.

## Development Commands

### Core Development Workflow
```bash
make compose-up          # Start dependencies (Postgres + Redis)
make migrate-up          # Apply database migrations  
make dev                 # Start API with live reload (Air)
make sqlc                # Generate Go code from SQL queries (after schema changes)
make swagger             # Generate API documentation (after API changes)
```

### Testing Commands
```bash
make test                # Unit tests
make test-e2e            # Integration tests (dockerized)
make conformance         # SDK conformance tests across all SDKs
make test-rbac-admin     # RBAC admin-specific tests
make test-fga            # Fine-grained authorization tests
```

### SDK Development
```bash
# TypeScript SDK
cd sdk/ts && npm run build && npm test && npm run conformance

# Examples  
cd examples/nextjs && npm run dev && npm run test:e2e
```

### UI Development
```bash
cd ui && npm run dev && npm run build && npm run test && npm run test:e2e
```

## Architecture

### Domain-Driven Design Structure
The codebase follows Domain-Driven Design with clear separation:

- `/cmd/` - Applications (api server, seeding tools, migrations)
- `/internal/` - Domain slices with controller/domain/service layers:
  - `auth/` - Authentication domain (login, MFA, SSO, JWT tokens)
  - `tenants/` - Multi-tenancy management and isolation
  - `settings/` - Tenant-specific configuration
  - `db/` - Database layer with sqlc-generated type-safe queries
- `/migrations/` - PostgreSQL schema migrations managed by Goose
- `/sdk/` - Client SDKs (TypeScript/JavaScript, Go SDK in development)

### Multi-Tenant Architecture
Strict tenant isolation at all layers:
- Database: All tables include `tenant_id` with proper indexing
- Application: Tenant context propagated through all service layers
- Rate limiting: Tenant-aware with Redis-backed fixed-window limiting
- Testing: Use `rl-` prefix for rate limit bucket isolation in tests

### Key Technologies
- **Backend**: Go 1.21+ with Echo v4, PostgreSQL (pgx/v5), Redis
- **Code Generation**: sqlc for database queries, Air for live reload
- **Frontend**: React 19 + Vite + TailwindCSS (admin UI), Next.js 14 (examples)
- **Testing**: Go testing, Playwright E2E, k6 load testing
- **Deployment**: Docker + Kubernetes with Helm charts

## Development Setup

### Prerequisites
- Go 1.21+, Docker + Docker Compose, Node.js 18+

### Required CLI Tools (install once)
```bash
go install github.com/air-verse/air@latest
go install github.com/pressly/goose/v3/cmd/goose@latest  
go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
```

### Environment Configuration
Copy `.env.example` to `.env` and customize. Multiple environment files supported (`.env.test`, `.env.k6`, `.env.conformance`).

## Database Development

### Making Schema Changes
1. Create new migration: `goose -dir migrations create your_migration_name sql`
2. Write up/down SQL in the generated file
3. Apply migration: `make migrate-up`
4. Update SQL queries in `/internal/db/query/`
5. Generate Go code: `make sqlc`

### Multi-Tenant Data Model
All domain tables include `tenant_id` for strict isolation. Cross-tenant relationships (like users belonging to multiple tenants) use junction tables with proper foreign key constraints.

## Authentication Features

### Supported Methods
- Password-based with configurable policies
- Magic link (passwordless)
- TOTP MFA with backup codes  
- WorkOS SSO integration
- JWT access + refresh token strategy

### Fine-Grained Authorization (FGA)
Group-based permissions with ACL tuple management. Test authorization flows with `make test-fga`.

## Testing Strategy

### Test Types and Commands
- **Unit Tests**: `make test` - Domain logic and service layer testing
- **Integration Tests**: `make test-e2e` - Full dockerized stack with real HTTP requests
- **Conformance Tests**: `make conformance` - Cross-SDK compatibility testing
- **Load Tests**: k6 scenarios in `/ops/k6/` for performance validation
- **E2E Tests**: Playwright for UI and user workflow testing

### Test Isolation
Tests use dedicated containers with tenant-scoped test data. Rate limiting tests require `rl-` prefix for bucket isolation.

## Monitoring and Observability

API exposes Prometheus metrics at `/metrics`, health checks at `/livez` and `/readyz`. Structured logging uses zerolog. Configuration for Grafana dashboards and alerts in `/ops/`.

## Code Generation

After making changes:
- Database schema changes → `make sqlc` (generates type-safe Go queries)
- API changes → `make swagger` (updates OpenAPI documentation)
- Environment changes require restart of `make dev`