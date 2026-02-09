# Multi-Region Deployment Guide

## Overview

Guard IAM supports multi-region deployments for high availability and low-latency access. This guide covers the recommended architecture and configuration.

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Region A    │     │  Region B    │     │  Region C    │
│  (Primary)   │     │  (Replica)   │     │  (Replica)   │
│              │     │              │     │              │
│  Guard API   │     │  Guard API   │     │  Guard API   │
│  PostgreSQL  │────▶│  PG Replica  │────▶│  PG Replica  │
│  Redis       │     │  Redis       │     │  Redis       │
└─────────────┘     └─────────────┘     └─────────────┘
```

## Database Configuration

### Primary Region
- Full read/write PostgreSQL instance
- All migrations run here
- Connection pool tuning via `DB_MAX_CONNS`, `DB_MIN_CONNS`, `DB_MAX_CONN_LIFETIME`, `DB_MAX_CONN_IDLE_TIME`

### Read Replicas
- Set `DATABASE_READ_REPLICA_URL` to point read-heavy queries to replicas
- Guard automatically routes read queries when configured
- Replication lag should be monitored (< 100ms recommended)

## Redis Configuration

Each region should have its own Redis instance for:
- Rate limiting (sliding window counters)
- SSO state storage
- Session caching

Redis circuit breaker (`internal/platform/ratelimit/circuit.go`) ensures the API remains available even if Redis is temporarily unreachable.

## JWT Key Management

### Per-Region Signing Keys
- Each region can have its own signing key via the `signing_keys` table
- JWKS endpoint aggregates all active keys for cross-region token verification
- Key rotation is managed via the `RotatingManager` (`internal/auth/keys/rotation.go`)

### Cross-Region Token Verification
1. All regions expose `/.well-known/jwks.json`
2. Tokens signed in Region A can be verified in Region B using the shared JWKS
3. `kid` header in JWTs identifies which key was used

## Load Balancing

### DNS-Based Routing
- Use GeoDNS or latency-based routing (e.g., AWS Route 53, Cloudflare)
- Each region runs identical Guard API instances

### Health Checks
- `/healthz` — basic liveness
- `/readyz` — full readiness (DB + Redis connectivity)

## Data Consistency

### Eventual Consistency Model
- Auth operations (login, token refresh) are region-local
- User management changes propagate via PostgreSQL replication
- Refresh token families span regions (family_id is globally unique)

### Conflict Resolution
- Last-write-wins for user profile updates
- Token revocation propagates via DB replication
- Audit logs are region-tagged for traceability

## Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `DATABASE_URL` | Primary PostgreSQL connection | `postgres://...` |
| `DATABASE_READ_REPLICA_URL` | Read replica connection | `postgres://...` |
| `REDIS_URL` | Regional Redis instance | `redis://...` |
| `DB_MAX_CONNS` | Max connection pool size | `25` |
| `DB_MIN_CONNS` | Min connection pool size | `5` |
| `DB_MAX_CONN_LIFETIME` | Max connection lifetime | `1h` |
| `DB_MAX_CONN_IDLE_TIME` | Max idle connection time | `30m` |
| `PUBLIC_BASE_URL` | Region-specific base URL | `https://us.guard.example.com` |

## Monitoring

- Each region exports Prometheus metrics at `/metrics`
- Grafana dashboards in `ops/grafana/` support multi-region views
- Key metrics: `guard_db_*`, `guard_redis_*`, `guard_http_*`, `guard_auth_*`
