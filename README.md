# Guard CAS

[![CI](https://github.com/corvusHold/guard/actions/workflows/ci.yml/badge.svg)](https://github.com/corvusHold/guard/actions/workflows/ci.yml)

Central Authentication Service (multi-tenant). See `PROJECT.md` for architecture and API spec.

## Prerequisites
- Go (>= 1.21)
- Docker + Docker Compose
- CLI tools (install once):
  - Air (live reload): `go install github.com/air-verse/air@latest`
  - Goose (migrations): `go install github.com/pressly/goose/v3/cmd/goose@latest`
  - sqlc (codegen): `go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest`

## Run local services
```bash
make compose-up
```
- Postgres: `localhost:5433` (user/pass/db: guard/guard/guard)
- Valkey (Redis): `localhost:6380`

## Configure
```bash
cp .env.example .env
# then edit .env as needed
```

## Development
```bash
make dev
```
This builds and runs `./cmd/api` with live reload via `air`.

## Database migrations
```bash
make migrate-up     # apply
make migrate-down   # rollback latest
make migrate-status # list
```

## sqlc
```bash
make sqlc
```

## Tests
```bash
make test
```

## Conformance quickstart

Run the SDK conformance suite against your local stack:

```bash
# bring up dependencies if not already running
make compose-up

# run all scenarios
make conformance

# run a single scenario by prefix/substring (e.g., 011)
SCENARIO_FILTER=011 make conformance
```

Notes:

- The Makefile flushes the test Redis (Valkey) before running to avoid cross-run rate-limit pollution.
- Seeding includes two non-MFA tenants: `NONMFA_*` and `NONMFA2_*`. Scenario 011 uses `NONMFA2_*` to isolate its rate‑limit bucket.
- For isolated buckets within a tenant, scenarios may use the `rl-` prefix in `tenant_id` query param. See:
  - `docs/rate-limiting.md` (rl- prefix and debugging)
  - `sdk/conformance/README.md` (scenario overrides and isolation examples)

## Observability
- Prometheus metrics are exposed at `/metrics` from `./cmd/api`.
- Liveness and readiness endpoints: `/livez` and `/readyz`.
- Optionally restrict access to `/metrics` to specific CIDRs via `METRICS_ALLOW_CIDRS` (comma-separated CIDRs).

Metrics included:

- Auth outcomes
  - `guard_auth_outcomes_total{action="password|magic|mfa|sso", result="success|failure"}`
  - `guard_auth_mfa_outcomes_total{method="totp|backup_code|unknown", result="success|failure"}`
  - `guard_auth_sso_outcomes_total{provider="dev|workos|other", result="success|failure"}`

- Database (Postgres)
  - `guard_db_up` (1=up, 0=down)
  - `guard_db_ping_seconds` (histogram)

- Cache (Redis/Valkey)
  - `guard_redis_up` (1=up, 0=down)
  - `guard_redis_ping_seconds` (histogram)

- HTTP server
  - `guard_http_requests_total{method, route, status}`
  - `guard_http_request_duration_seconds{method, route, status}` (histogram)
  - `guard_http_rate_limit_exceeded_total{endpoint, source}` (HTTP 429s)

Notes:

- Background collectors ping Postgres and Redis every 10s to update `*_up` gauges and `*_ping_seconds` histograms.
- Metrics endpoint can be ACL-restricted via `METRICS_ALLOW_CIDRS` (comma-separated CIDRs) and client IP extraction can be proxy-aware via `TRUST_PROXY`/`TRUST_PROXY_CIDRS`.

Profiling (pprof):

- Available at `/debug/pprof/*` in non-production environments (enabled when `APP_ENV` is not `prod`/`production`).
- Endpoints: `/`, `/cmdline`, `/profile`, `/symbol`, `/trace`, `/heap`, `/goroutine`, `/allocs`, `/mutex`, `/block`, `/threadcreate`.

See also: [Rate limiting documentation](docs/rate-limiting.md) for tenant-aware limits and overrides.

Prometheus setup examples:

- Sample Prometheus config and alerts live in `ops/prometheus/`:
  - `ops/prometheus/prometheus.yml` (scrape config)
  - `ops/prometheus/alerts.yml` (alerting rules)

## k6 smoke test

Run a lightweight smoke against health and Swagger endpoints:

```bash
docker compose run --rm k6 k6 run /scripts/smoke.js
```

Environment variables:

- `K6_BASE_URL` (default: `http://localhost:8080`)

Example override:

```bash
K6_BASE_URL=http://api:8080 docker compose run --rm k6 k6 run /scripts/smoke.js
```

### Seeding for k6 scenarios

Prepare a default tenant/user and write credentials to `.env.k6` used by k6 Make targets:

```bash
make seed-test            # creates/reuses tenant+user and writes K6_* vars to .env.k6
make k6-login-stress      # uses .env.k6 automatically
make k6-rate-limit-login  # uses .env.k6 automatically
```

You can override defaults:

```bash
TENANT_NAME=my-tenant EMAIL=dev@example.com PASSWORD='Password123!' make seed-test
```

## Client IP behind proxies/CDN (Cloudflare)

If you deploy behind Cloudflare or another proxy, configure Echo to extract the real client IP from proxy headers so that rate limiting keys and logs attribute correctly.

Example (prefer Cloudflare's `CF-Connecting-IP`, then `X-Forwarded-For`, then `X-Real-IP`, then `RemoteAddr`):

```go
// in cmd/api/main.go, after creating `e := echo.New()`
e.IPExtractor = func(r *http.Request) string {
    if ip := r.Header.Get("CF-Connecting-IP"); ip != "" {
        return ip
    }
    // Fallback to X-Forwarded-For (left-most value)
    if xff := r.Header.Get(echo.HeaderXForwardedFor); xff != "" {
        if i := strings.IndexByte(xff, ','); i >= 0 {
            return strings.TrimSpace(xff[:i])
        }
        return strings.TrimSpace(xff)
    }
    if ip := r.Header.Get(echo.HeaderXRealIP); ip != "" {
        return ip
    }
    host, _, _ := net.SplitHostPort(r.RemoteAddr)
    return host
}
```

Security notes:

- Only enable proxy header trust when your app is actually behind that proxy/CDN; otherwise headers can be spoofed by clients.
- For stricter security, restrict trust by verifying `r.RemoteAddr` is a known proxy IP (e.g., Cloudflare’s published IP ranges) before using headers.

Enable this behavior by setting an environment variable when running behind a proxy/CDN:

```bash
export TRUST_PROXY=true
# then start the API
go run ./cmd/api
```

Optionally restrict trusted proxies via CIDRs (recommended):

```bash
export TRUST_PROXY=true
export TRUST_PROXY_CIDRS="173.245.48.0/20,103.21.244.0/22,103.22.200.0/22,103.31.4.0/22,141.101.64.0/18,108.162.192.0/18,190.93.240.0/20,188.114.96.0/20,197.234.240.0/22,198.41.128.0/17,162.158.0.0/15,104.16.0.0/13,104.24.0.0/14,172.64.0.0/13,131.0.72.0/22"
# IPv6 ranges are also available from Cloudflare docs
```

Cloudflare IP ranges: https://www.cloudflare.com/ips/

## Notes
- `.env` is gitignored; use `.env.example` for defaults.
- Postgres and Valkey are defined in `docker-compose.yml`.
- Implementation starts with Step 01/02 in `TODO.md`.

## MFA Challenge Flow (Password Login)

When a user has MFA enabled, `POST /v1/auth/password/login` returns a 202 with a short-lived challenge token instead of tokens.

Example login request:

```bash
curl -s -X POST \
  -H 'Content-Type: application/json' \
  http://localhost:8080/v1/auth/password/login \
  -d '{
    "tenant_id": "<TENANT_UUID>",
    "email": "user@example.com",
    "password": "Password!123"
  }'
```

Possible responses:

- 200 OK (no MFA):

```json
{
  "access_token": "...",
  "refresh_token": "..."
}
```

- 202 Accepted (MFA required):

```json
{
  "challenge_token": "<short-lived-jwt>",
  "methods": ["totp", "backup_code"]
}
```

Then verify the challenge with `POST /v1/auth/mfa/verify` using either TOTP or a backup code.

TOTP verification:

```bash
curl -s -X POST \
  -H 'Content-Type: application/json' \
  http://localhost:8080/v1/auth/mfa/verify \
  -d '{
    "challenge_token": "<challenge-from-login>",
    "method": "totp",
    "code": "123456"
  }'
```

Backup code verification:

```bash
curl -s -X POST \
  -H 'Content-Type: application/json' \
  http://localhost:8080/v1/auth/mfa/verify \
  -d '{
    "challenge_token": "<challenge-from-login>",
    "method": "backup_code",
    "code": "BACKUP-CODE-HERE"
  }'
```

Successful verification returns tokens:

```json
{
  "access_token": "...",
  "refresh_token": "..."
}
```

Notes:

- Challenge tokens are short-lived and signed per-tenant.
- Backup codes are single-use and will be consumed on successful verification.
- Swagger UI: http://localhost:8080/swagger/index.html

## WorkOS SSO Setup and Tenant Settings API

Use the tenant-scoped settings API to configure WorkOS SSO per tenant. The SSO flow is started at `/v1/auth/sso/google/start` (provider path is `google` for WorkOS-backed SSO) and completed at `/v1/auth/sso/google/callback`. Logout is supported via `POST /v1/auth/logout` and revokes the refresh token chain.

Required environment variables:

- `PUBLIC_BASE_URL` (e.g., `http://localhost:8080`)
- Database and Redis (see docker compose section)

Per-tenant settings (whitelist):

- `sso.provider` (set to `workos`)
- `sso.workos.client_id`
- `sso.workos.client_secret` (or `sso.workos.api_key`)
- `sso.state_ttl` (e.g., `10m`)
- `sso.redirect_allowlist` (comma-separated URL prefixes)

Endpoints:

- GET `/v1/tenants/{id}/settings` — returns the subset of SSO-related settings; secrets are masked.
- PUT `/v1/tenants/{id}/settings` — upserts any of the whitelisted keys.

Example curl (PUT):

```bash
TENANT_ID="<TENANT_UUID>"
curl -s -X PUT \
  -H 'Content-Type: application/json' \
  http://localhost:8080/v1/tenants/$TENANT_ID/settings \
  -d '{
    "sso_provider": "workos",
    "workos_client_id": "client_test_123",
    "workos_client_secret": "secret_test_456",
    "sso_state_ttl": "10m",
    "sso_redirect_allowlist": "http://localhost:3000/callback,http://localhost:5173/callback"
  }'
```

Start SSO:

```bash
curl -i "http://localhost:8080/v1/auth/sso/google/start?tenant_id=$TENANT_ID&connection_id=conn_123"
```

On success, you will be redirected to WorkOS authorize. After the callback, the API returns access and refresh tokens. To revoke session(s), call:

```bash
curl -s -X POST \
  -H 'Content-Type: application/json' \
  http://localhost:8080/v1/auth/logout \
  -d '{"refresh_token":"<REFRESH_TOKEN_FROM_LOGIN>"}'
```

Notes:

- Callback URL is `${PUBLIC_BASE_URL}/v1/auth/sso/google/callback` and must be allowed in WorkOS.
- If `sso.workos.client_secret` is not set, `sso.workos.api_key` is used for the token exchange.
- `sso.redirect_allowlist` is enforced for Dev SSO and may be reused by UIs.
