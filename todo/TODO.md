# Guard CAS – Build TODO (Ordered)

> Use `docker-compose.yml` to run Postgres (localhost:5433) and Valkey/Redis (localhost:6380) for local development.

## 00. Environment & Dev Tooling
- [x] Create `.env` and `.env.example` with: `DATABASE_URL`, `REDIS_ADDR`, `JWT_SIGNING_KEY`, SMTP creds, WorkOS keys.
- [x] Add `Makefile` targets: `compose-up/down`, `dev` (air), `migrate-up/down`, `sqlc`, `test`, `lint`.
- [x] Add `air.toml` for live reload.
- [x] Write `README.md` with setup/run instructions.

## 01. Dependencies & Module
- [x] Update `go.mod` with deps:
  - Echo v4, pgx, go-redis/v9, goose, sqlc runtime, godotenv, jwt/v5, bcrypt, pquerna/otp+totp, validator, zerolog or logrus, google/uuid, SMTP client.

## 02. HTTP Server Bootstrap
- [x] Create `cmd/api/main.go`.
- [x] Load env (godotenv in dev).
- [x] Init logger, Postgres pool, Redis client.
- [x] Echo middlewares: recovery, request ID, logging, CORS, secure headers.
- [x] Routes: `GET /healthz`, placeholder `GET /auth/me`.
- [x] Graceful shutdown.

## 03. Database Migrations (goose)
- [x] Add goose dependency and Makefile task or `cmd/migration/` wrapper.
- [x] Create initial migrations in `migrations/`:
  - `tenants`, `users`, `user_tenants` (M:N).
  - `auth_identities` (password/SSO linkage).
  - `refresh_tokens` (rotation + invalidation).
  - `email_verifications`, `magic_links`.
  - `mfa_secrets`, `mfa_backup_codes`.
  - `audit_logs`.
  - `sso_providers`, `sso_identities`.
- [x] Run `goose up` against local Postgres.

## 04. sqlc Setup & Queries
- [x] Add `sqlc.yaml` (Postgres, pgx).
- [x] Create SQL in `internal/db/queries/` for:
  - Users: create/find/update, tenant bindings.
  - Identities: upsert/find by email+tenant, SSO IDs.
  - Tokens: insert/rotate/revoke refresh tokens.
  - Email verifications & magic links: upsert/consume.
  - Audit logs insert.
  - SSO providers, SSO identities.
- [x] Generate to `internal/db/sqlc/` and commit.

## 05. Core Internal Packages
- [x] `internal/config` (typed config).
- [x] `internal/logger` (structured logging).
- [x] `internal/db` (pgx pool, migrations helpers).
 - [ ] `internal/cache` (Redis wrapper, key namespaces, TTL helpers).
 - [ ] `internal/password` (bcrypt + password policy).
 - [ ] `internal/tokens` (JWT sign/verify, claims, refresh rotation, blacklist via Redis).
 - [ ] `internal/rate` (login/magic-link rate limits via Redis).
- [x] `internal/email` (SMTP/Brevo adapters + templates; allow no-op in dev).
- [x] `internal/events` (audit publisher; stub initially).

## 06. HTTP DTOs, Middleware, Router
- [x] Per-domain DTOs/controllers under `internal/auth/...` and `internal/tenants/...`.
- [x] JWT middleware under `internal/auth/middleware` (adds user + tenant context).
- [x] Router wiring via factories `tenants.Register()` and `auth.Register()` in `cmd/api/main.go`.

## 07. Password Auth Flow
- [ ] `POST /auth/password/register` (create user, link tenant, send verification email).
- [ ] `POST /auth/password/verify` (consume token, mark verified/active).
- [x] `POST /auth/password/login` (password check, optional MFA challenge).
- [x] Issue access + refresh tokens on success.

## 08. Token Management
- [x] `POST /auth/refresh` (rotate refresh, detect reuse).
- [x] `POST /auth/revoke` (logout; revoke current chain).
- [x] `POST /auth/introspect` (validate and return claims for backends).

## 09. Magic Link (Passwordless)
- [x] `POST /auth/magic-link` (create token, send email; rate-limit).
- [x] `GET /auth/magic-link/verify` (consume token, issue tokens).

## 10. MFA (TOTP)
- [x] `POST /auth/mfa/enable` (provision secret, QR, backup codes).
- [x] `POST /auth/mfa/verify` (complete setup and login verification).

## 11. SSO (WorkOS)
- [x] `GET /auth/sso/{provider}/initiate` (build URL/state per tenant).
- [x] `POST /auth/sso/callback` (exchange code, map identity, issue tokens).
- [x] Store provider configs per tenant.

## 12. Observability & Ops
- [x] Structured logs with correlation IDs.
- [ ] Prometheus metrics (HTTP, DB, cache, auth outcomes).
- [ ] `/readyz` and `/livez` endpoints.
- [ ] Optional: `pprof` in dev.

## 13. Security Hardening
- [x] CORS and secure headers.
- [ ] Account lockout/back-off on repeated failures.
- [ ] JWT signing key rotation support.
- [ ] Strict tenant isolation checks in all repos/queries.
- [x] Audit events for sensitive actions.

## 14. Testing
- [x] Unit tests: password, tokens, MFA, DTO validation.
- [x] Integration tests with Compose Postgres + Valkey.
- [x] HTTP handler tests (Echo).

## 15. CI/CD
- [x] GitHub Actions: build, lint, test, sqlc gen check, migrations dry-run.
- [ ] Optional: Docker image build + release workflow.

---

## Release Plan

### package 1 — Developer Experience & Observability Polish

Goal: make end-to-end monitoring, alerting, and testing turnkey for developers.

Scope:
- Seed CLI and Makefile ergonomics
  - Add `cmd/seed` with subcommands: `tenant create`, `user create`, optional `user mfa-enable`.
  - Flags: `--tenant-id`, `--tenant-name`, `--email`, `--password`, `--mfa`.
  - Makefile target `seed-test` to create a default tenant+user for k6: `TENANT_ID, EMAIL, PASSWORD`.

- k6 scenarios
  - Fix `ops/k6/mfa_verify_invalid.js` thresholds to assert on the positive check rather than `http_req_failed`.
    - Remove `http_req_failed` threshold; add threshold: `checks{check\="got 401/400"}: pct>=95`.
  - Add `ops/k6/mfa_e2e.js`: password login -> 202 challenge -> `POST /v1/auth/mfa/verify` -> 200 tokens.
    - Env: `K6_BASE_URL, K6_TENANT_ID, K6_EMAIL, K6_PASSWORD, K6_TOTP` (when MFA already provisioned).
    - Thresholds: success checks >= 95%, p95 < 500ms.
  - Add `ops/k6/sso_dev.js`: `GET /v1/auth/sso/dev/initiate` -> simulated callback -> tokens.
    - Thresholds: success checks >= 95%.
  - Makefile targets: `k6-mfa-e2e`, `k6-sso-dev`.

- Grafana dashboard polish (`ops/grafana/dashboards/guard.json`)
  - SLO panels: success rate and error ratio per endpoint and overall.
  - Latency p95/p99 per endpoint.
  - 429 rate-limiting spikes per route.
  - Current firing alerts panel via Prometheus `ALERTS{alertstate="firing"}`.
  - Links to Prometheus queries for drill-down.

- Alerting validation playbook
  - DB down: `docker compose stop db` → Alert `GuardDatabaseDown` within ~1–2m.
  - Redis down: `docker compose stop valkey` → Alert `GuardRedisDown` within ~1–2m.
  - Rate-limit spike: run `make k6-rate-limit-login` for several minutes → alert for spike.
  - Observe in Alertmanager UI and webhook delivery (`docker compose logs guard_am_receiver`).

- Docs
  - README quickstart: `make obsv-up`, `make seed-test`, run k6 scenarios, open Grafana/Prometheus/Alertmanager URLs.
  - Document k6 env vars and expected responses (200/202/429).

Acceptance Criteria:
- `make seed-test` creates a working tenant+user used by k6 scripts.
- `make k6-login-stress`, `make k6-rate-limit-login`, `make k6-mfa-e2e`, and `make k6-sso-dev` pass thresholds.
- Grafana shows SLO/error/latency/429 panels with data during tests.
- At least one alert is observed firing in Alertmanager and delivered to the webhook receiver.

Out of Scope:
- Security features (lockout, key rotation) and deep SSO hardening.

---

### package 2 — Security & SSO Hardening

Goal: strengthen security guarantees and SSO correctness; expand CI/CD and documentation.

Scope:
- SSO hardening (Dev + WorkOS)
  - State replay protection, expiry/TTL, invalidation tests.
  - Validate `redirect_uri` against per-tenant allowlist; explicit failure audit events.
  - Integration tests assert audit events for failure paths (401/5xx/transport errors).

- Security
  - Account lockout/back-off on repeated login/magic/MFA failures; metrics and configs.
  - JWT signing key rotation with KID, dual-publish window, rollover tests and docs.

- Identity management
  - Identity linking flows (SSO + password + magic), conflict resolution strategies, tests.
  - Strict tenant isolation checks in all repos/queries; regression tests.

- CI/CD and Ops
  - Docker image build and release workflow.
  - E2E job using docker-compose; flaky-test detection; artifact/log upload on failure.
  - Optional: code scanning and dependency alerts triage.

- Docs
  - Full API/flow examples; multi-tenant SSO setup guide; rate limiting, metrics, alerts.

Acceptance Criteria:
- All SSO state/redirect validations enforced with passing integration tests and audit coverage.
- Lockout/back-off behavior measurable via Prometheus; configuration documented.
- Key rotation process documented and tested end-to-end.
- CI publishes images on tagged releases; E2E suite is green.

Out of Scope:
- Product UX work beyond API/observability tightening.

## Next Steps (Hardening & Polish)

- [ ] SSO: State replay/expiry defenses and explicit TTL/invalidation tests.
- [ ] SSO: Validate `redirect_uri` against per-tenant allowlist; add tests.
- [ ] SSO: Publish and assert audit events for failure paths (401/5xx/transport).
- [ ] Security: Implement rate limiting for login and magic-link endpoints.
- [ ] Security: JWT signing key rotation and rollover tests.
- [ ] Accounts: Identity linking flows (SSO + password + magic) and conflict resolution.
- [ ] Docs: Expand README with full examples for all flows; multi-tenant SSO setup guide.
- [ ] CI: Cache sqlc/goose and add flaky-test detection; upload logs on failure.
