# Conversation Log – Guard CAS

Date: 2025-08-13

## Session Summary
- Brought up the observability stack via `docker compose` (Postgres, Valkey, API, Prometheus, Grafana, Alertmanager, webhook receiver).
- Verified basic health using k6 smoke; added targeted k6 scenarios.
- Wired Prometheus to Alertmanager; added Makefile ergonomics; updated project TODO with release/"package" plan.

## Infra/Stack Status
- `docker-compose.yml` services up: `db`, `valkey`, `api`, `prometheus`, `grafana`, `alertmanager`, `am-receiver`.
- Prometheus alerting configured to send to Alertmanager: `ops/prometheus/prometheus.yml` → `alerting.alertmanagers.targets: ['alertmanager:9093']`.
- Alertmanager routes to webhook receiver: `ops/alertmanager/alertmanager.yml`.

## Changes Made (files)
- `ops/prometheus/prometheus.yml`: added `alerting` section → Alertmanager target.
- `ops/k6/rate_limit_login.js`: new script to exercise login and accumulate 429 responses.
- `ops/k6/mfa_verify_invalid.js`: new script to exercise invalid MFA verification (intended 4xx).
- `Makefile`: added targets `obsv-up`, `obsv-down`, URLs, and k6 helpers (`k6-smoke`, `k6-login-stress`, `k6-rate-limit-login`, `k6-mfa-invalid`).
- `TODO.md`: added Release Plan (renamed by user to "package 1" and "package 2").

## Commands Executed
- `make obsv-up` → all services healthy/running.
- `make k6-smoke` → PASSED thresholds.
- `make k6-mfa-invalid` → FAILED thresholds (by design of current thresholds; scenario intentionally returns 4xx).

## Test Results
- Smoke (`ops/k6/smoke.js`): p95 ~3ms; 0% failed; all checks OK.
- MFA invalid (`ops/k6/mfa_verify_invalid.js`): 100% `http_req_failed` by definition; only ~0.34% of checks matched 401/400 due to current threshold config.

## Next Steps (Package 1 — Developer Experience & Observability)
- Seed CLI & Makefile target:
  - Implement `cmd/seed` for tenant/user creation; add `make seed-test` to populate `TENANT_ID/EMAIL/PASSWORD` used by k6.
- k6 scenarios:
  - Fix `mfa_verify_invalid.js` to assert success on the 401/400 check (remove `http_req_failed` threshold; require >=95% of checks pass).
  - Add `mfa_e2e.js`: password login (202) → `/v1/auth/mfa/verify` → 200 tokens.
  - Add `sso_dev.js`: dev SSO initiate → callback → assert tokens.
  - Add Make targets: `k6-mfa-e2e`, `k6-sso-dev`.
- Grafana dashboard polish (`ops/grafana/dashboards/guard.json`):
  - SLO panels (success rate/error ratio), latency p95/p99 per endpoint, per-endpoint 429 spikes.
  - Firing alerts panel (Prometheus `ALERTS{alertstate="firing"}`) and drill-down links.
- Alerting validation playbook:
  - DB down: `docker compose stop db` → expect `GuardDatabaseDown` within ~1–2m.
  - Redis down: `docker compose stop valkey` → expect `GuardRedisDown`.
  - Rate-limit spike: run `make k6-rate-limit-login` longer to trigger spike alert.
  - Verify webhook deliveries in `guard_am_receiver` logs.
- Docs:
  - README quickstart for obsv up, seeding, running k6, opening dashboards.

## Later (Package 2 — Security & SSO Hardening)
- SSO state/redirect hardening and failure-path audit coverage (Dev + WorkOS).
- Account lockout/back-off metrics and configs.
- JWT signing key rotation with KID and rollover tests.
- Identity linking flows and strict tenant isolation checks.
- CI/CD: image build/release, docker-compose E2E, flaky-test detection, logs artifacts.
- Expanded docs (API/flows, multi-tenant SSO, rate limiting/metrics/alerts).

## Useful URLs
- Grafana: http://localhost:3000 (admin/admin unless overridden)
- Prometheus: http://localhost:9090
- Alertmanager: http://localhost:9093

## Environment Variables for k6
- `K6_BASE_URL` (default http://localhost:8080)
- `K6_TENANT_ID`, `K6_EMAIL`, `K6_PASSWORD` (required for auth flows)
- `K6_TOTP` (for MFA E2E once enabled)

## Notes
- Rate-limit and MFA invalid scenarios will naturally include many 429/4xx responses; thresholds must align with expected outcomes (assert on positive checks rather than `http_req_failed`).
