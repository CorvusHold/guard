# Conformance Suite (Language-Agnostic)

The conformance suite defines runnable scenarios that each SDK must pass to ensure consistent behavior across languages.

## Structure
- `schema.json` — JSON Schema describing a scenario file
- `scenarios/` — Scenario files (JSON/YAML) referencing the public HTTP API

Each language SDK will implement a small runner that:
1) Loads scenarios, 2) Executes requests against a configured base URL, 3) Asserts expectations, 4) Reports results.

## Environment
Scenarios may reference environment variables for secrets/tenant and user credentials. Recommended variables (aligned with existing local dev flow):
- `BASE_URL` (e.g., http://localhost:8080)
- `TENANT_ID`
- `EMAIL`
- `PASSWORD`
 - `TOTP_CODE` (optional; for MFA scenarios)
 - `MAGIC_TOKEN` (optional; for magic verify scenarios)

To start a local stack, see repo README (e.g., `make obsv-up`) and seed credentials (e.g., `make seed-test`) which writes `.env.k6`.

## Notes
- Scenarios should cover happy paths and error cases: password login (200), MFA challenge (202), refresh/revoke, `me`/`introspect`, SSO start/callback, and rate limiting (429).
- The initial set will be curated after endpoint mapping is verified against the OpenAPI spec.

## requiresEnv and skipping
Each scenario may include `requiresEnv: ["VAR1", "VAR2", ...]`.
If any required env var is missing/empty, the TS runner will skip that scenario and report it as skipped (does not fail the run).

## Scenario features
- **setup.env overrides**: A scenario may define `setup.env` to override environment variables for that scenario only. Overrides support interpolation like `"{{NONMFA_TENANT_ID}}"`.
  Example:
  ```json
  {
    "setup": {
      "env": {
        "TENANT_ID": "{{NONMFA_TENANT_ID}}",
        "EMAIL": "{{NONMFA_EMAIL}}",
        "PASSWORD": "{{NONMFA_PASSWORD}}"
      }
    }
  }
  ```
- **Delays (waitMs)**: Optional `waitMs` at the scenario-level (`setup.waitMs`) or step-level (`step.waitMs`) adds small sleeps to reduce rate-limit flakiness.
- **MFA helpers**: The TS runner computes `TOTP_CODE` from `TOTP_SECRET` after applying overrides, so MFA scenarios only need `TOTP_SECRET`.
- **Non-MFA tenant separation**: CI seeds a second tenant/user for non‑MFA flows and exposes:
  - `NONMFA_TENANT_ID`
  - `NONMFA_EMAIL`
  - `NONMFA_PASSWORD`
  Non‑MFA scenarios (e.g., `001-password-login-success.json`, `003-refresh-logout.json`) should override `TENANT_ID/EMAIL/PASSWORD` to these values.

- **Rate-limit isolation (rl- prefix + second tenant)**:
  - The conformance `Makefile` resets test Redis (Valkey) with `FLUSHALL` before running to avoid cross-run bucket pollution.
  - CI also seeds a second non‑MFA tenant/user and exposes:
    - `NONMFA2_TENANT_ID`
    - `NONMFA2_EMAIL`
    - `NONMFA2_PASSWORD`
  - The rate‑limit login scenario (`011-password-login-rate-limit-429.json`) uses the `NONMFA2_*` credentials to avoid consuming buckets used by earlier scenarios.
  - For isolated buckets within a single tenant, scenarios can pass `tenant_id=rl-<TENANT_ID>` in the query string while including the raw `tenant_id` in the JSON body. Middleware strips `rl-` before validation/settings, but the rate-limit key still isolates as intended.
  
  Example step fragment:
  ```json
  {
    "request": {
      "method": "POST",
      "path": "/v1/auth/password/login",
      "headers": { "content-type": "application/json" },
      "query": { "tenant_id": "rl-{{TENANT_ID}}" },
      "body": { "tenant_id": "{{TENANT_ID}}", "email": "{{EMAIL}}", "password": "{{PASSWORD}}" }
    },
    "expect": { "status": 200 }
  }
  ```

## Retry behavior (429)
- The TS runner automatically retries requests that receive HTTP 429 when 429 is not the expected status for that step.
- Default retries: `RATE_LIMIT_RETRIES=2` (set in the top-level Makefile). Override by passing an env/Make variable, e.g.:
  - `make conformance RATE_LIMIT_RETRIES=0` (disable)
  - `make conformance RATE_LIMIT_RETRIES=3` (increase)
- Backoff respects `Retry-After` header when present; otherwise exponential backoff is used.
- Use `rl-<TENANT_ID>` isolation only in dedicated rate-limit scenarios (e.g., 011/012). Avoid using `rl-` in other scenarios to prevent unintended 429s mid-suite.

## Running with .env.k6
The Make target `make seed-test` writes `.env.k6` at repo root with `TENANT_ID`, `EMAIL`, `PASSWORD` for local testing.
Example:

```bash
cd sdk/ts
set -a && source ../../.env.k6 && set +a
BASE_URL=http://localhost:8080 npm run conformance
```
