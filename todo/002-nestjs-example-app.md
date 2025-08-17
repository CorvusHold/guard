# Issue: Create Example App with NestJS using Guard CAS

## Summary
Build a minimal NestJS example app that integrates with Guard CAS via the TypeScript SDK. Demonstrate password login, MFA challenge/verify, token refresh/revoke, and Dev SSO flow. Include basic routes and e2e tests to validate end-to-end behavior against the local compose stack.

## Motivation
- Provide a canonical server-side integration example for Node/NestJS
- Accelerate adoption by showing best practices and pitfalls (e.g., MFA, rate limits)

## Scope
- NestJS project under `examples/nestjs-guard/`
- Uses `@guard-cas/sdk` for all calls to Guard CAS
- Routes:
  - `POST /auth/login` → password login; return 200 tokens or 202 MFA challenge
  - `POST /auth/mfa/verify` → verify TOTP/backup codes
  - `POST /auth/refresh` and `POST /auth/revoke`
  - `GET /auth/me` → profile
  - `GET /auth/sso/dev/start` and `GET /auth/sso/callback` (dev provider)
- Config via `.env` (BASE_URL, TENANT_ID)
- Minimal templated pages or JSON-only responses (keep simple)
- e2e tests using `supertest` against a running local stack

## Deliverables
- NestJS project with scripts: `dev`, `test`, `e2e`, `start`
- README with setup instructions and example requests
- Dockerfile/compose (optional) for running example
- e2e tests covering: login (200 + 202), MFA verify, refresh, revoke, me, SSO dev

## Acceptance Criteria
- Example app boots locally and passes e2e tests against `make obsv-up`
- Demonstrates handling of 429 responses and `Retry-After`
- Uses the official SDK and compiles without TS errors

## Tasks
- [ ] Scaffold NestJS project in `examples/nestjs-guard/`
- [ ] Wire `@guard-cas/sdk` and env config
- [ ] Implement auth routes and controllers
- [ ] Add e2e tests with `supertest`
- [ ] Write README with instructions and cURL examples
- [ ] Optional: Dockerfile + compose for the example

## References
- TypeScript SDK issue in `todo/001-typescript-sdk.md`
- Swagger docs at `/swagger/index.html`
- `README.md` (observability, metrics, k6) and `docs/rate-limiting.md`
