# Issue: Create TypeScript SDK for Guard CAS

## Summary
Build and publish an official TypeScript SDK that wraps Guard CAS HTTP APIs with typed methods, token handling, and ergonomics for Node.js and browser environments. The SDK should simplify common auth flows (password, magic link, MFA, SSO), expose typed DTOs per Swagger, and provide good DX with docs and examples.

## Motivation
- Reduce boilerplate for clients integrating with Guard CAS
- Provide a single, well-documented package for typical auth flows
- Enable consistent handling of MFA challenges and rate limits

## Scope
- Typed client for all existing `/v1/auth/*` endpoints from OpenAPI (`docs/swagger.json`, mirrored at `sdk/spec/openapi.json`)
- Flows: password, magic link, token refresh/revoke, profile (`/me`, `/introspect`), MFA (TOTP + backup codes) challenge/verify, password reset (request/confirm), and SSO start/callback helpers
- Response wrapper: return `{ data, meta }` with `meta.requestId` per conventions in `sdk/conventions/`
- Tenancy: simple ways to pass tenant context (body/query for now per `docs/rate-limiting.md`; header convention TBD in spec mapping)
- Rate-limit awareness: surface `Retry-After`, status, and provide ergonomic retry helpers (opt-in)
- Works with native `fetch` (browsers) and `undici` (Node). Pluggable HTTP layer via injected `fetch` and interceptors
- No server-only secrets embedded; bearer tokens supplied by the host app
- Error taxonomy aligned with conventions; typed errors with machine-readable codes

## Deliverables
- Package: `@guard-cas/sdk` (npm)
- Source in `sdk/ts/` with build via `tsup` or `tsc`
- Typed DTOs generated from `sdk/spec/openapi.json` (kept in sync with `docs/swagger.json`)
- README with quickstart, API reference, examples
- Unit tests for method shapes and error handling
- CI job to test and build (no publish on PRs)

## Proposed API Surface (initial)
- `new GuardClient({ baseUrl, tenantId, fetchImpl?, storage? })`
- Methods (names may be adjusted to align with controller DTOs):
  - `signup(data)`
  - `loginWithPassword({ tenantId, email, password })` → handles 200 and 202 (MFA challenge)
  - `verifyMfa({ challengeToken, method, code })`
  - `loginWithMagicLink({ email, tenantId })`
  - `verifyMagicToken({ token })` (GET/POST)
  - `refresh({ refreshToken })`, `revoke({ refreshToken })`
  - `me({ accessToken })`, `introspect({ token })`
  - Password reset: `requestPasswordReset({ tenantId, email })`, `confirmPasswordReset({ tenantId, token, newPassword })`
  - MFA TOTP: `startTotp()`, `activateTotp({ code })`, `disableTotp()`
  - MFA Backup Codes: `generateBackupCodes({ count? })`, `consumeBackupCode({ code })`, `getBackupCodeCount()`
  - SSO: `startSso({ provider, redirectUri, stateParams? })`, `handleSsoCallback({ provider, query })`
- Token utilities: optional in-memory store; consumer can opt-in

## Acceptance Criteria
- SDK compiles and passes unit tests on CI
- README includes examples for password + MFA challenge/verify, magic link verify, password reset, and SSO start/callback
- Works against local compose stack (`make obsv-up`) using `.env.k6` values
- Handles 429 responses by surfacing `Retry-After` and status; retry helper demonstrated
- Types are generated from `sdk/spec/openapi.json` and match `docs/swagger.json`
- Responses follow `{ data, meta }` with `meta.requestId` and typed errors consistent with conventions
- CI enforces spec sync (`docs/` vs `sdk/spec/`), OpenAPI lint, and contract-breaking diffs

## Tasks
- Scaffolding & Tooling
  - [ ] Init `sdk/ts/` with `package.json`, `tsconfig.json`, ESLint, Prettier, Vitest/Jest
  - [ ] Build config with `tsup` or `tsc` (CJS+ESM), type exports, source maps
  - [ ] Set up `undici` as default Node fetch; allow injected `fetchImpl`

- DTOs & Spec Sync
  - [ ] Copy/verify OpenAPI in `sdk/spec/` matches `docs/swagger.json`
  - [ ] Generate TypeScript DTOs from `sdk/spec/openapi.json` (e.g., `openapi-typescript`)
  - [ ] Create response wrapper types `{ data, meta }` with `requestId`
  - [ ] Create typed error model aligned with conventions (code, message, details)

- HTTP Layer
  - [ ] Implement pluggable fetch client with interceptors (auth header, error unwrap, rate-limit handling)
  - [ ] Expose retry helper that respects `Retry-After`

- Methods (Endpoints)
  - [ ] Signup, Password login (handle 202 MFA), Refresh, Revoke
  - [ ] Me, Introspect
  - [ ] Magic: send, verify (GET/POST)
  - [ ] MFA: `startTotp`, `activateTotp`, `disableTotp`
  - [ ] MFA Backup Codes: generate, consume, count
  - [ ] MFA Verify (challenge token)
  - [ ] Password Reset: request, confirm
  - [ ] SSO: start (build redirect URL, state), callback (parse tokens)

- Errors, Rate Limiting, and Metadata
  - [ ] Normalize errors to typed errors; include `requestId` from responses
  - [ ] Surface `Retry-After` and status; document recommended backoff
  - [ ] Include `{ data, meta }` consistently in all method returns

- Testing
  - [ ] Unit tests for all methods (happy + error paths, DTO shapes)
  - [ ] Simulate 202 MFA challenge and verify path
  - [ ] Tests for magic link verify GET vs POST
  - [ ] Tests for password reset request/confirm
  - [ ] SSO helpers: state/redirect URL building, callback parsing
  - [ ] Rate-limit behavior and retry helper

- Docs & Examples
  - [ ] README quickstart (Node + Browser), API reference, error taxonomy
  - [ ] Examples: `examples/node` and `examples/browser` showcasing flows

- CI
  - [ ] Build & test on PRs
  - [ ] Spec sync check: fail if `sdk/spec/openapi.(json|yaml)` != `docs/swagger.(json|yaml)`
  - [ ] OpenAPI lint (e.g., `swagger-cli validate` or `spectral lint`)
  - [ ] Contract-break detection (diff spec, run conformance where applicable)

## References
- `docs/swagger.json`, `docs/swagger.yaml`
- Rate limiting: `docs/rate-limiting.md`
- Observability stack: `docker-compose.yml`, `Makefile` (k6 targets)
