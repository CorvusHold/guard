# Corvus Guard Test Protocol

This document defines the end-to-end testing protocol for the Corvus Guard repository. It covers backend Go tests, UI Playwright E2E, environment setup, test data seeding, and CI-oriented guidance. It is written for both humans and AI agents contributing to the repo.

## Goals

- Ensure no regression in progressive login, onboarding, auth flows, and admin panels.
- Provide deterministic, fast, and reproducible local runs.
- Establish conventions for selectors, toasts, and network mocks to make tests resilient.

---

## Repository Overview

- Backend services (Go): `internal/` packages and HTTP controller in `internal/auth/controller/`.
- UI (Vite + React + TypeScript): `ui/`.
- SDK (TS): `sdk/ts/` (used by UI, important for routes and methods like `updateTenantSettings` which uses `PUT`).
- Documentation: `docs/` (this file), plus onboarding docs such as `TENANT_ONBOARDING.md` and `WORKFLOWS.md`.

---

## Quick Commands

- Run backend unit tests: `go test ./...`
- Run UI E2E tests: `cd ui && pnpm run test:e2e`
- Lint (UI via Biome): `cd ui && pnpm run lint`
- Typecheck (UI): `cd ui && pnpm run typecheck`
- Run Go integration tests (dockerized test stack, build tag): `make test-integration`

> Note: The onboarding integration test in `internal/auth/controller/http_tenant_onboarding_integration_test.go` is gated with the `integration` build tag to keep default unit tests fast and green.

---

## Backend Testing

### Unit tests

- Command: `go test ./...`
- Purpose: Standard package-level unit tests without external dependencies.
- Lint: `make lint` (runs `go vet ./...`).

### Integration tests (dockerized stack)

- Command: `make test-integration`
- What it does:
  - Brings up a dedicated Postgres/Redis stack using `docker-compose.test.yml`.
  - Runs test DB migrations in the `api_test` container.
  - Executes `go test -tags=integration -v ./...`.
  - Tears down the test stack.
- Environment:
  - Uses `.env.test` or `.env.test.example` to populate `DATABASE_URL` and `REDIS_ADDR`.
- Build tags:
  - Integration-only files include `//go:build integration` to separate them from default unit tests.

### WorkOS SSO integration suite

- Tests live at `internal/auth/controller/http_sso_workos_integration_test.go`.
- These tests require `DATABASE_URL` and `REDIS_ADDR` to be set and will skip otherwise.
- Scenarios covered: success callback, token exchange failures, state replay/expiry, missing state/code, invalid state, profile with missing email.

---

## UI E2E Testing (Playwright)

### Requirements

- Node.js + pnpm installed.
- UI dev server is served by Vite preview during tests (Playwright launches the app).

### Commands

- Full suite: `cd ui && pnpm run test:e2e`
- Single file: `cd ui && pnpm run test:e2e -- e2e/your-test.spec.ts`
- Open UI mode: `cd ui && pnpm run test:e2e:ui`

### Lint and Typecheck

- Lint via Biome: `cd ui && pnpm run lint`
- Typecheck via TS: `cd ui && pnpm run typecheck`

### Conventions for Robust Tests

- Prefer `data-testid` attributes for selectors.
  - Examples (already present):
    - Tenant Dashboard: `tenant-name`, `tenant-id`, `tenant-status`, stats testids.
    - Settings Panel: `settings-loading`, `tenant-settings-panel`, `unsaved-changes`, `save-settings`.
    - Toasts: use specific per-toast ids (e.g., `settings-saved-toast`, `settings-error-toast`).
- Toasts
  - `ui/src/lib/toast.tsx` supports `testId` per toast; default is `data-testid="toast"`.
  - When asserting a specific toast, prefer a unique test id instead of filtering by text to avoid strict mode conflicts.
- Settings update method
  - The TS SDK uses `PUT` for `updateTenantSettings` (`sdk/ts/src/client.ts`). Ensure route mocks/assertions use `PUT`, not `PATCH`.
- Network mocks
  - Use `page.route("**/path", handler)` to mock deterministic responses for UI E2E.
  - When possible, assert toasts or UI state without waiting for `waitForResponse`. Click + deterministic mock is sufficient when the mock is registered before navigation/interaction.
- Unsaved changes
  - For forms that display unsaved banners, ensure a change is made before clicking Save to trigger the banner and toasts.

### Example Toast Tests

- Success path: `ui/e2e/toast-provider.spec.ts` (asserts `settings-saved-toast`).
- Error path: `ui/e2e/toast-provider-error.spec.ts` (mocks `PUT 500`, asserts `settings-error-toast`).

---

## Progressive Login and Onboarding

The E2E suite includes comprehensive tests for progressive login and tenant onboarding flows. Ensure that selectors match expectations.

- Progressive login
  - Key component: `ui/src/components/auth/SimpleProgressiveLoginForm.tsx`
  - Ensure copy and ARIA semantics align with tests.
  - Join-organization info toast uses `title: "Contact your organization"` and matching description.

- Tenant Onboarding Wizard
  - Component: `ui/src/components/admin/tenants/TenantOnboardingWizard.tsx`
  - Steps have `onboarding-step-*` test ids and navigation buttons: `next-step`, `complete-onboarding`.
  - Validation errors have specific test ids to assert error states.

- Tenant Dashboard
  - Component: `ui/src/components/admin/tenants/TenantDashboard.tsx`
  - Test ids on overview, tabs, and stats to make assertions straightforward.

Refer to `docs/TENANT_ONBOARDING.md` and `docs/WORKFLOWS.md` for domain context and comprehensive workflows.

---

## CI Recommendations

- Cache pnpm store and Go build caches to speed up runs.
- Run in stages:
  1. UI lint + typecheck.
  2. Backend unit tests (`go test ./...`).
  3. UI E2E (Playwright) with shards if needed.
  4. Optional: Integration tests via `make test-integration` behind a nightly or workflow dispatch.
- Artifacts: Save Playwright test-results (screenshots/videos) on failure.

---

## Adding New Tests

1. Prefer adding `data-testid` attributes to components to avoid brittle selectors.
2. For toasts, always pass a unique `testId` as part of the toast item.
3. For network-driven UI, prefer `page.route` mocks to avoid relying on actual backends.
4. When modifying SDK calls, update the E2E test expectations (methods, paths).
5. Keep tests deterministic—avoid time-based flakiness.

---

## Troubleshooting

- Playwright strict mode conflicts when multiple toasts present
  - Use unique toast test ids instead of `.filter({ hasText })`.
- Method mismatch (PUT vs PATCH)
  - Confirm against `sdk/ts/src/client.ts` before writing route predicates.
- Integration test compile failures in default runs
  - Place `//go:build integration` at the top of integration-only test files.

---

## Appendix: Useful Make Targets

- `make test` → `go test ./...`
- `make test-integration` → runs dockerized integration suite with `-tags=integration`
- `make compose-up-test` / `make compose-down-test` → manage test stack
- `make migrate-up-test-dc` → migrations in `api_test` container

---

## Contact & Contributions

- Follow this protocol and the conventions in this document when adding or modifying tests.
- For large changes, update this `TEST_PROTOCOL.md` and `docs/agents.md` accordingly.
