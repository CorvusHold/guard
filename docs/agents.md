# Agent Guide: Contributing to Corvus Guard

This guide provides conventions and procedures for AI agents contributing code and tests to the Corvus Guard repository. It complements `docs/TEST_PROTOCOL.md`, `docs/TENANT_ONBOARDING.md`, and `docs/WORKFLOWS.md`.

## Core Principles

- Prefer small, reviewable changes. Keep edits localized and include a short summary of the intent.
- Maintain determinism. Tests must be reproducible and should not depend on wall-clock timing or external services.
- Favor explicit selectors and contracts over brittle heuristics.
- When adding integration tests that require external services, gate them behind a build tag (`//go:build integration`) and provide a Makefile target.

## Project Layout (Key Paths)

- Backend controllers and tests: `internal/auth/controller/`
- Backend services: `internal/**`
- UI (React + Vite + TS): `ui/`
- TS SDK: `sdk/ts/`
- Docs: `docs/`

## Test Protocol (Must Read)

See `docs/TEST_PROTOCOL.md` for the canonical testing procedure. Highlights:

- Backend unit tests: `go test ./...`
- UI E2E (Playwright): `cd ui && pnpm run test:e2e`
- UI lint/typecheck: `cd ui && pnpm run lint && pnpm run typecheck`
- Go integration tests (dockerized): `make test-integration`

## UI Testing Conventions

- Use `data-testid` attributes for all interactable or asserted elements. Examples:
  - Settings: `settings-loading`, `tenant-settings-panel`, `unsaved-changes`, `save-settings`
  - Dashboard: `tenant-name`, `tenant-id`, `tenant-status`, `total-users-stat`, etc.
  - Toasts: set a unique `testId` per toast, e.g., `settings-saved-toast`, `settings-error-toast`.
- For network dependencies, mock with `page.route` and ensure the mock is registered before navigation or clicking.
- Avoid Playwright strict mode ambiguity by selecting via unique test ids.
- Confirm SDK semantics before writing assertions. For example, `updateTenantSettings` uses `PUT` (see `sdk/ts/src/client.ts`).

## Backend Testing Conventions

- Keep default `go test ./...` green and fast.
- Place long-running or external dependency tests under `//go:build integration`.
- Use `Makefile` helpers for integration runs: `make test-integration`.
- Share helpers (e.g., suite setup, typed request/response structs) in test utility files to avoid duplication.

## Adding or Modifying Tests

1. Add/update `data-testid` in UI components.
2. Write deterministic E2E specs under `ui/e2e/*.spec.ts`.
3. Prefer success and error-path tests (both). Example:
   - `toast-provider.spec.ts` (success), `toast-provider-error.spec.ts` (error).
4. Update `docs/TEST_PROTOCOL.md` when you change testing procedures or conventions.

## Commit and PR Guidance

- Describe the change succinctly: what was changed, why, and the test coverage added.
- Link to the relevant spec files and components in the description.
- Ensure `go test ./...`, `pnpm run lint`, `pnpm run typecheck`, and `pnpm run test:e2e` pass locally before submitting.

## CI Hints

- Store Playwright artifacts (screenshots/videos) on failures for debugging.
- Run UI lint/typecheck before the E2E stage.
- Keep integration tests optional or on a separate job (nightly/dispatch).

## Style and Structure

- UI imports at the top of files; avoid mid-file imports.
- Keep test selectors stable and human-readable.
- Ensure any new test code documents its intent (e.g., comments on route method `PUT` vs `PATCH`).

## Security & Secrets

- Do not hardcode real API keys.
- For SSO/Email integrations, use mocks or test fixtures.

## When in Doubt

- Align with `docs/TEST_PROTOCOL.md` and existing test patterns.
- Surface ambiguous requirements to maintainers with a minimal failing test and proposed fix.
