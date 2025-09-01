# Task 1: Runtime config bootstrap (localStorage + query params) and SDK bootstrap

## Scope
- UI: At app start, detect Guard base URL runtime config.
  - Check localStorage for `{ guard_base_url, source }`.
  - If missing and URL contains `guard-base-url` and `source`, persist to localStorage.
  - If still missing, show a form to enter base URL; persist with `source = "direct"`.
  - Provide a small "Reset config" action for testing.
- SDK: Provide a lazy `getClient()` that reads the runtime config and instantiates `GuardClient` with `baseUrl` only (tenant left unset for now).
- Tests: Playwright E2E covering the three entry paths and reset.

## Implementation Plan
- Add `ui/src/lib/runtime.ts` with helpers: `getRuntimeConfig()`, `setRuntimeConfig()`, `ensureRuntimeConfigFromQuery()`.
- Add `ui/src/lib/sdk.ts` with `getClient()` using `sdk/ts/src/client` GuardClient.
- Update `ui/vite.config.ts` to allow importing from `../sdk/ts` via `server.fs.allow`.
- Update `ui/src/components/App.tsx` to:
  - On mount, call `ensureRuntimeConfigFromQuery()` then `getRuntimeConfig()`.
  - If missing, render a base URL form; otherwise render a basic home with the configured base URL and a Reset button.
- Add Playwright E2E:
  - `runtime-config.spec.ts` with tests:
    1. Shows form when no config nor query; saves URL and sets `source=direct`.
    2. Auto-persist from query `?guard-base-url=...&source=redirect`.
    3. Uses existing localStorage config across reloads.
    4. Reset clears and shows form again.
- Update `ui/package.json`: add `@playwright/test`, scripts: `test:e2e`.

## Completion Criteria
- All Playwright tests pass locally: `pnpm exec playwright install --with-deps && pnpm test:e2e`.
- Manual sanity: running `pnpm dev` supports both direct-entry and query-redirect flows.
