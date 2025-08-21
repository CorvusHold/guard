# Guard Next.js Example (TypeScript, App Router)

A minimal Next.js app demonstrating password login, MFA verification, token refresh, and logout using `@corvushold/guard-sdk`.

## Prerequisites
- Node 18+
- Guard API running and reachable (e.g., via this repo's `make compose-up` or `make compose-up-test`)

## Setup
1. Copy environment file and set values:
   ```bash
   cp .env.local.example .env.local
   # Edit .env.local
   # GUARD_BASE_URL=http://localhost:8080 (if using docker-compose from this repo)
   # GUARD_TENANT_ID=<your tenant id>
   ```

2. Install dependencies:
   ```bash
   npm install
   ```
   This example uses `link:../../sdk/ts` to consume the local SDK. `next.config.mjs` is configured with `transpilePackages` to transpile it.

3. Run the app:
   ```bash
   npm run dev
   ```

4. Open http://localhost:3000 and try logging in with a seeded user.
   - On 200 OK, access/refresh cookies are set and the profile is displayed.
   - On 202 Accepted, an MFA challenge is returned; enter the TOTP code to complete login.

## App structure
- `app/api/login/route.ts` — Calls `client.passwordLogin()`; sets cookies on 200; returns challenge on 202.
- `app/api/mfa/verify/route.ts` — Calls `client.mfaVerify()`; sets cookies on success.
- `app/api/refresh/route.ts` — Calls `client.refresh()`; rotates cookies.
- `app/api/logout/route.ts` — Calls `client.logout()`; clears cookies.
- `app/api/me/route.ts` — Calls `client.me()` with cookies-driven token storage.
- `app/page.tsx` — Simple UI to exercise the flows.
- `lib/client.ts` — Helpers to construct `GuardClient`.
- `lib/storage.ts` — Minimal cookie-backed `TokenStorage` used server-side.

## Notes
- The example stores access/refresh tokens in httpOnly cookies for server-side API routes.
- `@corvushold/guard-sdk` automatically attaches `Authorization` from the configured storage.
- Tenancy currently relies on `tenant_id` provided in body/query. `GuardClient` accepts an optional `tenantId` default.

## Rate limiting and retries
The example API routes (login, refresh, logout, MFA verify) handle HTTP 429 with a bounded backoff. You can tune this behavior via environment variables in `.env.local`:

- `GUARD_RATE_LIMIT_MAX_WAIT_SECS` — Max seconds to wait per retry when the server hints a `retry_after` value. Defaults to `2`.
- `GUARD_RATE_LIMIT_MAX_ATTEMPTS` — Max number of attempts for a single API call when encountering 429. Defaults to `3`.

Convenience scripts are provided to set these values:

```bash
# Set max wait per retry (seconds)
npm run set:rate-wait -- 2

# Set max retry attempts
npm run set:rate-attempts -- 5
```

These values are useful to adjust between fast local runs and potentially higher contention in CI.

## Troubleshooting
- If TypeScript cannot resolve aliases like `@/lib/*`, ensure `tsconfig.json` includes `baseUrl` and `paths` (already configured).
- If `@corvushold/guard-sdk` types are missing, ensure `npm install` completed successfully.
- If calling the API returns connection errors, verify `GUARD_BASE_URL` and that the Guard API is up and reachable.

## E2E Test Runbook
This example includes Playwright E2E tests you can run locally. Ensure:
  
- Guard API is running and seeded users exist (admin without MFA).
- `.env.local` contains `GUARD_BASE_URL` and `GUARD_TENANT_ID`.
  
### 1) Owner Settings Test
- Create an owner user and export its credentials to the current shell, then run the test:
  
```bash
cd examples/nextjs
# Exports OWNER_EMAIL/OWNER_PASSWORD in this shell
node scripts/owner_setup.mjs
  
npm run test:e2e -- tests/e2e/settings_owner_access.spec.ts
```
  
Notes:
- The Settings page only sends non-empty fields to the backend to avoid validation errors.
- Success condition: UI shows "Settings saved." after clicking Save.
  
### 2) WorkOS SSO (Dev Adapter) Test
- Configure the tenant to use the dev SSO provider and allow redirects to this Next app, then run the opt-in SSO test:
  
```bash
cd examples/nextjs
GUARD_BASE_URL=http://localhost:8081 \
ADMIN_EMAIL=nomfa@example.com \
ADMIN_PASSWORD=Password123! \
node scripts/configure_sso_dev.mjs
  
RUN_SSO_E2E=true npm run test:e2e -- tests/e2e/sso_workos.spec.ts
```
  
What it does:
- Starts the WorkOS SSO flow via `/api/sso/workos/start`.
- Uses the dev adapter to callback into `/api/sso/workos/callback`.
- Sets `guard_access_token`/`guard_refresh_token` cookies and verifies `/protected` can be accessed.
  
### Playwright config notes
- Tests run the Next.js app on `http://localhost:3001` with `ENABLE_TEST_ROUTES=true`.
- `GUARD_BASE_URL` and `GUARD_TENANT_ID` are read by Next.js from `.env.local`.

### Convenience scripts
For quicker runs, you can use the provided npm scripts (they set required env and handle retries where appropriate):

```bash
# Configure tenant SSO to dev provider and allow redirects to http://localhost:3001
npm run sso:dev

# Run Owner Settings E2E (auto-creates an owner and exports OWNER_* for the test)
npm run test:owner

# Run Settings persistence E2E (provider + allowlist)
npm run test:settings:persistence

# Run opt-in WorkOS SSO E2E with dev adapter
npm run test:sso
```

Notes:
- `scripts/configure_sso_dev.mjs` includes retry/backoff to avoid 429 rate limit flakes.
- Ensure `.env.local` has `GUARD_TENANT_ID`; `GUARD_BASE_URL` defaults to `http://localhost:8081` in scripts.
