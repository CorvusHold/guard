# Guard OAuth2 SPA POC (Vite + React + TypeScript)

This POC is a standalone SPA that integrates with Guard as an OAuth2/OIDC provider.

It demonstrates:
- OAuth2 Authorization Code + PKCE sign-in
- user identity fetch (`/api/v1/auth/me`)
- logout with token revocation (`/oauth/revoke`)
- signup helper (creates user, then continues through OAuth login)

## Prerequisites
- Guard API running (default: `http://localhost:8080`)
- `jq` installed (for bootstrap script)
- `pnpm` installed
- `curl`, `openssl`, and `python3` installed (required by `scripts/oauth2-smoke.sh`)

## Quick start

1) Bootstrap tenant, user, and OAuth client:

```bash
chmod +x scripts/bootstrap.sh
./scripts/bootstrap.sh
```

This writes `examples/oauth2-poc/.env.local` and prints credentials.

2) Install and run:

```bash
pnpm install
pnpm dev
```

3) Open `http://localhost:3003`.

## Config

The app reads from `.env.local` (or manual UI form):

```env
VITE_GUARD_BASE_URL=http://localhost:8080
VITE_OAUTH_CLIENT_ID=<client_id>
VITE_REDIRECT_URI=http://localhost:3003/callback
VITE_OAUTH_SCOPE=openid profile email offline_access
VITE_TENANT_ID=<tenant_uuid>
```

## Test workflow

For an API-level end-to-end smoke (signup + oauth + me + revoke), run:

```bash
chmod +x scripts/oauth2-smoke.sh
./scripts/oauth2-smoke.sh
```

This script:
1. signs up a new user
2. logs in via password to get a user token
3. performs OAuth authorize + consent decision
4. exchanges code at `/oauth/token`
5. fetches `/api/v1/auth/me`
6. revokes refresh token

## Security note

This is intentionally a **debug/demo SPA**. It performs code exchange in the browser to make OAuth behavior observable.
For production, prefer backend token exchange (BFF/server session).
