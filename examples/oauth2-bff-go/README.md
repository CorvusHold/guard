# Guard OAuth2 BFF Example (Go SDK)

This example demonstrates a **server-side OAuth2 Authorization Code + PKCE flow** using the Go SDK.

It includes:
- A backend (`backend/main.go`) that performs OAuth code exchange via `sdk/go`
- A minimal frontend (`backend/static/index.html`) that only triggers login/logout/profile calls
- Session-scoped token persistence in the backend (`TokenStore` bound to an HTTP session)
- Refresh retry logic for `/api/me` via `OAuth2Refresh`

## Why this example

Use this as a reference for production-style BFF architecture where:
- OAuth tokens are **never exposed to browser JavaScript**
- Token exchange happens server-side (`/oauth/callback`)
- Application session is managed with an HTTP-only cookie

## Prerequisites

- Guard API running (default: `http://localhost:8080`)
- A public OAuth client configured in Guard
- Go 1.24+
- `jq`, `curl`, `openssl`, and `python3` installed (for setup/smoke scripts)

## Bootstrap (recommended)

Use the bootstrap script to create a tenant, bootstrap user, and OAuth client for this BFF example:

```bash
bash examples/oauth2-bff-go/scripts/bootstrap.sh
```

This writes `examples/oauth2-bff-go/backend/.env` with:
- Guard base URL
- OAuth client id
- Redirect URI
- Tenant id and bootstrap test credentials
- pre-granted consent for the bootstrap user (so first browser login can redirect back to BFF callback)

## Configure

Copy and fill the backend env file:

```bash
cp examples/oauth2-bff-go/backend/.env.example examples/oauth2-bff-go/backend/.env
```

Required values:
- `OAUTH_CLIENT_ID`: OAuth client ID from Guard admin
- `OAUTH_REDIRECT_URI`: must exactly match Guard client redirect URI (default: `http://localhost:3004/oauth/callback`)

## Run

```bash
cd examples/oauth2-bff-go/backend
set -a && source .env && set +a
go run .
```

Open `http://localhost:3004`.

## Smoke test (end-to-end)

Run the full automated BFF flow test:

```bash
bash examples/oauth2-bff-go/scripts/oauth2-bff-smoke.sh
```

Smoke script validates:
1. BFF `/oauth/login` returns an authorize redirect
2. user signup/login works
3. Guard authorize + consent decision returns callback code
4. BFF callback exchanges code server-side via SDK
5. BFF `/api/me` resolves to the created user
6. logout clears session

## Fresh-state workflow (recommended for manual browser testing)

If you were previously logged in to Guard with another account/tenant:

1. Click **Reset Local Session** in the BFF UI (calls `POST /api/reset`)
2. Click **Fresh Login (force account chooser)** (calls `/oauth/login?fresh=1`)
3. Authenticate with a user that belongs to this app tenant

This avoids stale BFF state and forces a fresh Guard login prompt.

## Flow (debug checklist)

1. Click **Login via Guard**
2. Browser redirects to Guard `/oauth/authorize`
3. Guard returns to `GET /oauth/callback?code=...&state=...`
4. Backend validates state and calls:
   - `ExchangeOAuth2Code(...)`
5. Backend stores access/refresh token in session token store
6. Frontend calls `GET /api/me` (backend calls Guard `/api/v1/auth/me`)
7. If `/me` fails and refresh token exists, backend tries:
   - `OAuth2Refresh(...)`
   - retries `/api/v1/auth/me`

## Endpoints in this example

- `GET /oauth/login` — starts OAuth2 auth code flow
- `GET /oauth/login?fresh=1` — clears local state and requests a fresh login prompt at Guard
- `GET /oauth/callback` — exchanges code for tokens server-side
- `GET /api/me` — returns current user profile via backend
- `POST /api/logout` — revokes token chain and clears session
- `POST /api/reset` — clears local BFF session and returns next-step guidance
- `GET /api/config` — debug config view

## Notes

- This example uses an in-memory session store for clarity; use Redis/DB-backed sessions in production.
- `state` and `code_verifier` are generated per login and expire quickly.
- The backend uses `AuthModeBearer` with a custom session `TokenStore`.
- Browser flow expects prior consent for the user/client/scopes combination. The bootstrap script pre-grants it for the bootstrap user.
- Tenant safety is enforced: if authenticated user tenant does not match `TENANT_ID`, BFF blocks access, clears local session, and returns `tenant_access_denied`.
