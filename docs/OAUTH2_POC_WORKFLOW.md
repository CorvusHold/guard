# OAuth2 POC Workflow (Vite React SPA)

This runbook provides a reproducible integration workflow to validate Guard OAuth2/OIDC with a standalone SPA client.

## What this validates

- OAuth2 Authorization Code + PKCE
- Consent decision
- Token exchange (`/oauth/token`)
- User identity fetch (`/api/v1/auth/me`)
- Logout + token revocation (`/oauth/revoke`)
- Signup path followed by OAuth login

## POC location

- `examples/oauth2-poc/`

## End-to-end architecture

1. SPA calls `GuardClient.buildOAuth2AuthorizeUrl(...)`
2. Browser redirects to `GET /oauth/authorize`
3. User authenticates in Guard login
4. User approves consent (`POST /oauth/authorize/decision`)
5. Guard redirects SPA callback with `code` and `state`
6. SPA exchanges code for tokens at `POST /oauth/token`
7. SPA calls `GET /api/v1/auth/me` using access token
8. SPA logout revokes refresh token via `POST /oauth/revoke`

## Quickstart

### 1) Start Guard API

Run your normal local stack (example):

```bash
make dev
```

### 2) Bootstrap OAuth tenant/client and SPA env

```bash
cd examples/oauth2-poc
chmod +x scripts/bootstrap.sh
./scripts/bootstrap.sh
```

This script:
- creates a bootstrap tenant + admin user + admin token
- creates a **public** OAuth client with redirect URI `http://localhost:3003/callback`
- writes `.env.local` used by the SPA
- prints test credentials

### 3) Run SPA

```bash
cd examples/oauth2-poc
pnpm install
pnpm dev
```

Open: `http://localhost:3003`

## Manual test checklist

1. **Config loaded**
   - confirm Guard URL, client_id, redirect URI are present in the UI
2. **Sign-in (OAuth)**
   - click **Sign in with OAuth2**
   - complete Guard login + consent
   - verify callback processed and debug state contains tokens/user
3. **Profile identity**
   - verify `/api/v1/auth/me` returns expected email/ID
4. **Logout**
   - click **Logout**
   - verify local session cleared and revoke endpoint called
5. **Signup + OAuth**
   - use signup helper in POC
   - verify user created and redirected through OAuth login flow

## Scripted smoke workflow

A non-UI script is provided for fast regression/debug:

```bash
cd examples/oauth2-poc
chmod +x scripts/oauth2-smoke.sh
./scripts/oauth2-smoke.sh
```

This validates signup, authorize/consent, token exchange, me, and revoke in sequence.

## Troubleshooting matrix

### `invalid_client` on `/oauth/token`
- check `VITE_OAUTH_CLIENT_ID`
- ensure client exists in same tenant and is active

### `invalid_grant` on code exchange
- code already used or expired
- `redirect_uri` mismatch between authorize and token calls
- PKCE verifier/challenge mismatch

### redirect loop to Guard login
- user session not established in Guard
- consent not approved

### callback has `error=access_denied`
- consent denied at `/oauth/authorize/decision`

### `/api/v1/auth/me` returns 401
- access token missing/expired/invalid
- wrong Guard base URL

## Security note

This POC intentionally performs token exchange client-side to maximize observability and speed debugging.
For production, prefer server-side/BFF token exchange and HTTP-only session cookies.
