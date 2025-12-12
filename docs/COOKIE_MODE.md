# Cookie Mode Authentication

Guard supports two authentication modes: **bearer** (default) and **cookie**.

## Overview

- **Bearer mode**: Tokens are returned in the response body and must be stored client-side (localStorage, memory, etc.). The client sends tokens via `Authorization: Bearer <token>` header.
- **Cookie mode**: Tokens are set as HTTP-only secure cookies by the server. The client sends cookies automatically with `credentials: 'include'`.

## How It Works

### Backend Behavior

The backend detects the authentication mode via the `X-Auth-Mode` request header:

- **No header or `X-Auth-Mode: bearer`**: Returns tokens in JSON response body
- **`X-Auth-Mode: cookie`**: Sets HTTP-only secure cookies and returns `{"success": true}`

#### Affected Endpoints

The following endpoints support cookie mode:

1. **POST /api/v1/auth/password/login** - Sets cookies on successful login
2. **POST /api/v1/auth/password/signup** - Sets cookies on successful signup
3. **POST /api/v1/auth/mfa/verify** - Sets cookies after MFA verification
4. **POST /api/v1/auth/refresh** - Reads refresh token from cookie, sets new cookies
5. **POST /api/v1/auth/logout** - Clears cookies
6. **GET /api/v1/auth/me** - Reads access token from cookie if no Bearer header present

#### Cookie Details

Two cookies are set:

```
guard_access_token
  - Value: JWT access token
  - MaxAge: ACCESS_TOKEN_TTL (default 15 minutes)
  - HttpOnly: true
  - Secure: true (if HTTPS)
  - SameSite: Strict
  - Path: /

guard_refresh_token
  - Value: JWT refresh token
  - MaxAge: REFRESH_TOKEN_TTL (default 30 days)
  - HttpOnly: true
  - Secure: true (if HTTPS)
  - SameSite: Strict
  - Path: /
```

### SDK Behavior

The TypeScript SDK automatically sends the `X-Auth-Mode` header when configured with `authMode: 'cookie'`:

```typescript
import { GuardClient } from '@corvushold/guard-sdk';

const client = new GuardClient({
  baseUrl: 'http://localhost:8080',
  tenantId: 'your-tenant-id',
  authMode: 'cookie', // Enables cookie mode
});

// Login - cookies are set automatically
await client.passwordLogin({
  email: 'user@example.com',
  password: 'password123',
  tenant_id: 'your-tenant-id',
});

// Subsequent requests automatically include cookies
const profile = await client.me();
```

The SDK also sets `credentials: 'include'` when in cookie mode to ensure cookies are sent with cross-origin requests (requires proper CORS configuration).

## Discovery

The OAuth 2.0 metadata endpoint (`/.well-known/oauth-authorization-server`) announces the server's default auth mode:

```json
{
  "issuer": "http://localhost:8080",
  "guard_auth_modes_supported": ["bearer", "cookie"],
  "guard_auth_mode_default": "cookie",
  "guard_version": "1.0.0"
}
```

The SDK can discover and auto-configure:

```typescript
const metadata = await GuardClient.discover('http://localhost:8080');
const client = new GuardClient({
  baseUrl: 'http://localhost:8080',
  authMode: metadata.guard_auth_mode_default as 'bearer' | 'cookie',
});
```

## Configuration

Set the default auth mode via environment variable:

```bash
DEFAULT_AUTH_MODE=cookie  # or "bearer"
```

This only affects the metadata announcement. The actual mode is determined per-request via the `X-Auth-Mode` header.

## Security Considerations

### Cookie Mode

**Pros:**
- Tokens stored in HTTP-only cookies, not accessible to JavaScript
- Automatic CSRF protection via SameSite=Strict
- No risk of XSS token theft

**Cons:**
- Requires same-origin or proper CORS with credentials
- CSRF protection must be implemented for state-changing operations
- Cookies sent automatically (can't selectively omit)

### Bearer Mode

**Pros:**
- Works cross-origin without CORS credentials
- Client has full control over token storage and transmission
- Easier to implement in native mobile apps

**Cons:**
- Tokens accessible to JavaScript (XSS risk if stored in localStorage)
- Client must implement secure token storage
- Manual token refresh logic required

## Testing

Run cookie mode tests:

```bash
go test ./internal/auth/controller/... -v -run TestHTTP_CookieMode
```

## Migration

To migrate from bearer to cookie mode:

1. Update SDK configuration to use `authMode: 'cookie'`
2. Remove manual token storage logic (localStorage, etc.)
3. Ensure CORS is configured with `credentials: true` if cross-origin
4. Update logout to call the logout endpoint (cookies cleared server-side)

## Troubleshooting

### Cookies not being set

- Check that `X-Auth-Mode: cookie` header is present in request
- Verify CORS allows credentials if cross-origin
- Check browser console for cookie errors

### Cookies not being sent

- Verify `credentials: 'include'` is set in fetch options
- Check SameSite policy (Strict requires same-origin navigation)
- Ensure cookies haven't expired

### /me endpoint returns 401

- Check that cookies are being sent with request
- Verify access token hasn't expired
- Try refreshing tokens via /api/v1/auth/refresh
