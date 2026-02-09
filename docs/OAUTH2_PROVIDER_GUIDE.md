# OAuth 2.0 Provider Integration Guide

This guide explains how to connect an external application to Corvus Guard as an OAuth 2.0 / OpenID Connect provider. Guard acts as the **authorization server** — your app redirects users to Guard for authentication and receives tokens back.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Step 1: Register an OAuth Client](#step-1-register-an-oauth-client)
- [Step 2: Discovery Endpoints](#step-2-discovery-endpoints)
- [Step 3: Authorization Code Flow (with PKCE)](#step-3-authorization-code-flow-with-pkce)
- [Step 4: Exchange Code for Tokens](#step-4-exchange-code-for-tokens)
- [Step 5: Use the Tokens](#step-5-use-the-tokens)
- [Step 6: Refresh Tokens](#step-6-refresh-tokens)
- [Step 7: Revoke Tokens](#step-7-revoke-tokens)
- [Client Credentials Flow (M2M)](#client-credentials-flow-m2m)
- [OpenID Connect (OIDC)](#openid-connect-oidc)
- [Consent & Scopes](#consent--scopes)
- [Security Best Practices](#security-best-practices)
- [Example Integrations](#example-integrations)
- [Endpoint Reference](#endpoint-reference)

---

## Overview

Guard implements the following OAuth 2.0 / OIDC standards:

| Standard | Description |
|----------|-------------|
| [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) | OAuth 2.0 Authorization Framework |
| [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) | PKCE (Proof Key for Code Exchange) |
| [RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009) | Token Revocation |
| [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414) | Authorization Server Metadata |
| [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) | ID Tokens, UserInfo, Discovery |

**Supported grant types:**
- `authorization_code` — Web/mobile apps (with PKCE for public clients)
- `client_credentials` — Machine-to-machine (M2M)
- `refresh_token` — Token renewal

**Supported scopes:**
- `openid` — Required for OIDC; returns an ID token
- `profile` — User's name (given_name, family_name)
- `email` — User's email address and verification status
- `offline_access` — Issues a refresh token

---

## Prerequisites

1. A running Guard instance (e.g., `https://guard.example.com`)
2. A tenant created in Guard
3. An admin user with access to the tenant

---

## Step 1: Register an OAuth Client

Use the Guard Admin API to register your application as an OAuth client.

### For a web application (confidential client):

```bash
curl -X POST https://guard.example.com/api/v1/auth/admin/oauth-clients \
  -H "Authorization: Bearer <admin-access-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Web App",
    "client_type": "confidential",
    "redirect_uris": ["https://myapp.example.com/callback"],
    "scopes": ["openid", "profile", "email", "offline_access"],
    "grant_types": ["authorization_code", "refresh_token"]
  }'
```

### For a single-page app or mobile app (public client):

```bash
curl -X POST https://guard.example.com/api/v1/auth/admin/oauth-clients \
  -H "Authorization: Bearer <admin-access-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My SPA",
    "client_type": "public",
    "redirect_uris": ["https://myapp.example.com/callback"],
    "scopes": ["openid", "profile", "email"],
    "grant_types": ["authorization_code"]
  }'
```

### Response:

```json
{
  "client": {
    "id": "a1b2c3d4-...",
    "client_id": "grd_abc123...",
    "client_type": "confidential",
    "name": "My Web App",
    "redirect_uris": ["https://myapp.example.com/callback"],
    "scopes": ["openid", "profile", "email", "offline_access"],
    "grant_types": ["authorization_code", "refresh_token"],
    "is_active": true
  },
  "client_secret": "grd_sec_xyz789..."
}
```

> **Important:** The `client_secret` is only returned once at creation time. Store it securely. Public clients do not receive a secret.

---

## Step 2: Discovery Endpoints

Guard publishes standard discovery documents so your app can auto-configure itself.

### OAuth 2.0 Authorization Server Metadata (RFC 8414)

```
GET https://guard.example.com/.well-known/oauth-authorization-server
```

### OpenID Connect Discovery

```
GET https://guard.example.com/.well-known/openid-configuration
```

### JWKS (for verifying ID token signatures)

```
GET https://guard.example.com/.well-known/jwks.json
```

### Example discovery response:

```json
{
  "issuer": "https://guard.example.com",
  "authorization_endpoint": "https://guard.example.com/oauth/authorize",
  "token_endpoint": "https://guard.example.com/oauth/token",
  "revocation_endpoint": "https://guard.example.com/oauth/revoke",
  "userinfo_endpoint": "https://guard.example.com/api/v1/auth/me",
  "jwks_uri": "https://guard.example.com/.well-known/jwks.json",
  "introspection_endpoint": "https://guard.example.com/api/v1/auth/introspect",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
  "scopes_supported": ["openid", "profile", "email", "offline_access"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
  "code_challenge_methods_supported": ["S256"],
  "id_token_signing_alg_values_supported": ["ES256", "HS256"],
  "subject_types_supported": ["public"]
}
```

Most OAuth/OIDC libraries (e.g., `openid-client`, `next-auth`, `spring-security-oauth2`) can auto-configure from these URLs.

---

## Step 3: Authorization Code Flow (with PKCE)

This is the recommended flow for all user-facing applications.

### 3a. Generate PKCE parameters (required for public clients, recommended for all)

```javascript
// Generate a random code_verifier (43-128 characters)
const codeVerifier = generateRandomString(64);

// Derive code_challenge = BASE64URL(SHA256(code_verifier))
const encoder = new TextEncoder();
const data = encoder.encode(codeVerifier);
const digest = await crypto.subtle.digest('SHA-256', data);
const codeChallenge = base64UrlEncode(digest);
```

### 3b. Redirect the user to Guard's authorization endpoint

```
GET https://guard.example.com/oauth/authorize
  ?client_id=grd_abc123
  &redirect_uri=https://myapp.example.com/callback
  &response_type=code
  &scope=openid profile email offline_access
  &state=<random-csrf-state>
  &nonce=<random-nonce>
  &code_challenge=<code_challenge>
  &code_challenge_method=S256
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `client_id` | Yes | Your registered client ID |
| `redirect_uri` | Yes | Must exactly match a registered redirect URI |
| `response_type` | Yes | Must be `code` |
| `scope` | No | Space-separated scopes (defaults to `openid`) |
| `state` | Recommended | CSRF protection; returned unchanged in the callback |
| `nonce` | Recommended | Binds the ID token to the session; returned in the ID token |
| `code_challenge` | Required for public clients | PKCE challenge |
| `code_challenge_method` | Required with `code_challenge` | Must be `S256` |

### 3c. User authenticates and consents

Guard will:
1. Check if the user is logged in (via cookie or Bearer token)
2. If not, redirect to the login page
3. Show a consent screen (unless the user previously approved these scopes)
4. Redirect back to your `redirect_uri` with an authorization code

### 3d. Receive the callback

```
https://myapp.example.com/callback?code=<authorization_code>&state=<state>
```

**Always verify that `state` matches what you sent in step 3b.**

---

## Step 4: Exchange Code for Tokens

### Confidential client (with client secret):

```bash
curl -X POST https://guard.example.com/oauth/token \
  -u "grd_abc123:grd_sec_xyz789" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=<authorization_code>" \
  -d "redirect_uri=https://myapp.example.com/callback" \
  -d "code_verifier=<code_verifier>"
```

### Public client (PKCE only, no secret):

```bash
curl -X POST https://guard.example.com/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=<authorization_code>" \
  -d "redirect_uri=https://myapp.example.com/callback" \
  -d "client_id=grd_abc123" \
  -d "code_verifier=<code_verifier>"
```

### Token response:

```json
{
  "access_token": "eyJhbGciOiJFUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "eyJhbGciOiJFUzI1NiIs...",
  "id_token": "eyJhbGciOiJFUzI1NiIs...",
  "scope": "openid profile email offline_access"
}
```

> **Note:** Authorization codes are single-use and expire after 10 minutes.

---

## Step 5: Use the Tokens

### Access protected resources:

```bash
curl https://guard.example.com/api/v1/auth/me \
  -H "Authorization: Bearer <access_token>"
```

### Verify the ID token:

The ID token is a signed JWT. Verify it using the JWKS endpoint:

```javascript
import { createRemoteJWKSet, jwtVerify } from 'jose';

const JWKS = createRemoteJWKSet(
  new URL('https://guard.example.com/.well-known/jwks.json')
);

const { payload } = await jwtVerify(idToken, JWKS, {
  issuer: 'https://guard.example.com',
  audience: 'grd_abc123', // your client_id
});

console.log('User ID:', payload.sub);
console.log('Email:', payload.email);
console.log('Name:', payload.name);
```

### ID token claims:

| Claim | Scope Required | Description |
|-------|---------------|-------------|
| `sub` | `openid` | User ID (UUID) |
| `iss` | `openid` | Issuer URL |
| `aud` | `openid` | Client ID |
| `iat` | `openid` | Issued at (Unix timestamp) |
| `exp` | `openid` | Expiration (Unix timestamp) |
| `auth_time` | `openid` | Time of authentication |
| `nonce` | `openid` | Nonce from the authorization request |
| `name` | `profile` | Full name |
| `given_name` | `profile` | First name |
| `family_name` | `profile` | Last name |
| `email` | `email` | Email address |
| `email_verified` | `email` | Whether the email is verified |

---

## Step 6: Refresh Tokens

When the access token expires, use the refresh token to get a new one:

```bash
curl -X POST https://guard.example.com/oauth/token \
  -u "grd_abc123:grd_sec_xyz789" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=<refresh_token>"
```

Response is the same format as the initial token exchange.

---

## Step 7: Revoke Tokens

When a user logs out, revoke their tokens:

```bash
curl -X POST https://guard.example.com/oauth/revoke \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=<refresh_token>" \
  -d "token_type_hint=refresh_token"
```

Per RFC 7009, the server always responds with `200 OK`, even if the token was already invalid.

---

## Client Credentials Flow (M2M)

For server-to-server communication without a user context:

### Register a client credentials client:

```bash
curl -X POST https://guard.example.com/api/v1/auth/admin/oauth-clients \
  -H "Authorization: Bearer <admin-access-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Backend Service",
    "client_type": "confidential",
    "redirect_uris": ["https://not-used.example.com"],
    "scopes": ["openid"],
    "grant_types": ["client_credentials"]
  }'
```

### Request a token:

```bash
curl -X POST https://guard.example.com/oauth/token \
  -u "grd_abc123:grd_sec_xyz789" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "scope=openid"
```

### Response:

```json
{
  "access_token": "eyJhbGciOiJFUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "openid"
}
```

> Client credentials tokens represent the application, not a user. The `sub` claim contains the `client_id`.

---

## OpenID Connect (OIDC)

Guard is a compliant OIDC provider. To use Guard with any OIDC-compatible library:

### Configuration values:

| Setting | Value |
|---------|-------|
| Issuer / Discovery URL | `https://guard.example.com` |
| Authorization Endpoint | `https://guard.example.com/oauth/authorize` |
| Token Endpoint | `https://guard.example.com/oauth/token` |
| UserInfo Endpoint | `https://guard.example.com/api/v1/auth/me` |
| JWKS URI | `https://guard.example.com/.well-known/jwks.json` |
| Revocation Endpoint | `https://guard.example.com/oauth/revoke` |

### Next-Auth / Auth.js example:

```typescript
// auth.ts
import NextAuth from "next-auth";

export const { handlers, signIn, signOut, auth } = NextAuth({
  providers: [
    {
      id: "guard",
      name: "Corvus Guard",
      type: "oidc",
      issuer: "https://guard.example.com",
      clientId: process.env.GUARD_CLIENT_ID,
      clientSecret: process.env.GUARD_CLIENT_SECRET,
      authorization: { params: { scope: "openid profile email" } },
    },
  ],
});
```

### Generic `openid-client` (Node.js):

```typescript
import { Issuer } from 'openid-client';

const guardIssuer = await Issuer.discover('https://guard.example.com');

const client = new guardIssuer.Client({
  client_id: 'grd_abc123',
  client_secret: 'grd_sec_xyz789',
  redirect_uris: ['https://myapp.example.com/callback'],
  response_types: ['code'],
});

// Generate authorization URL
const authUrl = client.authorizationUrl({
  scope: 'openid profile email',
  state: generateRandomState(),
  code_challenge: codeChallenge,
  code_challenge_method: 'S256',
});

// Exchange code for tokens (in callback handler)
const tokenSet = await client.callback(
  'https://myapp.example.com/callback',
  { code, state },
  { code_verifier: codeVerifier, state: expectedState }
);

console.log('Access Token:', tokenSet.access_token);
console.log('ID Token Claims:', tokenSet.claims());
```

### Spring Security (Java/Kotlin):

```yaml
# application.yml
spring:
  security:
    oauth2:
      client:
        registration:
          guard:
            client-id: grd_abc123
            client-secret: grd_sec_xyz789
            scope: openid,profile,email
            authorization-grant-type: authorization_code
            redirect-uri: "{baseUrl}/login/oauth2/code/guard"
        provider:
          guard:
            issuer-uri: https://guard.example.com
```

### Go (`golang.org/x/oauth2`):

```go
import (
    "golang.org/x/oauth2"
)

var oauthConfig = &oauth2.Config{
    ClientID:     "grd_abc123",
    ClientSecret: "grd_sec_xyz789",
    RedirectURL:  "https://myapp.example.com/callback",
    Scopes:       []string{"openid", "profile", "email"},
    Endpoint: oauth2.Endpoint{
        AuthURL:  "https://guard.example.com/oauth/authorize",
        TokenURL: "https://guard.example.com/oauth/token",
    },
}

// Redirect user
url := oauthConfig.AuthCodeURL("random-state",
    oauth2.SetAuthURLParam("code_challenge", codeChallenge),
    oauth2.SetAuthURLParam("code_challenge_method", "S256"),
)
http.Redirect(w, r, url, http.StatusFound)

// Exchange code (in callback handler)
token, err := oauthConfig.Exchange(ctx, code,
    oauth2.SetAuthURLParam("code_verifier", codeVerifier),
)
```

---

## Consent & Scopes

When a user authorizes your app for the first time, Guard shows a consent screen listing the requested scopes. The user can approve or deny.

**Consent is persisted.** If the user has previously approved the same scopes for your client, Guard will skip the consent screen and redirect immediately with an authorization code.

If your app requests additional scopes later, the consent screen will appear again for the new scopes.

To programmatically revoke a user's consent (as an admin), use the consent grant management in the database.

---

## Security Best Practices

1. **Always use PKCE** — Even for confidential clients, PKCE prevents authorization code interception attacks.

2. **Validate `state`** — Always generate a random `state` parameter and verify it in the callback to prevent CSRF.

3. **Validate `nonce`** — Include a `nonce` in the authorization request and verify it appears in the ID token.

4. **Verify ID tokens** — Always verify the JWT signature using the JWKS endpoint. Check `iss`, `aud`, `exp`, and `nonce`.

5. **Store secrets securely** — Never expose `client_secret` in client-side code. Public clients must use PKCE without a secret.

6. **Use short-lived access tokens** — Guard issues 15-minute access tokens by default. Use refresh tokens to renew them.

7. **Revoke tokens on logout** — Call `/oauth/revoke` when the user logs out.

8. **Register exact redirect URIs** — Guard performs exact-match validation on redirect URIs. No wildcards.

---

## Endpoint Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/oauth/authorize` | GET | Authorization endpoint (user-facing) |
| `/oauth/authorize/decision` | POST | Consent decision (approve/deny) |
| `/oauth/token` | POST | Token exchange (code, refresh, client_credentials) |
| `/oauth/revoke` | POST | Token revocation (RFC 7009) |
| `/api/v1/auth/me` | GET | UserInfo endpoint |
| `/api/v1/auth/introspect` | POST | Token introspection |
| `/api/v1/auth/admin/oauth-clients` | POST | Register a new OAuth client |
| `/api/v1/auth/admin/oauth-clients` | GET | List OAuth clients |
| `/api/v1/auth/admin/oauth-clients/:id` | GET | Get client details |
| `/api/v1/auth/admin/oauth-clients/:id` | PATCH | Update client |
| `/api/v1/auth/admin/oauth-clients/:id` | DELETE | Delete client |
| `/.well-known/oauth-authorization-server` | GET | OAuth 2.0 metadata (RFC 8414) |
| `/.well-known/openid-configuration` | GET | OIDC discovery |
| `/.well-known/jwks.json` | GET | JSON Web Key Set |

---

## Troubleshooting

### "invalid_client" error on token exchange
- Verify `client_id` and `client_secret` are correct
- For Basic auth: `Authorization: Basic base64(client_id:client_secret)`
- For public clients: pass `client_id` as a form parameter, no secret

### "invalid_grant" error
- Authorization codes are single-use and expire after 10 minutes
- Ensure `redirect_uri` exactly matches what was used in the authorization request
- For PKCE: verify the `code_verifier` matches the `code_challenge` sent earlier

### Consent screen keeps appearing
- Ensure you request the same scopes each time
- If you add new scopes, consent will be re-requested

### ID token verification fails
- Fetch the JWKS from `/.well-known/jwks.json` (cache with TTL)
- Verify `iss` matches your Guard URL
- Verify `aud` matches your `client_id`
- Check that the token hasn't expired (`exp`)
