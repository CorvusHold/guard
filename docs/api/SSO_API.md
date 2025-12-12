# SSO API Documentation

This document describes the API endpoints for managing and using SSO (Single Sign-On) authentication in Guard.

## Table of Contents

- [Public SSO Endpoints](#public-sso-endpoints)
- [Admin API Endpoints](#admin-api-endpoints)
- [Error Codes](#error-codes)
- [Examples](#examples)

## Public SSO Endpoints

These endpoints are used by end-users to authenticate via SSO providers.

### Initiate SSO Login

Initiates an SSO authentication flow.

**Endpoint:** `GET /auth/sso/{slug}/login`

**Parameters:**
- `slug` (path, required): Provider slug (e.g., "google", "okta")
- `tenant_id` (query, required): Tenant UUID
- `redirect_url` (query, optional): URL to redirect to after successful authentication
- `login_hint` (query, optional): Email or username hint for the IdP
- `force_authn` (query, optional): Force re-authentication even if user has valid session

**Response:**
- HTTP 302: Redirects to the identity provider's authorization URL

**Example:**
```bash
curl -L "https://auth.example.com/auth/sso/google/login?tenant_id=123e4567-e89b-12d3-a456-426614174000&redirect_url=https://app.example.com/dashboard"
```

---

### Handle SSO Callback

Handles the callback from the identity provider after authentication.

**Endpoint:** `GET /auth/sso/{slug}/callback` (OIDC)
**Endpoint:** `POST /auth/sso/{slug}/callback` (SAML)

**Parameters:**
- `slug` (path, required): Provider slug
- `tenant_id` (query/form, required): Tenant UUID
- `code` (query, OIDC only): Authorization code
- `state` (query, OIDC only): State token for CSRF protection
- `SAMLResponse` (form, SAML only): Base64-encoded SAML response
- `RelayState` (form, SAML only): SAML relay state

**Response:**
```json
{
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "email_verified": true,
    "is_active": true
  },
  "is_new_user": false,
  "identity_id": "uuid"
}
```

**Error Response:**
```json
{
  "error": "error description"
}
```

---

### Get SAML Metadata

Returns SAML Service Provider metadata (for configuring the IdP).

**Endpoint:** `GET /auth/sso/{slug}/metadata`

**Parameters:**
- `slug` (path, required): Provider slug
- `tenant_id` (query, required): Tenant UUID

**Response (SAML):**
```xml
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="...">
  <md:SPSSODescriptor>
    ...
  </md:SPSSODescriptor>
</md:EntityDescriptor>
```

**Response (OIDC):**
```json
{
  "issuer": "https://accounts.google.com",
  "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
  "token_endpoint": "https://oauth2.googleapis.com/token",
  "userinfo_endpoint": "https://openidconnect.googleapis.com/api/v1/userinfo",
  "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs"
}
```

---

## Admin API Endpoints

These endpoints require authentication with an admin bearer token.

### Authentication

All admin endpoints require a bearer token in the `Authorization` header:

```
Authorization: Bearer <token>
```

The token must belong to a user with the "admin" role.

---

### Create SSO Provider

Creates a new SSO provider configuration.

**Endpoint:** `POST /api/v1/sso/providers`

**Headers:**
- `Authorization: Bearer <token>`
- `Content-Type: application/json`

**Request Body (OIDC Example):**
```json
{
  "tenant_id": "123e4567-e89b-12d3-a456-426614174000",
  "name": "Google Workspace",
  "slug": "google",
  "provider_type": "oidc",
  "enabled": true,
  "allow_signup": true,
  "trust_email_verified": true,
  "domains": ["example.com"],
  "issuer": "https://accounts.google.com",
  "client_id": "xxx.apps.googleusercontent.com",
  "client_secret": "GOCSPX-xxx",
  "scopes": ["openid", "profile", "email"]
}
```

**Request Body (SAML Example):**
```json
{
  "tenant_id": "123e4567-e89b-12d3-a456-426614174000",
  "name": "Okta",
  "slug": "okta",
  "provider_type": "saml",
  "enabled": true,
  "allow_signup": true,
  "trust_email_verified": true,
  "domains": ["example.com"],
  "idp_metadata_url": "https://example.okta.com/app/xxx/sso/saml/metadata",
  "want_assertions_signed": true,
  "want_response_signed": true
}
```

**Response:**
```json
{
  "id": "uuid",
  "tenant_id": "uuid",
  "name": "Google Workspace",
  "slug": "google",
  "provider_type": "oidc",
  "enabled": true,
  "allow_signup": true,
  "trust_email_verified": true,
  "domains": ["example.com"],
  "issuer": "https://accounts.google.com",
  "client_id": "xxx.apps.googleusercontent.com",
  "client_secret": "GOC...xxx",
  "scopes": ["openid", "profile", "email"],
  "created_at": "2025-01-14T12:00:00Z",
  "updated_at": "2025-01-14T12:00:00Z"
}
```

**Note:** The `client_secret` and `sp_private_key` fields are masked in responses for security.

---

### List SSO Providers

Lists all SSO providers for a tenant.

**Endpoint:** `GET /api/v1/sso/providers`

**Headers:**
- `Authorization: Bearer <token>`

**Query Parameters:**
- `tenant_id` (optional): Tenant UUID (defaults to authenticated user's tenant)

**Response:**
```json
{
  "providers": [
    {
      "id": "uuid",
      "name": "Google Workspace",
      "slug": "google",
      "provider_type": "oidc",
      "enabled": true,
      ...
    },
    {
      "id": "uuid",
      "name": "Okta",
      "slug": "okta",
      "provider_type": "saml",
      "enabled": true,
      ...
    }
  ],
  "total": 2
}
```

---

### Get SSO Provider

Retrieves a single SSO provider configuration.

**Endpoint:** `GET /api/v1/sso/providers/{id}`

**Headers:**
- `Authorization: Bearer <token>`

**Parameters:**
- `id` (path, required): Provider UUID

**Response:**
```json
{
  "id": "uuid",
  "tenant_id": "uuid",
  "name": "Google Workspace",
  "slug": "google",
  "provider_type": "oidc",
  "enabled": true,
  ...
}
```

---

### Update SSO Provider

Updates an existing SSO provider configuration.

**Endpoint:** `PUT /api/v1/sso/providers/{id}`

**Headers:**
- `Authorization: Bearer <token>`
- `Content-Type: application/json`

**Parameters:**
- `id` (path, required): Provider UUID

**Request Body:**
```json
{
  "name": "Updated Name",
  "enabled": false
}
```

**Note:** This endpoint is currently not fully implemented and returns HTTP 501.

---

### Delete SSO Provider

Deletes an SSO provider configuration.

**Endpoint:** `DELETE /api/v1/sso/providers/{id}`

**Headers:**
- `Authorization: Bearer <token>`

**Parameters:**
- `id` (path, required): Provider UUID

**Response:**
- HTTP 204 No Content

---

### Test SSO Provider

Tests an SSO provider configuration by attempting to fetch metadata.

**Endpoint:** `POST /api/v1/sso/providers/{id}/test`

**Headers:**
- `Authorization: Bearer <token>`

**Parameters:**
- `id` (path, required): Provider UUID

**Response (Success):**
```json
{
  "success": true,
  "metadata": {
    "issuer": "https://accounts.google.com",
    "authorization_endpoint": "...",
    ...
  }
}
```

**Response (Failure):**
```json
{
  "success": false,
  "error": "failed to fetch OIDC discovery: connection timeout"
}
```

---

## Error Codes

### HTTP Status Codes

- `200 OK`: Request succeeded
- `201 Created`: Resource created successfully
- `204 No Content`: Resource deleted successfully
- `302 Found`: Redirect (used in SSO initiation)
- `400 Bad Request`: Invalid request parameters or configuration
- `401 Unauthorized`: Missing or invalid bearer token
- `403 Forbidden`: User lacks required permissions (e.g., not admin)
- `404 Not Found`: Resource not found
- `500 Internal Server Error`: Server error
- `501 Not Implemented`: Feature not yet implemented

### Application Error Codes

Errors in the `error` field may include:

- `invalid_provider`: Provider configuration is invalid
- `provider_disabled`: Provider is disabled
- `state_mismatch`: CSRF state token mismatch
- `state_expired`: State token has expired
- `callback_error`: Error processing IdP callback
- `domain_not_allowed`: User's email domain is not allowed
- `user_link_error`: Error linking user identity
- `signup_not_allowed`: User signup is not allowed for this provider

---

## Examples

### Complete OIDC Flow

1. **Create Provider (Admin)**

```bash
curl -X POST https://auth.example.com/api/v1/sso/providers \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "123e4567-e89b-12d3-a456-426614174000",
    "name": "Google Workspace",
    "slug": "google",
    "provider_type": "oidc",
    "enabled": true,
    "allow_signup": true,
    "issuer": "https://accounts.google.com",
    "client_id": "xxx.apps.googleusercontent.com",
    "client_secret": "GOCSPX-xxx",
    "scopes": ["openid", "profile", "email"]
  }'
```

2. **User Initiates Login**

```bash
curl -L "https://auth.example.com/auth/sso/google/login?tenant_id=123e4567-e89b-12d3-a456-426614174000"
```

This redirects to Google's authorization page.

3. **User Authenticates**

User authenticates with Google and is redirected back to:
```
https://auth.example.com/auth/sso/google/callback?code=xxx&state=xxx&tenant_id=xxx
```

4. **Guard Processes Callback**

Guard exchanges the code for tokens, creates/links the user account, and returns:

```json
{
  "user": {
    "id": "user-uuid",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "email_verified": true,
    "is_active": true
  },
  "is_new_user": true,
  "identity_id": "identity-uuid"
}
```

---

### Complete SAML Flow

1. **Create Provider (Admin)**

```bash
curl -X POST https://auth.example.com/api/v1/sso/providers \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "123e4567-e89b-12d3-a456-426614174000",
    "name": "Okta",
    "slug": "okta",
    "provider_type": "saml",
    "enabled": true,
    "allow_signup": true,
    "idp_metadata_url": "https://example.okta.com/app/xxx/sso/saml/metadata",
    "want_assertions_signed": true
  }'
```

2. **Download SP Metadata (for IdP configuration)**

```bash
curl "https://auth.example.com/auth/sso/okta/metadata?tenant_id=123e4567-e89b-12d3-a456-426614174000" > sp-metadata.xml
```

Upload this metadata to your IdP (Okta, Azure AD, etc.).

3. **User Initiates Login**

```bash
curl -L "https://auth.example.com/auth/sso/okta/login?tenant_id=123e4567-e89b-12d3-a456-426614174000"
```

This redirects to Okta's login page.

4. **User Authenticates**

User authenticates with Okta, and Okta POSTs the SAML response to:
```
POST https://auth.example.com/auth/sso/okta/callback
```

5. **Guard Processes SAML Response**

Guard validates the SAML assertion, creates/links the user account, and returns the user info.

---

## Security Considerations

1. **CSRF Protection**: All SSO flows use state tokens to prevent CSRF attacks
2. **State Expiration**: State tokens expire after 10 minutes
3. **Replay Protection**: State tokens can only be used once (atomic get-and-delete)
4. **Domain Restriction**: Providers can restrict authentication to specific email domains
5. **Secret Masking**: Sensitive fields (client secrets, private keys) are masked in API responses
6. **TLS Required**: All endpoints should be accessed over HTTPS in production
7. **Audit Logging**: All SSO attempts are logged for security auditing

---

## Provider Configuration Reference

### Common Fields

- `tenant_id` (UUID): Tenant this provider belongs to
- `name` (string): Human-readable provider name
- `slug` (string): URL-friendly identifier (used in endpoints)
- `provider_type` (string): "oidc" or "saml"
- `enabled` (boolean): Whether provider is active
- `allow_signup` (boolean): Allow new user registration
- `trust_email_verified` (boolean): Trust email_verified claim from IdP
- `domains` (array): Allowed email domains (empty = all allowed)
- `attribute_mapping` (object): Custom attribute mapping

### OIDC-Specific Fields

- `issuer` (string): OIDC issuer URL
- `authorization_endpoint` (string): OAuth2 authorization endpoint
- `token_endpoint` (string): OAuth2 token endpoint
- `userinfo_endpoint` (string): OIDC userinfo endpoint
- `jwks_uri` (string): JSON Web Key Set URI
- `client_id` (string): OAuth2 client ID
- `client_secret` (string): OAuth2 client secret
- `scopes` (array): OAuth2 scopes to request
- `response_type` (string): OAuth2 response type (default: "code")
- `response_mode` (string): OAuth2 response mode

### SAML-Specific Fields

- `entity_id` (string): SP entity ID
- `acs_url` (string): Assertion Consumer Service URL
- `slo_url` (string): Single Logout URL
- `idp_metadata_url` (string): IdP metadata URL
- `idp_metadata_xml` (string): IdP metadata XML (alternative to URL)
- `idp_entity_id` (string): IdP entity ID
- `idp_sso_url` (string): IdP SSO URL
- `idp_slo_url` (string): IdP SLO URL
- `idp_certificate` (string): IdP signing certificate
- `sp_certificate` (string): SP certificate (for signing)
- `sp_private_key` (string): SP private key (for signing)
- `sp_certificate_expires_at` (timestamp): SP certificate expiration
- `want_assertions_signed` (boolean): Require signed assertions
- `want_response_signed` (boolean): Require signed responses
- `sign_requests` (boolean): Sign authentication requests
- `force_authn` (boolean): Force re-authentication

---

## Error Responses

All SSO endpoints return errors in the following format:

```json
{
  "error": "human-readable error message"
}
```

### Common Error Codes

| HTTP Status | Error Message | Description |
|-------------|---------------|-------------|
| 404 | `SSO provider '{slug}' not found` | Provider doesn't exist or belongs to different tenant |
| 400 | `SSO provider '{slug}' is currently disabled` | Provider is disabled |
| 400 | `invalid or expired SSO state token` | State token is invalid, expired, or already used |
| 403 | `email domain '{domain}' is not allowed for this SSO provider` | User's email domain not in allowed list |
| 403 | `account signup is disabled for this SSO provider` | Signup disabled and user doesn't exist |
| 400 | `configuration validation failed for '{field}': {message}` | Provider configuration is invalid |
| 400 | `provider callback failed` | IdP callback processing failed |
| 401 | `missing bearer token` | Authentication required but not provided |
| 403 | `admin role required` | Insufficient permissions for admin operation |

---

## Rate Limits

All SSO endpoints are rate-limited to prevent abuse:

| Endpoint | Limit | Window | Key |
|----------|-------|--------|-----|
| `/auth/sso/:slug/login` | 10 requests | 1 minute | IP address |
| `/auth/sso/:slug/callback` | 20 requests | 1 minute | IP address |
| Admin endpoints (`/api/v1/sso/*`) | Standard API limits | - | Bearer token |

When rate limits are exceeded, the API returns HTTP 429 (Too Many Requests).

---

## Security Considerations

### State Token Security

- **Expiration:** State tokens expire after 10 minutes
- **Single-use:** Tokens can only be used once (atomic get-delete)
- **IP/User-Agent binding:** Tokens are validated against the original client's IP and User-Agent (warnings logged for mismatches)
- **Cryptographic randomness:** Tokens use 32 bytes of cryptographically secure random data

### HTTPS Required

All SSO endpoints MUST be accessed over HTTPS in production. HTTP is only allowed for local development.

### CSRF Protection

- OIDC flows use state tokens for CSRF protection
- SAML POST binding relies on state validation and secure cookies
- All state tokens are cryptographically random and single-use

### Domain Restrictions

Configure the `domains` array to restrict SSO access to specific email domains:

```json
{
  "domains": ["example.com", "corp.example.com"]
}
```

If empty, all domains are allowed.

### Audit Logging

All SSO authentication attempts are logged with:
- Timestamp
- IP address
- User agent
- Provider information (type, slug, ID)
- Success/failure status
- Error details (on failure)
- User information (on success)

Events published:
- `auth.sso.login.success`
- `auth.sso.login.failure`
- `auth.sso.provider.created`
- `auth.sso.provider.updated`
- `auth.sso.provider.deleted`

---

## Monitoring & Metrics

### Prometheus Metrics

The following metrics are exposed at `/metrics`:

#### SSO Authentication
- `guard_sso_initiate_total{provider_type, provider_slug, tenant_id}` - Counter of SSO initiations
- `guard_sso_callback_total{provider_type, provider_slug, status}` - Counter of callbacks (success/failure)
- `guard_sso_auth_duration_seconds{provider_type, status}` - Histogram of authentication duration

#### Provider Status
- `guard_sso_providers_count{provider_type, enabled}` - Gauge of provider count by type and status

### Health Checks

Check overall system health:
```bash
curl http://localhost:8080/health
```

Test specific provider configuration:
```bash
curl -H "Authorization: Bearer <token>" \
  http://localhost:8080/api/v1/sso/providers/{id}/test
```

This validates configuration and tests connectivity to the IdP.

---

## Support

For issues or questions, please refer to:
- [Troubleshooting Guide](../sso/TROUBLESHOOTING.md)
- [Deployment Guide](../sso/DEPLOYMENT.md)
- Main Guard documentation
- Your system administrator
