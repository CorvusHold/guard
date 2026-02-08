# Admin Settings UI Guide

## Overview

The Admin Settings UI allows tenant administrators to configure critical security settings including SSO redirect allowlists and CORS origins directly from the browser.

## Accessing Admin Settings

1. Navigate to `/admin` in your Guard UI
2. Enter your tenant ID
3. Click "Load" to fetch current settings

## Key Settings

### SSO Redirect Allowlist

**Purpose**: Prevents redirect attacks by validating SSO callback URLs

**Format**: Comma-separated list of allowed callback URLs
- Must include scheme (http/https)
- Must include host and port
- Path prefixes are supported

**Examples**:
```bash
http://localhost:3001,https://app.packitoo.com
http://localhost:3001/api/guard,https://app.example.com/callback
```

**When to Update**:
- Adding new development environments
- Deploying to new production domains
- Changing callback URL paths

**Security Note**: This prevents attackers from redirecting SSO flows to malicious sites. Always keep this list minimal and specific.

### CORS Allowed Origins

**Purpose**: Controls which browser origins can make API requests

**Format**: Comma-separated list of allowed origins
- Must include scheme (http/https)
- Must include host and port
- No trailing slashes

**Examples**:
```bash
https://app.packitoo.com,http://localhost:3000,http://localhost:3001
https://app.example.com,https://staging.example.com
```

**When to Update**:
- Adding new frontend applications
- Supporting multiple development ports
- Deploying to new domains

**Security Note**: This is separate from the global CORS configuration in Helm values. Tenant-specific CORS settings override global settings for that tenant.

## Common Scenarios

### Scenario 1: Local Development Setup

**Problem**: Getting 403 errors when testing SSO locally

**Solution**:
1. Go to Admin Settings
2. Load your tenant settings
3. Update SSO Redirect Allowlist: `http://localhost:3001,http://localhost:3000`
4. Update CORS Allowed Origins: `http://localhost:3001,http://localhost:3000`
5. Click "Save Settings"

### Scenario 2: Production Deployment

**Problem**: Need to add production domain

**Solution**:
1. Load tenant settings
2. Add production URLs to both fields:
   - SSO Redirect Allowlist: `https://app.packitoo.com,http://localhost:3001`
   - CORS Allowed Origins: `https://app.packitoo.com,http://localhost:3001`
3. Save settings

### Scenario 3: Multiple Environments

**Problem**: Supporting dev, staging, and production

**Solution**:
```
SSO Redirect Allowlist:
http://localhost:3001,https://staging.example.com,https://app.example.com

CORS Allowed Origins:
http://localhost:3001,https://staging.example.com,https://app.example.com
```

## Differences Between Settings

| Setting | Purpose | Validates |
|---------|---------|-----------|
| **SSO Redirect Allowlist** | SSO security | Callback URLs in SSO flows |
| **CORS Allowed Origins** | Browser security | Origin header in API requests |
| **Global CORS (Helm)** | Fallback | Origins when no tenant-specific setting |

**Key Point**: You need BOTH settings configured:
- CORS allows the browser to make the request
- SSO Redirect Allowlist validates the callback URL

## API Reference

### GET Settings
```bash
curl -X GET "https://auth.packitoo.com/api/v1/tenants/{tenant_id}/settings" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Update Settings
```bash
curl -X PUT "https://auth.packitoo.com/api/v1/tenants/{tenant_id}/settings" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "sso_redirect_allowlist": "http://localhost:3001,https://app.example.com",
    "app_cors_allowed_origins": "http://localhost:3001,https://app.example.com"
  }'
```

## Troubleshooting

### 403 Error on SSO Login

**Symptom**: 
```json
{"status":403,"error":"redirect_url not allowed"}
```

**Cause**: Callback URL not in SSO redirect allowlist

**Fix**: Add your callback URL to the SSO Redirect Allowlist field

### CORS Error in Browser Console

**Symptom**:
```
Access to fetch at 'https://auth.packitoo.com' from origin 'http://localhost:3001' 
has been blocked by CORS policy
```

**Cause**: Origin not in CORS allowed origins

**Fix**: Add your frontend origin to the CORS Allowed Origins field

### Settings Not Saving

**Symptom**: No success message after clicking Save

**Cause**: Usually validation errors or authentication issues

**Fix**:
1. Check error message displayed
2. Verify URLs have proper format (scheme + host + port)
3. Ensure you have admin/owner role
4. Check browser console for detailed errors

## E2E Testing

The admin settings UI has comprehensive Playwright tests covering:

✅ Load and save settings
✅ Update SSO redirect allowlist
✅ Update CORS origins
✅ Empty values handling
✅ Help text visibility
✅ Portal link generation

Run tests:
```bash
cd ui
npm run build && npm run preview &
npx playwright test admin-settings.spec.ts
```

## Best Practices

1. **Keep Lists Minimal**: Only add URLs you actually use
2. **Use HTTPS in Production**: Avoid http:// in production settings
3. **Include Port Numbers**: `localhost:3001` ≠ `localhost:3000`
4. **Test After Changes**: Verify SSO flows work after updating
5. **Document Changes**: Keep track of which URLs are for which environments
6. **Regular Audits**: Review and remove unused URLs periodically

## Security Considerations

- **Never use wildcards**: Each URL must be explicitly listed
- **Validate before adding**: Ensure URLs are owned by your organization
- **Monitor for changes**: Set up alerts for settings modifications
- **Principle of least privilege**: Only grant admin access to trusted users
- **Audit logs**: All settings changes are logged for compliance

## Settings Resolution Model

Guard uses a 3-layer settings resolution chain:

1. **Tenant DB** (`app_settings WHERE tenant_id = <uuid>`) — highest priority
2. **Global DB** (`app_settings WHERE tenant_id IS NULL`) — fallback
3. **Env / config.Config** — lowest priority, used as default when DB has no value

Most settings (JWT signing key, token TTLs, email provider, SSO config) are resolved at request-handling time using the `tenant_id` from the parsed request body. The service layer passes `cfg.X` as the default, so the chain works transparently.

### CORS and Rate Limits: `X-Tenant-ID` Header Required

CORS and rate limit middleware run **before** the request body is parsed. They cannot extract `tenant_id` from JSON bodies. To enable per-tenant CORS origins and rate limit overrides on auth endpoints (`/password/login`, `/signup`, `/magic/send`, etc.), clients **must** send the `X-Tenant-ID` header.

The resolution order for tenant context in middleware is:
1. `X-Tenant-ID` request header
2. `?tenant_id=` query parameter
3. `:id` / `:tenant_id` route parameters (for `/api/v1/tenants/:id/*` paths)

The TS SDK (`@corvushold/guard-sdk`) automatically sends `X-Tenant-ID` on every request when `tenantId` is configured in the client constructor. If you use a custom HTTP client, include this header for tenant-scoped CORS and rate limits to work.

### Example: Configuring Tenant CORS

```bash
# Set tenant-specific CORS origins (augments global CORS_ALLOWED_ORIGINS env)
curl -X PUT "https://auth.example.com/api/v1/tenants/{tenant_id}/settings" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"app_cors_allowed_origins": "https://app.tenant.com,https://staging.tenant.com"}'
```

Browser requests from `https://app.tenant.com` will then be allowed, provided the SDK (or custom client) sends `X-Tenant-ID: <tenant_id>` in the request headers.

## Related Documentation

- [SSO Implementation Guide](./sso/OIDC_IMPLEMENTATION.md)
- [Tenant Onboarding](./TENANT_ONBOARDING.md)
- [Cookie Mode Guide](./COOKIE_MODE.md)
