# Tenant-aware Rate Limiting

Guard provides fixed-window rate limiting for all `/v1/auth/*` endpoints. In multi-tenant deployments, limits and windows can be configured per-tenant and per-endpoint via settings.

## Backend

- Default: in-memory fixed window (single-process only).
- Recommended: Redis/Valkey-backed shared store enabled automatically by the auth factory when configured.
- On store errors, limiter fails open (request proceeds) to preserve availability.

## Keys and Scoping

Keys are derived as `prefix:ten:<tenant_id>` if a tenant can be determined from either:

- `tenant_id` query parameter, or
- JSON body field `tenant_id` (request body is non-destructively read and restored).

If no tenant can be resolved, the key falls back to `prefix:ip:<client_ip>`.

### Real client IP behind proxies/CDN (Cloudflare)

If Guard is deployed behind Cloudflare or another reverse proxy, configure Echo to extract the real client IP from proxy headers. This ensures IP-scoped rate limiting and logs are accurate.

Example extractor (prefers Cloudflare's `CF-Connecting-IP`, then `X-Forwarded-For`, then `X-Real-IP`, then `RemoteAddr`):

```go
// in cmd/api/main.go, after creating `e := echo.New()`
e.IPExtractor = func(r *http.Request) string {
    if ip := r.Header.Get("CF-Connecting-IP"); ip != "" {
        return ip
    }
    // Fallback to X-Forwarded-For (left-most value)
    if xff := r.Header.Get(echo.HeaderXForwardedFor); xff != "" {
        if i := strings.IndexByte(xff, ','); i >= 0 {
            return strings.TrimSpace(xff[:i])
        }
        return strings.TrimSpace(xff)
    }
    if ip := r.Header.Get(echo.HeaderXRealIP); ip != "" {
        return ip
    }
    host, _, _ := net.SplitHostPort(r.RemoteAddr)
    return host
}
```

Security notes:

- Only trust these headers when your app is actually behind a trusted proxy/CDN; otherwise clients can spoof them.
- For additional safety, restrict trust by verifying that `r.RemoteAddr` belongs to Cloudflare’s published IP ranges before honoring headers.

## Defaults

Unless overridden, these per-endpoint defaults apply:

- Signup: 2 requests / 1m
- Login: 2 requests / 1m
- Magic link (send/verify): 5 requests / 1m
- Token lifecycle (refresh/logout/me/introspect/revoke): 10 requests / 1m
- MFA (all operations): 10 requests / 1m

## Settings (per-tenant or global)

Override limits and windows by upserting settings. Tenant-specific overrides take precedence over global values.

- Signup:
  - `auth.ratelimit.signup.limit` (int)
  - `auth.ratelimit.signup.window` (duration, e.g. `30s`, `2m`)
- Login:
  - `auth.ratelimit.login.limit`
  - `auth.ratelimit.login.window`
- Magic link:
  - `auth.ratelimit.magic.limit`
  - `auth.ratelimit.magic.window`
- Token lifecycle (refresh, logout, me, introspect, revoke):
  - `auth.ratelimit.token.limit`
  - `auth.ratelimit.token.window`
- MFA (TOTP/backup):
  - `auth.ratelimit.mfa.limit`
  - `auth.ratelimit.mfa.window`
- SSO (start/callback):
  - `auth.ratelimit.sso.limit`
  - `auth.ratelimit.sso.window`

Duration uses Go's duration format, e.g. `2s`, `1m`, `5m`.

## Example: set login to 1 req / 60s for a tenant

```sql
-- SQL upsert via repository (illustrative)
INSERT INTO app_settings (id, tenant_id, key, value, is_secret)
VALUES (gen_random_uuid(), '00000000-0000-0000-0000-000000000000', 'auth.ratelimit.login.limit', '1', false)
ON CONFLICT (tenant_id, key) DO UPDATE SET value = EXCLUDED.value;
```

Or using the settings repository in Go tests:

```go
sr := settingsrepo.New(pool)
_ = sr.Upsert(ctx, domain.KeyRLLoginLimit, &tenantID, "1", false)
_ = sr.Upsert(ctx, domain.KeyRLLoginWindow, &tenantID, "60s", false)
```

## HTTP Responses

Exceeding the limit returns `429 Too Many Requests` with a `Retry-After` header indicating seconds to wait before retrying.

## Swagger

All relevant `/v1/auth/*` endpoints now document `429` responses. See `docs/swagger.yaml` or the Swagger UI at `/swagger/index.html`.
