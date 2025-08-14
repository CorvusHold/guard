# Guard SDK Conventions (Cross-Language)

This document defines shared conventions for all Guard SDKs (TS, Go, Rust).

## HTTP Transport
- Pluggable transport per language (e.g., `fetch`, `reqwest`, `net/http`).
- Default JSON encoder/decoder with UTF-8.
- Timeouts are configurable by the host application.

## Headers
- Authorization: `Authorization: Bearer <access_token>`
- Request ID passthrough: if the server returns a request identifier header (canonical: `X-Request-ID`), SDKs should expose it on errors and responses when feasible. Note: header names are case-insensitive; use `X-Request-ID` in docs/examples for consistency.
- Client identification: add `X-Guard-Client: <lang>-sdk/<version>` to aid observability.
- Tenant context: the API may require tenant context via header and/or request body. The canonical header name will be confirmed during endpoint mapping. SDKs MUST support:
  - A client-level default tenant
  - Per-call override of tenant

## Error Model
- Map 4xx/5xx responses into typed errors.
- Base error shape to expose to consumers:
  - `status`: HTTP status code
  - `code` (optional): stable service error code if provided by API
  - `message`: human-readable message if provided by API
  - `requestId` (optional): from response header
  - `raw` (optional): access to raw response (debugging only)

## Rate Limiting
- On HTTP 429, surface a `RateLimitError` variant including:
  - `retryAfter` (seconds) parsed from `Retry-After` header when present
  - `nextRetryAt` (absolute time) derived from `retryAfter` when feasible
- SDKs MUST NOT auto-retry non-idempotent requests by default.
- Provide a helper to check if an error is a rate-limit error and derive retry hints.
 - Future headers (server may add): `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`. Benefits include better UX (show usage/remaining), adaptive backoff, and observability. Until present, SDKs must rely on `Retry-After` only.

## Token Management
- SDKs accept an injected token provider/storage abstraction.
- Provide reference in-memory storage; browser SDKs may provide a localStorage-backed implementation guarded for browser environments.
- The SDKs should not persist secrets without explicit consumer opt-in.

## Tenant Handling
- The client accepts a default `tenantId` and supports per-call overrides.
- Injection location (header and/or body) follows API requirements; final names confirmed during OpenAPI mapping.
 - Note: For rate limiting today, tenant is derived from `tenant_id` query parameter or JSON body field `tenant_id` (see `docs/rate-limiting.md`). Header-based conventions will be confirmed during endpoint mapping.

### Optional (Future): Tenant Header
- Proposed header: `X-Guard-Tenant`
- Purpose:
  - Easier proxy/gateway routing and sharding without parsing body/query
  - Avoid leaking tenant in URLs for GET/redirect flows
  - Uniform observability field in logs/metrics
  - Clear keying for rate-limit/caching at the edge
  - BFF/aggregator can set it on behalf of public clients
- Security and precedence:
  - Treat as a trusted-hop header only; server must validate tenant against auth context
  - If both header and body/query are present, precedence is server-defined; SDKs SHOULD NOT set conflicting locations by default
  - Disabled by default in SDKs until server adopts the header explicitly

## Retries and Idempotency
- No automatic retries by default.
- Provide optional retry helpers for idempotent GETs with backoff, leaving policy decisions to consumers.

## Observability
- Preserve and expose `requestId` on errors.
- Include `X-Guard-Client` header for attribution.

## Response Metadata
- SDKs MUST expose `requestId` on both successful and error responses when the server returns `X-Request-ID`.
- Minimal metadata suggested for success responses:
  - `status` (HTTP status code)
  - `requestId` (from `X-Request-ID` if present)
  - `headers` (optional pass-through for advanced consumers)

### Standard Response Wrapper (Cross-Language)
- All SDK methods SHOULD return a response wrapper with `data` and `meta`:
  - `data`: the typed DTO for the operation
  - `meta`: `{ status: number, requestId?: string, headers?: Record<string,string> }`

Language examples:
- TypeScript: `{ data: T, meta: { status: number, requestId?: string, headers?: Record<string,string> } }`
- Go:
  ```go
  type Meta struct {
      Status    int
      RequestID string
      Headers   map[string]string // optional
  }
  type Response[T any] struct {
      Data T
      Meta Meta
  }
  ```
- Rust:
  ```rust
  pub struct Meta {
      pub status: u16,
      pub request_id: Option<String>,
      pub headers: Option<std::collections::HashMap<String, String>>, // optional
  }
  pub struct Response<T> {
      pub data: T,
      pub meta: Meta,
  }
  ```

## Compatibility
- SDKs version independently with semver.
- Maintain an API ↔ SDK compatibility matrix in `sdk/COMPATIBILITY.md` (to be added).
