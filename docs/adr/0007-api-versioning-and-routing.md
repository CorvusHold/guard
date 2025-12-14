# 0007 – API Versioning and `/api/v1` Routing

## Status

Proposed

## Context

Today, Guard’s JSON APIs are exposed at mixed paths:

- `/api/v1/auth/...`
- `/api/v1/sso/...`
- `/api/v1/tenants/{id}/settings`
- `/tenants`, `/tenants/{id}`, `/tenants/by-name/{name}`, `/tenants/{id}/deactivate`

There is no `/api/` prefix, some endpoints are unversioned, and the current layout makes it harder to introduce a new major API version (for example, `/api/v2`) without another broad refactor.

At the same time, there are several special endpoints that should not be moved under a versioned `/api` prefix:

- OAuth2 discovery: `/.well-known/oauth-authorization-server` (RFC 8414)
- Health and readiness: `/healthz`, `/livez`, `/readyz`
- Metrics and debug tooling: `/metrics`, `/debug/pprof/...`
- Swagger UI and spec: `/swagger/*`
- Browser-centric SSO flows under `/auth/sso/...` that handle redirects and SAML POSTs rather than JSON APIs.

We want a consistent, scalable API versioning scheme where:

- All **JSON APIs** live under `/api/v1/...`.
- It is straightforward to introduce `/api/v2/...` later.
- Operational endpoints and protocol-mandated paths stay where standards and tooling expect them.

This ADR defines that scheme and how to migrate to it.

## Decision

### 1. Canonical JSON API base

All JSON APIs will be served under the canonical base:

- Base prefix: `/api/v1`
- Namespaces:
  - `/api/v1/auth/...`
  - `/api/v1/sso/...`
  - `/api/v1/tenants/...`

### 2. Old → new mappings (breaking)

The following path changes are **breaking** for clients:

- Auth JSON APIs
  - Old: `/v1/auth/...`
  - New: `/api/v1/auth/...`

- SSO admin & portal JSON APIs
  - Old: `/v1/sso/...`
  - New: `/api/v1/sso/...`

- Tenant settings APIs
  - Old: `/v1/tenants/{id}/settings`
  - New: `/api/v1/tenants/{id}/settings`

- Tenant management APIs
  - Old: `/tenants`, `/tenants/{id}`, `/tenants/by-name/{name}`, `/tenants/{id}/deactivate`
  - New: `/api/v1/tenants`, `/api/v1/tenants/{id}`, `/api/v1/tenants/by-name/{name}`, `/api/v1/tenants/{id}/deactivate`

These new paths are considered canonical from this ADR forward.

### 3. Endpoints that remain outside `/api`

The following endpoints MUST remain outside `/api`:

- OAuth2 discovery (RFC 8414)
  - `/.well-known/oauth-authorization-server`

- Operational endpoints
  - `/healthz`
  - `/livez`
  - `/readyz`
  - `/metrics`
  - `/debug/pprof/...`
  - `/swagger/*`

- Browser-oriented SSO redirect/SAML flows
  - `/auth/sso/t/:tenant_id/:slug/login`
  - `/auth/sso/t/:tenant_id/:slug/callback` (GET/POST)
  - `/auth/sso/t/:tenant_id/:slug/metadata`
  - `/auth/sso/t/:tenant_id/:slug/logout` (GET/POST)
  - Legacy compatibility redirects under `/auth/sso/:slug/...`

These endpoints are either required at fixed locations by standards or are operational/debug endpoints typically left unversioned.

### 4. Routing architecture for future versions

Routing will be restructured around versioned Echo groups:

- In `cmd/api/main.go`:
  - `api := e.Group("/api")`
  - `apiV1 := api.Group("/v1")`

- Domain slices will expose registration functions that take an `*echo.Group` for a specific API version:

  - `tenants.RegisterV1(apiV1, pgPool)`
  - `auth.RegisterV1(apiV1, pgPool, cfg)`
  - `settings.RegisterV1(apiV1, pgPool, cfg)`
  - `sso.RegisterV1(apiV1, ...)` for the JSON SSO admin & portal APIs

Within these functions, routes are defined **relative** to the provided group:

- Tenants:
  - `apiV1.POST("/tenants", ...)` → `/api/v1/tenants`
- Auth:
  - `authGroup := apiV1.Group("/auth")` then `authGroup.POST("/password/login", ...)` → `/api/v1/auth/password/login`
- Settings:
  - `apiV1.GET("/tenants/:id/settings", ...)` → `/api/v1/tenants/:id/settings`
- SSO admin & portal:
  - `ssoGroup := apiV1.Group("/sso")` then `ssoGroup.GET("/sp-info", ...)` → `/api/v1/sso/sp-info`

Future API versions (e.g. `/api/v2`) will follow the same pattern:

- `apiV2 := api.Group("/v2")`
- `tenants.RegisterV2(apiV2, ...)`, etc.

### 5. OpenAPI / Swagger

OpenAPI/Swagger will be updated to treat `/api` as the base path for JSON APIs:

- `@BasePath` in `cmd/api/main.go` becomes `/api` instead of `/`.
- All JSON API `@Router` annotations are updated to match `/api/v1/...` paths, for example:
  - `/v1/auth/refresh` → `/api/v1/auth/refresh`
  - `/tenants` → `/api/v1/tenants`
  - `/v1/tenants/{id}/settings` → `/api/v1/tenants/{id}/settings`
  - `/v1/sso/sp-info` → `/api/v1/sso/sp-info`

Non-API endpoints keep their existing documented paths, if present.

`swag init -g cmd/api/main.go -o docs` remains the source of truth for `docs/swagger.json`, which is then synced into `sdk/spec/openapi.json` and `sdk/spec/openapi.yaml` via the existing tooling.

### 6. Release model

This change is **breaking** for existing clients. It will be shipped in a new major version of Guard and its SDKs.

- SDKs (Go, TS) will be bumped to a new major version and updated to target `/api/v1/...`.
- UI and examples should be updated to use the new SDKs and/or new paths.
- Optionally, thin compatibility aliases may be provided for one release cycle (old paths forwarding to new handlers), but the ADR does not require them; the canonical contract is `/api/v1/...`.

## Consequences

### Pros

- Clear and consistent API surface under a single `/api/v1` base.
- Simple path to introduce `/api/v2` without editing existing v1 handlers.
- Operational endpoints and standards-constrained paths are not polluted with versioning concerns.

### Cons

- Breaking change for any client, script, or test using legacy paths.
- Requires updates across SDKs, UI, tests, k6 scripts, and infrastructure.

## AI Agent Implementation To‑Do List

This section defines a concrete checklist for an automated AI agent implementing this ADR in the Guard repository.

### Phase 1 – Discovery & validation

- **[P1] Inventory current routes**
  - List all Echo route registrations for:
    - `/api/v1/auth/...`, `/api/v1/sso/...`, `/api/v1/tenants/...`, `/tenants...`.
  - Confirm which endpoints are JSON APIs vs runtime/SSO/pprof/metrics.

- **[P2] Inventory consumers**
  - Search for all occurrences of `/api/v1/auth`, `/api/v1/sso`, `/api/v1/tenants`, `/tenants`, etc.
  - Categorize by location:
    - Go tests, SDKs, UI, k6 scripts, Helm/infra, docs.

### Phase 2 – Router refactor

- **[P3] Add versioned groups in `cmd/api/main.go`**
  - Introduce `api := e.Group("/api")` and `apiV1 := api.Group("/v1")`.
  - Ensure existing non-API endpoints remain on the root `e`:
    - `.well-known`, health, metrics, pprof, swagger, SSO browser flows.

- **[P4] Refactor domain registration functions**

  For each domain slice (tenants, auth, settings, SSO admin):

  - Add new functions that accept `*echo.Group` for v1, for example:
    - `tenants.RegisterV1(apiV1, pgPool)`
    - `auth.RegisterV1(apiV1, pgPool, cfg)`
    - `settings.RegisterV1(apiV1, pgPool, cfg)`
    - `sso.RegisterV1(apiV1, ...)`
  - Inside these functions, change absolute paths to be relative to `apiV1`:
    - Tenants: from `/tenants` → group relative `/tenants` (effective `/api/v1/tenants`).
    - Auth: from `/api/v1/auth` group to `apiV1.Group("/auth")`.
    - Settings: from `/api/v1/tenants/:id/settings` to `apiV1.GET("/tenants/:id/settings", ...)`.
    - SSO admin/portal: from `/api/v1/sso/...` to `apiV1.Group("/sso")` relative.
  - Update `cmd/api/main.go` to call the new `RegisterV1` functions.

- **[P5] Optional: legacy wrappers (if desired)**
  - If temporary backwards compatibility is desired:
    - Implement thin wrappers `Register(e *echo.Echo, ...)` that create `apiV1 := e.Group("/api/v1")` and call `RegisterV1`.
    - Otherwise, remove or deprecate old `Register` functions as part of the breaking change.

### Phase 3 – OpenAPI / Swagger

- **[P6] Update base path**
  - Change `@BasePath` from `/` to `/api` in `cmd/api/main.go`.

- **[P7] Update `@Router` annotations**
  - For every JSON API endpoint, update `@Router` to match `/api/v1/...` paths.
  - Verify that `.well-known` and health/metrics/debug endpoints keep their existing paths.

- **[P8] Regenerate specs**
  - Run `swag init -g cmd/api/main.go -o docs`.
  - Ensure `sdk/spec/openapi.yaml` and `sdk/spec/openapi.json` remain in sync via existing scripts.

### Phase 4 – SDKs and UI

- **[P9] Go SDK**
  - Identify all hard-coded paths using legacy `/v1/...` and update them to `/api/v1/...`.
  - Centralize the versioned base path (`/api/v1`) to avoid scattering.
  - Bump the Go SDK major version and update any docs referencing old URLs.

- **[P10] TS SDK**
  - Update TS client configuration to hit `/api/v1/...`.
  - Ensure base URL logic composes host + `/api/v1`.
  - Bump the TS SDK major version and adjust documentation.

- **[P11] UI**
  - Prefer updating the UI to use the new SDK versions.
  - If any UI code calls backend endpoints directly, adjust URLs to `/api/v1/...`.

### Phase 5 – Tests, scripts, infra

- **[P12] Backend tests**
  - Update all test requests that target old paths:
    - `/v1/auth/...`, `/v1/sso/...`, `/v1/tenants/...`, `/tenants...`.
  - Replace with `/api/v1/...` equivalents.
  - Ensure all Go tests pass (`go test ./...`).

- **[P13] Load tests and scripts**
  - Update k6 scripts under `ops/k6/` and any shell scripts to use `/api/v1/...`.

- **[P14] Helm / infra / monitoring**
  - Update any ingress routes or monitors that refer to old prefixes.
  - Keep health checks as-is (`/livez`, `/readyz`, `/healthz`).

### Phase 6 – Documentation & migration guide

- **[P15] Update docs**
  - Document the new canonical paths and versioning scheme.
  - Include an “old → new” path mapping table.

- **[P16] Migration notes**
  - Add a migration guide section for customers and SDK consumers:
    - How to upgrade SDKs.
    - Expected behavior if old URLs are still used (e.g., 404s or deprecation where aliases exist).
