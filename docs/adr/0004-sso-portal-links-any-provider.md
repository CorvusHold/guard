# ADR-0004: SSO Portal Links For Any Provider

**Status**: Proposed  
**Date**: 2025-12-04  
**Deciders**: Guard Platform Team

## Context and Problem Statement

Today, Guard exposes an SSO organization portal link generator only for WorkOS:

- HTTP endpoint: `GET /api/v1/auth/sso/workos/portal-link`
- Controller: `ssoOrganizationPortalLinkGenerator` in `internal/auth/controller/http.go`
- Service: `OrganizationPortalLinkGeneratorWorkOS` in `internal/auth/service/sso_workos.go`

This endpoint:

- Is restricted to authenticated tenant admins (Bearer token, `admin` role).
- Validates `tenant_id`, `organization_id`, and `intent`.
- Calls the WorkOS `portal/generate_link` API using tenant-scoped credentials.
- Returns a `domain.PortalLink` DTO containing a WorkOS-hosted Admin Portal URL.

This works well for WorkOS tenants, but it has two gaps relative to ADR-0001 (native SSO/OIDC/SAML) and ADR-0002 (SSO provider edit strategy):

1. Only WorkOS can generate a portal link. Native OIDC and future SAML providers have no equivalent onboarding portal.
2. The portal experience is vendor-owned. For non-WorkOS providers we want to leverage our own UI module to give IdP admins a focused, tenant-scoped setup experience.

We have a concrete product requirement:

- For any SSO OIDC provider configured in Guard, platform operators and tenant admins must be able to generate a portal link and send it to the customer’s IdP administrator.
- The recipient uses that link to configure SSO for a given tenant without first creating a Guard admin account or having general access to the Guard Admin UI.

We want to keep the good parts of the WorkOS flow (shareable link, IdP-admin focused) while generalizing it to all providers and aligning with our native SSO direction.

## Decision

We will generalize the SSO portal link concept as follows:

1. Treat `OrganizationPortalLinkGenerator` in the SSO service as a provider-agnostic capability.
2. Preserve the existing WorkOS behavior by delegating to the WorkOS Admin Portal for tenants whose SSO provider is `workos`.
3. For all non-WorkOS SSO providers (native OIDC, future SAML, dev adapter), generate a Guard-hosted SSO Setup Portal link that points at our own UI.
4. Continue to expose a single HTTP surface for admins to create links:
   - `GET /api/v1/auth/sso/{provider}/portal-link`
   - `provider` is either:
     - `workos` (WorkOS adapter), or
     - a configured SSO provider slug from `sso_providers.slug` (for native providers).
5. Restrict portal link creation to Guard-authenticated tenant admins, as today.
6. Allow the link recipient to access a minimal SSO Setup Portal without having a Guard user account, by authenticating them via a high-entropy, signed portal token that is:
   - tenant-scoped
   - provider-scoped
   - time-limited
   - auditable and revocable

In short: WorkOS continues to use the WorkOS Admin Portal; all other providers use a Guard-hosted SSO Setup Portal, and both are surfaced through a common `portal-link` API.

## Decision Drivers

- Reduce dependence on vendor-specific admin portals while we roll out native SSO (ADR-0001).
- Give platform operators a consistent way to onboard customers’ IdP admins regardless of provider.
- Avoid forcing IdP admins to become full Guard admins just to configure SSO.
- Reuse the Guard Admin UI where possible instead of duplicating configuration flows elsewhere.
- Maintain strong tenant isolation, auditability, and rate limiting.

## Design Overview

### API Surface

We standardize on the existing controller route:

- `GET /api/v1/auth/sso/{provider}/portal-link`

Parameters (unchanged at HTTP level, semantics extended):

- Path:
  - `provider`: SSO adapter or provider slug.
    - `workos` → WorkOS Admin Portal link.
    - any other configured SSO provider slug (for now, primarily OIDC) → Guard SSO Setup Portal link.
- Query:
  - `tenant_id` (required, UUID string)
  - `organization_id` (required only for WorkOS; ignored for internal portal links unless later extended)
  - `intent` (optional; WorkOS intents already supported, extended for internal UI as described below)

Authentication and authorization remain as implemented today:

- `Bearer` token required.
- Token must be active via `/api/v1/auth/introspect`.
- Caller must have `admin` role in the tenant.
- Caller’s tenant ID must match `tenant_id` in the query.

Response contract remains the same for all providers:

- `200 OK` with body `domain.PortalLink`:
  - `link` (string): absolute URL to either the vendor portal (WorkOS) or Guard’s SSO Setup Portal.

This keeps SDK and client semantics stable. The TS SDK already models `PortalLink` as a DTO with a required `link` string; that contract does not change.

### Service Layer Behavior

The `SSOService` interface in `internal/auth/domain/types.go` already defines:

- `OrganizationPortalLinkGenerator(ctx, in SSOOrganizationPortalLinkGeneratorInput) (PortalLink, error)`

We will keep this shape and change the implementation logic in `internal/auth/service/sso.go` to:

1. Resolve the provider from the HTTP path and tenant context.
   - If `in.Provider == "workos"`, ensure the tenant has WorkOS SSO configured; otherwise return a provider-not-configured error.
   - Otherwise, look up a row in `sso_providers` by `(tenant_id, slug = in.Provider, enabled = true)`; if none is found, return a provider-not-found error.
2. Branch by provider type:
   - If the resolved provider type is `workos`, delegate to `OrganizationPortalLinkGeneratorWorkOS` (current behavior).
   - Otherwise, build an internal portal link using Guard’s UI.

High-level pseudo-code (illustrative, not binding):

- Resolve `tenantID` and `providerSlug` from the HTTP layer and authenticated user.
- If `providerSlug == "workos"`:
  - Verify tenant has WorkOS configured; if not, fail with `PROVIDER_NOT_CONFIGURED`.
  - Call `OrganizationPortalLinkGeneratorWorkOS` and return its `PortalLink`.
- Else:
  - Look up `ssoProvider` by `(tenant_id = tenantID, slug = providerSlug, enabled = true)`; if not found, fail with `PROVIDER_NOT_FOUND`.
  - Generate a new SSO portal token bound to `tenantID` and `ssoProvider.ID` (see below).
  - Construct a URL of the form `{ui_base_url}/portal/sso-setup?token={raw_token}`; `tenant` and `provider` query parameters, if present, are cosmetic and not used for authorization.
  - Return `domain.PortalLink{Link: url}`.

### Portal Token Model

To allow non-Guard users to access the SSO Setup Portal safely we introduce a portal token concept.

Key properties:

- High-entropy, unguessable random value (similar to magic link tokens).
- Stored server-side in a persistent store (Postgres) with a hashed token value.
- Bound to:
  - `tenant_id`
  - `sso_provider_id` (foreign key to `sso_providers.id`)
  - `intent` (sso, dsync, user_management, etc.)
  - `created_by_user_id` (the Guard admin who generated the link)
- Includes lifecycle and observability fields:
  - `token_hash` (e.g. SHA-256 of the raw token, `UNIQUE`)
  - `max_uses` (INT, default `1`, upper-bounded; multi-use is an explicit opt-in)
  - `use_count` (INT, starts at `0`, incremented atomically on each successful validation)
  - `created_at` and `last_used_at`
  - `expires_at` (TTL, e.g. 7 days by default, with a configurable upper bound)
  - `revoked_at` (explicit invalidation)

Illustrative schema (simplified):

```sql
CREATE TABLE sso_portal_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    sso_provider_id UUID NOT NULL REFERENCES sso_providers(id) ON DELETE CASCADE,
    intent TEXT NOT NULL,
    token_hash BYTEA NOT NULL UNIQUE,
    max_uses INT NOT NULL DEFAULT 1,
    use_count INT NOT NULL DEFAULT 0,
    created_by_user_id UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX idx_sso_portal_tokens_tenant
    ON sso_portal_tokens(tenant_id, expires_at)
    WHERE revoked_at IS NULL;
```

When the Admin UI asks for a portal link, the backend will:

- Create a portal token record.
- Return a URL pointing at the SSO Setup Portal route with the raw token as a query parameter.

When the SSO Setup Portal is opened by an IdP admin, the UI will:

- Send the raw token to a dedicated backend endpoint (for example, `POST /api/v1/sso/portal/session`) to exchange it for a short-lived, scoped session token or for an access-granted response.
- The backend validates the portal token:
  - Lookup by hash.
  - Check `tenant_id`, provider, `expires_at`, and revocation flags.
  - Increment usage counters.
- If valid, the backend allows a limited set of SSO configuration operations for that tenant and provider via dedicated portal endpoints and/or a portal-scoped session token.

### Internal SSO Setup Portal UI

For non-WorkOS providers, the `link` field will point to a Guard-hosted SSO Setup Portal, implemented as a route in our UI.

Core principles:

- The portal route lives under the public UI base URL, for example:
  - `{app.public_base_url}/portal/sso-setup` or
  - `{app.public_base_url}/portal/sso/{tenant_slug}/{provider_slug}`
- The route:
  - Does not require a Guard user session.
  - Requires a valid portal token, initially passed as a query parameter.
  - Uses the TS SDK to exchange the portal token for a short-lived, portal-scoped session (`POST /api/v1/sso/portal/session`), then calls portal-specific backend APIs with that session (for example via a bearer token or cookie that is not accepted by general admin endpoints).
  - Shows a minimal, opinionated configuration surface for the provider (client ID, client secret, issuer, redirect URIs, etc.), aligned with ADR-0001 and ADR-0002.
  - Does not expose the rest of the Admin UI (no navigation to users, settings, RBAC, etc.).

This SSO Setup Portal should be implemented as a reusable module in the UI codebase so that:

- It can be embedded into different hosting contexts if needed.
- It shares validation, field mapping, and UX patterns with the main Admin SSO management pages.

### Intent Semantics

The `intent` query parameter is already used for WorkOS to drive different Admin Portal views (sso, dsync, audit_logs, log_streams, domain_verification, certificate_renewal, plus the custom user_management mapping).

For internal portal links we will:

- Continue to accept the same `intent` values at the HTTP level.
- Map these intents to appropriate entry points in the SSO Setup Portal UI, for example:
  - `sso` → main SSO provider configuration form.
  - `user_management` → SSO plus basic user provisioning hints.
  - `dsync` → SCIM or directory sync configuration (future).
- Treat unsupported intents as `400 Bad Request` with a structured error code (for example, `UNSUPPORTED_INTENT`) for internal portal links. As we support more intents, we will add them explicitly to the mapping and test matrix rather than relying on implicit coercion.

WorkOS intents continue to be validated against the existing `compatibleWorkOSIntents` map, and we maintain current behavior there.

### Portal Session and Provider Endpoints

To make portal link consumption explicit and avoid reusing general admin endpoints, we introduce dedicated portal endpoints:

- `POST /api/v1/sso/portal/session`
  - **Purpose**: Exchange a raw portal token for a short-lived, portal-scoped session.
  - **Request body**:

    ```json
    {
      "token": "<raw_portal_token>"
    }
    ```

  - **Behavior**:
    - Look up the portal token by `token_hash`.
    - Validate `expires_at`, `revoked_at`, `max_uses` and `use_count`.
    - Increment `use_count` atomically (and update `last_used_at`) if the token is still within `max_uses`.
    - Derive `tenant_id`, `sso_provider_id`, and `intent` exclusively from the stored token, ignoring any client-supplied tenant/provider parameters.
  - **Response (success)**:

    ```json
    {
      "portal_session_token": "<jwt or opaque token>",
      "tenant_id": "<uuid>",
      "provider_slug": "<slug>",
      "intent": "sso",
      "expires_at": "<rfc3339>"
    }
    ```

  - **Response (error examples)**:
    - `400 INVALID_PORTAL_TOKEN` – token not found or malformed.
    - `400 TOKEN_EXPIRED` – `expires_at < now`.
    - `400 TOKEN_REVOKED` – `revoked_at` is set.
    - `400 TOKEN_MAX_USES_EXCEEDED` – `use_count >= max_uses`.

- `GET /api/v1/sso/portal/provider`
  - **Purpose**: Retrieve masked provider configuration for the portal session.
  - **Authentication**: Requires a valid portal session token (for example, `Authorization: Bearer <portal_session_token>` with a dedicated audience/claim such as `portal_sso_setup`).
  - **Behavior**:
    - Resolve `tenant_id` and `sso_provider_id` from the portal session token.
    - Load provider configuration and mask secrets in line with ADR-0002 (for example, `client_secret` shown as `"***MASKED***"`).
    - Fail if the provider is disabled or does not belong to the same tenant.
  - **Response (success)**: JSON DTO containing provider fields that are relevant for the portal (non-secret fields plus masked secrets).
  - **Response (error examples)**:
    - `401 UNAUTHORIZED` – missing or invalid portal session token.
    - `403 PROVIDER_DISABLED` – provider disabled.
    - `404 PROVIDER_NOT_FOUND` – no matching provider for the session.

Portal-driven SSO configuration edits (Phase 2) will reuse the same portal session token as their authentication mechanism and will be limited to a small set of dedicated portal endpoints that respect ADR-0002 mutability tiers.

### Sequence: Portal Link Generation (Internal Provider)

At a high level, portal link generation for a native provider follows this sequence:

1. Guard Admin UI → `GET /api/v1/auth/sso/{provider_slug}/portal-link?tenant_id=...&intent=sso` (Bearer admin token).
2. Controller → `SSOService.OrganizationPortalLinkGenerator` with `tenantID` and `providerSlug`.
3. Service:
   - Resolves `ssoProvider` for `(tenant_id, slug)`.
   - Creates a new `sso_portal_tokens` row bound to `tenant_id` and `ssoProvider.ID`.
4. Service constructs `{ui_base_url}/portal/sso-setup?token=<raw_token>` and returns `PortalLink{link}`.
5. Controller returns `200 OK` with `PortalLink` to the Admin UI.

### Sequence: Portal Link Consumption (Internal Provider)

When an IdP admin follows a Guard-hosted portal link:

1. Browser navigates to `{ui_base_url}/portal/sso-setup?token=<raw_token>`.
2. SSO Setup Portal UI:
   - Immediately exchanges the `token` via `POST /api/v1/sso/portal/session`.
   - On success, stores the `portal_session_token` in memory (for example, JS state) and removes the `token` query parameter from the URL (for example, via `history.replaceState`) to limit leakage in logs and referrers.
3. UI calls `GET /api/v1/sso/portal/provider` with the portal session token to fetch masked provider configuration.
4. Phase 2: UI performs portal-scoped configuration edits using portal-specific endpoints, authenticated by the same portal session token.
5. Backend records audit events for all portal-driven reads and writes, keyed by `tenant_id`, `sso_provider_id`, and `portal_token_id`.

## Security and Compliance Considerations

- **Portal link generation**:
  - Only Guard tenant admins can generate portal links.
  - Admin identity and tenant context are enforced via `Introspect` in the controller.
- **Portal link consumption**:
  - Portal tokens are unguessable and time-limited.
  - Each token is scoped to a single tenant and provider.
  - All operations performed via a portal token are restricted to SSO configuration APIs for that tenant and provider.
  - Authorization decisions for portal flows derive `tenant_id`, `sso_provider_id`, and `intent` exclusively from the validated portal token or portal session, not from client-supplied query or body parameters.

- **Audit logging**:
  - We will reuse or extend existing audit events used for WorkOS portal link generation (`auth.sso.portal_link_generator.*`) to cover internal portal links.
  - All configuration changes made via the SSO Setup Portal must be logged with:
    - `tenant_id`
    - `sso_provider_id` or slug
    - `portal_token_id` (or similar) as the actor identifier when there is no Guard user
    - a before/after diff at field level, consistent with ADR-0002 expectations

- **Revocation**:
  - Portal tokens can be explicitly revoked (for example via an Admin UI action or API) to immediately invalidate previously shared links.
  - Revoked tokens cause the SSO Setup Portal to display a clear error and not show or persist configuration.

- **Rate limiting**:
  - Portal link generation continues to be covered by the `/api/v1/auth/sso` rate limiting keys in `internal/settings/domain` (or dedicated keys if necessary).
  - Portal token consumption endpoints should have their own conservative limits, similar to magic link verification, to avoid abuse.
  - Portal session creation and portal configuration endpoints should be rate limited per tenant and IP to mitigate token stuffing and brute-force attempts.

- **Clickjacking and token exposure**:
  - The SSO Setup Portal will send appropriate security headers (for example, `Content-Security-Policy` with a restrictive `frame-ancestors` directive) to prevent clickjacking.
  - The UI is responsible for exchanging the portal token immediately on load and then removing it from the URL to reduce the risk of token exposure via logs, browser history, or referrer headers.

## Operations and Monitoring

To support real-world operations and incident response, we will:

- **Metrics**
  - Track creation and lifecycle of portal tokens:
    - `guard_sso_portal_tokens_created_total{tenant_id, provider_type, intent}`
    - `guard_sso_portal_tokens_revoked_total{tenant_id, provider_type, intent}`
    - `guard_sso_portal_tokens_expired_total{tenant_id, provider_type, intent}`
  - Track portal token usage and failures:
    - `guard_sso_portal_session_requests_total{tenant_id, outcome}` where `outcome ∈ {success, invalid, expired, revoked, max_uses_exceeded}`
    - `guard_sso_portal_provider_reads_total{tenant_id, provider_type}`
  - Track portal-driven configuration writes separately from admin-driven writes, using a dedicated label or metric dimension (for example, `actor="portal_token"`).

- **Cleanup and Retention**
  - Run a periodic job to hard-delete or archive expired `sso_portal_tokens` after a configurable retention period (for example, 30 days after `expires_at`) to keep the table small and queries efficient.
  - Ensure indices on `(tenant_id, expires_at)` and `token_hash` support efficient validation and cleanup.

- **Alerting**
  - Alert on unusual patterns, for example:
    - Sudden spikes in `invalid` or `revoked` outcomes for `guard_sso_portal_session_requests_total` per tenant.
    - Tenants with an unusually high number of active (non-expired, non-revoked) portal tokens.
  - Use these signals to trigger security reviews (for example, repeated use of old links, evidence of leaked tokens) and to guide tuning of TTLs, `max_uses`, and rate limits.

## Alternatives Considered

1. Keep WorkOS-only portal links and require native SSO to be configured via Guard Admin login.
   - Rejected because it conflicts with the requirement to onboard IdP admins without creating Guard accounts and provides a worse experience for non-WorkOS providers.

2. Implement a separate vendor-like portal per provider type.
   - Rejected as it duplicates WorkOS’s model without the economies of scale, and would fragment the configuration UX across multiple small portals.

3. Require tenants to embed Guard UI components directly into their own admin consoles.
   - Useful as a future option, but still requires us to define a secure portal token model and backend contracts. The SSO Setup Portal described here can later be exported as an embeddable module, so we start with a hosted version.

## Consequences

### Positive

- Unified API for generating SSO onboarding links across providers.
- WorkOS integration remains first-class while we gain a native path for all other IdPs.
- IdP admins can configure SSO for a tenant without needing a Guard user account or full Admin UI access.
- The SSO Setup Portal reuses our own UI and SDK, reducing duplication and keeping flows consistent.

### Negative

- Additional complexity in the auth model: portal tokens introduce another session-like concept to manage and audit.
- More UI surface to maintain and test across providers.
- We must be careful not to leak broader admin capabilities into the SSO Setup Portal.

### Neutral

- The existing `portal-link` HTTP endpoint and `PortalLink` DTO remain stable, minimizing SDK churn.
- Implementation can be rolled out incrementally: first internal portal links for dev or a single OIDC provider, then generalized.

## Implementation Notes and Phasing

Phase 1 (backend and UI foundation):

- Extend `OrganizationPortalLinkGenerator` to branch between WorkOS and internal portal links.
- Introduce the portal token model and persistence.
- Implement minimal SSO Setup Portal UI that can render provider configuration read-only using a portal token.

Phase 2 (edit flows and audit):

- Enable editing of SSO provider configuration via the SSO Setup Portal, following ADR-0002 mutability rules.
- Add full audit logging for portal-driven changes.
- Expose portal link generation in the Guard Admin UI.

Phase 3 (refinements and additional intents):

- Refine intent mapping for more advanced views (directory sync, audit, etc.).
- Add revocation UI for portal links.
- Document the feature in tenant onboarding docs, including operational runbooks.

## Related ADRs

- ADR-0001: Native SSO/OIDC/SAML Implementation
- ADR-0002: SSO Provider Edit Strategy and Immutability Patterns
- ADR-0003: Guard CLI Seed Alignment
