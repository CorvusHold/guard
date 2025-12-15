# SSO Database Schema

This document describes the database schema for the native SSO/OIDC/SAML implementation.

## Overview

The SSO implementation uses four main tables:

1. **`sso_providers`** - SSO provider configuration (multi-tenant, multi-provider)
2. **`sso_auth_attempts`** - Audit trail of authentication attempts
3. **`sso_sessions`** - Active SSO sessions (for Single Logout support)
4. **`auth_identities`** - Extended with SSO-specific columns

## Entity Relationship Diagram

```
┌─────────────────┐
│    tenants      │
│─────────────────│
│ id (PK)         │
│ name            │
└────────┬────────┘
         │
         │ 1:N
         │
┌────────▼─────────────────────────────────────┐
│           sso_providers                      │
│──────────────────────────────────────────────│
│ id (PK)                                      │
│ tenant_id (FK → tenants)                     │
│ name                                         │
│ slug                    (UNIQUE per tenant)  │
│ provider_type          (oidc/saml/oauth2)    │
│                                              │
│ -- OIDC Configuration --                     │
│ issuer                                       │
│ authorization_endpoint                       │
│ token_endpoint                               │
│ userinfo_endpoint                            │
│ jwks_uri                                     │
│ client_id                                    │
│ client_secret                                │
│ scopes[]                                     │
│ response_type                                │
│ response_mode                                │
│                                              │
│ -- SAML Configuration --                     │
│ entity_id                                    │
│ acs_url                                      │
│ slo_url                                      │
│ idp_metadata_url                             │
│ idp_metadata_xml                             │
│ idp_entity_id                                │
│ idp_sso_url                                  │
│ idp_slo_url                                  │
│ idp_certificate                              │
│ sp_certificate                               │
│ sp_private_key                               │
│ sp_certificate_expires_at                    │
│ want_assertions_signed                       │
│ want_response_signed                         │
│ sign_requests                                │
│ force_authn                                  │
│                                              │
│ -- Common Fields --                          │
│ attribute_mapping (JSONB)                    │
│ enabled                                      │
│ allow_signup                                 │
│ trust_email_verified                         │
│ domains[]                                    │
│ created_at, updated_at                       │
│ created_by, updated_by (FK → users)          │
└────────┬─────────────────────────────────────┘
         │
         │ 1:N
         │
┌────────▼─────────────────────────────┐        ┌──────────────────┐
│      sso_auth_attempts               │        │      users       │
│──────────────────────────────────────│        │──────────────────│
│ id (PK)                              │        │ id (PK)          │
│ tenant_id (FK → tenants)             │◄───────┤                  │
│ provider_id (FK → sso_providers)     │   N:1  │                  │
│ user_id (FK → users)                 │        │                  │
│ state                                │        └──────────────────┘
│ status (initiated/success/failed)    │
│ error_code                           │
│ error_message                        │
│ ip_address                           │
│ user_agent                           │
│ initiated_at, completed_at           │
└──────────────────────────────────────┘

┌────────────────────────────────────┐
│        sso_sessions                │
│────────────────────────────────────│
│ id (PK)                            │
│ tenant_id (FK → tenants)           │
│ provider_id (FK → sso_providers)   │
│ user_id (FK → users)               │
│ session_index                      │
│ name_id                            │
│ id_token_hint                      │
│ created_at                         │
│ expires_at                         │
│ terminated_at                      │
└────────────────────────────────────┘

┌────────────────────────────────────┐
│        auth_identities             │
│────────────────────────────────────│
│ id (PK)                            │
│ user_id (FK → users)               │
│ tenant_id (FK → tenants)           │
│ email                              │
│ password_hash                      │
│                                    │
│ -- SSO Extensions --               │
│ sso_provider_id (FK → sso_prov.)   │
│ sso_subject                        │
│ sso_attributes (JSONB)             │
│ created_at, updated_at             │
└────────────────────────────────────┘
```

## Table Specifications

### `sso_providers`

Stores SSO provider configurations. Each tenant can have multiple providers.

#### Columns

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `id` | UUID | NO | Primary key |
| `tenant_id` | UUID | NO | Foreign key to tenants table |
| `name` | VARCHAR(255) | NO | Human-readable provider name |
| `slug` | VARCHAR(255) | NO | URL-safe identifier (unique per tenant) |
| `provider_type` | VARCHAR(50) | NO | Provider type: `oidc`, `saml`, `oauth2`, `workos`, `dev` |
| `issuer` | TEXT | YES | OIDC issuer URL |
| `authorization_endpoint` | TEXT | YES | OIDC authorization endpoint |
| `token_endpoint` | TEXT | YES | OIDC token endpoint |
| `userinfo_endpoint` | TEXT | YES | OIDC userinfo endpoint |
| `jwks_uri` | TEXT | YES | OIDC JWKS URI for key discovery |
| `client_id` | TEXT | YES | OAuth 2.0 / OIDC client ID |
| `client_secret` | TEXT | YES | OAuth 2.0 / OIDC client secret |
| `scopes` | TEXT[] | YES | OIDC scopes (default: `['openid', 'profile', 'email']`) |
| `response_type` | VARCHAR(50) | YES | OIDC response type (default: `code`) |
| `response_mode` | VARCHAR(50) | YES | OIDC response mode |
| `entity_id` | TEXT | YES | SAML SP entity ID |
| `acs_url` | TEXT | YES | SAML Assertion Consumer Service URL |
| `slo_url` | TEXT | YES | SAML Single Logout URL |
| `idp_metadata_url` | TEXT | YES | SAML IdP metadata URL |
| `idp_metadata_xml` | TEXT | YES | SAML IdP metadata XML |
| `idp_entity_id` | TEXT | YES | SAML IdP entity ID |
| `idp_sso_url` | TEXT | YES | SAML IdP SSO URL |
| `idp_slo_url` | TEXT | YES | SAML IdP SLO URL |
| `idp_certificate` | TEXT | YES | SAML IdP X.509 certificate (PEM) |
| `sp_certificate` | TEXT | YES | SAML SP X.509 certificate (PEM) |
| `sp_private_key` | TEXT | YES | SAML SP private key (PEM) |
| `sp_certificate_expires_at` | TIMESTAMPTZ | YES | SAML SP certificate expiry date |
| `want_assertions_signed` | BOOLEAN | YES | SAML: require signed assertions (default: true) |
| `want_response_signed` | BOOLEAN | YES | SAML: require signed responses (default: false) |
| `sign_requests` | BOOLEAN | YES | SAML: sign authentication requests (default: false) |
| `force_authn` | BOOLEAN | YES | SAML: force re-authentication (default: false) |
| `attribute_mapping` | JSONB | YES | Maps IdP attributes to user profile fields |
| `enabled` | BOOLEAN | YES | Provider is active (default: true) |
| `allow_signup` | BOOLEAN | YES | Allow new user creation (default: true) |
| `trust_email_verified` | BOOLEAN | YES | Trust IdP email verification (default: true) |
| `domains` | TEXT[] | YES | Email domains for auto-routing |
| `created_at` | TIMESTAMPTZ | NO | Creation timestamp |
| `updated_at` | TIMESTAMPTZ | NO | Last update timestamp |
| `created_by` | UUID | YES | User who created the provider |
| `updated_by` | UUID | YES | User who last updated the provider |

#### Constraints

- **Primary Key**: `id`
- **Unique**: `(tenant_id, slug)`
- **Check**: `provider_type IN ('oidc', 'saml', 'oauth2', 'workos', 'dev')`
- **Check**: OIDC providers must have `issuer` and `client_id`
- **Check**: SAML providers must have `entity_id` and `idp_entity_id`

#### Indexes

| Index Name | Columns | Type | Condition |
|------------|---------|------|-----------|
| `idx_sso_providers_tenant` | `tenant_id` | B-tree | `enabled = TRUE` |
| `idx_sso_providers_slug` | `(tenant_id, slug)` | B-tree | - |
| `idx_sso_providers_domains` | `domains` | GIN | `enabled = TRUE` |
| `idx_sso_providers_type` | `provider_type` | B-tree | `enabled = TRUE` |

#### Attribute Mapping Format

The `attribute_mapping` JSONB column maps IdP attributes to Guard user profile fields.

**Default mapping**:
```json
{
  "email": ["email", "mail", "emailAddress"],
  "first_name": ["firstName", "givenName", "given_name"],
  "last_name": ["lastName", "surname", "sn", "family_name"],
  "display_name": ["displayName", "name", "cn"]
}
```

**Custom mapping example**:
```json
{
  "email": ["emailAddress"],
  "first_name": ["givenName"],
  "last_name": ["sn"],
  "phone": ["telephoneNumber"],
  "department": ["ou", "department"]
}
```

The array format allows fallback: Guard will try each attribute name in order until one is found.

---

### `sso_auth_attempts`

Audit trail of all SSO authentication attempts (initiated, success, failed).

#### Columns

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `id` | UUID | NO | Primary key |
| `tenant_id` | UUID | NO | Foreign key to tenants |
| `provider_id` | UUID | NO | Foreign key to sso_providers |
| `user_id` | UUID | YES | Foreign key to users (null until success) |
| `state` | VARCHAR(255) | YES | OAuth/OIDC state parameter |
| `status` | VARCHAR(50) | NO | Status: `initiated`, `success`, `failed` |
| `error_code` | VARCHAR(100) | YES | Error code if failed |
| `error_message` | TEXT | YES | Error message if failed |
| `ip_address` | INET | YES | Client IP address |
| `user_agent` | TEXT | YES | Client user agent |
| `initiated_at` | TIMESTAMPTZ | NO | When the attempt started |
| `completed_at` | TIMESTAMPTZ | YES | When the attempt completed |

#### Constraints

- **Primary Key**: `id`
- **Check**: `status IN ('initiated', 'success', 'failed')`

#### Indexes

| Index Name | Columns | Type | Condition |
|------------|---------|------|-----------|
| `idx_sso_auth_attempts_tenant` | `(tenant_id, initiated_at DESC)` | B-tree | - |
| `idx_sso_auth_attempts_provider` | `(provider_id, initiated_at DESC)` | B-tree | - |
| `idx_sso_auth_attempts_user` | `(user_id, initiated_at DESC)` | B-tree | `user_id IS NOT NULL` |
| `idx_sso_auth_attempts_state` | `state` | B-tree | `status = 'initiated'` |

---

### `sso_sessions`

Active SSO sessions for Single Logout (SLO) support.

#### Columns

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `id` | UUID | NO | Primary key |
| `tenant_id` | UUID | NO | Foreign key to tenants |
| `provider_id` | UUID | NO | Foreign key to sso_providers |
| `user_id` | UUID | NO | Foreign key to users |
| `session_index` | VARCHAR(255) | YES | SAML session index |
| `name_id` | VARCHAR(255) | YES | SAML NameID |
| `id_token_hint` | TEXT | YES | OIDC ID token for RP-initiated logout |
| `created_at` | TIMESTAMPTZ | NO | Session creation timestamp |
| `expires_at` | TIMESTAMPTZ | YES | Session expiry timestamp |
| `terminated_at` | TIMESTAMPTZ | YES | Session termination timestamp |

#### Constraints

- **Primary Key**: `id`
- **Unique**: `(provider_id, session_index)`

#### Indexes

| Index Name | Columns | Type | Condition |
|------------|---------|------|-----------|
| `idx_sso_sessions_user` | `user_id` | B-tree | `terminated_at IS NULL` |
| `idx_sso_sessions_expiry` | `expires_at` | B-tree | `terminated_at IS NULL` |

---

### `auth_identities` (SSO Extensions)

The existing `auth_identities` table is extended with SSO-specific columns.

#### New Columns

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `sso_provider_id` | UUID | YES | Foreign key to sso_providers |
| `sso_subject` | TEXT | YES | SSO provider's unique identifier for the user |
| `sso_attributes` | JSONB | YES | Additional attributes from SSO provider |

#### New Indexes

| Index Name | Columns | Type | Condition |
|------------|---------|------|-----------|
| `idx_auth_identities_sso_provider` | `(sso_provider_id, sso_subject)` | B-tree | `sso_provider_id IS NOT NULL` |

---

## Query Patterns

### Find Provider by Domain

Domain-based routing allows automatic provider detection based on email domain.

```sql
SELECT * FROM sso_providers
WHERE tenant_id = $1
  AND enabled = TRUE
  AND $2 = ANY(domains)  -- $2 is the email domain
ORDER BY created_at DESC
LIMIT 1;
```

**Example**: User enters `alice@acme.com`. Guard extracts domain `acme.com` and finds the provider configured with that domain.

### Get Active Sessions for User

```sql
SELECT * FROM sso_sessions
WHERE user_id = $1
  AND terminated_at IS NULL
  AND (expires_at IS NULL OR expires_at > NOW())
ORDER BY created_at DESC;
```

### Audit Trail Query

```sql
SELECT
  a.id,
  a.status,
  a.initiated_at,
  a.completed_at,
  a.error_code,
  p.name as provider_name,
  p.provider_type,
  u.id as user_id
FROM sso_auth_attempts a
JOIN sso_providers p ON a.provider_id = p.id
LEFT JOIN users u ON a.user_id = u.id
WHERE a.tenant_id = $1
  AND a.initiated_at >= $2  -- start date
  AND a.initiated_at <= $3  -- end date
ORDER BY a.initiated_at DESC
LIMIT $4 OFFSET $5;
```

---

## Performance Considerations

### Indexes

All critical query paths have indexes:

- **Provider lookup by slug**: Composite index on `(tenant_id, slug)`
- **Domain-based routing**: GIN index on `domains` array
- **Auth attempt lookups**: Partial index on `state` for initiated attempts only
- **Session management**: Partial indexes on active sessions only

### JSONB Storage

- **`attribute_mapping`**: Typically small (<1 KB), infrequently updated
- **`sso_attributes`**: Can grow larger (user profile data), read-heavy

For JSONB query optimization, consider:
```sql
-- Extract specific attribute
SELECT sso_attributes->>'department' FROM auth_identities WHERE id = $1;

-- GIN index for JSONB queries (add if needed)
CREATE INDEX idx_auth_identities_sso_attrs ON auth_identities USING GIN(sso_attributes);
```

### Certificate Expiry Monitoring

SAML SP certificates expire. Add monitoring query:

```sql
SELECT
  id,
  tenant_id,
  name,
  slug,
  sp_certificate_expires_at,
  EXTRACT(EPOCH FROM (sp_certificate_expires_at - NOW())) / 86400 as days_until_expiry
FROM sso_providers
WHERE sp_certificate_expires_at IS NOT NULL
  AND sp_certificate_expires_at < NOW() + INTERVAL '30 days'
  AND enabled = TRUE
ORDER BY sp_certificate_expires_at ASC;
```

---

## Migration Strategy

The migration `000006_sso_providers.sql` handles:

1. **Idempotent execution**: Drops old simple tables if they exist
2. **Cascade deletes**: Provider deletion cascades to auth attempts and sessions
3. **Triggers**: Auto-update `updated_at` timestamp

**Running migrations**:

```bash
# Up migration
make migrate-up

# Down migration (WARNING: destroys all SSO data)
make migrate-down

# Check status
make migrate-status
```

---

## Security Considerations

### Secrets Storage

- **`client_secret`**: OAuth/OIDC client secret (encrypt at rest recommended)
- **`sp_private_key`**: SAML SP private key (encrypt at rest **required**)
- **`id_token_hint`**: May contain PII (short-lived, cleaned up on logout)

### PII in Logs

Never log:
- `client_secret`
- `sp_private_key`
- `sso_attributes` (may contain sensitive user data)

### State Management

- OAuth `state` parameter stored temporarily in `sso_auth_attempts`
- Also stored in Redis with 10-minute TTL
- State is cryptographically random (256 bits)

---

## Future Enhancements

Potential schema additions:

1. **Provider versioning**: Track configuration changes over time
2. **Analytics**: Aggregated login success/failure metrics
3. **Rate limiting**: Per-provider rate limit counters
4. **Webhooks**: SSO event notifications

---

**Schema Version**: 1.0
**Last Updated**: 2025-01-13
**Migration**: `000006_sso_providers.sql`
