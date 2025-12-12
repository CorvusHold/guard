# ADR-0002: SSO Provider Edit Strategy and Immutability Patterns

**Status:** Accepted
**Date:** 2025-01-14
**Deciders:** Guard Platform Team
**Technical Story:** Phase 6 - SSO Management UI Implementation

## Context and Problem Statement

During Phase 6 implementation of the SSO Provider Management UI, we encountered the reality that the backend UPDATE endpoint (`PUT /api/v1/sso/providers/:id`) returns `501 Not Implemented`. This raises critical questions about edit functionality, data mutability, and the long-term strategy for managing SSO provider configurations.

We need to make a clear decision on:
1. Whether SSO providers should be mutable after creation
2. How to handle the edit workflow in the UI
3. What fields, if any, should be editable
4. The security and operational implications of provider mutations

## Decision Drivers

* **Security:** SSO providers are security-critical resources that affect authentication flows
* **Operational Safety:** Changes to providers can break active user authentication
* **Auditability:** Need clear audit trail of who changed what and when
* **User Experience:** Admins expect to be able to fix typos and update configurations
* **Backend Complexity:** Full edit support requires careful validation and migration logic
* **Secret Management:** Secrets cannot be retrieved after creation (masked in responses)

## Considered Options

### Option 1: Full Edit Support (Reject)
Allow editing all fields of a provider after creation.

**Pros:**
- Matches user expectations from other admin interfaces
- Flexible for configuration changes
- No need to delete/recreate

**Cons:**
- High security risk (changing provider type mid-flight could break auth)
- Complex backend validation required
- Difficult to audit what actually changed
- Race conditions during active authentication flows
- Secrets retrieval problem (cannot show existing secrets)

### Option 2: Immutable Providers (Recommended - ACCEPTED)
Treat SSO providers as immutable after creation. To make changes, delete and recreate.

**Pros:**
- Simple mental model: create once, delete when done
- No race conditions or mid-flight changes
- Clear audit trail (creation and deletion events)
- Forces deliberate decision-making for changes
- No secret retrieval problems
- Lower backend complexity

**Cons:**
- Cannot fix typos without deleting
- Must reconfigure IdP callback URLs on recreation
- Users lose provider ID on recreation (breaks external references)
- Less convenient for minor changes

### Option 3: Selective Mutability (ACCEPTED - Phase 1)
Allow editing ONLY safe, non-breaking fields. Immutable for critical fields.

**Pros:**
- Balance between safety and usability
- Can fix common mistakes (names, descriptions)
- No breaking changes to authentication flows
- Simpler than full edit support
- Maintains security for critical fields

**Cons:**
- Requires clear documentation of what's editable
- Partial edit still requires backend UPDATE endpoint
- May confuse users (why can I edit this but not that?)

## Decision Outcome

**Chosen option:** **Option 3 - Selective Mutability** (Hybrid Approach)

We will implement a **tiered mutability model** where fields are categorized by their safety and impact:

### Tier 1: ALWAYS IMMUTABLE (Cannot Change After Creation)
These fields are foundational to the provider's identity and authentication flow:

- `provider_type` (oidc/saml) - Changing would break entire auth flow
- `slug` - Changing would break callback URLs and links
- `tenant_id` - Changing would violate tenant isolation

**Rationale:** These fields define the provider's core identity and changing them is equivalent to creating a new provider.

### Tier 2: CONDITIONALLY EDITABLE (Can Change When Safe)
These fields can be edited IF the provider is disabled:

- `issuer` (OIDC)
- `client_id` (OIDC)
- `authorization_endpoint`, `token_endpoint`, `jwks_uri` (OIDC)
- `idp_entity_id`, `idp_sso_url`, `idp_slo_url` (SAML)
- `idp_certificate` (SAML)

**Rationale:** These fields affect authentication flow, but can be safely changed when the provider is not actively authenticating users.

**Validation Rule:** `if provider.enabled == true: reject_edit("Disable provider before editing authentication endpoints")`

### Tier 3: ALWAYS EDITABLE (Safe Changes)
These fields can be edited at any time:

- `name` - Display name only, doesn't affect auth flow
- `enabled` - Toggle to enable/disable (special handling)
- `allow_signup` - Policy change, doesn't break existing users
- `trust_email_verified` - Policy change
- `domains` - Allow-list, additive is safe, removal needs warning

**Rationale:** These are policy and metadata fields that don't affect the authentication protocol itself.

### Tier 4: WRITE-ONLY (Never Retrievable, Can Be Updated)
These fields cannot be read but can be replaced:

- `client_secret` (OIDC)
- `sp_private_key` (SAML)

**Rationale:** Security best practice - secrets are write-only. UI shows "***MASKED***" and allows replacing but not viewing.

## Implementation Strategy

### Phase 1: Immediate (Current State - UI Ready)
**Status:** ✅ UI Implemented, ⏳ Backend Pending

**UI Behavior:**
1. Edit button available on provider list
2. Edit form pre-populated with current values
3. Secrets shown as "***MASKED***" with optional "Update Secret" flow
4. `provider_type` selector disabled (showing current type, not editable)
5. `slug` field disabled (showing current slug, not editable)
6. When UPDATE endpoint returns 501:
   - Show clear error: "Edit functionality not yet available. Please delete and recreate provider."
   - Provide link to deletion flow
   - Log warning for tracking

**Backend Required:**
- Implement `PUT /api/v1/sso/providers/:id` endpoint
- Validate mutability rules per tier
- Return 400 Bad Request with clear message for disallowed changes
- Audit log all successful edits

**API Contract:**
```json
PUT /api/v1/sso/providers/:id

Request:
{
  "name": "New Name",              // ✅ Always allowed
  "enabled": false,                // ✅ Always allowed
  "client_secret": "new_secret"    // ✅ Write-only update
}

Response (Success):
{
  "id": "uuid",
  "name": "New Name",
  "enabled": false,
  "client_secret": "new...xxx",    // Masked
  "updated_at": "2025-01-14T12:00:00Z"
}

Response (Error - Immutable Field):
{
  "error": "Cannot modify immutable field: provider_type",
  "code": "IMMUTABLE_FIELD",
  "field": "provider_type"
}

Response (Error - Requires Disabled):
{
  "error": "Provider must be disabled before editing authentication endpoints",
  "code": "PROVIDER_MUST_BE_DISABLED",
  "field": "issuer"
}
```

### Phase 2: Enhanced Safety (Future)
**Status:** 🔮 Future Work

1. **Dry-Run Mode:**
   - `PUT /api/v1/sso/providers/:id?dry_run=true`
   - Returns validation results without applying changes

2. **Change Preview:**
   - Show diff of what will change
   - Require explicit confirmation for breaking changes

3. **Rollback Support:**
   - Store previous version on edit
   - Allow one-click rollback within 24 hours

4. **Active Session Warning:**
   - Check for active auth sessions using provider
   - Warn before editing if users are currently authenticating

### Phase 3: Advanced Workflows (Future)
**Status:** 🔮 Future Work

1. **Provider Versioning:**
   - Multiple versions of same provider
   - Gradual rollover from old to new version
   - Zero-downtime updates

2. **Staged Updates:**
   - Submit changes for review/approval
   - Apply changes during maintenance window
   - Automatic rollback on errors

3. **Provider Templates:**
   - Create provider from template
   - Update multiple providers from template changes

## Consequences

### Positive

✅ **Security:** Critical fields cannot be accidentally changed
✅ **Clarity:** Clear rules about what can/cannot change
✅ **Auditability:** Every meaningful change is tracked
✅ **Safety:** Cannot break active authentication flows
✅ **User Experience:** Can fix common issues (names, toggles, secrets)
✅ **Implementation:** Simpler than full edit support

### Negative

⚠️ **Inconvenience:** Cannot fix typos in critical fields without deletion
⚠️ **Documentation:** Must clearly document tier rules
⚠️ **User Confusion:** "Why can I edit this but not that?"
⚠️ **Migration:** Changing endpoints requires disable → edit → enable flow

### Neutral

ℹ️ **Backend Work:** Still requires UPDATE endpoint implementation
ℹ️ **Testing:** Need tests for each tier's rules
ℹ️ **Monitoring:** Should track edit failures and reasons

## Compliance and Security Considerations

### Audit Requirements
Every edit MUST be logged with:
- User ID (who made the change)
- Timestamp (when)
- Old value (what was changed from)
- New value (what was changed to)
- Provider ID (which provider)
- Tenant ID (which tenant)
- Change result (success/failure)

### Secret Rotation
When `client_secret` or `sp_private_key` are updated:
1. Old secret remains valid for 5 minutes (grace period)
2. New secret becomes active immediately
3. Audit log records secret rotation (not the secret itself)
4. Email notification to tenant admins

### Breaking Change Protection
Before allowing Tier 2 edits:
1. Verify provider is disabled
2. Check no auth sessions in past 5 minutes
3. Require explicit confirmation in UI
4. Log warning if provider has recent activity

## Documentation Requirements

### For Administrators
Create `docs/sso/EDITING_PROVIDERS.md`:
- Clear table of editable vs immutable fields
- Step-by-step guide for common changes
- Workarounds for immutable field changes
- Security implications of editing live providers

### For Developers
Update `docs/sso/UI_DEVELOPMENT.md`:
- Tier system explanation
- Validation logic
- Error handling for edit failures
- Testing strategies for mutability rules

### API Documentation
Update `docs/api/SSO_API.md`:
- Document PUT endpoint
- List editable fields per tier
- Error codes and messages
- Examples for each tier

## Validation Rules (Backend Implementation)

```go
// Pseudo-code for backend validation
func ValidateProviderUpdate(existing, updated *SsoProvider) error {
    // Tier 1: Always Immutable
    if existing.ProviderType != updated.ProviderType {
        return ErrImmutableField("provider_type")
    }
    if existing.Slug != updated.Slug {
        return ErrImmutableField("slug")
    }
    if existing.TenantID != updated.TenantID {
        return ErrImmutableField("tenant_id")
    }

    // Tier 2: Conditionally Editable (only when disabled)
    if existing.Enabled {
        tier2Fields := []string{
            "issuer", "client_id", "authorization_endpoint",
            "idp_entity_id", "idp_sso_url", "idp_certificate",
        }
        for _, field := range tier2Fields {
            if fieldChanged(existing, updated, field) {
                return ErrProviderMustBeDisabled(field)
            }
        }
    }

    // Tier 3: Always Editable - no validation needed

    // Tier 4: Write-Only - validate but don't read
    if updated.ClientSecret != "" && updated.ClientSecret != "***MASKED***" {
        // New secret provided, will be hashed and stored
        validateSecretStrength(updated.ClientSecret)
    }

    return nil
}
```

## Migration Path for Existing Providers

For providers created before this ADR:
1. All existing providers remain editable per tier rules
2. No breaking changes to existing API behavior
3. Gradually roll out tier enforcement with warnings first
4. Full enforcement in v2.0.0

## Metrics and Monitoring

Track these metrics:
- Edit attempts by field (which fields are users trying to edit?)
- Edit failures by reason (immutable field, requires disabled, etc.)
- Time between create and first edit
- Delete-recreate patterns (users working around immutability)

Use this data to:
- Identify fields that should move tiers
- Improve error messages
- Create better documentation
- Consider automation for common workflows

## Review and Revision

This ADR should be reviewed:
- ✅ Before implementing backend UPDATE endpoint
- After 3 months of production use (gather user feedback)
- When considering provider versioning (may change strategy)
- If security audit identifies issues

## Related ADRs

- [ADR-0001: Native SSO/OIDC/SAML Implementation](0001-native-sso-oidc-saml-implementation.md)
- Future: ADR-0003: Provider Versioning and Zero-Downtime Updates

## References

- [OIDC Specification - Dynamic Client Registration](https://openid.net/specs/openid-connect-registration-1_0.html)
- [SAML 2.0 Metadata Best Practices](https://www.oasis-open.org/committees/download.php/35391/)
- [NIST SP 800-63B - Authentication and Lifecycle Management](https://pages.nist.gov/800-63-3/sp800-63b.html)

## Appendix: Field-by-Field Mutability Matrix

| Field | Tier | Editable? | Conditions | Rationale |
|-------|------|-----------|------------|-----------|
| `id` | 1 | ❌ Never | N/A | Primary key |
| `tenant_id` | 1 | ❌ Never | N/A | Tenant isolation |
| `provider_type` | 1 | ❌ Never | N/A | Core identity |
| `slug` | 1 | ❌ Never | N/A | URL component |
| `name` | 3 | ✅ Always | None | Display only |
| `enabled` | 3 | ✅ Always | None | Toggle state |
| `allow_signup` | 3 | ✅ Always | None | Policy setting |
| `trust_email_verified` | 3 | ✅ Always | None | Policy setting |
| `domains` | 3 | ✅ Always | Warn on removal | Allow-list |
| `issuer` | 2 | ⚠️ When disabled | `enabled = false` | Auth endpoint |
| `client_id` | 2 | ⚠️ When disabled | `enabled = false` | Auth credential |
| `client_secret` | 4 | 🔒 Write-only | None | Secret |
| `authorization_endpoint` | 2 | ⚠️ When disabled | `enabled = false` | Auth endpoint |
| `token_endpoint` | 2 | ⚠️ When disabled | `enabled = false` | Auth endpoint |
| `userinfo_endpoint` | 2 | ⚠️ When disabled | `enabled = false` | Auth endpoint |
| `jwks_uri` | 2 | ⚠️ When disabled | `enabled = false` | Key endpoint |
| `scopes` | 3 | ✅ Always | Warn on removal | Additive is safe |
| `response_type` | 2 | ⚠️ When disabled | `enabled = false` | Protocol param |
| `response_mode` | 2 | ⚠️ When disabled | `enabled = false` | Protocol param |
| `idp_entity_id` | 2 | ⚠️ When disabled | `enabled = false` | SAML identity |
| `idp_sso_url` | 2 | ⚠️ When disabled | `enabled = false` | SAML endpoint |
| `idp_slo_url` | 2 | ⚠️ When disabled | `enabled = false` | SAML endpoint |
| `idp_certificate` | 2 | ⚠️ When disabled | `enabled = false` | Trust anchor |
| `entity_id` | 2 | ⚠️ When disabled | `enabled = false` | SP identity |
| `acs_url` | 2 | ⚠️ When disabled | `enabled = false` | SP endpoint |
| `slo_url` | 2 | ⚠️ When disabled | `enabled = false` | SP endpoint |
| `sp_certificate` | 2 | ⚠️ When disabled | `enabled = false` | SP cert |
| `sp_private_key` | 4 | 🔒 Write-only | None | Secret |
| `want_assertions_signed` | 3 | ✅ Always | None | Security policy |
| `want_response_signed` | 3 | ✅ Always | None | Security policy |
| `sign_requests` | 2 | ⚠️ When disabled | `enabled = false` | Protocol change |
| `force_authn` | 3 | ✅ Always | None | Policy setting |
| `attribute_mapping` | 3 | ✅ Always | None | Claim mapping |
| `created_at` | 1 | ❌ Never | N/A | Audit field |
| `updated_at` | 1 | ❌ Auto | N/A | Audit field |
| `created_by` | 1 | ❌ Never | N/A | Audit field |
| `updated_by` | 1 | ❌ Auto | N/A | Audit field |

**Legend:**
- ✅ Always - Can be edited at any time
- ⚠️ When disabled - Can only be edited when `enabled = false`
- ❌ Never - Cannot be edited after creation
- 🔒 Write-only - Cannot be read, can be replaced
- ❌ Auto - Automatically managed by system

---

**Status:** Accepted
**Next Review:** After backend UPDATE endpoint implementation
**Owner:** Guard Platform Team
**Last Updated:** 2025-01-14
