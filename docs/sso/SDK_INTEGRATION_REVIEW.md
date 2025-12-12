# SSO Provider SDK Integration Review

**Date:** 2025-01-14
**Reviewer:** Guard Platform Team
**Related ADR:** [ADR-0002: SSO Provider Edit Strategy](../adr/0002-sso-provider-edit-strategy.md)

## Executive Summary

✅ **Status: ALIGNED** - The SDK implementation is fully aligned with ADR-0002 and current backend capabilities.

This document reviews the TypeScript SDK integration for SSO Provider Management to ensure:
1. Alignment with ADR-0002 (Edit Strategy and Mutability Patterns)
2. Type safety and correctness
3. Proper error handling
4. Documentation completeness
5. Future-proofing for planned features

---

## SDK Methods Review

### ✅ ssoListProviders()

**Location:** `sdk/ts/src/client.ts:653-657`

**Signature:**
```typescript
async ssoListProviders(params: { tenant_id?: string } = {}): Promise<ResponseWrapper<SsoProvidersListResp>>
```

**API Endpoint:** `GET /api/v1/sso/providers?tenant_id={tenant_id}`

**Alignment Status:** ✅ **ALIGNED**
- Properly optional tenant_id (falls back to client.tenantId)
- Returns typed response with providers array and total count
- Uses query string for tenant_id (correct per backend API)

**Recommendations:**
- Consider adding pagination parameters in future:
  ```typescript
  params: {
    tenant_id?: string;
    limit?: number;
    offset?: number;
    provider_type?: 'oidc' | 'saml'; // server-side filtering
  }
  ```

---

### ✅ ssoCreateProvider()

**Location:** `sdk/ts/src/client.ts:660-665`

**Signature:**
```typescript
async ssoCreateProvider(body: CreateSsoProviderReq): Promise<ResponseWrapper<SsoProviderItem>>
```

**API Endpoint:** `POST /api/v1/sso/providers`

**Alignment Status:** ✅ **ALIGNED**
- Accepts complete CreateSsoProviderReq with all required and optional fields
- Returns created provider (201 Created)
- Body properly JSON stringified

**Type Safety:** ✅ **EXCELLENT**
- `CreateSsoProviderReq` includes all fields per ADR-0002
- Required fields: `tenant_id`, `name`, `slug`, `provider_type`
- Optional fields properly typed with `?:`

**Recommendations:**
- None - implementation is correct and complete

---

### ✅ ssoGetProvider()

**Location:** `sdk/ts/src/client.ts:668-672`

**Signature:**
```typescript
async ssoGetProvider(id: string): Promise<ResponseWrapper<SsoProviderItem>>
```

**API Endpoint:** `GET /api/v1/sso/providers/:id`

**Alignment Status:** ✅ **ALIGNED**
- Returns full SsoProviderItem with masked secrets
- Properly encodes ID in URL path

**Recommendations:**
- None - implementation is correct

---

### ⚠️ ssoUpdateProvider() - CRITICAL REVIEW

**Location:** `sdk/ts/src/client.ts:675-680`

**Signature:**
```typescript
async ssoUpdateProvider(id: string, body: UpdateSsoProviderReq): Promise<ResponseWrapper<SsoProviderItem>>
```

**API Endpoint:** `PUT /api/v1/sso/providers/:id`

**Backend Status:** ⚠️ **RETURNS 501 NOT IMPLEMENTED**

**Alignment Status:** ✅ **ALIGNED WITH ADR-0002**

**SDK Implementation:** ✅ **CORRECT**
- Method signature is correct
- Will work when backend implements endpoint
- UI handles 501 response gracefully

**UpdateSsoProviderReq Type Review:**
```typescript
export interface UpdateSsoProviderReq {
  // Tier 3: Always Editable
  name?: string;                      // ✅ Correct
  enabled?: boolean;                  // ✅ Correct
  allow_signup?: boolean;             // ✅ Correct
  trust_email_verified?: boolean;     // ✅ Correct
  domains?: string[];                 // ✅ Correct
  attribute_mapping?: Record<string, any>; // ✅ Correct

  // OIDC fields (Tier 2: Conditionally Editable + Tier 4: Write-Only)
  issuer?: string;                    // ✅ Correct (Tier 2)
  authorization_endpoint?: string;    // ✅ Correct (Tier 2)
  token_endpoint?: string;            // ✅ Correct (Tier 2)
  userinfo_endpoint?: string;         // ✅ Correct (Tier 2)
  jwks_uri?: string;                  // ✅ Correct (Tier 2)
  client_id?: string;                 // ✅ Correct (Tier 2)
  client_secret?: string;             // ✅ Correct (Tier 4: Write-Only)
  scopes?: string[];                  // ✅ Correct (Tier 3)
  response_type?: string;             // ✅ Correct (Tier 2)
  response_mode?: string;             // ✅ Correct (Tier 2)

  // SAML fields (Tier 2: Conditionally Editable + Tier 4: Write-Only)
  entity_id?: string;                 // ✅ Correct (Tier 2)
  acs_url?: string;                   // ✅ Correct (Tier 2)
  slo_url?: string;                   // ✅ Correct (Tier 2)
  idp_metadata_url?: string;          // ✅ Correct (Tier 2)
  idp_metadata_xml?: string;          // ✅ Correct (Tier 2)
  idp_entity_id?: string;             // ✅ Correct (Tier 2)
  idp_sso_url?: string;               // ✅ Correct (Tier 2)
  idp_slo_url?: string;               // ✅ Correct (Tier 2)
  idp_certificate?: string;           // ✅ Correct (Tier 2)
  sp_certificate?: string;            // ✅ Correct (Tier 2)
  sp_private_key?: string;            // ✅ Correct (Tier 4: Write-Only)
  want_assertions_signed?: boolean;   // ✅ Correct (Tier 3)
  want_response_signed?: boolean;     // ✅ Correct (Tier 3)
  sign_requests?: boolean;            // ✅ Correct (Tier 2)
  force_authn?: boolean;              // ✅ Correct (Tier 3)
}
```

**IMPORTANT: Missing Immutable Fields (Tier 1)**
The following fields are correctly ABSENT from UpdateSsoProviderReq:
- ❌ `id` - Cannot be changed (primary key)
- ❌ `tenant_id` - Cannot be changed (isolation)
- ❌ `provider_type` - Cannot be changed (identity)
- ❌ `slug` - Cannot be changed (URL component)
- ❌ `created_at` - Auto-managed
- ❌ `updated_at` - Auto-managed
- ❌ `created_by` - Auto-managed
- ❌ `updated_by` - Auto-managed

**Alignment with ADR-0002:** ✅ **PERFECT**
- Tier 1 (immutable) fields excluded from update type
- Tier 2 (conditionally editable) fields included
- Tier 3 (always editable) fields included
- Tier 4 (write-only) fields included

**Backend Implementation Required:**
When backend implements PUT endpoint, it MUST:
1. Validate Tier 1 fields are not present in request
2. Validate Tier 2 fields only when `enabled = false`
3. Accept Tier 3 fields always
4. Accept Tier 4 fields (secrets) for replacement
5. Return appropriate error codes per ADR-0002

**Example Backend Validation:**
```go
// Backend should validate like this:
if req.ProviderType != nil {
    return ErrImmutableField("provider_type")
}
if req.Slug != nil {
    return ErrImmutableField("slug")
}
if existing.Enabled && req.Issuer != nil {
    return ErrProviderMustBeDisabled("issuer")
}
```

**Recommendations:**
1. ✅ **SDK Type is Correct** - No changes needed
2. ⚠️ **Backend Must Implement** - Per ADR-0002 validation rules
3. ✅ **UI Handles 501** - Already implemented gracefully
4. 📝 **Document Tiers in JSDoc** - Add comments to UpdateSsoProviderReq

---

### ✅ ssoDeleteProvider()

**Location:** `sdk/ts/src/client.ts:683-687`

**Signature:**
```typescript
async ssoDeleteProvider(id: string): Promise<ResponseWrapper<unknown>>
```

**API Endpoint:** `DELETE /api/v1/sso/providers/:id`

**Alignment Status:** ✅ **ALIGNED**
- Returns 204 No Content (correct for DELETE)
- Properly encodes ID in URL path

**Recommendations:**
- Consider returning deletion confirmation with metadata:
  ```typescript
  Promise<ResponseWrapper<{ deleted_id: string; deleted_at: string }>>
  ```

---

### ✅ ssoTestProvider()

**Location:** `sdk/ts/src/client.ts:690-694`

**Signature:**
```typescript
async ssoTestProvider(id: string): Promise<ResponseWrapper<SsoTestProviderResp>>
```

**API Endpoint:** `POST /api/v1/sso/providers/:id/test`

**Alignment Status:** ✅ **ALIGNED**
- Returns success/failure with optional metadata or error
- Type properly models both success and error cases

**SsoTestProviderResp Review:**
```typescript
export interface SsoTestProviderResp {
  success: boolean;              // ✅ Required - indicates test result
  metadata?: Record<string, any>; // ✅ Optional - discovered OIDC/parsed SAML metadata
  error?: string;                // ✅ Optional - error message if success=false
}
```

**Recommendations:**
- Consider more specific metadata types:
  ```typescript
  metadata?: {
    oidc?: {
      issuer: string;
      authorization_endpoint: string;
      token_endpoint: string;
      // ... other discovered endpoints
    };
    saml?: {
      idp_entity_id: string;
      idp_sso_url: string;
      // ... other parsed metadata
    };
  };
  ```

---

## Type Definitions Review

### ✅ SsoProviderItem

**Location:** `sdk/ts/src/client.ts:142-188`

**Completeness:** ✅ **COMPLETE**
- All fields from backend model included
- Proper optional/required designation
- Comments indicate masked fields

**Alignment with ADR-0002:** ✅ **PERFECT**
- Includes all Tier 1 (immutable) fields
- Includes all Tier 2 (conditionally editable) fields
- Includes all Tier 3 (always editable) fields
- Includes all Tier 4 (write-only) fields with masking note

**Secret Handling:** ✅ **CORRECT**
```typescript
client_secret?: string; // masked in responses
sp_private_key?: string; // masked in responses
```
Comments clearly indicate these are masked - UI should expect "***MASKED***" or similar.

**Recommendations:**
1. ✅ Type is complete and correct
2. 📝 Add JSDoc comments documenting tier classifications
3. 📝 Add JSDoc examples for common use cases

---

### ✅ CreateSsoProviderReq

**Location:** `sdk/ts/src/client.ts:195-234`

**Required Fields:** ✅ **CORRECT**
```typescript
tenant_id: string;      // ✅ Required
name: string;           // ✅ Required
slug: string;           // ✅ Required
provider_type: SsoProviderType; // ✅ Required
```

**Optional Fields:** ✅ **CORRECT**
All other fields properly optional with `?:`

**Validation Responsibility:**
- ✅ SDK: Type enforcement only
- ✅ UI: Form validation before submission
- ⚠️ Backend: Authoritative validation (must implement)

**Recommendations:**
- Consider adding runtime validation helper:
  ```typescript
  export function validateCreateProvider(req: CreateSsoProviderReq): string | null {
    if (!req.name?.trim()) return "Name is required";
    if (!req.slug?.match(/^[a-z0-9-]+$/)) return "Invalid slug format";
    if (req.provider_type === 'oidc' && !req.client_id) return "Client ID required for OIDC";
    // ... more validations per ADR-0002
    return null;
  }
  ```

---

### ✅ UpdateSsoProviderReq

**Reviewed above in ssoUpdateProvider() section**

**Summary:** ✅ **PERFECTLY ALIGNED WITH ADR-0002**
- Excludes Tier 1 (immutable) fields
- Includes Tier 2, 3, 4 fields as optional
- Type system enforces immutability at compile time

---

### ✅ SsoProvidersListResp

**Location:** `sdk/ts/src/client.ts:190-193`

**Structure:** ✅ **CORRECT**
```typescript
export interface SsoProvidersListResp {
  providers: SsoProviderItem[];
  total: number;
}
```

**Alignment:** ✅ **MATCHES BACKEND API**

**Recommendations:**
- Consider adding pagination metadata for future:
  ```typescript
  export interface SsoProvidersListResp {
    providers: SsoProviderItem[];
    total: number;
    limit?: number;
    offset?: number;
    has_more?: boolean;
  }
  ```

---

### ✅ SsoProviderType

**Location:** `sdk/ts/src/client.ts:140`

**Definition:** ✅ **CORRECT**
```typescript
export type SsoProviderType = 'oidc' | 'saml';
```

**Extensibility:** ✅ **READY FOR FUTURE**
Easy to add new types: `'oidc' | 'saml' | 'ldap' | 'cas'`

---

## Error Handling Review

### Response Wrapper Pattern

**Structure:**
```typescript
ResponseWrapper<T> {
  data: T;
  meta: {
    status: number;        // HTTP status code
    requestId?: string;    // Request ID for tracing
    headers: Record<string, string>;
  }
}
```

**Error Cases:**
- ✅ 200-299: data contains successful response
- ✅ 400-499: data may contain `{ error: string }`
- ✅ 500-599: data may contain `{ error: string }`
- ✅ 501: data contains `{ error: "Not Implemented" }` for UPDATE

**UI Error Handling:** ✅ **PROPERLY IMPLEMENTED**
```typescript
if (res.meta.status >= 200 && res.meta.status < 300) {
  // Success
} else if (res.meta.status === 501) {
  // Special handling for unimplemented UPDATE
  setError('Edit functionality not yet available. Please delete and recreate provider.')
} else {
  // Generic error
  const errorMsg = (res.data as any)?.error || 'Failed to ...'
  setError(errorMsg)
}
```

**Recommendations:**
- ✅ Current error handling is robust
- Consider adding error type discriminators:
  ```typescript
  interface ApiError {
    error: string;
    code?: 'IMMUTABLE_FIELD' | 'PROVIDER_MUST_BE_DISABLED' | 'VALIDATION_ERROR';
    field?: string;
    details?: Record<string, any>;
  }
  ```

---

## Integration Points Review

### UI to SDK Integration

**Import Path:** ✅ **CORRECT**
```typescript
import { getClient } from '@/lib/sdk'
import type { SsoProviderItem, ... } from '@/lib/sdk'
```

**Type Re-exports:** ✅ **PROPERLY CONFIGURED**
```typescript
// ui/src/lib/sdk.ts
export type {
  SsoProviderItem,
  SsoProviderType,
  SsoProvidersListResp,
  CreateSsoProviderReq,
  UpdateSsoProviderReq,
  SsoTestProviderResp
} from '../../../sdk/ts/src/client'
```

**Monorepo Structure:** ✅ **CORRECTLY HANDLED**
- UI imports from relative path to SDK source
- Types properly exported from SDK
- No circular dependencies

---

## Security Review

### Secret Handling

**SDK Level:** ✅ **CORRECT**
- Secrets never logged
- Secrets marked as masked in types
- Write-only pattern supported

**Transport:** ✅ **SECURE**
- Secrets sent in request body (POST/PUT)
- HTTPS enforced for API calls
- No secrets in URLs or query strings

**Response Masking:** ✅ **EXPECTED**
- Backend must mask secrets in responses
- SDK types document masking: `// masked in responses`
- UI expects masked values: "***MASKED***"

---

## Performance Review

### SDK Method Efficiency

**All methods:** ✅ **EFFICIENT**
- No unnecessary round trips
- Proper HTTP methods used
- Minimal payload sizes
- No chatty API patterns

**Caching:** ⏳ **NOT IMPLEMENTED** (acceptable)
- Providers fetched on demand
- No automatic caching (prevents stale data)
- UI manages its own state

**Recommendations:**
- Consider adding caching layer in future:
  ```typescript
  async ssoListProviders(params, options?: { cache?: boolean }) {
    // Check cache if enabled
    // Fetch from API if miss or disabled
  }
  ```

---

## Documentation Review

### JSDoc Coverage

**Current State:** ⚠️ **MINIMAL**
- Methods have brief comments
- Types lack detailed documentation
- No usage examples in code

**Recommendations:**
Add comprehensive JSDoc:

```typescript
/**
 * List SSO providers for a tenant
 *
 * @param params - Query parameters
 * @param params.tenant_id - Tenant ID (optional, uses client.tenantId if not provided)
 * @returns List of providers and total count
 *
 * @example
 * ```typescript
 * const client = getClient();
 * const res = await client.ssoListProviders({ tenant_id: 'tenant-123' });
 * if (res.meta.status === 200) {
 *   console.log(res.data.providers);
 * }
 * ```
 *
 * @see https://docs.guard.example.com/api/sso#list-providers
 */
async ssoListProviders(params: { tenant_id?: string } = {}): Promise<ResponseWrapper<SsoProvidersListResp>>
```

---

## Alignment Matrix: SDK vs ADR-0002

| ADR-0002 Requirement | SDK Implementation | Status |
|---------------------|-------------------|--------|
| Tier 1 fields immutable | Excluded from UpdateSsoProviderReq | ✅ |
| Tier 2 fields conditionally editable | Included in UpdateSsoProviderReq | ✅ |
| Tier 3 fields always editable | Included in UpdateSsoProviderReq | ✅ |
| Tier 4 fields write-only | Included in UpdateSsoProviderReq | ✅ |
| Secrets masked in responses | Documented in type comments | ✅ |
| UPDATE endpoint may return 501 | UI handles gracefully | ✅ |
| Type safety enforced | TypeScript strict mode | ✅ |
| No breaking changes | All methods additive | ✅ |

**Overall Alignment:** ✅ **100% ALIGNED**

---

## Future-Proofing Review

### Extensibility

**Adding New Provider Types:**
```typescript
// Easy to extend
export type SsoProviderType = 'oidc' | 'saml' | 'ldap' | 'cas';
```

**Adding New Fields:**
```typescript
// Just add to interfaces, all optional fields backward compatible
export interface SsoProviderItem {
  // ... existing fields
  new_field?: string; // ✅ Backward compatible
}
```

**Versioning Strategy:** ✅ **READY**
- Can version types: `SsoProviderItemV2`
- Can version endpoints: `/v2/sso/providers`
- Response wrapper supports different data types

---

## Testing Recommendations

### SDK Unit Tests

**Should test:**
1. Method signatures and return types
2. URL construction and encoding
3. Query string building
4. Request body JSON stringification
5. Error response handling
6. Response wrapper structure

**Example Test:**
```typescript
describe('ssoUpdateProvider', () => {
  it('should correctly encode provider ID in URL', async () => {
    const client = new GuardClient({ baseUrl: 'https://api.test' });
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ id: 'test-id', name: 'Updated' })
    });

    await client.ssoUpdateProvider('provider-with-special/chars', { name: 'Updated' });

    expect(mockFetch).toHaveBeenCalledWith(
      'https://api.test/api/v1/sso/providers/provider-with-special%2Fchars',
      expect.objectContaining({ method: 'PUT' })
    );
  });

  it('should handle 501 Not Implemented for UPDATE', async () => {
    const client = new GuardClient({ baseUrl: 'https://api.test' });
    const mockFetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 501,
      json: async () => ({ error: 'Not Implemented' })
    });

    const res = await client.ssoUpdateProvider('id', { name: 'New' });

    expect(res.meta.status).toBe(501);
    expect((res.data as any).error).toBe('Not Implemented');
  });
});
```

---

## Action Items

### Immediate (Required)

1. ✅ **SDK Implementation** - Already complete and correct
2. ⏳ **Backend UPDATE Endpoint** - Must implement per ADR-0002
   - Validate Tier 1 fields are immutable
   - Validate Tier 2 fields only when disabled
   - Accept Tier 3 fields always
   - Accept Tier 4 write-only updates
3. ✅ **UI Error Handling** - Already handles 501 gracefully

### Short-Term (Nice to Have)

1. 📝 **Add JSDoc Comments** - Document all SDK methods and types
2. 🧪 **Add SDK Unit Tests** - Test URL construction, encoding, error cases
3. 📖 **Update API Documentation** - Document UPDATE endpoint behavior per ADR-0002
4. 🔍 **Add Runtime Validation** - Helper functions for client-side validation

### Long-Term (Future Enhancements)

1. 🎯 **Add Pagination** - Support limit/offset in list methods
2. 🗄️ **Add Caching Layer** - Optional caching for list operations
3. 🔄 **Add Retry Logic** - Automatic retry for transient failures
4. 📊 **Add Telemetry** - Track API call patterns and errors
5. 🔐 **Add Request Signing** - Optional request signing for enhanced security

---

## Conclusion

### Overall Assessment: ✅ **EXCELLENT**

The TypeScript SDK implementation for SSO Provider Management is **fully aligned** with ADR-0002 and implements all required functionality correctly.

**Strengths:**
- ✅ Type-safe and correct
- ✅ Properly models immutability per ADR-0002
- ✅ Handles current 501 limitation gracefully
- ✅ Ready for backend UPDATE implementation
- ✅ Extensible for future features
- ✅ No breaking changes required

**Areas for Improvement:**
- 📝 Add comprehensive JSDoc documentation
- 🧪 Add unit tests for SDK methods
- 🔍 Consider runtime validation helpers

**Recommendation:** ✅ **APPROVED FOR PRODUCTION**

The SDK is production-ready and correctly implements the SSO Provider Management API contract. Once the backend implements the UPDATE endpoint per ADR-0002 validation rules, full CRUD functionality will work seamlessly without SDK changes.

---

## Appendix: Code Examples

### Example 1: Creating an OIDC Provider

```typescript
import { getClient } from '@/lib/sdk';

const client = getClient();

const res = await client.ssoCreateProvider({
  tenant_id: 'tenant-123',
  name: 'Google Workspace',
  slug: 'google',
  provider_type: 'oidc',
  enabled: true,
  allow_signup: true,
  trust_email_verified: true,
  domains: ['example.com'],
  issuer: 'https://accounts.google.com',
  client_id: 'xxx.apps.googleusercontent.com',
  client_secret: 'GOCSPX-xxx',
  scopes: ['openid', 'profile', 'email']
});

if (res.meta.status === 201) {
  console.log('Provider created:', res.data);
  console.log('Secret is masked:', res.data.client_secret); // "GOC...xxx"
}
```

### Example 2: Updating a Provider (Tier 3 Fields)

```typescript
// Update always-editable fields
const res = await client.ssoUpdateProvider('provider-id', {
  name: 'Google Workspace (Updated)',
  enabled: false,
  allow_signup: false,
  domains: ['example.com', 'another.com']
});

if (res.meta.status === 200) {
  console.log('Updated:', res.data);
} else if (res.meta.status === 501) {
  console.error('UPDATE not yet implemented');
  // UI shows: "Edit functionality not yet available"
}
```

### Example 3: Updating Authentication Endpoints (Tier 2)

```typescript
// First, disable the provider
await client.ssoUpdateProvider('provider-id', { enabled: false });

// Then, update authentication endpoints
const res = await client.ssoUpdateProvider('provider-id', {
  issuer: 'https://new-issuer.com',
  client_id: 'new-client-id'
});

if (res.meta.status === 400) {
  // Backend rejected because provider wasn't disabled
  const error = (res.data as any).error;
  console.error(error); // "Provider must be disabled before editing..."
}

// Finally, re-enable
await client.ssoUpdateProvider('provider-id', { enabled: true });
```

### Example 4: Rotating Secrets (Tier 4)

```typescript
// Secrets are write-only, never read
const res = await client.ssoUpdateProvider('provider-id', {
  client_secret: 'new-secret-value'  // Old secret remains in response masked
});

if (res.meta.status === 200) {
  console.log('Secret rotated');
  console.log('Still masked:', res.data.client_secret); // "new...xxx"
}
```

---

**Review Status:** ✅ COMPLETE
**Next Review:** After backend UPDATE endpoint implementation
**Reviewer:** Guard Platform Team
**Date:** 2025-01-14
