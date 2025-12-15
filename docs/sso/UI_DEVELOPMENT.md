# SSO Provider Management UI - Development Guide

## Overview

This document provides technical details about the SSO Provider Management UI implementation for developers working on or extending the Guard platform frontend.

## Architecture

### Component Structure

```
ui/src/components/admin/sso/
├── SsoProvidersPanel.tsx       # Main container component
├── SsoProviderList.tsx         # Table/list view with filters
├── SsoProviderForm.tsx         # Create/edit form orchestrator
├── SsoProviderOidcFields.tsx   # OIDC-specific form fields
├── SsoProviderSamlFields.tsx   # SAML-specific form fields
└── test.tsx                    # Unit tests
```

### Data Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    SsoProvidersPanel                        │
│  - Manages state (providers, loading, error)                │
│  - Handles API calls via GuardClient SDK                   │
│  - Controls view switching (list/create/edit)               │
└──────────────┬──────────────────────────────┬───────────────┘
               │                              │
     ┌─────────┴─────────┐        ┌──────────┴──────────┐
     │ SsoProviderList    │        │ SsoProviderForm     │
     │  - Display providers│        │  - Form orchestration│
     │  - Filters & search │        │  - Validation        │
     │  - Actions (edit,   │        │  - Submission        │
     │    delete, test)    │        └──────────┬──────────┘
     └────────────────────┘                    │
                                    ┌──────────┴──────────┐
                                    │                     │
                   ┌────────────────┴────┐  ┌────────────┴────────┐
                   │ SsoProviderOidcFields│  │ SsoProviderSamlFields│
                   │  - OIDC config      │  │  - SAML config       │
                   └─────────────────────┘  └──────────────────────┘
```

## SDK Integration

### Type System

All SSO-related types are exported from `@/lib/sdk`:

```typescript
import type {
  SsoProviderItem,
  SsoProviderType,
  SsoProvidersListResp,
  CreateSsoProviderReq,
  UpdateSsoProviderReq,
  SsoTestProviderResp
} from '@/lib/sdk'
```

### API Methods

The GuardClient SDK provides these methods:

- `ssoListProviders(params)` - List providers for a tenant
- `ssoCreateProvider(body)` - Create a new provider
- `ssoGetProvider(id)` - Get provider details
- `ssoUpdateProvider(id, body)` - Update existing provider
- `ssoDeleteProvider(id)` - Delete a provider
- `ssoTestProvider(id)` - Test provider configuration

### Example Usage

```typescript
import { getClient } from '@/lib/sdk'

const client = getClient()

// List providers
const res = await client.ssoListProviders({ tenant_id: 'tenant-123' })
if (res.meta.status === 200) {
  console.log(res.data.providers)
}

// Create OIDC provider
const createRes = await client.ssoCreateProvider({
  tenant_id: 'tenant-123',
  name: 'Google Workspace',
  slug: 'google',
  provider_type: 'oidc',
  enabled: true,
  allow_signup: true,
  trust_email_verified: true,
  issuer: 'https://accounts.google.com',
  client_id: 'xxx.apps.googleusercontent.com',
  client_secret: 'secret',
  scopes: ['openid', 'profile', 'email']
})
```

## Component Details

### SsoProvidersPanel

**Purpose:** Main container that manages SSO provider state and view switching.

**State:**
- `providers: SsoProviderItem[]` - List of providers
- `loading: 'list' | 'create' | 'update' | 'delete' | 'test' | null`
- `error: string | null`
- `showCreateForm: boolean` - Toggle between list and create view
- `editingProvider: SsoProviderItem | null` - Provider being edited

**Key Methods:**
- `loadProviders()` - Fetches providers from API
- `handleCreate(provider)` - Success callback after creation
- `handleUpdate(provider)` - Success callback after update
- `handleDelete(id)` - Deletes provider
- `handleTest(id)` - Tests provider configuration

### SsoProviderList

**Purpose:** Displays providers in a table with filters, search, and actions.

**Features:**
- Filter by provider type (All, OIDC, SAML)
- Search by name or slug
- Row actions: Edit, Delete, Test
- Delete confirmation modal with name verification
- Loading skeleton states
- Empty state messaging

**Props:**
```typescript
interface SsoProviderListProps {
  providers: SsoProviderItem[]
  loading: boolean
  onEdit: (provider: SsoProviderItem) => void
  onDelete: (id: string) => void
  onTest: (id: string) => void
}
```

### SsoProviderForm

**Purpose:** Orchestrates the create/edit form with validation and submission.

**Key Features:**
- Auto-generates slug from name
- Manages domain list (add/remove)
- Provider type selector (OIDC/SAML) - disabled when editing
- Conditional rendering of OIDC vs SAML fields
- Form validation before submission
- Handles both create and update modes

**Validation Rules:**
- Name is required
- Slug is required and must be alphanumeric with hyphens
- OIDC: client_id, issuer required; client_secret required for new providers
- SAML: Either idp_metadata_url or manual configuration required

### SsoProviderOidcFields

**Purpose:** OIDC-specific configuration fields.

**Configuration Modes:**
- **Automatic (Discovery):** Only requires issuer URL, endpoints discovered via `/.well-known/openid-configuration`
- **Manual:** Requires all endpoints explicitly

**Fields:**
- Issuer, authorization/token/userinfo endpoints, JWKS URI
- Client ID and secret
- Scopes (multi-input with add/remove)
- Advanced: Response type and mode

### SsoProviderSamlFields

**Purpose:** SAML-specific configuration fields.

**Configuration Modes:**
- **Metadata URL:** Fetch metadata from IdP URL
- **Metadata XML:** Paste metadata XML directly
- **Manual:** Enter all IdP details manually

**Sections:**
1. **IdP Configuration:** Entity ID, SSO/SLO URLs, certificate
2. **SP Configuration:** Entity ID, ACS URL, SLO URL (auto-generated if empty)
3. **Security Options:** Signing requirements, force re-auth
4. **Signing Certificates:** SP certificate and private key (if `sign_requests` enabled)

## Styling Conventions

The UI follows the existing Guard admin panel patterns:

### Spacing
- Vertical: `space-y-3` or `space-y-4`
- Grid gaps: `gap-2`, `gap-3`, `gap-4`
- Padding: `p-3`, `p-4`, `px-3 py-2`

### Borders
- Border radius: `rounded-md` for inputs, `rounded-xl` for cards
- Border color: `border` (default), `border-red-200` (error), `border-green-200` (success)

### Colors
- Error: `border-red-200 bg-red-50 text-red-700`
- Success: `border-green-200 bg-green-50 text-green-800`
- Muted text: `text-muted-foreground`

### Typography
- Headers: `text-base font-medium` or `text-sm font-medium`
- Body: `text-sm`
- Help text: `text-xs text-muted-foreground`

## State Management

### Toast Notifications

Use the `useToast` hook for user feedback:

```typescript
import { useToast } from '@/lib/toast'

const { show } = useToast()

// Success
show({
  variant: 'success',
  title: 'Provider created',
  description: 'SSO provider was created successfully'
})

// Error
show({
  variant: 'error',
  title: 'Failed to create provider',
  description: error.message
})
```

### Tenant Context

Get the current tenant ID from context:

```typescript
import { useTenant } from '@/lib/tenant'

const { tenantId } = useTenant()
```

## Testing

### Test File Naming

Tests must be named `test.tsx` (not `.test.tsx`) to match the vitest config pattern.

### Mocking the SDK

```typescript
vi.mock('@/lib/sdk', () => ({
  getClient: vi.fn(() => ({
    ssoListProviders: vi.fn(),
    ssoCreateProvider: vi.fn(),
    // ... other methods
  }))
}))
```

### Mocking Toast

```typescript
vi.mock('@/lib/toast', () => ({
  useToast: () => ({
    show: vi.fn()
  })
}))
```

### Test Example

```typescript
it('renders providers list', async () => {
  const { getClient } = await import('@/lib/sdk')
  const mockClient = getClient()

  vi.mocked(mockClient.ssoListProviders).mockResolvedValue({
    data: { providers: mockProviders, total: 2 },
    meta: { status: 200 }
  })

  render(<SsoProvidersPanel tenantId="tenant-1" />)

  await waitFor(() => {
    expect(screen.getByText('Google Workspace')).toBeInTheDocument()
  })
})
```

## Integration with AdminSettings

The SSO tab is integrated into the main AdminSettings component:

### Tab State

```typescript
const [activeTab, setActiveTab] = useState<
  'settings' | 'users' | 'account' | 'fga' | 'rbac' | 'tenants' | 'sso'
>('settings')
```

### Tab Button

```typescript
<Button
  variant={activeTab === 'sso' ? 'default' : 'secondary'}
  size="sm"
  onClick={() => setActiveTab('sso')}
  data-testid="tab-sso"
>
  SSO Providers
</Button>
```

### Tab Content

```typescript
{activeTab === 'sso' && (
  <div className="rounded-xl border p-4 space-y-3">
    <h2 className="text-base font-medium">SSO Provider Management</h2>
    {!tenantId ? (
      <div className="text-sm text-muted-foreground">
        Enter a tenant ID above and click Load to manage SSO providers.
      </div>
    ) : (
      <SsoProvidersPanel tenantId={tenantId} />
    )}
  </div>
)}
```

### URL Hash Persistence

The active tab is persisted in the URL hash: `#tab=sso`

## Known Limitations

### UPDATE Endpoint

The `PUT /api/v1/sso/providers/:id` endpoint currently returns 501 Not Implemented. The UI handles this gracefully by showing an error message.

**Workaround:** Users can delete and recreate providers until the update endpoint is implemented.

### Secrets Masking

Sensitive fields (`client_secret`, `sp_private_key`) are masked in GET responses. The UI shows a placeholder and requires re-entering secrets during edits.

### Provider Type Immutability

Once created, the provider type (OIDC/SAML) cannot be changed. The type selector is disabled in edit mode.

## Development Workflow

### Local Development

```bash
cd ui
npm run dev
```

The UI will be available at `http://localhost:5173`.

### Type Checking

```bash
cd ui
npm run typecheck
```

### Building

```bash
cd ui
npm run build
```

### Testing

```bash
cd ui
npm test                    # Run all tests
npm test -- --ui            # Interactive test UI
npm test -- src/components/admin/sso/test.tsx  # Run SSO tests only
```

## Extending the UI

### Adding New Provider Types

1. Update `SsoProviderType` in SDK client types
2. Add new badge variant in `SsoProviderList`
3. Create new fields component (e.g., `SsoProviderLdapFields.tsx`)
4. Add conditional rendering in `SsoProviderForm`
5. Update backend API to support new type

### Adding New Form Fields

1. Add field to `CreateSsoProviderReq` type in SDK
2. Add field to form state in `SsoProviderForm`
3. Add input component in appropriate fields file
4. Update form validation
5. Update submit handler to include new field

### Customizing Validation

Validation logic is in `SsoProviderForm.validateForm()`. Add custom rules:

```typescript
function validateForm(): string | null {
  // Existing validations...

  // Add custom validation
  if (form.provider_type === 'oidc' && !form.scopes?.includes('openid')) {
    return 'OIDC providers must include the "openid" scope'
  }

  return null
}
```

## Troubleshooting

### "Cannot find module '@corvushold/guard-sdk'"

Import types from `@/lib/sdk` not from the package name:

```typescript
// ❌ Wrong
import type { SsoProviderItem } from '@corvushold/guard-sdk'

// ✅ Correct
import type { SsoProviderItem } from '@/lib/sdk'
```

### Tests Not Running

Ensure test files are named `test.tsx` not `.test.tsx`.

### Build Errors

Run `npm run typecheck` to see TypeScript errors before building.

### API Errors

Check the browser console for detailed error responses. The SDK returns full response objects:

```typescript
{
  data: { /* response data or error */ },
  meta: {
    status: 200,  // HTTP status code
    requestId: 'xxx',
    headers: { /* response headers */ }
  }
}
```

## Security Considerations

### Secrets Handling

- Never log `client_secret` or `sp_private_key` to console
- Secrets are masked in API responses
- Clear form state after submission
- Use `type="password"` for secret inputs

### Input Validation

- Validate URLs before submission
- Sanitize slug to prevent injection
- Validate email domain formats
- Check required fields client-side

### Error Messages

- Don't expose sensitive details in error messages
- Provide helpful but generic errors for security failures
- Log detailed errors server-side only

## Performance Optimization

### Code Splitting

The SSO management UI is lazy-loaded as part of the admin settings panel.

### Memoization

Consider memoizing expensive operations:

```typescript
const filteredProviders = useMemo(() => {
  return providers.filter(/* expensive filter logic */)
}, [providers, filterCriteria])
```

### Debouncing

Search input could benefit from debouncing:

```typescript
const [debouncedSearch] = useDebounce(searchQuery, 300)
```

## Resources

- [SSO API Documentation](../api/SSO_API.md)
- [ADR-0001: Native SSO Implementation](../adr/0001-native-sso-oidc-saml-implementation.md)
- [Backend Integration Design](../sso/SSO_INTEGRATION_DESIGN.md)
- [React Testing Library Docs](https://testing-library.com/docs/react-testing-library/intro/)
- [Vitest Documentation](https://vitest.dev/)

## Contributing

When contributing to the SSO UI:

1. Follow existing component patterns
2. Add TypeScript types for all props
3. Include `data-testid` attributes for testing
4. Write unit tests for new components
5. Update this documentation for significant changes
6. Test with both OIDC and SAML providers
7. Test error scenarios
8. Ensure mobile responsiveness

## Contact

For questions about the SSO UI implementation, please refer to the project's main README or contact the Guard development team.
