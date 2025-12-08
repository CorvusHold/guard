import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import SsoProvidersPanel from './SsoProvidersPanel'
import type { SsoProviderItem } from '@/lib/sdk'

// Create stable mock functions
const mockSsoListProviders = vi.fn()
const mockSsoCreateProvider = vi.fn()
const mockSsoUpdateProvider = vi.fn()
const mockSsoDeleteProvider = vi.fn()
const mockSsoTestProvider = vi.fn()

// Mock the SDK with stable references
vi.mock('@/lib/sdk', () => ({
  getClient: vi.fn(() => ({
    ssoListProviders: mockSsoListProviders,
    ssoCreateProvider: mockSsoCreateProvider,
    ssoUpdateProvider: mockSsoUpdateProvider,
    ssoDeleteProvider: mockSsoDeleteProvider,
    ssoTestProvider: mockSsoTestProvider
  }))
}))

// Mock the toast
vi.mock('@/lib/toast', () => ({
  useToast: () => ({
    show: vi.fn()
  })
}))

describe('SsoProvidersPanel', () => {
  const mockProviders: SsoProviderItem[] = [
    {
      id: '1',
      tenant_id: 'tenant-1',
      name: 'Google Workspace',
      slug: 'google',
      provider_type: 'oidc',
      enabled: true,
      allow_signup: true,
      trust_email_verified: true,
      domains: ['example.com'],
      issuer: 'https://accounts.google.com',
      client_id: 'test-client-id',
      scopes: ['openid', 'profile', 'email'],
      created_at: '2025-01-01T00:00:00Z',
      updated_at: '2025-01-01T00:00:00Z'
    },
    {
      id: '2',
      tenant_id: 'tenant-1',
      name: 'Okta SAML',
      slug: 'okta',
      provider_type: 'saml',
      enabled: false,
      allow_signup: true,
      trust_email_verified: true,
      domains: [],
      idp_entity_id: 'http://www.okta.com/exk123',
      idp_sso_url: 'https://example.okta.com/app/xxx/sso/saml',
      want_assertions_signed: true,
      want_response_signed: false,
      created_at: '2025-01-02T00:00:00Z',
      updated_at: '2025-01-02T00:00:00Z'
    }
  ]

  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders the panel with providers', async () => {
    mockSsoListProviders.mockResolvedValue({
      data: {
        providers: mockProviders,
        total: 2
      },
      meta: { status: 200 }
    })

    render(<SsoProvidersPanel tenantId="tenant-1" />)

    await waitFor(() => {
      expect(screen.getByTestId('sso-providers-panel')).toBeInTheDocument()
    })

    await waitFor(() => {
      expect(screen.getByText('Google Workspace')).toBeInTheDocument()
      expect(screen.getByText('Okta SAML')).toBeInTheDocument()
    })
  })

  it('shows error when loading fails', async () => {
    mockSsoListProviders.mockResolvedValue({
      data: { error: 'Failed to load' },
      meta: { status: 500 }
    })

    render(<SsoProvidersPanel tenantId="tenant-1" />)

    await waitFor(() => {
      expect(screen.getByTestId('sso-error')).toBeInTheDocument()
      expect(screen.getByText('Failed to load')).toBeInTheDocument()
    })
  })

  it('shows empty state when no providers exist', async () => {
    mockSsoListProviders.mockResolvedValue({
      data: {
        providers: [],
        total: 0
      },
      meta: { status: 200 }
    })

    render(<SsoProvidersPanel tenantId="tenant-1" />)

    await waitFor(() => {
      expect(screen.getByText(/no SSO providers configured/i)).toBeInTheDocument()
    })
  })

  it('can open create form', async () => {
    mockSsoListProviders.mockResolvedValue({
      data: {
        providers: [],
        total: 0
      },
      meta: { status: 200 }
    })

    render(<SsoProvidersPanel tenantId="tenant-1" />)

    await waitFor(() => {
      expect(screen.getByTestId('sso-create')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByTestId('sso-create'))

    await waitFor(() => {
      expect(screen.getByText('Create SSO Provider')).toBeInTheDocument()
    })
  })

  it('can refresh providers list', async () => {
    mockSsoListProviders.mockResolvedValue({
      data: {
        providers: mockProviders,
        total: 2
      },
      meta: { status: 200 }
    })

    render(<SsoProvidersPanel tenantId="tenant-1" />)

    await waitFor(() => {
      expect(screen.getByTestId('sso-refresh')).toBeInTheDocument()
    })

    // Click refresh
    fireEvent.click(screen.getByTestId('sso-refresh'))

    // Should call the API again
    await waitFor(() => {
      expect(mockSsoListProviders).toHaveBeenCalledTimes(2)
    })
  })

  it('handles delete provider', async () => {
    mockSsoListProviders.mockResolvedValue({
      data: {
        providers: mockProviders,
        total: 2
      },
      meta: { status: 200 }
    })

    mockSsoDeleteProvider.mockResolvedValue({
      data: {},
      meta: { status: 204 }
    })

    render(<SsoProvidersPanel tenantId="tenant-1" />)

    await waitFor(() => {
      expect(screen.getByText('Google Workspace')).toBeInTheDocument()
    })

    // Find and click delete button
    const deleteButtons = screen.getAllByText('Delete')
    fireEvent.click(deleteButtons[0])

    // Confirm deletion modal should appear
    await waitFor(() => {
      expect(screen.getByText(/Are you sure you want to delete/i)).toBeInTheDocument()
    })

    // Type the provider name to confirm
    const confirmInput = screen.getByPlaceholderText('Google Workspace')
    fireEvent.change(confirmInput, { target: { value: 'Google Workspace' } })

    // Click delete button in modal
    const confirmDeleteButton = screen.getByRole('button', { name: /delete provider/i })
    fireEvent.click(confirmDeleteButton)

    // Should call delete API
    await waitFor(() => {
      expect(mockSsoDeleteProvider).toHaveBeenCalledWith('1')
    })
  })

  it('handles test provider', async () => {
    mockSsoListProviders.mockResolvedValue({
      data: {
        providers: mockProviders,
        total: 2
      },
      meta: { status: 200 }
    })

    mockSsoTestProvider.mockResolvedValue({
      data: {
        success: true,
        metadata: {}
      },
      meta: { status: 200 }
    })

    render(<SsoProvidersPanel tenantId="tenant-1" />)

    await waitFor(() => {
      expect(screen.getByText('Google Workspace')).toBeInTheDocument()
    })

    // Find and click test button
    const testButtons = screen.getAllByText('Test')
    fireEvent.click(testButtons[0])

    // Should call test API
    await waitFor(() => {
      expect(mockSsoTestProvider).toHaveBeenCalledWith('1')
    })
  })
})
