import { useState, useEffect } from 'react'
import { getClient } from '@/lib/sdk'
import { useToast } from '@/lib/toast'
import type { SsoProviderItem, SsoProviderType, CreateSsoProviderReq, UpdateSsoProviderReq } from '@/lib/sdk'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import SsoProviderOidcFields from './SsoProviderOidcFields'
import SsoProviderSamlFields from './SsoProviderSamlFields'

export interface SsoProviderFormProps {
  tenantId: string
  provider?: SsoProviderItem
  onSuccess: (provider: SsoProviderItem) => void
  onCancel: () => void
}

type FormData = Partial<CreateSsoProviderReq>

export default function SsoProviderForm({
  tenantId,
  provider,
  onSuccess,
  onCancel
}: SsoProviderFormProps) {
  const [form, setForm] = useState<FormData>({
    tenant_id: tenantId,
    provider_type: 'oidc',
    enabled: true,
    allow_signup: true,
    trust_email_verified: true,
    domains: [],
    scopes: ['openid', 'profile', 'email']
  })
  const [domainInput, setDomainInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const { show } = useToast()

  // Pre-populate form for editing
  useEffect(() => {
    if (provider) {
      setForm({
        tenant_id: provider.tenant_id,
        name: provider.name,
        slug: provider.slug,
        provider_type: provider.provider_type,
        enabled: provider.enabled,
        allow_signup: provider.allow_signup,
        trust_email_verified: provider.trust_email_verified,
        domains: provider.domains || [],
        // OIDC fields
        issuer: provider.issuer,
        authorization_endpoint: provider.authorization_endpoint,
        token_endpoint: provider.token_endpoint,
        userinfo_endpoint: provider.userinfo_endpoint,
        jwks_uri: provider.jwks_uri,
        client_id: provider.client_id,
        client_secret: '', // Don't pre-fill secrets
        scopes: provider.scopes || ['openid', 'profile', 'email'],
        response_type: provider.response_type,
        response_mode: provider.response_mode,
        // SAML fields
        entity_id: provider.entity_id,
        acs_url: provider.acs_url,
        slo_url: provider.slo_url,
        idp_metadata_url: provider.idp_metadata_url,
        idp_entity_id: provider.idp_entity_id,
        idp_sso_url: provider.idp_sso_url,
        idp_slo_url: provider.idp_slo_url,
        idp_certificate: provider.idp_certificate,
        want_assertions_signed: provider.want_assertions_signed,
        want_response_signed: provider.want_response_signed,
        sign_requests: provider.sign_requests,
        force_authn: provider.force_authn
      })
    }
  }, [provider])

  function updateForm(key: keyof FormData, value: any) {
    setForm(prev => ({ ...prev, [key]: value }))
  }

  function generateSlug(name: string): string {
    return name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '')
  }

  function handleNameChange(name: string) {
    updateForm('name', name)
    // Auto-generate slug only if not editing
    if (!provider && name) {
      updateForm('slug', generateSlug(name))
    }
  }

  function addDomain() {
    if (domainInput.trim()) {
      const domains = [...(form.domains || []), domainInput.trim()]
      updateForm('domains', domains)
      setDomainInput('')
    }
  }

  function removeDomain(domain: string) {
    const domains = (form.domains || []).filter(d => d !== domain)
    updateForm('domains', domains)
  }

  function validateForm(): string | null {
    if (!form.name?.trim()) return 'Provider name is required'
    if (!form.slug?.trim()) return 'Slug is required'
    if (!/^[a-z0-9-]+$/.test(form.slug)) return 'Slug must contain only lowercase letters, numbers, and hyphens'

    if (form.provider_type === 'oidc') {
      if (!form.client_id?.trim()) return 'Client ID is required for OIDC'
      if (!provider && !form.client_secret?.trim()) return 'Client Secret is required for OIDC'
      if (!form.issuer?.trim()) return 'Issuer is required for OIDC'
    }

    if (form.provider_type === 'saml') {
      if (!form.idp_metadata_url?.trim() && !form.idp_entity_id?.trim()) {
        return 'Either IdP Metadata URL or manual configuration is required for SAML'
      }
    }

    return null
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()

    const validationError = validateForm()
    if (validationError) {
      setError(validationError)
      show({
        variant: 'error',
        title: 'Validation failed',
        description: validationError
      })
      return
    }

    setError(null)
    setLoading(true)

    try {
      if (provider) {
        // Update existing provider
        const updateData: UpdateSsoProviderReq = {
          name: form.name,
          enabled: form.enabled,
          allow_signup: form.allow_signup,
          trust_email_verified: form.trust_email_verified,
          domains: form.domains
        }

        // Include provider-specific fields only if changed
        if (form.provider_type === 'oidc') {
          if (form.client_id) updateData.client_id = form.client_id
          if (form.client_secret) updateData.client_secret = form.client_secret
          if (form.issuer) updateData.issuer = form.issuer
          if (form.scopes) updateData.scopes = form.scopes
          if (form.authorization_endpoint) updateData.authorization_endpoint = form.authorization_endpoint
          if (form.token_endpoint) updateData.token_endpoint = form.token_endpoint
          if (form.userinfo_endpoint) updateData.userinfo_endpoint = form.userinfo_endpoint
          if (form.jwks_uri) updateData.jwks_uri = form.jwks_uri
          if (form.response_type) updateData.response_type = form.response_type
          if (form.response_mode) updateData.response_mode = form.response_mode
        } else if (form.provider_type === 'saml') {
          if (form.idp_metadata_url) updateData.idp_metadata_url = form.idp_metadata_url
          if (form.idp_entity_id) updateData.idp_entity_id = form.idp_entity_id
          if (form.idp_sso_url) updateData.idp_sso_url = form.idp_sso_url
          if (form.idp_slo_url) updateData.idp_slo_url = form.idp_slo_url
          if (form.idp_certificate) updateData.idp_certificate = form.idp_certificate
          if (form.entity_id) updateData.entity_id = form.entity_id
          if (form.acs_url) updateData.acs_url = form.acs_url
          if (form.slo_url) updateData.slo_url = form.slo_url
          updateData.want_assertions_signed = form.want_assertions_signed
          updateData.want_response_signed = form.want_response_signed
          updateData.sign_requests = form.sign_requests
          updateData.force_authn = form.force_authn
        }

        const res = await getClient().ssoUpdateProvider(provider.id, updateData)

        if (res.meta.status >= 200 && res.meta.status < 300) {
          onSuccess(res.data)
        } else if (res.meta.status === 501) {
          setError('Update functionality is not yet implemented on the server')
          show({
            variant: 'error',
            title: 'Not implemented',
            description: 'The update endpoint is not yet available. Please contact your administrator.'
          })
        } else {
          const errorMsg = (res.data as any)?.error || 'Failed to update provider'
          setError(errorMsg)
          show({
            variant: 'error',
            title: 'Update failed',
            description: errorMsg
          })
        }
      } else {
        // Create new provider
        const createData: CreateSsoProviderReq = {
          tenant_id: tenantId,
          name: form.name!,
          slug: form.slug!,
          provider_type: form.provider_type as SsoProviderType,
          enabled: form.enabled,
          allow_signup: form.allow_signup,
          trust_email_verified: form.trust_email_verified,
          domains: form.domains
        }

        // Add provider-specific fields
        if (form.provider_type === 'oidc') {
          createData.issuer = form.issuer
          createData.client_id = form.client_id
          createData.client_secret = form.client_secret
          createData.scopes = form.scopes
          createData.authorization_endpoint = form.authorization_endpoint
          createData.token_endpoint = form.token_endpoint
          createData.userinfo_endpoint = form.userinfo_endpoint
          createData.jwks_uri = form.jwks_uri
          createData.response_type = form.response_type
          createData.response_mode = form.response_mode
        } else if (form.provider_type === 'saml') {
          createData.idp_metadata_url = form.idp_metadata_url
          createData.idp_metadata_xml = form.idp_metadata_xml
          createData.idp_entity_id = form.idp_entity_id
          createData.idp_sso_url = form.idp_sso_url
          createData.idp_slo_url = form.idp_slo_url
          createData.idp_certificate = form.idp_certificate
          createData.entity_id = form.entity_id
          createData.acs_url = form.acs_url
          createData.slo_url = form.slo_url
          createData.sp_certificate = form.sp_certificate
          createData.sp_private_key = form.sp_private_key
          createData.want_assertions_signed = form.want_assertions_signed
          createData.want_response_signed = form.want_response_signed
          createData.sign_requests = form.sign_requests
          createData.force_authn = form.force_authn
        }

        const res = await getClient().ssoCreateProvider(createData)

        if (res.meta.status === 201 || res.meta.status === 200) {
          onSuccess(res.data)
        } else {
          const errorMsg = (res.data as any)?.error || 'Failed to create provider'
          setError(errorMsg)
          show({
            variant: 'error',
            title: 'Creation failed',
            description: errorMsg
          })
        }
      }
    } catch (e: any) {
      const errorMsg = e?.message || String(e)
      setError(errorMsg)
      show({
        variant: 'error',
        title: provider ? 'Update failed' : 'Creation failed',
        description: errorMsg
      })
    } finally {
      setLoading(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      {error && (
        <div className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700">
          {error}
        </div>
      )}

      {/* Basic Configuration */}
      <div className="space-y-4">
        <h4 className="text-sm font-medium">Basic Configuration</h4>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="space-y-2">
            <Label htmlFor="name">Provider Name *</Label>
            <Input
              id="name"
              value={form.name || ''}
              onChange={e => handleNameChange(e.target.value)}
              placeholder="Google Workspace"
              required
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="slug">Slug *</Label>
            <Input
              id="slug"
              value={form.slug || ''}
              onChange={e => updateForm('slug', e.target.value)}
              placeholder="google"
              disabled={!!provider}
              required
            />
            <p className="text-xs text-muted-foreground">
              Login URL: /auth/sso/{form.slug || 'slug'}/login
            </p>
          </div>
        </div>

        <div className="flex flex-wrap gap-4">
          <div className="flex items-center space-x-2">
            <Switch
              id="enabled"
              checked={form.enabled ?? true}
              onCheckedChange={checked => updateForm('enabled', checked)}
            />
            <Label htmlFor="enabled">Enabled</Label>
          </div>

          <div className="flex items-center space-x-2">
            <Switch
              id="allow_signup"
              checked={form.allow_signup ?? true}
              onCheckedChange={checked => updateForm('allow_signup', checked)}
            />
            <Label htmlFor="allow_signup">Allow Signup</Label>
          </div>

          <div className="flex items-center space-x-2">
            <Switch
              id="trust_email_verified"
              checked={form.trust_email_verified ?? true}
              onCheckedChange={checked => updateForm('trust_email_verified', checked)}
            />
            <Label htmlFor="trust_email_verified">Trust Email Verified</Label>
          </div>
        </div>

        <div className="space-y-2">
          <Label>Allowed Domains</Label>
          <div className="flex gap-2">
            <Input
              value={domainInput}
              onChange={e => setDomainInput(e.target.value)}
              placeholder="example.com"
              onKeyDown={e => {
                if (e.key === 'Enter') {
                  e.preventDefault()
                  addDomain()
                }
              }}
            />
            <Button type="button" onClick={addDomain} variant="outline">
              Add
            </Button>
          </div>
          {form.domains && form.domains.length > 0 && (
            <div className="flex flex-wrap gap-2 mt-2">
              {form.domains.map(domain => (
                <span
                  key={domain}
                  className="inline-flex items-center gap-1 px-2 py-1 rounded-md bg-muted text-sm"
                >
                  {domain}
                  <button
                    type="button"
                    onClick={() => removeDomain(domain)}
                    className="text-muted-foreground hover:text-foreground"
                  >
                    ×
                  </button>
                </span>
              ))}
            </div>
          )}
          <p className="text-xs text-muted-foreground">
            Leave empty to allow all domains
          </p>
        </div>
      </div>

      {/* Provider Type Selection */}
      {!provider && (
        <div className="space-y-2">
          <Label>Provider Type *</Label>
          <Tabs
            value={form.provider_type}
            onValueChange={value => updateForm('provider_type', value as SsoProviderType)}
          >
            <TabsList className="grid w-full grid-cols-2">
              <TabsTrigger value="oidc">OIDC / OAuth 2.0</TabsTrigger>
              <TabsTrigger value="saml">SAML 2.0</TabsTrigger>
            </TabsList>
          </Tabs>
        </div>
      )}

      {/* Provider-Specific Fields */}
      {form.provider_type === 'oidc' ? (
        <SsoProviderOidcFields form={form} updateForm={updateForm} isEditing={!!provider} />
      ) : (
        <SsoProviderSamlFields form={form} updateForm={updateForm} isEditing={!!provider} />
      )}

      {/* Actions */}
      <div className="flex justify-end gap-3 pt-4 border-t">
        <Button type="button" variant="outline" onClick={onCancel} disabled={loading}>
          Cancel
        </Button>
        <Button type="submit" disabled={loading}>
          {loading ? 'Saving...' : provider ? 'Update Provider' : 'Create Provider'}
        </Button>
      </div>
    </form>
  )
}
