import { useState, useEffect } from 'react'
import { getClient } from '@/lib/sdk'
import { useToast } from '@/lib/toast'
import type { SsoProviderItem } from '@/lib/sdk'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import SsoProviderList from './SsoProviderList'
import SsoProviderForm from './SsoProviderForm'

export interface SsoProvidersPanelProps {
  tenantId: string
}

export default function SsoProvidersPanel({ tenantId }: SsoProvidersPanelProps) {
  const [providers, setProviders] = useState<SsoProviderItem[]>([])
  const [loading, setLoading] = useState<'list' | 'create' | 'update' | 'delete' | 'test' | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [showCreateForm, setShowCreateForm] = useState(false)
  const [editingProvider, setEditingProvider] = useState<SsoProviderItem | null>(null)
  const { show } = useToast()

  useEffect(() => {
    loadProviders()
  }, [tenantId])

  async function loadProviders() {
    if (!tenantId) {
      setError('tenant_id is required')
      return
    }

    setError(null)
    setLoading('list')

    try {
      const res = await getClient().ssoListProviders({ tenant_id: tenantId })

      if (res.meta.status >= 200 && res.meta.status < 300) {
        setProviders(res.data.providers || [])
      } else {
        const errorMsg = (res.data as any)?.error || 'Failed to load SSO providers'
        setError(errorMsg)
        show({
          variant: 'error',
          title: 'Failed to load providers',
          description: errorMsg
        })
      }
    } catch (e: any) {
      const errorMsg = e?.message || String(e)
      setError(errorMsg)
      show({
        variant: 'error',
        title: 'Failed to load providers',
        description: errorMsg
      })
    } finally {
      setLoading(null)
    }
  }

  async function handleCreate(provider: SsoProviderItem) {
    setShowCreateForm(false)
    await loadProviders()
    show({
      variant: 'success',
      title: 'Provider created',
      description: `SSO provider "${provider.name}" was created successfully`
    })
  }

  async function handleUpdate(provider: SsoProviderItem) {
    setEditingProvider(null)
    await loadProviders()
    show({
      variant: 'success',
      title: 'Provider updated',
      description: `SSO provider "${provider.name}" was updated successfully`
    })
  }

  async function handleDelete(id: string) {
    setLoading('delete')
    try {
      const res = await getClient().ssoDeleteProvider(id)

      if (res.meta.status === 204 || res.meta.status === 200) {
        show({
          variant: 'success',
          title: 'Provider deleted'
        })
        await loadProviders()
      } else {
        const errorMsg = (res.data as any)?.error || 'Failed to delete provider'
        show({
          variant: 'error',
          title: 'Delete failed',
          description: errorMsg
        })
      }
    } catch (e: any) {
      show({
        variant: 'error',
        title: 'Delete failed',
        description: e?.message || String(e)
      })
    } finally {
      setLoading(null)
    }
  }

  async function handleTest(id: string) {
    setLoading('test')
    try {
      const res = await getClient().ssoTestProvider(id)

      if (res.meta.status >= 200 && res.meta.status < 300) {
        if (res.data.success) {
          show({
            variant: 'success',
            title: 'Connection successful',
            description: 'Provider configuration is valid'
          })
        } else {
          show({
            variant: 'error',
            title: 'Connection failed',
            description: res.data.error || 'Unknown error'
          })
        }
      } else {
        const errorMsg = (res.data as any)?.error || 'Failed to test provider'
        show({
          variant: 'error',
          title: 'Test failed',
          description: errorMsg
        })
      }
    } catch (e: any) {
      show({
        variant: 'error',
        title: 'Test failed',
        description: e?.message || String(e)
      })
    } finally {
      setLoading(null)
    }
  }

  if (showCreateForm) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Create SSO Provider</CardTitle>
          <CardDescription>
            Configure a new OIDC or SAML SSO provider for your tenant
          </CardDescription>
        </CardHeader>
        <CardContent>
          <SsoProviderForm
            tenantId={tenantId}
            onSuccess={handleCreate}
            onCancel={() => setShowCreateForm(false)}
          />
        </CardContent>
      </Card>
    )
  }

  if (editingProvider) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Edit SSO Provider</CardTitle>
          <CardDescription>
            Update configuration for {editingProvider.name}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <SsoProviderForm
            tenantId={tenantId}
            provider={editingProvider}
            onSuccess={handleUpdate}
            onCancel={() => setEditingProvider(null)}
          />
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="space-y-4" data-testid="sso-providers-panel">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-base font-medium">SSO Providers</h3>
          <p className="text-sm text-muted-foreground">
            Manage OIDC and SAML SSO providers for authentication
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            onClick={loadProviders}
            disabled={loading !== null}
            variant="outline"
            size="sm"
            data-testid="sso-refresh"
          >
            Refresh
          </Button>
          <Button
            onClick={() => setShowCreateForm(true)}
            disabled={loading !== null}
            size="sm"
            data-testid="sso-create"
          >
            Create Provider
          </Button>
        </div>
      </div>

      {error && (
        <div
          className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700"
          data-testid="sso-error"
        >
          {error}
        </div>
      )}

      <SsoProviderList
        providers={providers}
        loading={loading === 'list'}
        onEdit={setEditingProvider}
        onDelete={handleDelete}
        onTest={handleTest}
      />
    </div>
  )
}
