import { useState } from 'react'
import type { SsoProviderItem } from '@/lib/sdk'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Modal } from '@/components/ui/modal'
import { Input } from '@/components/ui/input'

export interface SsoProviderListProps {
  providers: SsoProviderItem[]
  loading: boolean
  onEdit: (provider: SsoProviderItem) => void
  onDelete: (id: string) => void
  onTest: (id: string) => void
}

export default function SsoProviderList({
  providers,
  loading,
  onEdit,
  onDelete,
  onTest
}: SsoProviderListProps) {
  const [filterType, setFilterType] = useState<'all' | 'oidc' | 'saml'>('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [deletingProvider, setDeletingProvider] = useState<SsoProviderItem | null>(null)
  const [deleteConfirmText, setDeleteConfirmText] = useState('')

  const filteredProviders = providers.filter(p => {
    if (filterType !== 'all' && p.provider_type !== filterType) return false
    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      return (
        p.name.toLowerCase().includes(query) ||
        p.slug.toLowerCase().includes(query)
      )
    }
    return true
  })

  function handleDeleteClick(provider: SsoProviderItem) {
    setDeletingProvider(provider)
    setDeleteConfirmText('')
  }

  function handleDeleteConfirm() {
    if (deletingProvider && deleteConfirmText === deletingProvider.name) {
      onDelete(deletingProvider.id)
      setDeletingProvider(null)
      setDeleteConfirmText('')
    }
  }

  if (loading) {
    return (
      <div className="rounded-md border p-4">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left border-b">
              <th className="py-2 pr-3 font-medium">Name</th>
              <th className="py-2 pr-3 font-medium">Type</th>
              <th className="py-2 pr-3 font-medium">Slug</th>
              <th className="py-2 pr-3 font-medium">Status</th>
              <th className="py-2 pr-3 font-medium">Domains</th>
              <th className="py-2 font-medium">Actions</th>
            </tr>
          </thead>
          <tbody>
            {[1, 2, 3].map(i => (
              <tr key={i} className="border-b">
                <td className="py-3 pr-3">
                  <Skeleton className="h-4 w-32" />
                </td>
                <td className="py-3 pr-3">
                  <Skeleton className="h-5 w-12" />
                </td>
                <td className="py-3 pr-3">
                  <Skeleton className="h-4 w-20" />
                </td>
                <td className="py-3 pr-3">
                  <Skeleton className="h-5 w-16" />
                </td>
                <td className="py-3 pr-3">
                  <Skeleton className="h-4 w-24" />
                </td>
                <td className="py-3">
                  <div className="flex gap-1">
                    <Skeleton className="h-7 w-12" />
                    <Skeleton className="h-7 w-12" />
                    <Skeleton className="h-7 w-12" />
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    )
  }

  return (
    <>
      <div className="space-y-3">
        {/* Filters */}
        <div className="flex gap-3 items-center">
          <div className="flex gap-2">
            <Button
              variant={filterType === 'all' ? 'default' : 'outline'}
              size="sm"
              onClick={() => setFilterType('all')}
            >
              All
            </Button>
            <Button
              variant={filterType === 'oidc' ? 'default' : 'outline'}
              size="sm"
              onClick={() => setFilterType('oidc')}
            >
              OIDC
            </Button>
            <Button
              variant={filterType === 'saml' ? 'default' : 'outline'}
              size="sm"
              onClick={() => setFilterType('saml')}
            >
              SAML
            </Button>
          </div>
          <Input
            type="text"
            placeholder="Search by name or slug..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="max-w-xs"
          />
        </div>

        {/* Table */}
        <div className="rounded-md border">
          {filteredProviders.length === 0 ? (
            <div className="p-8 text-center text-sm text-muted-foreground">
              {providers.length === 0 ? (
                <>
                  <p className="mb-2">No SSO providers configured</p>
                  <p className="text-xs">
                    Click "Create Provider" to add your first OIDC or SAML provider
                  </p>
                </>
              ) : (
                <p>No providers match your filters</p>
              )}
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left border-b bg-muted/50">
                    <th className="py-2 px-3 font-medium">Name</th>
                    <th className="py-2 px-3 font-medium">Type</th>
                    <th className="py-2 px-3 font-medium">Slug</th>
                    <th className="py-2 px-3 font-medium">Status</th>
                    <th className="py-2 px-3 font-medium">Domains</th>
                    <th className="py-2 px-3 font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredProviders.map(provider => (
                    <tr key={provider.id} className="border-b hover:bg-muted/30">
                      <td className="py-3 px-3 font-medium">{provider.name}</td>
                      <td className="py-3 px-3">
                        <Badge variant={provider.provider_type === 'oidc' ? 'default' : 'secondary'}>
                          {provider.provider_type.toUpperCase()}
                        </Badge>
                      </td>
                      <td className="py-3 px-3 font-mono text-xs">{provider.slug}</td>
                      <td className="py-3 px-3">
                        <Badge variant={provider.enabled ? 'default' : 'secondary'}>
                          {provider.enabled ? 'Enabled' : 'Disabled'}
                        </Badge>
                      </td>
                      <td className="py-3 px-3 text-xs text-muted-foreground">
                        {provider.domains && provider.domains.length > 0 ? (
                          <span title={provider.domains.join(', ')}>
                            {provider.domains.length} domain{provider.domains.length !== 1 ? 's' : ''}
                          </span>
                        ) : (
                          <span className="italic">All domains</span>
                        )}
                      </td>
                      <td className="py-3 px-3">
                        <div className="flex gap-1">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => onTest(provider.id)}
                            title="Test connection"
                          >
                            Test
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => onEdit(provider)}
                            title="Edit provider"
                          >
                            Edit
                          </Button>
                          <Button
                            variant="destructive"
                            size="sm"
                            onClick={() => handleDeleteClick(provider)}
                            title="Delete provider"
                          >
                            Delete
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* Delete Confirmation Modal */}
      {deletingProvider && (
        <Modal
          open={true}
          title="Delete SSO Provider"
          onClose={() => {
            setDeletingProvider(null)
            setDeleteConfirmText('')
          }}
        >
          <div className="space-y-4">
            <div className="space-y-2 text-sm">
              <p className="font-medium text-red-700">
                Are you sure you want to delete "{deletingProvider.name}"?
              </p>
              <p className="text-muted-foreground">
                This action cannot be undone. Users will no longer be able to sign in using this provider.
              </p>
            </div>

            <div className="space-y-2">
              <label htmlFor="delete-confirm" className="block text-sm font-medium">
                Type <strong>{deletingProvider.name}</strong> to confirm
              </label>
              <Input
                id="delete-confirm"
                type="text"
                value={deleteConfirmText}
                onChange={e => setDeleteConfirmText(e.target.value)}
                placeholder={deletingProvider.name}
              />
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  setDeletingProvider(null)
                  setDeleteConfirmText('')
                }}
              >
                Cancel
              </Button>
              <Button
                variant="destructive"
                size="sm"
                onClick={handleDeleteConfirm}
                disabled={deleteConfirmText !== deletingProvider.name}
              >
                Delete Provider
              </Button>
            </div>
          </div>
        </Modal>
      )}
    </>
  )
}
