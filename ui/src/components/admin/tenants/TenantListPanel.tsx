import { useEffect, useState } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { useAuth } from '@/lib/auth'
import { useTenant } from '@/lib/tenant'
import { getClient } from '@/lib/sdk'
import { useToast } from '@/lib/toast'

interface Tenant {
  id: string
  name: string
  is_active: boolean
  parent_tenant_id?: string
  created_at: string
  updated_at: string
}

interface TenantListResponse {
  items: Tenant[]
  total: number
  page: number
  page_size: number
  total_pages: number
}

interface TenantListPanelProps {
  onTenantSelected?: (tenantId: string, tenantName: string) => void
  refreshTrigger?: number
}

// Helper to get tenant name by ID from the list
const getTenantNameById = (tenants: Tenant[], id: string): string => {
  const tenant = tenants.find(t => t.id === id)
  return tenant?.name || id
}

export default function TenantListPanel({ onTenantSelected, refreshTrigger }: TenantListPanelProps) {
  const { user } = useAuth()
  const { tenantId: currentTenantId, tenantName: currentTenantName, setTenant } = useTenant()
  const { show: showToast } = useToast()
  const [tenants, setTenants] = useState<Tenant[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [page, setPage] = useState(1)
  const [totalPages, setTotalPages] = useState(1)

  const fetchTenants = async (searchQ = '', pageNum = 1) => {
    if (!user?.accessToken) return

    setLoading(true)
    setError(null)

    try {
      const client = getClient()
      const res = await client.listTenants({
        q: searchQ.trim() || undefined,
        page: pageNum,
        page_size: 10,
        active: 1
      })
      if (!(res.meta.status >= 200 && res.meta.status < 300)) {
        throw new Error('Failed to fetch tenants')
      }
      const data = res.data as TenantListResponse
      setTenants(data.items)
      setTotalPages(data.total_pages)
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to fetch tenants'
      setError(message)
      showToast({ description: message, variant: 'error' })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchTenants(searchQuery, page)
  }, [user?.accessToken, page, refreshTrigger])

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    setPage(1)
    fetchTenants(searchQuery, 1)
  }

  const handleTenantSelect = (tenant: Tenant) => {
    setTenant(tenant.id, tenant.name)
    onTenantSelected?.(tenant.id, tenant.name)
    showToast({ description: `Switched to tenant: ${tenant.name}`, variant: 'success' })
  }

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    })
  }

  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle>Tenant Management</CardTitle>
        <CardDescription>
          View and switch between available tenants
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Search */}
        <form onSubmit={handleSearch} className="flex gap-2">
          <div className="flex-1">
            <Label htmlFor="search" className="sr-only">Search tenants</Label>
            <Input
              id="search"
              type="text"
              placeholder="Search tenants..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              disabled={loading}
            />
          </div>
          <Button type="submit" disabled={loading}>
            Search
          </Button>
        </form>

        {/* Current Tenant */}
        {currentTenantId && (
          <div className="p-3 bg-blue-50 border border-blue-200 rounded-md">
            <p className="text-sm font-medium text-blue-900">
              Current Tenant: {currentTenantName || currentTenantId}
            </p>
          </div>
        )}

        {/* Error */}
        {error && (
          <div className="p-3 text-sm text-red-600 bg-red-50 border border-red-200 rounded-md">
            {error}
          </div>
        )}

        {/* Loading */}
        {loading && (
          <div className="text-center py-4">
            <p className="text-sm text-muted-foreground">Loading tenants...</p>
          </div>
        )}

        {/* Tenants List */}
        {!loading && tenants.length > 0 && (
          <div className="space-y-2">
            {tenants.map((tenant) => (
              <div
                key={tenant.id}
                className={`p-4 border rounded-lg hover:bg-gray-50 transition-colors ${
                  tenant.id === currentTenantId ? 'border-blue-500 bg-blue-50' : 'border-gray-200'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <h3 className="font-medium">{tenant.name}</h3>
                      {tenant.is_active && (
                        <Badge variant="secondary" className="text-xs">
                          Active
                        </Badge>
                      )}
                      {tenant.id === currentTenantId && (
                        <Badge variant="default" className="text-xs">
                          Current
                        </Badge>
                      )}
                    </div>
                    <p className="text-sm text-muted-foreground mt-1">
                      ID: {tenant.id}
                    </p>
                    {tenant.parent_tenant_id && (
                      <p className="text-xs text-muted-foreground">
                        Parent: {getTenantNameById(tenants, tenant.parent_tenant_id)}
                      </p>
                    )}
                    <p className="text-xs text-muted-foreground">
                      Created: {formatDate(tenant.created_at)}
                    </p>
                  </div>
                  <div className="flex gap-2">
                    {tenant.id !== currentTenantId && (
                      <Button
                        size="sm"
                        onClick={() => handleTenantSelect(tenant)}
                        disabled={loading}
                      >
                        Switch
                      </Button>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Empty State */}
        {!loading && tenants.length === 0 && (
          <div className="text-center py-8">
            <p className="text-muted-foreground">
              {searchQuery ? 'No tenants found matching your search.' : 'No tenants available.'}
            </p>
          </div>
        )}

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex justify-center gap-2 pt-4">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page === 1 || loading}
            >
              Previous
            </Button>
            <span className="flex items-center px-3 text-sm">
              Page {page} of {totalPages}
            </span>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              disabled={page === totalPages || loading}
            >
              Next
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
