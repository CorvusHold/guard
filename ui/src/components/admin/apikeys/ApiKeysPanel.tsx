import { useCallback, useEffect, useState } from 'react'
import { Button } from '@/components/ui/button'
import { Modal } from '@/components/ui/modal'
import { Skeleton } from '@/components/ui/skeleton'
import { Label } from '@/components/ui/label'
import { useToast } from '@/lib/toast'
import { formatRateLimitError } from '@/lib/rateLimit'
import { getRuntimeConfig } from '@/lib/runtime'
import { Key, Plus, Trash2, Copy, Clock, Shield } from 'lucide-react'

interface ApiKeysPanelProps {
  tenantId: string
}

interface ApiKeyItem {
  id: string
  tenant_id: string
  name: string
  key_prefix: string
  scopes: string[]
  created_by?: string | null
  expires_at?: string | null
  revoked_at?: string | null
  last_used_at?: string | null
  created_at: string
  updated_at: string
}

interface CreateApiKeyResponse {
  id: string
  tenant_id: string
  name: string
  key_prefix: string
  scopes: string[]
  raw_key: string
  expires_at?: string | null
  created_at: string
}

async function apiFetch(path: string, opts?: RequestInit) {
  const cfg = getRuntimeConfig()
  if (!cfg) throw new Error('Guard base URL not configured')
  const token = localStorage.getItem('guard_access_token')
  const res = await fetch(`${cfg.guard_base_url}${path}`, {
    ...opts,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(opts?.headers || {})
    }
  })
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new Error(body.error || `HTTP ${res.status}`)
  }
  if (res.status === 204) return null
  return res.json()
}

export default function ApiKeysPanel({
  tenantId
}: ApiKeysPanelProps): React.JSX.Element {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [keys, setKeys] = useState<ApiKeyItem[]>([])
  const [showCreate, setShowCreate] = useState(false)
  const [creating, setCreating] = useState(false)
  const [newKeyName, setNewKeyName] = useState('')
  const [newKeyScopes, setNewKeyScopes] = useState('')
  const [createdKey, setCreatedKey] = useState<CreateApiKeyResponse | null>(null)
  const [copied, setCopied] = useState(false)
  const { show } = useToast()

  const load = useCallback(async () => {
    setError(null)
    setLoading(true)
    try {
      const data = await apiFetch('/api/v1/auth/admin/api-keys')
      setKeys(data?.api_keys ?? [])
    } catch (e: any) {
      const rlMsg = formatRateLimitError(e, 'while loading API keys')
      if (rlMsg) {
        setError(rlMsg)
        show({ variant: 'error', title: 'Too Many Requests', description: rlMsg })
      } else {
        setError(e?.message || String(e))
        show({ variant: 'error', title: 'Error', description: e?.message || String(e) })
      }
    } finally {
      setLoading(false)
    }
  }, [show])

  useEffect(() => {
    if (tenantId) load()
  }, [tenantId, load])

  const handleCreate = async () => {
    if (!newKeyName.trim()) return
    setCreating(true)
    try {
      const body: Record<string, unknown> = { name: newKeyName.trim() }
      if (newKeyScopes.trim()) {
        body.scopes = newKeyScopes.split(',').map((s) => s.trim()).filter(Boolean)
      }
      const data = await apiFetch('/api/v1/auth/admin/api-keys', {
        method: 'POST',
        body: JSON.stringify(body)
      })
      setCreatedKey(data as CreateApiKeyResponse)
      show({ variant: 'success', title: 'API key created' })
      load()
    } catch (e: any) {
      show({ variant: 'error', title: 'Failed to create API key', description: e?.message })
    } finally {
      setCreating(false)
    }
  }

  const handleRevoke = async (keyId: string) => {
    if (!confirm('Are you sure you want to revoke this API key? This cannot be undone.')) return
    try {
      await apiFetch(`/api/v1/auth/admin/api-keys/${keyId}/revoke`, { method: 'POST' })
      show({ variant: 'success', title: 'API key revoked' })
      load()
    } catch (e: any) {
      show({ variant: 'error', title: 'Failed to revoke', description: e?.message })
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const getStatus = (key: ApiKeyItem) => {
    if (key.revoked_at) return 'revoked'
    if (key.expires_at && new Date(key.expires_at) < new Date()) return 'expired'
    return 'active'
  }

  const statusColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'text-green-600 bg-green-50'
      case 'revoked':
        return 'text-red-600 bg-red-50'
      case 'expired':
        return 'text-yellow-600 bg-yellow-50'
      default:
        return 'text-gray-600 bg-gray-50'
    }
  }

  return (
    <div className="space-y-4" data-testid="api-keys-panel">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold flex items-center gap-2">
          <Key className="w-5 h-5" />
          API Keys
        </h3>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={load} disabled={loading} data-testid="refresh-api-keys">
            Refresh
          </Button>
          <Button size="sm" onClick={() => { setShowCreate(true); setNewKeyName(''); setNewKeyScopes(''); setCreatedKey(null) }} data-testid="create-api-key-btn">
            <Plus className="w-4 h-4 mr-1" /> Create Key
          </Button>
        </div>
      </div>

      {error && <div className="text-red-600 text-sm" data-testid="api-keys-error">{error}</div>}

      {loading ? (
        <div className="space-y-2">
          <Skeleton className="h-12 w-full" />
          <Skeleton className="h-12 w-full" />
        </div>
      ) : keys.length === 0 ? (
        <div className="text-center py-8 text-gray-500" data-testid="api-keys-empty">
          <Key className="w-12 h-12 mx-auto mb-2 opacity-30" />
          <p>No API keys yet.</p>
          <p className="text-sm">Create one for service-to-service authentication.</p>
        </div>
      ) : (
        <div className="border rounded-lg divide-y" data-testid="api-keys-list">
          {keys.map((k) => {
            const status = getStatus(k)
            return (
              <div key={k.id} className="p-4 flex items-center justify-between" data-testid={`api-key-${k.id}`}>
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-medium">{k.name}</span>
                    <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${statusColor(status)}`}>
                      {status}
                    </span>
                  </div>
                  <div className="flex items-center gap-4 text-sm text-gray-500">
                    <span className="font-mono text-xs bg-gray-100 px-1.5 py-0.5 rounded">{k.key_prefix}...</span>
                    {k.scopes?.length > 0 && (
                      <span className="flex items-center gap-1">
                        <Shield className="w-3 h-3" />
                        {k.scopes.join(', ')}
                      </span>
                    )}
                    <span className="flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      Created {new Date(k.created_at).toLocaleDateString()}
                    </span>
                    {k.last_used_at && (
                      <span>Last used {new Date(k.last_used_at).toLocaleDateString()}</span>
                    )}
                  </div>
                </div>
                {status === 'active' && (
                  <Button
                    variant="outline"
                    size="sm"
                    className="text-red-600 hover:text-red-700"
                    onClick={() => handleRevoke(k.id)}
                    data-testid={`revoke-api-key-${k.id}`}
                  >
                    <Trash2 className="w-4 h-4 mr-1" /> Revoke
                  </Button>
                )}
              </div>
            )
          })}
        </div>
      )}

      {/* Create API Key Modal */}
      <Modal open={showCreate} onClose={() => setShowCreate(false)} title="Create API Key">
        {createdKey ? (
          <div className="space-y-4" data-testid="created-key-display">
            <div className="bg-green-50 border border-green-200 rounded-lg p-4">
              <p className="text-sm font-medium text-green-800 mb-2">API key created successfully!</p>
              <p className="text-xs text-green-600 mb-3">Copy this key now — it will not be shown again.</p>
              <div className="flex items-center gap-2">
                <code className="flex-1 bg-white border rounded px-3 py-2 text-sm font-mono break-all" data-testid="raw-key-value">
                  {createdKey.raw_key}
                </code>
                <Button size="sm" variant="outline" onClick={() => copyToClipboard(createdKey.raw_key)} data-testid="copy-key-btn">
                  <Copy className="w-4 h-4" />
                  {copied ? ' Copied!' : ' Copy'}
                </Button>
              </div>
            </div>
            <Button className="w-full" onClick={() => { setShowCreate(false); setCreatedKey(null) }}>
              Done
            </Button>
          </div>
        ) : (
          <div className="space-y-4">
            <div>
              <Label htmlFor="key-name">Name</Label>
              <input
                id="key-name"
                type="text"
                className="w-full border rounded px-3 py-2 mt-1"
                placeholder="e.g., polyglotify-prod"
                value={newKeyName}
                onChange={(e) => setNewKeyName(e.target.value)}
                data-testid="api-key-name-input"
              />
            </div>
            <div>
              <Label htmlFor="key-scopes">Scopes (comma-separated, optional)</Label>
              <input
                id="key-scopes"
                type="text"
                className="w-full border rounded px-3 py-2 mt-1"
                placeholder="e.g., users:read, invitations:write"
                value={newKeyScopes}
                onChange={(e) => setNewKeyScopes(e.target.value)}
                data-testid="api-key-scopes-input"
              />
              <p className="text-xs text-gray-500 mt-1">
                Available: users:read, users:write, invitations:read, invitations:write, settings:read
              </p>
            </div>
            <div className="flex gap-2 justify-end">
              <Button variant="outline" onClick={() => setShowCreate(false)}>Cancel</Button>
              <Button onClick={handleCreate} disabled={creating || !newKeyName.trim()} data-testid="confirm-create-key">
                {creating ? 'Creating...' : 'Create Key'}
              </Button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  )
}
