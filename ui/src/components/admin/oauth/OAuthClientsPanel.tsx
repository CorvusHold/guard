import { useState, useEffect } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Modal } from '@/components/ui/modal'
import {
  Loader2,
  Plus,
  RefreshCw,
  Trash2,
  Copy,
  Check,
  KeyRound,
  Globe
} from 'lucide-react'
import { getClient } from '@/lib/sdk'
import { useToast } from '@/lib/toast'
import type {
  OAuthClientItem,
  CreateOAuthClientReq
} from '../../../../../sdk/ts/src/client'

interface OAuthClientsPanelProps {
  tenantId: string
}

export default function OAuthClientsPanel({ tenantId }: OAuthClientsPanelProps) {
  const { show: showToast } = useToast()
  const [loading, setLoading] = useState(false)
  const [clients, setClients] = useState<OAuthClientItem[]>([])
  const [error, setError] = useState<string | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [creating, setCreating] = useState(false)
  const [newSecret, setNewSecret] = useState<string | null>(null)
  const [copiedSecret, setCopiedSecret] = useState(false)
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null)

  // Edit modal state
  const [editing, setEditing] = useState<OAuthClientItem | null>(null)
  const [editSaving, setEditSaving] = useState(false)
  const [editName, setEditName] = useState('')
  const [editRedirectURIs, setEditRedirectURIs] = useState('')
  const [editScopes, setEditScopes] = useState('')
  const [editGrantTypes, setEditGrantTypes] = useState('')
  const [editLogo, setEditLogo] = useState('')
  const [editError, setEditError] = useState<string | null>(null)

  // Create form state
  const [formName, setFormName] = useState('')
  const [formType, setFormType] = useState<'confidential' | 'public'>('confidential')
  const [formRedirectURIs, setFormRedirectURIs] = useState('')
  const [formScopes, setFormScopes] = useState('openid profile email')
  const [formGrantTypes, setFormGrantTypes] = useState('authorization_code refresh_token')

  useEffect(() => {
    loadClients()
  }, [tenantId])

  const toSafeHTTPSURL = (value: string): string | null => {
    const trimmed = value.trim()
    if (!trimmed) return null
    try {
      const parsed = new URL(trimmed)
      if (parsed.protocol !== 'https:') return null
      return parsed.toString()
    } catch {
      return null
    }
  }

  const loadClients = async () => {
    setLoading(true)
    setError(null)
    try {
      const client = getClient()
      const res = await client.listOAuthClients()
      if (!(res.meta.status >= 200 && res.meta.status < 300)) {
        throw new Error('Failed to load OAuth clients')
      }
      setClients((res.data as any)?.clients ?? [])
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to load clients'
      setError(message)
    } finally {
      setLoading(false)
    }
  }

  const openEdit = (client: OAuthClientItem) => {
    setError(null)
    setEditError(null)
    setEditing(client)
    setEditName(client.name ?? '')
    setEditRedirectURIs((client.redirect_uris ?? []).join('\n'))
    setEditScopes((client.scopes ?? []).join(' '))
    setEditGrantTypes((client.grant_types ?? []).join(' '))
    setEditLogo(client.logo_uri ?? '')
  }

  const resetEdit = () => {
    setEditing(null)
    setEditSaving(false)
    setEditError(null)
    setEditName('')
    setEditRedirectURIs('')
    setEditScopes('')
    setEditGrantTypes('')
    setEditLogo('')
  }

  const handleEditSave = async () => {
    if (!editing) return
    if (!editName.trim() || !editRedirectURIs.trim()) {
      setEditError('Name and at least one redirect URI are required')
      return
    }
    const logoPreviewURL = toSafeHTTPSURL(editLogo)
    if (editLogo.trim() && !logoPreviewURL) {
      setEditError('Logo URL must be a valid HTTPS URL')
      return
    }
    setEditSaving(true)
    setEditError(null)
    try {
      const client = getClient()
      const body = {
        name: editName.trim(),
        redirect_uris: editRedirectURIs.split('\n').map((u) => u.trim()).filter(Boolean),
        scopes: editScopes.split(/\s+/).filter(Boolean),
        grant_types: editGrantTypes.split(/\s+/).filter(Boolean),
        logo_uri: logoPreviewURL ?? undefined,
      }
      const res = await client.updateOAuthClient(editing.id, body)
      if (!(res.meta.status >= 200 && res.meta.status < 300)) {
        throw new Error('Failed to update client')
      }
      showToast({ description: 'OAuth client updated', variant: 'success' })
      resetEdit()
      loadClients()
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to update client'
      setEditError(message)
    } finally {
      setEditSaving(false)
    }
  }

  const handleCreate = async () => {
    if (!formName.trim() || !formRedirectURIs.trim()) {
      setError('Name and at least one redirect URI are required')
      return
    }
    setCreating(true)
    setError(null)
    try {
      const client = getClient()
      const body: CreateOAuthClientReq = {
        name: formName.trim(),
        client_type: formType,
        redirect_uris: formRedirectURIs.split('\n').map((u) => u.trim()).filter(Boolean),
        scopes: formScopes.split(/\s+/).filter(Boolean),
        grant_types: formGrantTypes.split(/\s+/).filter(Boolean),
        logo_uri: undefined,
      }
      const res = await client.createOAuthClient(body)
      if (!(res.meta.status >= 200 && res.meta.status < 300)) {
        throw new Error('Failed to create client')
      }
      const data = res.data as any
      if (data?.client_secret) {
        setNewSecret(data.client_secret)
      }
      showToast({ description: 'OAuth client created', variant: 'success' })
      resetForm()
      setShowCreate(false)
      loadClients()
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to create client'
      setError(message)
    } finally {
      setCreating(false)
    }
  }

  const handleDelete = async (id: string) => {
    try {
      const client = getClient()
      const res = await client.deleteOAuthClient(id)
      if (!(res.meta.status >= 200 && res.meta.status < 300)) {
        throw new Error('Failed to delete client')
      }
      showToast({ description: 'OAuth client deleted', variant: 'success' })
      setDeleteConfirm(null)
      loadClients()
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to delete client'
      setError(message)
    }
  }

  const handleToggleActive = async (c: OAuthClientItem) => {
    try {
      const client = getClient()
      const res = await client.updateOAuthClient(c.id, { is_active: !c.is_active })
      if (!(res.meta.status >= 200 && res.meta.status < 300)) {
        throw new Error('Failed to update client')
      }
      loadClients()
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to update client'
      setError(message)
    }
  }

  const resetForm = () => {
    setFormName('')
    setFormType('confidential')
    setFormRedirectURIs('')
    setFormScopes('openid profile email')
    setFormGrantTypes('authorization_code refresh_token')
  }

  const safeEditLogoURL = toSafeHTTPSURL(editLogo)

  const copySecret = () => {
    if (newSecret) {
      navigator.clipboard.writeText(newSecret)
      setCopiedSecret(true)
      setTimeout(() => setCopiedSecret(false), 2000)
    }
  }

  if (loading && clients.length === 0) {
    return (
      <div className="flex items-center justify-center py-8" data-testid="oauth-clients-loading">
        <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
        <span className="ml-2 text-sm text-muted-foreground">Loading OAuth clients...</span>
      </div>
    )
  }

  return (
    <div className="space-y-4" data-testid="oauth-clients-panel">
      {/* Secret display banner */}
      {newSecret && (
        <Alert className="border-green-200 bg-green-50" data-testid="new-client-secret">
          <KeyRound className="h-4 w-4 text-green-600" />
          <AlertDescription className="space-y-2">
            <p className="text-sm font-medium text-green-800">
              Client secret created — copy it now, it won't be shown again.
            </p>
            <div className="flex items-center gap-2">
              <code className="flex-1 rounded bg-white px-2 py-1 text-xs font-mono border">
                {newSecret}
              </code>
              <Button
                variant="outline"
                size="sm"
                onClick={copySecret}
                data-testid="copy-secret-button"
              >
                {copiedSecret ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
              </Button>
            </div>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setNewSecret(null)}
              className="text-green-700"
            >
              Dismiss
            </Button>
          </AlertDescription>
        </Alert>
      )}

      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Globe className="h-5 w-5 text-muted-foreground" />
          <h3 className="text-sm font-medium">OAuth 2.0 Clients</h3>
          <Badge variant="secondary" className="text-xs">{clients.length}</Badge>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={loadClients}
            disabled={loading}
            data-testid="oauth-clients-refresh"
          >
            <RefreshCw className="mr-1 h-3 w-3" />
            Refresh
          </Button>
          <Button
            size="sm"
            onClick={() => setShowCreate(!showCreate)}
            data-testid="oauth-clients-create-toggle"
          >
            <Plus className="mr-1 h-3 w-3" />
            New Client
          </Button>
        </div>
      </div>

      {/* Create form */}
      {showCreate && (
        <div className="rounded-md border p-4 space-y-3" data-testid="oauth-create-form">
          <h4 className="text-sm font-medium">Register New OAuth Client</h4>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label className="text-xs">Name</Label>
              <Input
                placeholder="My App"
                value={formName}
                onChange={(e) => setFormName(e.target.value)}
                data-testid="oauth-form-name"
              />
            </div>
            <div className="space-y-1">
              <Label className="text-xs">Client Type</Label>
              <select
                className="w-full rounded-md border px-3 py-2 text-sm"
                value={formType}
                onChange={(e) => setFormType(e.target.value as 'confidential' | 'public')}
                data-testid="oauth-form-type"
              >
                <option value="confidential">Confidential (server-side)</option>
                <option value="public">Public (SPA/mobile)</option>
              </select>
            </div>
          </div>
          <div className="space-y-1">
            <Label className="text-xs">Redirect URIs (one per line)</Label>
            <textarea
              className="w-full rounded-md border px-3 py-2 text-sm min-h-[60px]"
              placeholder="https://myapp.example.com/callback"
              value={formRedirectURIs}
              onChange={(e) => setFormRedirectURIs(e.target.value)}
              data-testid="oauth-form-redirects"
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label className="text-xs">Scopes (space-separated)</Label>
              <Input
                placeholder="openid profile email"
                value={formScopes}
                onChange={(e) => setFormScopes(e.target.value)}
                data-testid="oauth-form-scopes"
              />
            </div>
            <div className="space-y-1">
              <Label className="text-xs">Grant Types (space-separated)</Label>
              <Input
                placeholder="authorization_code refresh_token"
                value={formGrantTypes}
                onChange={(e) => setFormGrantTypes(e.target.value)}
                data-testid="oauth-form-grants"
              />
            </div>
          </div>
          <div className="flex gap-2">
            <Button
              size="sm"
              onClick={handleCreate}
              disabled={creating || !formName.trim() || !formRedirectURIs.trim()}
              data-testid="oauth-form-submit"
            >
              {creating ? <Loader2 className="mr-1 h-3 w-3 animate-spin" /> : <Plus className="mr-1 h-3 w-3" />}
              Create
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => { setShowCreate(false); resetForm() }}
            >
              Cancel
            </Button>
          </div>
        </div>
      )}

      {/* Client list */}
      {clients.length === 0 ? (
        <div className="text-center py-8 text-sm text-muted-foreground" data-testid="oauth-clients-empty">
          No OAuth clients registered yet. Click "New Client" to create one.
        </div>
      ) : (
        <div className="space-y-2">
          {clients.map((c) => (
            <div
              key={c.id}
              className="rounded-md border p-3 space-y-2"
              data-testid={`oauth-client-${c.id}`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="font-medium text-sm">{c.name}</span>
                  <Badge variant={c.is_active ? 'default' : 'secondary'} className="text-xs">
                    {c.is_active ? 'Active' : 'Inactive'}
                  </Badge>
                  <Badge variant="outline" className="text-xs">
                    {c.client_type}
                  </Badge>
                </div>
                <div className="flex gap-1">
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => openEdit(c)}
                    data-testid={`oauth-edit-${c.id}`}
                  >
                    Edit
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => handleToggleActive(c)}
                    data-testid={`oauth-toggle-${c.id}`}
                  >
                    {c.is_active ? 'Deactivate' : 'Activate'}
                  </Button>
                  {deleteConfirm === c.id ? (
                    <div className="flex gap-1">
                      <Button
                        variant="destructive"
                        size="sm"
                        onClick={() => handleDelete(c.id)}
                        data-testid={`oauth-delete-confirm-${c.id}`}
                      >
                        Confirm
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => setDeleteConfirm(null)}
                      >
                        Cancel
                      </Button>
                    </div>
                  ) : (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setDeleteConfirm(c.id)}
                      data-testid={`oauth-delete-${c.id}`}
                    >
                      <Trash2 className="h-3 w-3 text-destructive" />
                    </Button>
                  )}
                </div>
              </div>
              <div className="grid grid-cols-2 gap-2 text-xs text-muted-foreground">
                <div>
                  <span className="font-medium">Client ID:</span>{' '}
                  <code className="bg-muted px-1 rounded">{c.client_id}</code>
                </div>
                <div>
                  <span className="font-medium">Scopes:</span>{' '}
                  {c.scopes?.join(', ') || 'none'}
                </div>
                <div>
                  <span className="font-medium">Grant Types:</span>{' '}
                  {c.grant_types?.join(', ') || 'none'}
                </div>
                <div>
                  <span className="font-medium">Redirect URIs:</span>{' '}
                  {c.redirect_uris?.length || 0}
                </div>
                {c.logo_uri && (
                  <div className="col-span-2 flex items-center gap-2">
                    <span className="font-medium">Logo:</span>
                    <code className="bg-muted px-1 rounded break-all text-[11px]">{c.logo_uri}</code>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      <Modal
        open={!!editing}
        onClose={resetEdit}
        title={editing ? `Edit OAuth Client (${editing.client_id})` : 'Edit OAuth Client'}
      >
        <div className="space-y-3" data-testid="oauth-edit-modal">
          {editError && (
            <Alert variant="destructive" data-testid="oauth-edit-error">
              <AlertDescription>{editError}</AlertDescription>
            </Alert>
          )}
          <Alert className="border-blue-200 bg-blue-50" data-testid="oauth-edit-warning">
            <AlertDescription className="text-xs text-blue-800">
              Updating a client will not regenerate the secret. Client type is read-only.
            </AlertDescription>
          </Alert>
          <div className="space-y-1">
            <Label className="text-xs">Name</Label>
            <Input
              value={editName}
              onChange={(e) => setEditName(e.target.value)}
              data-testid="oauth-edit-name"
            />
          </div>
          <div className="space-y-1">
            <Label className="text-xs">Client Type</Label>
            <Input value={editing?.client_type ?? ''} readOnly data-testid="oauth-edit-type" />
          </div>
          <div className="space-y-1">
            <Label className="text-xs">Redirect URIs (one per line)</Label>
            <textarea
              className="w-full rounded-md border px-3 py-2 text-sm min-h-[80px]"
              value={editRedirectURIs}
              onChange={(e) => setEditRedirectURIs(e.target.value)}
              data-testid="oauth-edit-redirects"
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label className="text-xs">Scopes (space-separated)</Label>
              <Input
                value={editScopes}
                onChange={(e) => setEditScopes(e.target.value)}
                data-testid="oauth-edit-scopes"
              />
            </div>
            <div className="space-y-1">
              <Label className="text-xs">Grant Types (space-separated)</Label>
              <Input
                value={editGrantTypes}
                onChange={(e) => setEditGrantTypes(e.target.value)}
                data-testid="oauth-edit-grants"
              />
            </div>
          </div>
          <div className="space-y-1">
            <Label className="text-xs">Logo URL (optional)</Label>
            <Input
              value={editLogo}
              onChange={(e) => setEditLogo(e.target.value)}
              placeholder="https://example.com/logo.png"
              data-testid="oauth-edit-logo"
            />
            {safeEditLogoURL && (
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <span>Preview:</span>
                <img src={safeEditLogoURL} alt="logo preview" className="h-6 w-6 rounded border" />
              </div>
            )}
            {editLogo.trim() && !safeEditLogoURL && (
              <p className="text-xs text-destructive" data-testid="oauth-edit-logo-warning">
                Logo preview only supports valid HTTPS URLs.
              </p>
            )}
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <Button
              size="sm"
              onClick={handleEditSave}
              disabled={editSaving || !editName.trim() || !editRedirectURIs.trim()}
              data-testid="oauth-edit-save"
            >
              {editSaving ? <Loader2 className="mr-1 h-3 w-3 animate-spin" /> : null}
              Save changes
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  )
}
