import { useCallback, useEffect, useMemo, useState } from 'react'
import { Button } from '@/components/ui/button'
import { Modal } from '@/components/ui/modal'
import { Skeleton } from '@/components/ui/skeleton'
import { Label } from '@/components/ui/label'
import { Input } from '@/components/ui/input'
import { getClient } from '@/lib/sdk'
import { useToast } from '@/lib/toast'
import { formatRateLimitError } from '@/lib/rateLimit'
import { Mail, Clock, UserPlus, Copy, X, Check } from 'lucide-react'

interface InvitationsPanelProps {
  tenantId: string
}

interface InvitationItem {
  id: string
  tenant_id?: string
  email: string
  role?: string
  status: string
  expires_at: string
  accepted_at?: string | null
  created_at: string
}

export default function InvitationsPanel({
  tenantId
}: InvitationsPanelProps): React.JSX.Element {
  const [loading, setLoading] = useState<boolean>(false)
  const [error, setError] = useState<string | null>(null)
  const [invitations, setInvitations] = useState<InvitationItem[]>([])
  const { show } = useToast()
  
  // Create invitation modal state
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [createEmail, setCreateEmail] = useState('')
  const [createRole, setCreateRole] = useState('')
  const [creating, setCreating] = useState(false)
  
  // Invite URL modal state
  const [inviteUrl, setInviteUrl] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  const canLoad = useMemo(() => !!tenantId, [tenantId])

  const load = useCallback(async () => {
    setError(null)
    if (!canLoad) {
      setError('tenant_id is required')
      return
    }
    setLoading(true)
    try {
      const c = getClient()
      const res = await c.listInvitations({ tenant_id: tenantId })
      if (res.meta.status >= 200 && res.meta.status < 300) {
        const list = res.data?.invitations ?? []
        setInvitations(list as InvitationItem[])
      } else {
        setError('Failed to load invitations')
        show({ variant: 'error', title: 'Failed to load invitations' })
      }
    } catch (e: any) {
      const rlMsg = formatRateLimitError(e, 'while loading invitations')
      if (rlMsg) {
        setError(rlMsg)
        show({ variant: 'error', title: 'Too Many Requests', description: rlMsg })
      } else {
        const msg = e?.message || String(e)
        setError(msg)
        show({
          variant: 'error',
          title: 'Error',
          description: msg
        })
      }
    } finally {
      setLoading(false)
    }
  }, [canLoad, show, tenantId])

  useEffect(() => {
    if (tenantId) {
      void load()
    }
  }, [tenantId, load])

  async function createInvitation() {
    if (!createEmail.trim()) {
      show({ variant: 'error', title: 'Email is required' })
      return
    }
    setCreating(true)
    setError(null)
    try {
      const c = getClient()
      const res = await c.createInvitation({
        tenant_id: tenantId,
        email: createEmail.trim(),
        role: createRole.trim() || undefined
      })
      if (res.meta.status >= 200 && res.meta.status < 300) {
        show({ variant: 'success', title: 'Invitation created' })
        setShowCreateModal(false)
        setCreateEmail('')
        setCreateRole('')
        // Show the invite URL
        if (res.data?.invite_url) {
          setInviteUrl(res.data.invite_url)
        }
        await load()
      } else {
        const errMsg = (res.data as any)?.error || 'Failed to create invitation'
        setError(errMsg)
        show({ variant: 'error', title: 'Failed to create invitation', description: errMsg })
      }
    } catch (e: any) {
      const rlMsg = formatRateLimitError(e, 'while creating invitation')
      if (rlMsg) {
        setError(rlMsg)
        show({ variant: 'error', title: 'Too Many Requests', description: rlMsg })
      } else {
        const msg = e?.message || String(e)
        setError(msg)
        show({
          variant: 'error',
          title: 'Error',
          description: msg
        })
      }
    } finally {
      setCreating(false)
    }
  }

  async function revokeInvitation(inv: InvitationItem) {
    setError(null)
    try {
      const c = getClient()
      const res = await c.revokeInvitation(inv.id)
      if (res.meta.status >= 200 && res.meta.status < 300) {
        show({ variant: 'success', title: 'Invitation revoked' })
        await load()
      } else {
        const errMsg = (res.data as any)?.error || 'Failed to revoke invitation'
        setError(errMsg)
        show({ variant: 'error', title: 'Failed to revoke invitation', description: errMsg })
      }
    } catch (e: any) {
      const rlMsg = formatRateLimitError(e, 'while revoking invitation')
      if (rlMsg) {
        setError(rlMsg)
        show({ variant: 'error', title: 'Too Many Requests', description: rlMsg })
      } else {
        const msg = e?.message || String(e)
        setError(msg)
        show({
          variant: 'error',
          title: 'Error',
          description: msg
        })
      }
    }
  }

  async function deleteInvitation(inv: InvitationItem) {
    setError(null)
    try {
      const c = getClient()
      const res = await c.deleteInvitation(inv.id)
      if (res.meta.status >= 200 && res.meta.status < 300) {
        show({ variant: 'success', title: 'Invitation deleted' })
        await load()
      } else {
        const errMsg = (res.data as any)?.error || 'Failed to delete invitation'
        setError(errMsg)
        show({ variant: 'error', title: 'Failed to delete invitation', description: errMsg })
      }
    } catch (e: any) {
      const rlMsg = formatRateLimitError(e, 'while deleting invitation')
      if (rlMsg) {
        setError(rlMsg)
        show({ variant: 'error', title: 'Too Many Requests', description: rlMsg })
      } else {
        const msg = e?.message || String(e)
        setError(msg)
        show({
          variant: 'error',
          title: 'Error',
          description: msg
        })
      }
    }
  }

  function copyInviteUrl() {
    if (inviteUrl) {
      navigator.clipboard.writeText(inviteUrl)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }

  function getStatusBadge(status: string) {
    switch (status) {
      case 'pending':
        return <span className="inline-flex items-center rounded-full bg-yellow-100 px-2 py-0.5 text-xs font-medium text-yellow-800">Pending</span>
      case 'accepted':
        return <span className="inline-flex items-center rounded-full bg-green-100 px-2 py-0.5 text-xs font-medium text-green-800">Accepted</span>
      case 'expired':
        return <span className="inline-flex items-center rounded-full bg-gray-100 px-2 py-0.5 text-xs font-medium text-gray-800">Expired</span>
      case 'revoked':
        return <span className="inline-flex items-center rounded-full bg-red-100 px-2 py-0.5 text-xs font-medium text-red-800">Revoked</span>
      default:
        return <span className="inline-flex items-center rounded-full bg-gray-100 px-2 py-0.5 text-xs font-medium text-gray-800">{status}</span>
    }
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium">Invitations</h3>
        <div className="flex gap-2">
          <Button
            data-testid="invitations-create"
            variant="default"
            onClick={() => setShowCreateModal(true)}
            disabled={loading || !canLoad}
          >
            <UserPlus className="h-4 w-4 mr-1" />
            Invite User
          </Button>
          <Button
            data-testid="invitations-refresh"
            variant="secondary"
            onClick={() => load()}
            disabled={loading || !canLoad}
          >
            {loading ? 'Loading...' : 'Refresh'}
          </Button>
        </div>
      </div>
      {error && (
        <div
          className="rounded-md border border-red-200 bg-red-50 p-2 text-sm text-red-700"
          data-testid="invitations-error"
        >
          {error}
        </div>
      )}
      {loading ? (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left border-b">
                <th className="py-2 pr-3">Email</th>
                <th className="py-2 pr-3">Role</th>
                <th className="py-2 pr-3">Status</th>
                <th className="py-2 pr-3">Expires</th>
                <th className="py-2 pr-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {[1, 2, 3].map((i) => (
                <tr key={i} className="border-b last:border-b-0">
                  <td className="py-2 pr-3"><Skeleton className="h-4 w-40" /></td>
                  <td className="py-2 pr-3"><Skeleton className="h-4 w-16" /></td>
                  <td className="py-2 pr-3"><Skeleton className="h-4 w-16" /></td>
                  <td className="py-2 pr-3"><Skeleton className="h-4 w-32" /></td>
                  <td className="py-2 pr-3"><Skeleton className="h-8 w-28" /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : !invitations.length ? (
        <div className="text-center py-8 text-muted-foreground">
          <Mail className="h-8 w-8 mx-auto mb-2 opacity-50" />
          <p>No invitations found</p>
          <p className="text-xs mt-1">Click "Invite User" to send an invitation</p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left border-b">
                <th className="py-2 pr-3">Email</th>
                <th className="py-2 pr-3">Role</th>
                <th className="py-2 pr-3">Status</th>
                <th className="py-2 pr-3">Expires</th>
                <th className="py-2 pr-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {invitations.map((inv) => (
                <tr key={inv.id} className="border-b last:border-b-0" data-testid={`invitation-row-${inv.id}`}>
                  <td className="py-2 pr-3">
                    <div className="flex items-center gap-2">
                      <Mail className="h-4 w-4 text-muted-foreground" />
                      <span>{inv.email}</span>
                    </div>
                  </td>
                  <td className="py-2 pr-3">
                    {inv.role || <span className="text-muted-foreground">—</span>}
                  </td>
                  <td className="py-2 pr-3">
                    {getStatusBadge(inv.status)}
                  </td>
                  <td className="py-2 pr-3">
                    <div className="flex items-center gap-1 text-muted-foreground">
                      <Clock className="h-3 w-3" />
                      <span className="text-xs">
                        {new Date(inv.expires_at).toLocaleDateString()}
                      </span>
                    </div>
                  </td>
                  <td className="py-2 pr-3">
                    <div className="flex gap-1">
                      {inv.status === 'pending' && (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => revokeInvitation(inv)}
                          data-testid={`revoke-invitation-${inv.id}`}
                        >
                          Revoke
                        </Button>
                      )}
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => deleteInvitation(inv)}
                        data-testid={`delete-invitation-${inv.id}`}
                      >
                        <X className="h-4 w-4" />
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Create Invitation Modal */}
      <Modal
        open={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        title="Invite User"
      >
        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="invite-email">Email Address</Label>
            <Input
              id="invite-email"
              type="email"
              placeholder="user@example.com"
              value={createEmail}
              onChange={(e) => setCreateEmail(e.target.value)}
              data-testid="invite-email-input"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="invite-role">Role (optional)</Label>
            <Input
              id="invite-role"
              type="text"
              placeholder="e.g., admin, member"
              value={createRole}
              onChange={(e) => setCreateRole(e.target.value)}
              data-testid="invite-role-input"
            />
            <p className="text-xs text-muted-foreground">
              The role will be assigned when the user accepts the invitation.
            </p>
          </div>
          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={() => setShowCreateModal(false)}>
              Cancel
            </Button>
            <Button
              onClick={createInvitation}
              disabled={creating || !createEmail.trim()}
              data-testid="send-invitation-btn"
            >
              {creating ? 'Sending...' : 'Send Invitation'}
            </Button>
          </div>
        </div>
      </Modal>

      {/* Invite URL Modal */}
      <Modal
        open={!!inviteUrl}
        onClose={() => setInviteUrl(null)}
        title="Invitation Created"
      >
        <div className="space-y-4">
          <p className="text-sm text-muted-foreground">
            Share this link with the user to complete their registration:
          </p>
          <div className="flex items-center gap-2">
            <Input
              readOnly
              value={inviteUrl || ''}
              className="font-mono text-xs"
              data-testid="invite-url-input"
            />
            <Button
              variant="outline"
              size="sm"
              onClick={copyInviteUrl}
              data-testid="copy-invite-url"
            >
              {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
            </Button>
          </div>
          <p className="text-xs text-muted-foreground">
            This link will expire in 7 days.
          </p>
          <div className="flex justify-end">
            <Button onClick={() => setInviteUrl(null)}>Done</Button>
          </div>
        </div>
      </Modal>
    </div>
  )
}
