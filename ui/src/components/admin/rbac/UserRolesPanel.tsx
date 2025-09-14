import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { getClient } from '@/lib/sdk'

export default function UserRolesPanel({ tenantId }: { tenantId: string }) {
  const [userId, setUserId] = useState('')
  const [roleId, setRoleId] = useState('')
  const [roleIds, setRoleIds] = useState<string[]>([])
  const [loading, setLoading] = useState<null | 'list' | 'add' | 'remove'>(null)
  const [error, setError] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)

  async function listUserRoles() {
    setError(null)
    setMessage(null)
    if (!tenantId) {
      setError('tenant_id is required')
      return
    }
    if (!userId.trim()) {
      setError('user_id is required')
      return
    }
    setLoading('list')
    try {
      const res = await getClient().rbacListUserRoles(userId.trim(), {
        tenant_id: tenantId
      })
      if (res.meta.status >= 200 && res.meta.status < 300) {
        const ids = Array.isArray((res.data as any)?.role_ids)
          ? (res.data as any).role_ids
          : []
        setRoleIds(ids)
      } else {
        setError('Failed to list user roles')
      }
    } catch (e: any) {
      setError(e?.message || String(e))
    } finally {
      setLoading(null)
    }
  }

  async function addUserRole() {
    setError(null)
    setMessage(null)
    if (!tenantId) {
      setError('tenant_id is required')
      return
    }
    if (!userId.trim()) {
      setError('user_id is required')
      return
    }
    if (!roleId.trim()) {
      setError('role_id is required')
      return
    }
    setLoading('add')
    try {
      const res = await getClient().rbacAddUserRole(userId.trim(), {
        tenant_id: tenantId,
        role_id: roleId.trim()
      } as any)
      if (res.meta.status >= 200 && res.meta.status < 400) {
        setMessage('Role added')
        await listUserRoles()
      } else {
        setError('Failed to add user role')
      }
    } catch (e: any) {
      setError(e?.message || String(e))
    } finally {
      setLoading(null)
    }
  }

  async function removeUserRole(id: string) {
    setError(null)
    setMessage(null)
    if (!tenantId) {
      setError('tenant_id is required')
      return
    }
    if (!userId.trim()) {
      setError('user_id is required')
      return
    }
    setLoading('remove')
    try {
      const res = await getClient().rbacRemoveUserRole(userId.trim(), {
        tenant_id: tenantId,
        role_id: id
      } as any)
      if (res.meta.status >= 200 && res.meta.status < 400) {
        setMessage('Role removed')
        await listUserRoles()
      } else {
        setError('Failed to remove user role')
      }
    } catch (e: any) {
      setError(e?.message || String(e))
    } finally {
      setLoading(null)
    }
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium">User Roles</h3>
      </div>
      {error && (
        <div
          className="rounded-md border border-red-200 bg-red-50 p-2 text-sm text-red-700"
          data-testid="rbac-user-roles-error"
        >
          {error}
        </div>
      )}
      {message && (
        <div
          className="rounded-md border border-green-200 bg-green-50 p-2 text-sm text-green-800"
          data-testid="rbac-user-roles-message"
        >
          {message}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-2 items-end">
        <input
          data-testid="rbac-user-id"
          className="w-full rounded-md border px-3 py-2 text-sm"
          placeholder="user_id"
          value={userId}
          onChange={(e) => setUserId(e.target.value)}
        />
        <Button
          data-testid="rbac-user-roles-list"
          onClick={listUserRoles}
          disabled={loading !== null}
        >
          List Roles
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-2 items-end">
        <input
          data-testid="rbac-user-role-id"
          className="w-full rounded-md border px-3 py-2 text-sm"
          placeholder="role_id to add"
          value={roleId}
          onChange={(e) => setRoleId(e.target.value)}
        />
        <Button
          data-testid="rbac-user-role-add"
          onClick={addUserRole}
          disabled={loading !== null}
        >
          Add Role
        </Button>
      </div>

      <div className="rounded-md border p-3 space-y-2">
        <div className="text-sm font-medium">Current Roles</div>
        {roleIds.length === 0 ? (
          <div
            className="text-sm text-muted-foreground"
            data-testid="rbac-user-roles-empty"
          >
            No roles
          </div>
        ) : (
          <div className="space-y-2">
            {roleIds.map((id) => (
              <div
                key={id}
                className="flex items-center justify-between"
                data-testid={`rbac-user-role-item-${id}`}
              >
                <div className="text-xs break-all">{id}</div>
                <Button
                  variant="destructive"
                  onClick={() => removeUserRole(id)}
                  data-testid={`rbac-user-role-remove-${id}`}
                  disabled={loading !== null}
                >
                  Remove
                </Button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
