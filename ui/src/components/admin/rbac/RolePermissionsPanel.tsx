import { useEffect, useState } from 'react'
import { Button } from '@/components/ui/button'
import { getClient } from '@/lib/sdk'

export default function RolePermissionsPanel({
  tenantId
}: {
  tenantId: string
}) {
  const [roles, setRoles] = useState<Array<{ id: string; name: string }>>([])
  const [roleId, setRoleId] = useState('')
  const [permissionKey, setPermissionKey] = useState('')
  const [scopeType, setScopeType] = useState('tenant')
  const [resourceType, setResourceType] = useState('')
  const [resourceId, setResourceId] = useState('')
  const [loading, setLoading] = useState<null | 'list' | 'grant' | 'revoke'>(
    null
  )
  const [error, setError] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)

  async function loadRoles() {
    setError(null)
    setMessage(null)
    if (!tenantId) {
      setError('tenant_id is required')
      return
    }
    setLoading('list')
    try {
      const res = await getClient().rbacListRoles({ tenant_id: tenantId })
      if (res.meta.status >= 200 && res.meta.status < 300) {
        const list = Array.isArray((res.data as any)?.roles)
          ? (res.data as any).roles
          : []
        setRoles(list.map((r: any) => ({ id: r.id, name: r.name })))
      } else {
        setError('Failed to list roles')
      }
    } catch (e: any) {
      setError(e?.message || String(e))
    } finally {
      setLoading(null)
    }
  }

  useEffect(() => {
    // no auto-load without tenant
  }, [])

  async function grant() {
    setError(null)
    setMessage(null)
    if (!roleId) {
      setError('role_id is required')
      return
    }
    if (!permissionKey.trim()) {
      setError('permission_key is required')
      return
    }
    setLoading('grant')
    try {
      const body: any = {
        permission_key: permissionKey.trim(),
        scope_type: scopeType || 'tenant'
      }
      if (resourceType) body.resource_type = resourceType
      if (resourceId) body.resource_id = resourceId
      const res = await getClient().rbacUpsertRolePermission(roleId, body)
      if (res.meta.status >= 200 && res.meta.status < 400) {
        setMessage('Permission granted')
      } else {
        setError('Failed to grant permission')
      }
    } catch (e: any) {
      setError(e?.message || String(e))
    } finally {
      setLoading(null)
    }
  }

  async function revoke() {
    setError(null)
    setMessage(null)
    if (!roleId) {
      setError('role_id is required')
      return
    }
    if (!permissionKey.trim()) {
      setError('permission_key is required')
      return
    }
    setLoading('revoke')
    try {
      const body: any = {
        permission_key: permissionKey.trim(),
        scope_type: scopeType || 'tenant'
      }
      if (resourceType) body.resource_type = resourceType
      if (resourceId) body.resource_id = resourceId
      const res = await getClient().rbacDeleteRolePermission(roleId, body)
      if (res.meta.status >= 200 && res.meta.status < 400) {
        setMessage('Permission revoked')
      } else {
        setError('Failed to revoke permission')
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
        <h3 className="text-sm font-medium">Role Permissions</h3>
        <Button
          data-testid="rbac-perms-load-roles"
          variant="secondary"
          onClick={loadRoles}
          disabled={loading !== null}
        >
          Load Roles
        </Button>
      </div>
      {error && (
        <div
          className="rounded-md border border-red-200 bg-red-50 p-2 text-sm text-red-700"
          data-testid="rbac-perms-error"
        >
          {error}
        </div>
      )}
      {message && (
        <div
          className="rounded-md border border-green-200 bg-green-50 p-2 text-sm text-green-800"
          data-testid="rbac-perms-message"
        >
          {message}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-5 gap-2 items-end">
        <select
          data-testid="rbac-perms-role-select"
          className="w-full rounded-md border px-3 py-2 text-sm"
          value={roleId}
          onChange={(e) => setRoleId(e.target.value)}
        >
          <option value="">Select role</option>
          {roles.map((r) => (
            <option key={r.id} value={r.id}>
              {r.name}
            </option>
          ))}
        </select>
        <input
          data-testid="rbac-perms-key"
          className="w-full rounded-md border px-3 py-2 text-sm"
          placeholder="permission_key"
          value={permissionKey}
          onChange={(e) => setPermissionKey(e.target.value)}
        />
        <input
          data-testid="rbac-perms-scope"
          className="w-full rounded-md border px-3 py-2 text-sm"
          placeholder="scope_type (e.g. tenant)"
          value={scopeType}
          onChange={(e) => setScopeType(e.target.value)}
        />
        <input
          data-testid="rbac-perms-rtype"
          className="w-full rounded-md border px-3 py-2 text-sm"
          placeholder="resource_type (optional)"
          value={resourceType}
          onChange={(e) => setResourceType(e.target.value)}
        />
        <input
          data-testid="rbac-perms-rid"
          className="w-full rounded-md border px-3 py-2 text-sm"
          placeholder="resource_id (optional)"
          value={resourceId}
          onChange={(e) => setResourceId(e.target.value)}
        />
      </div>
      <div className="flex gap-2">
        <Button
          data-testid="rbac-perms-grant"
          onClick={grant}
          disabled={loading !== null}
        >
          Grant
        </Button>
        <Button
          data-testid="rbac-perms-revoke"
          variant="destructive"
          onClick={revoke}
          disabled={loading !== null}
        >
          Revoke
        </Button>
      </div>
    </div>
  )
}
