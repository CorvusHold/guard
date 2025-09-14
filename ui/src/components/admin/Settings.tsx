import { useEffect, useMemo, useState } from 'react'
import { Button } from '@/components/ui/button'
import { useAuth } from '@/lib/auth'
import { ensureRuntimeConfigFromQuery, getRuntimeConfig } from '@/lib/runtime'
import { getClient } from '@/lib/sdk'
import { useTenant } from '@/lib/tenant'
import ACLPanel from './fga/ACLPanel'
import GroupMembersPanel from './fga/GroupMembersPanel'
import GroupsPanel from './fga/GroupsPanel'
import PermissionsViewer from './rbac/PermissionsViewer'
import RolePermissionsPanel from './rbac/RolePermissionsPanel'
import RolesPanel from './rbac/RolesPanel'
import UserRolesPanel from './rbac/UserRolesPanel'
import MyMfaPanel from './users/MyMfaPanel'
import MySessionsPanel from './users/MySessionsPanel'
import UsersPanel from './users/UsersPanel'
import TenantManagementPanel from './tenants/TenantManagementPanel'

interface SettingsForm {
  sso_provider: string
  workos_client_id: string
  workos_client_secret?: string
  workos_api_key?: string
  workos_default_connection_id?: string
  workos_default_organization_id?: string
  sso_state_ttl: string
  sso_redirect_allowlist: string
}

const INTENTS = [
  'sso',
  'dsync',
  'audit_logs',
  'log_streams',
  'domain_verification',
  'certificate_renewal',
  // UI-friendly alias the server maps to sso
  'user_management'
]

export default function AdminSettings() {
  const { user } = useAuth()
  const { tenantId, setTenantId } = useTenant()
  const [activeTab, setActiveTab] = useState<
    'settings' | 'users' | 'account' | 'fga' | 'rbac' | 'tenants'
  >('settings')
  const [fgaGroupId, setFgaGroupId] = useState('')
  const [loading, setLoading] = useState<'load' | 'save' | 'portal' | null>(
    null
  )
  const [error, setError] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)
  const [form, setForm] = useState<SettingsForm | null>(null)
  const [portalOrg, setPortalOrg] = useState('')
  const [portalIntent, setPortalIntent] = useState<string>('sso')
  const [portalLink, setPortalLink] = useState<string | null>(null)

  useEffect(() => {
    ensureRuntimeConfigFromQuery()
  }, [])

  const canSave = useMemo(() => !!tenantId && !!form, [tenantId, form])
  const isAdmin = useMemo(
    () =>
      Array.isArray((user as any)?.roles) &&
      (user as any).roles.includes('admin'),
    [user]
  )

  // --- Tab hash persistence (#tab=<name>) ---
  useEffect(() => {
    const applyFromHash = () => {
      try {
        const hash = window.location.hash || ''
        const m = hash.match(/tab=([a-z]+)/i)
        const val = (m?.[1] || '').toLowerCase()
        const allowed = ['settings', 'users', 'account', 'fga', 'rbac', 'tenants']
        if (allowed.includes(val)) {
          setActiveTab(val as typeof activeTab)
        }
      } catch {}
    }
    // If no hash-provided tab, allow ?source=<tab> to set initial tab
    try {
      if (!window.location.hash || !window.location.hash.includes('tab=')) {
        const params = new URLSearchParams(window.location.search)
        const src = (params.get('source') || '').toLowerCase()
        const allowed = ['settings', 'users', 'account', 'fga', 'rbac', 'tenants']
        if (allowed.includes(src)) {
          setActiveTab(src as typeof activeTab)
        }
      }
    } catch {}
    applyFromHash()
    window.addEventListener('hashchange', applyFromHash)
    return () => window.removeEventListener('hashchange', applyFromHash)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    try {
      const cur = `#tab=${activeTab}`
      const hasTabHash =
        typeof window !== 'undefined' && window.location.hash.includes('tab=')
      if (hasTabHash && window.location.hash !== cur) {
        window.location.hash = cur
      }
    } catch {}
  }, [activeTab])

  async function loadSettings() {
    setError(null)
    setMessage(null)
    setPortalLink(null)
    if (!tenantId) {
      setError('tenant_id is required')
      return
    }
    setLoading('load')
    try {
      const client = getClient()
      const res = await client.getTenantSettings(tenantId)
      if (res.meta.status >= 200 && res.meta.status < 300) {
        const s = res.data as any
        setForm({
          sso_provider: s.sso_provider || '',
          workos_client_id: s.workos_client_id || '',
          workos_client_secret: s.workos_client_secret || '',
          workos_api_key: s.workos_api_key || '',
          workos_default_connection_id: s.workos_default_connection_id || '',
          workos_default_organization_id:
            s.workos_default_organization_id || '',
          sso_state_ttl: s.sso_state_ttl || '',
          sso_redirect_allowlist: s.sso_redirect_allowlist || ''
        })
      } else {
        setError('Failed to load settings')
      }
    } catch (e: any) {
      setError(e?.message || String(e))
    } finally {
      setLoading(null)
    }
  }

  async function saveSettings() {
    if (!canSave) return
    setError(null)
    setMessage(null)
    setLoading('save')
    try {
      const client = getClient()
      const body: any = { ...form }
      const res = await client.updateTenantSettings(tenantId, body)
      if (res.meta.status >= 200 && res.meta.status < 300) {
        setMessage('Settings saved')
      } else {
        setError('Failed to save settings')
      }
    } catch (e: any) {
      setError(e?.message || String(e))
    } finally {
      setLoading(null)
    }
  }

  async function generatePortalLink() {
    setPortalLink(null)
    setMessage(null)
    setError(null)
    if (!tenantId) {
      setError('tenant_id is required')
      return
    }
    if (!portalOrg) {
      setError('organization_id is required')
      return
    }
    setLoading('portal')
    try {
      const client = getClient()
      const res = await client.getSsoOrganizationPortalLink('workos' as any, {
        tenant_id: tenantId,
        organization_id: portalOrg,
        intent: portalIntent
      })
      if (res.meta.status >= 200 && res.meta.status < 300 && res.data?.link) {
        setPortalLink(res.data.link)
      } else {
        setError('Failed to generate portal link')
      }
    } catch (e: any) {
      setError(e?.message || String(e))
    } finally {
      setLoading(null)
    }
  }

  return (
    <div className="flex min-h-svh flex-col items-center justify-start p-6">
      <div className="w-full max-w-3xl space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-xl font-semibold">Admin Settings</h1>
          <Button
            variant="secondary"
            data-testid="admin-logout"
            onClick={async () => {
              try {
                const c = getClient()
                await c.logout()
              } catch (_) {}
              // Proactively clear local bearer tokens if present
              try {
                const cfg = getRuntimeConfig()
                if (cfg?.auth_mode === 'bearer') {
                  localStorage.removeItem('guard_ui:guard_access_token')
                  localStorage.removeItem('guard_ui:guard_refresh_token')
                }
              } catch (_) {}
              window.location.href = '/'
            }}
          >
            Logout
          </Button>
        </div>

        <div className="rounded-xl border p-4 space-y-3">
          <div className="flex flex-wrap items-end gap-3">
            <div className="flex-1 min-w-60">
              <label className="block text-sm font-medium">Tenant ID</label>
              <input
                data-testid="admin-tenant-input"
                className="w-full rounded-md border px-3 py-2 text-sm"
                placeholder="tenant_uuid"
                value={tenantId}
                onChange={(e) => setTenantId(e.target.value)}
              />
            </div>
            <Button
              data-testid="admin-load-settings"
              onClick={loadSettings}
              disabled={loading !== null}
            >
              Load
            </Button>
          </div>
          {error && (
            <div
              className="rounded-md border border-red-200 bg-red-50 p-2 text-sm text-red-700"
              data-testid="admin-error"
            >
              {error}
            </div>
          )}
          {message && (
            <div
              className="rounded-md border border-green-200 bg-green-50 p-2 text-sm text-green-800"
              data-testid="admin-message"
            >
              {message}
            </div>
          )}
        </div>

        {/* Tabs */}
        <div className="rounded-xl border p-2">
          <div className="flex flex-wrap gap-2 p-1">
            <Button
              variant={activeTab === 'settings' ? 'default' : 'secondary'}
              size="sm"
              onClick={() => setActiveTab('settings')}
              data-testid="tab-settings"
            >
              Settings
            </Button>
            {isAdmin && (
              <Button
                variant={activeTab === 'users' ? 'default' : 'secondary'}
                size="sm"
                onClick={() => setActiveTab('users')}
                data-testid="tab-users"
              >
                Users
              </Button>
            )}
            <Button
              variant={activeTab === 'account' ? 'default' : 'secondary'}
              size="sm"
              onClick={() => setActiveTab('account')}
              data-testid="tab-account"
            >
              My Account
            </Button>
            {isAdmin && (
              <Button
                variant={activeTab === 'fga' ? 'default' : 'secondary'}
                size="sm"
                onClick={() => setActiveTab('fga')}
                data-testid="tab-fga"
              >
                FGA
              </Button>
            )}
            {isAdmin && (
              <Button
                variant={activeTab === 'rbac' ? 'default' : 'secondary'}
                size="sm"
                onClick={() => setActiveTab('rbac')}
                data-testid="tab-rbac"
              >
                RBAC
              </Button>
            )}
            {isAdmin && (
              <Button
                variant={activeTab === 'tenants' ? 'default' : 'secondary'}
                size="sm"
                onClick={() => setActiveTab('tenants')}
                data-testid="tab-tenants"
              >
                Tenants
              </Button>
            )}
          </div>
        </div>

        {activeTab === 'settings' && (
          <div className="rounded-xl border p-4 space-y-3">
            <h2 className="text-base font-medium">Tenant SSO Settings</h2>
            {!form ? (
              <div className="text-sm text-muted-foreground">
                Load settings to view and edit.
              </div>
            ) : (
              <div className="space-y-3">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-sm font-medium">
                      SSO Provider
                    </label>
                    <select
                      className="w-full rounded-md border px-3 py-2 text-sm"
                      value={form.sso_provider}
                      onChange={(e) =>
                        setForm({
                          ...(form as SettingsForm),
                          sso_provider: e.target.value
                        })
                      }
                    >
                      <option value="">(none)</option>
                      <option value="dev">dev</option>
                      <option value="workos">workos</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-medium">
                      WorkOS Client ID
                    </label>
                    <input
                      data-testid="admin-workos-client-id"
                      className="w-full rounded-md border px-3 py-2 text-sm"
                      value={form.workos_client_id}
                      onChange={(e) =>
                        setForm({
                          ...(form as SettingsForm),
                          workos_client_id: e.target.value
                        })
                      }
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium">
                      WorkOS Client Secret
                    </label>
                    <input
                      className="w-full rounded-md border px-3 py-2 text-sm"
                      type="password"
                      value={form.workos_client_secret || ''}
                      onChange={(e) =>
                        setForm({
                          ...(form as SettingsForm),
                          workos_client_secret: e.target.value
                        })
                      }
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium">
                      WorkOS API Key
                    </label>
                    <input
                      className="w-full rounded-md border px-3 py-2 text-sm"
                      type="password"
                      value={form.workos_api_key || ''}
                      onChange={(e) =>
                        setForm({
                          ...(form as SettingsForm),
                          workos_api_key: e.target.value
                        })
                      }
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium">
                      Default Connection ID
                    </label>
                    <input
                      data-testid="admin-workos-conn-id"
                      className="w-full rounded-md border px-3 py-2 text-sm"
                      value={form.workos_default_connection_id || ''}
                      onChange={(e) =>
                        setForm({
                          ...(form as SettingsForm),
                          workos_default_connection_id: e.target.value
                        })
                      }
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium">
                      Default Organization ID
                    </label>
                    <input
                      data-testid="admin-workos-org-id"
                      className="w-full rounded-md border px-3 py-2 text-sm"
                      value={form.workos_default_organization_id || ''}
                      onChange={(e) =>
                        setForm({
                          ...(form as SettingsForm),
                          workos_default_organization_id: e.target.value
                        })
                      }
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium">
                      State TTL (e.g. 10m)
                    </label>
                    <input
                      data-testid="admin-sso-state-ttl"
                      className="w-full rounded-md border px-3 py-2 text-sm"
                      value={form.sso_state_ttl}
                      onChange={(e) =>
                        setForm({
                          ...(form as SettingsForm),
                          sso_state_ttl: e.target.value
                        })
                      }
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium">
                      Redirect Allowlist (comma-separated)
                    </label>
                    <input
                      data-testid="admin-sso-redirect-allowlist"
                      className="w-full rounded-md border px-3 py-2 text-sm"
                      value={form.sso_redirect_allowlist}
                      onChange={(e) =>
                        setForm({
                          ...(form as SettingsForm),
                          sso_redirect_allowlist: e.target.value
                        })
                      }
                    />
                  </div>
                </div>
                <div className="flex gap-2">
                  <Button
                    data-testid="admin-save-settings"
                    disabled={!canSave || loading !== null}
                    onClick={saveSettings}
                  >
                    {loading === 'save' ? 'Saving...' : 'Save Settings'}
                  </Button>
                </div>
              </div>
            )}

            {/* WorkOS Admin Portal (within settings tab) */}
            <div className="rounded-xl border p-4 space-y-3 mt-4">
              <h2 className="text-base font-medium">WorkOS Admin Portal</h2>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <div>
                  <label className="block text-sm font-medium">
                    Organization ID
                  </label>
                  <input
                    data-testid="admin-portal-org-input"
                    className="w-full rounded-md border px-3 py-2 text-sm"
                    placeholder="org_123"
                    value={portalOrg}
                    onChange={(e) => setPortalOrg(e.target.value)}
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium">Intent</label>
                  <select
                    data-testid="admin-portal-intent-select"
                    className="w-full rounded-md border px-3 py-2 text-sm"
                    value={portalIntent}
                    onChange={(e) => setPortalIntent(e.target.value)}
                  >
                    {INTENTS.map((it) => (
                      <option key={it} value={it}>
                        {it}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="flex items-end">
                  <Button
                    data-testid="admin-generate-portal-link"
                    disabled={loading !== null}
                    onClick={generatePortalLink}
                  >
                    {loading === 'portal' ? 'Generating...' : 'Generate Link'}
                  </Button>
                </div>
              </div>
              {portalLink && (
                <div className="rounded-md border p-3 text-sm">
                  <div className="font-medium">Portal Link</div>
                  <div
                    className="break-all"
                    data-testid="admin-portal-link-output"
                  >
                    {portalLink}
                  </div>
                  <div className="pt-2">
                    <Button
                      variant="secondary"
                      onClick={() =>
                        window.open(portalLink, '_blank', 'noopener,noreferrer')
                      }
                    >
                      Open
                    </Button>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'users' && (
          <div className="rounded-xl border p-4 space-y-3">
            <h2 className="text-base font-medium">Users Management</h2>
            <div className="text-sm text-muted-foreground">
              List users for this tenant, update names, and block/unblock
              accounts.
            </div>
            {!tenantId ? (
              <div className="text-sm text-muted-foreground">
                Enter a tenant ID above and click Load to manage users.
              </div>
            ) : (
              <UsersPanel tenantId={tenantId} />
            )}
          </div>
        )}

        {activeTab === 'account' && (
          <>
            <div className="rounded-xl border p-4 space-y-3">
              <h2 className="text-base font-medium">My Sessions</h2>
              <div className="text-sm text-muted-foreground">
                View and revoke your active sessions for the current tenant.
              </div>
              <MySessionsPanel />
            </div>
            <div className="rounded-xl border p-4 space-y-3">
              <h2 className="text-base font-medium">My MFA</h2>
              <div className="text-sm text-muted-foreground">
                Enroll and manage TOTP and backup codes.
              </div>
              <MyMfaPanel />
            </div>
          </>
        )}

        {activeTab === 'fga' && (
          <div className="rounded-xl border p-4 space-y-4">
            <h2 className="text-base font-medium">FGA (Groups & ACL)</h2>
            <div className="space-y-6">
              {!tenantId ? (
                <div className="text-sm text-muted-foreground">
                  Enter a tenant ID above and click Load to manage groups and
                  ACL.
                </div>
              ) : (
                <>
                  <GroupsPanel tenantId={tenantId} />
                  <div className="space-y-2">
                    <h3 className="text-sm font-medium">
                      Manage Group Members
                    </h3>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                      <input
                        data-testid="fga-members-group-id"
                        className="w-full rounded-md border px-3 py-2 text-sm"
                        placeholder="Group ID"
                        value={fgaGroupId}
                        onChange={(e) => setFgaGroupId(e.target.value)}
                      />
                    </div>
                    {fgaGroupId ? (
                      <GroupMembersPanel groupId={fgaGroupId} />
                    ) : (
                      <div className="text-sm text-muted-foreground">
                        Enter a Group ID to add/remove members.
                      </div>
                    )}
                  </div>
                  <ACLPanel tenantId={tenantId} />
                </>
              )}
            </div>
          </div>
        )}

        {activeTab === 'rbac' && (
          <div className="rounded-xl border p-4 space-y-4">
            <h2 className="text-base font-medium">RBAC</h2>
            <div className="text-sm text-muted-foreground">
              Manage roles and permissions for the tenant.
            </div>
            <div className="space-y-6">
              <PermissionsViewer />
              <RolesPanel tenantId={tenantId} />
              <RolePermissionsPanel tenantId={tenantId} />
              <UserRolesPanel tenantId={tenantId} />
            </div>
          </div>
        )}

        {activeTab === 'tenants' && (
          <div className="rounded-xl border p-4">
            <TenantManagementPanel />
          </div>
        )}
      </div>
    </div>
  )
}
