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
import TenantSettingsPanel from './tenants/TenantSettingsPanel'
import SsoProvidersPanel from './sso/SsoProvidersPanel'

export default function AdminSettings() {
  const { user } = useAuth()
  const { tenantId, setTenantId } = useTenant()
  const [activeTab, setActiveTab] = useState<
    'settings' | 'users' | 'account' | 'fga' | 'rbac' | 'tenants' | 'sso'
  >('settings')
  const [fgaGroupId, setFgaGroupId] = useState('')

  useEffect(() => {
    ensureRuntimeConfigFromQuery()
  }, [])

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
        const allowed = ['settings', 'users', 'account', 'fga', 'rbac', 'tenants', 'sso']
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
        const allowed = ['settings', 'users', 'account', 'fga', 'rbac', 'tenants', 'sso']
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
          </div>
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
            {isAdmin && (
              <Button
                variant={activeTab === 'sso' ? 'default' : 'secondary'}
                size="sm"
                onClick={() => setActiveTab('sso')}
                data-testid="tab-sso"
              >
                SSO Providers
              </Button>
            )}
          </div>
        </div>

        {activeTab === 'settings' && (
          <div className="rounded-xl border p-4">
            {!tenantId ? (
              <div className="text-sm text-muted-foreground">
                Enter a tenant ID above to manage settings.
              </div>
            ) : (
              <TenantSettingsPanel tenantId={tenantId} tenantName="Current Tenant" hideSsoTab />
            )}
          </div>
        )}

        {activeTab === 'users' && (
          <div className="rounded-xl border p-4 space-y-3">
            <h2 className="text-base font-medium">Users Management</h2>
            <div className="text-sm text-muted-foreground">
              List users for this tenant, update names, and block/unblock accounts.
            </div>
            {!tenantId ? (
              <div className="text-sm text-muted-foreground">
                Enter a tenant ID above to manage users.
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
                  Enter a tenant ID above to manage groups and ACL.
                </div>
              ) : (
                <>
                  <GroupsPanel tenantId={tenantId} />
                  <div className="space-y-2">
                    <h3 className="text-sm font-medium">Manage Group Members</h3>
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

        {activeTab === 'sso' && (
          <div className="rounded-xl border p-4 space-y-3">
            <h2 className="text-base font-medium">SSO Provider Management</h2>
            {!tenantId ? (
              <div className="text-sm text-muted-foreground">
                Enter a tenant ID above and click Load to manage SSO providers.
              </div>
            ) : (
              <SsoProvidersPanel tenantId={tenantId} />
            )}
          </div>
        )}
      </div>
    </div>
  )
}
