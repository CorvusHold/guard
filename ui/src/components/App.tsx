import { useEffect, useState, useCallback } from 'react'
import UniversalLogin from '@/components/auth/UniversalLogin'
import AdminSettings from '@/components/admin/Settings'
import { Button } from '@/components/ui/button'
import {
  clearRuntimeConfig,
  ensureRuntimeConfigFromQuery,
  getRuntimeConfig,
  setRuntimeConfig
} from '@/lib/runtime'
import { GuardClient } from '../../../sdk/ts/src/client'
import { useTokenRefresh } from '@/lib/useTokenRefresh'
import { getClient } from '@/lib/sdk'
import { AuthProvider } from '@/lib/auth'
import { TenantProvider } from '@/lib/tenant'

interface UserProfile {
  id: string
  email: string
  first_name?: string
  last_name?: string
  roles?: string[]
}

function App() {
  const [baseUrl, setBaseUrl] = useState('')
  const [configured, setConfigured] = useState(false)
  const [saving, setSaving] = useState(false)
  const [authMode, setAuthMode] = useState<'bearer' | 'cookie'>('bearer')
  const [discovering, setDiscovering] = useState(false)
  const [discoveredMode, setDiscoveredMode] = useState<string | null>(null)
  const [discoveryError, setDiscoveryError] = useState<string | null>(null)
  const [user, setUser] = useState<UserProfile | null>(null)
  const [checkingAuth, setCheckingAuth] = useState(true)

  // Auto-refresh tokens in bearer mode (every 14 minutes, before 15min expiry)
  useTokenRefresh(14)

  // Check if user is already authenticated
  const checkAuth = useCallback(async () => {
    try {
      const client = getClient()
      const res = await client.me()
      if (res.meta.status === 200 && res.data) {
        setUser(res.data as UserProfile)
      }
    } catch {
      // Not authenticated, that's fine
      setUser(null)
    } finally {
      setCheckingAuth(false)
    }
  }, [])

  useEffect(() => {
    // Attempt to persist config from query params (redirect flow)
    ensureRuntimeConfigFromQuery()
    const cfg = getRuntimeConfig()
    if (cfg) {
      setBaseUrl(cfg.guard_base_url)
      setAuthMode(cfg.auth_mode || 'bearer')
      setConfigured(true)
      // Check if already authenticated
      checkAuth()
    } else {
      setCheckingAuth(false)
    }
  }, [checkAuth])

  async function discoverAuthMode() {
    if (!baseUrl.trim()) return

    setDiscovering(true)
    setDiscoveryError(null)
    setDiscoveredMode(null)

    try {
      const metadata = await GuardClient.discover(baseUrl.trim())
      const recommended = metadata.guard_auth_mode_default
      setDiscoveredMode(recommended || 'bearer')

      // Auto-apply the discovered mode
      if (recommended) {
        setAuthMode(recommended as 'bearer' | 'cookie')
      }
    } catch (error: any) {
      setDiscoveryError(error?.message || 'Failed to discover server configuration')
      console.error('Discovery error:', error)
    } finally {
      setDiscovering(false)
    }
  }

  function handleBaseUrlChange(url: string) {
    setBaseUrl(url)
    // Reset discovery state when URL changes
    setDiscoveredMode(null)
    setDiscoveryError(null)
  }

  function onSave(e: React.FormEvent) {
    e.preventDefault()
    if (!baseUrl.trim()) return
    setSaving(true)
    setRuntimeConfig({
      guard_base_url: baseUrl.trim(),
      source: 'direct',
      auth_mode: authMode
    })
    setConfigured(true)
    setSaving(false)
  }

  function onReset() {
    clearRuntimeConfig()
    setConfigured(false)
    setBaseUrl('')
    setUser(null)
  }

  const handleLoginSuccess = useCallback((userData: unknown) => {
    setUser(userData as UserProfile)
  }, [])

  const handleLogout = useCallback(async () => {
    try {
      const client = getClient()
      await client.logout()
    } catch {
      // Ignore logout errors
    }
    setUser(null)
  }, [])

  if (!configured) {
    return (
      <div className="flex min-h-svh flex-col items-center justify-center p-6">
        <div className="w-full max-w-md space-y-4 rounded-xl border p-6">
          <h1 className="text-xl font-semibold">Configure Guard</h1>
          <p className="text-sm text-muted-foreground">
            Enter your Guard API Base URL to continue.
          </p>
          <form onSubmit={onSave} className="space-y-3">
            <div>
              <label className="block text-sm font-medium">API Base URL</label>
              <input
                data-testid="base-url-input"
                type="url"
                required
                placeholder="http://localhost:8080"
                className="w-full rounded-md border px-3 py-2 text-sm"
                value={baseUrl}
                onChange={(e) => handleBaseUrlChange(e.target.value)}
              />
              {baseUrl.trim() && (
                <Button
                  data-testid="discover-button"
                  type="button"
                  variant="outline"
                  size="sm"
                  className="mt-2"
                  onClick={discoverAuthMode}
                  disabled={discovering || !baseUrl.trim()}
                >
                  {discovering ? 'Discovering...' : 'Auto-discover settings'}
                </Button>
              )}
              {discoveredMode && (
                <div
                  data-testid="discovered-mode"
                  className="mt-2 rounded-md bg-blue-50 border border-blue-200 p-2 text-sm text-blue-700"
                >
                  ✓ Server recommends: <strong>{discoveredMode}</strong> mode
                </div>
              )}
              {discoveryError && (
                <div
                  data-testid="discovery-error"
                  className="mt-2 rounded-md bg-yellow-50 border border-yellow-200 p-2 text-sm text-yellow-700"
                >
                  ⚠ {discoveryError}
                </div>
              )}
            </div>
            <div>
              <label className="block text-sm font-medium">Auth Mode</label>
              <select
                data-testid="auth-mode-select"
                className="w-full rounded-md border px-3 py-2 text-sm"
                value={authMode}
                onChange={(e) =>
                  setAuthMode(
                    (e.target.value as 'bearer' | 'cookie') || 'bearer'
                  )
                }
              >
                <option value="bearer">Bearer tokens (localStorage)</option>
                <option value="cookie">HTTP-only cookies</option>
              </select>
            </div>
            <Button
              data-testid="save-config"
              type="submit"
              disabled={saving || !baseUrl.trim()}
            >
              {saving ? 'Saving...' : 'Save'}
            </Button>
          </form>
        </div>
      </div>
    )
  }

  // Show loading while checking auth
  if (checkingAuth) {
    return (
      <div className="flex min-h-svh flex-col items-center justify-center p-6">
        <div className="text-muted-foreground">Loading...</div>
      </div>
    )
  }

  // Show logged-in state with admin panel
  if (user) {
    return (
      <AuthProvider>
        <TenantProvider>
          <div className="min-h-svh">
            {/* Header bar */}
            <div className="border-b bg-background">
              <div className="container mx-auto px-4 py-3 flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <h1 className="text-lg font-semibold">Guard Admin</h1>
                  <div className="text-sm text-muted-foreground">
                    <span data-testid="user-email">{user.email}</span>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <code className="text-xs rounded bg-secondary px-2 py-1">{baseUrl}</code>
                  <Button
                    data-testid="logout-button"
                    variant="outline"
                    size="sm"
                    onClick={handleLogout}
                  >
                    Logout
                  </Button>
                </div>
              </div>
            </div>
            {/* Admin panel */}
            <AdminSettings />
          </div>
        </TenantProvider>
      </AuthProvider>
    )
  }

  return (
    <div className="flex min-h-svh flex-col items-center justify-center p-6">
      <div className="w-full max-w-lg space-y-4 rounded-xl border p-6">
        <h1 className="text-xl font-semibold">Guard Admin</h1>
        <div className="text-sm text-muted-foreground">
          <span>Configured Base URL:&nbsp;</span>
          <code
            data-testid="configured-base-url"
            className="rounded bg-secondary px-1 py-0.5"
          >
            {baseUrl}
          </code>
        </div>
        <div className="text-sm text-muted-foreground">
          <span>Auth Mode:&nbsp;</span>
          <code
            data-testid="configured-auth-mode"
            className="rounded bg-secondary px-1 py-0.5"
          >
            {authMode}
          </code>
        </div>
        <div className="flex gap-2">
          <Button
            data-testid="reset-config"
            variant="secondary"
            onClick={onReset}
          >
            Reset config
          </Button>
        </div>
      </div>
      <div className="mt-4">
        <UniversalLogin onLoginSuccess={handleLoginSuccess} />
      </div>
    </div>
  )
}

export default App
