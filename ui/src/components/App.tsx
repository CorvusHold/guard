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

function parseBooleanFlag(value: string | null): boolean | null {
  if (value == null) return null
  const normalized = value.trim().toLowerCase()
  if (normalized === '' || normalized === '1' || normalized === 'true' || normalized === 'yes' || normalized === 'on') {
    return true
  }
  if (normalized === '0' || normalized === 'false' || normalized === 'no' || normalized === 'off') {
    return false
  }
  return null
}

function resolveShowSettingsFlag(): boolean {
  try {
    const params = new URLSearchParams(window.location.search)
    const fromQuery =
      parseBooleanFlag(params.get('show-settings')) ??
      parseBooleanFlag(params.get('settings')) ??
      parseBooleanFlag(params.get('guard-settings'))

    if (fromQuery != null) {
      return fromQuery
    }
  } catch {
    // ignore
  }
  return false
}

function isOAuthReturnFlow(): boolean {
  try {
    const params = new URLSearchParams(window.location.search)
    return !!params.get('return_to')
  } catch {
    return false
  }
}

function normalizeBaseUrl(input: string): string {
  const trimmed = input.trim()
  const parsed = new URL(trimmed)
  let path = parsed.pathname.replace(/\/+$/, '')

  if (path === '/api') {
    path = ''
  } else if (path.endsWith('/api')) {
    path = path.slice(0, -4)
  }

  return `${parsed.origin}${path}`
}

function App() {
  const [baseUrl, setBaseUrl] = useState('')
  const [configured, setConfigured] = useState(false)
  const [saving, setSaving] = useState(false)
  const [authMode, setAuthMode] = useState<'bearer' | 'cookie'>('bearer')
  const [showSettingsFlag, setShowSettingsFlag] = useState(false)
  const [showAdvancedSetup, setShowAdvancedSetup] = useState(false)
  const [discovering, setDiscovering] = useState(false)
  const [discoveredMode, setDiscoveredMode] = useState<string | null>(null)
  const [discoveryError, setDiscoveryError] = useState<string | null>(null)
  const [user, setUser] = useState<UserProfile | null>(null)
  const [checkingAuth, setCheckingAuth] = useState(true)

  const isOAuthFlow = isOAuthReturnFlow()

  // Auto-refresh tokens in bearer mode (every 14 minutes, before 15min expiry)
  useTokenRefresh(14)

  const continueOAuthFlowIfPresent = useCallback((): boolean => {
    try {
      const params = new URLSearchParams(window.location.search)
      const returnTo = params.get('return_to')
      if (!returnTo) return false

      const cfg = getRuntimeConfig()
      const guardBaseURL = (cfg?.guard_base_url || '').trim()
      if (!guardBaseURL) return false

      const base = new URL(guardBaseURL)
      const target = new URL(returnTo, base.origin)
      // Defensive guard: only allow redirects to the configured Guard origin.
      if (target.origin != base.origin) return false

      window.location.assign(target.toString())
      return true
    } catch {
      return false
    }
  }, [])

  function openSettings() {
    setConfigured(false)
    setShowAdvancedSetup(true)
  }

  // Check if user is already authenticated
  const checkAuth = useCallback(async () => {
    try {
      const client = getClient()
      const res = await client.me()
      if (res.meta.status === 200 && res.data) {
        if (continueOAuthFlowIfPresent()) {
          return
        }
        setUser(res.data as UserProfile)
      }
    } catch {
      // Not authenticated, that's fine
      setUser(null)
    } finally {
      setCheckingAuth(false)
    }
  }, [continueOAuthFlowIfPresent])

  useEffect(() => {
    setShowSettingsFlag(resolveShowSettingsFlag())
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

  async function discoverAuthMode(urlOverride?: string): Promise<'bearer' | 'cookie' | null> {
    const candidate = (urlOverride || baseUrl).trim()
    if (!candidate) return null

    setDiscovering(true)
    setDiscoveryError(null)
    setDiscoveredMode(null)

    try {
      const metadata = await GuardClient.discover(candidate)
      const recommended = metadata.guard_auth_mode_default
      const mode = recommended === 'cookie' ? 'cookie' : 'bearer'
      setDiscoveredMode(mode)

      // Auto-apply the discovered mode
      if (recommended) {
        setAuthMode(mode)
      }
      return mode
    } catch (error: any) {
      setDiscoveryError(error?.message || 'Failed to discover server configuration')
      console.error('Discovery error:', error)
      return null
    } finally {
      setDiscovering(false)
    }
  }

  async function probeBackendApi(candidateBaseUrl: string): Promise<boolean> {
    const probeUrl = `${candidateBaseUrl.replace(/\/+$/, '')}/api`
    try {
      await fetch(probeUrl, { method: 'GET' })
      return true
    } catch {
      return false
    }
  }

  function handleBaseUrlChange(url: string) {
    setBaseUrl(url)
    // Reset discovery state when URL changes
    setDiscoveredMode(null)
    setDiscoveryError(null)
  }

  async function onSave(e: React.FormEvent) {
    e.preventDefault()
    if (!baseUrl.trim()) return

    setSaving(true)
    setDiscoveryError(null)

    try {
      const normalizedBaseUrl = normalizeBaseUrl(baseUrl)
      let nextAuthMode: 'bearer' | 'cookie' = authMode

      const backendDetected = await probeBackendApi(normalizedBaseUrl)
      if (backendDetected) {
        const discovered = await discoverAuthMode(normalizedBaseUrl)
        if (discovered) {
          nextAuthMode = discovered
        }
      }

      setRuntimeConfig({
        guard_base_url: normalizedBaseUrl,
        source: 'direct',
        auth_mode: nextAuthMode
      })
      setBaseUrl(normalizedBaseUrl)
      setAuthMode(nextAuthMode)
      setConfigured(true)
    } catch (error: any) {
      setDiscoveryError(error?.message || 'Failed to save Guard configuration')
    } finally {
      setSaving(false)
    }
  }

  function onReset() {
    clearRuntimeConfig()
    setConfigured(false)
    setBaseUrl('')
    setUser(null)
    // Also clear auth tokens when resetting config to prevent stale tokens
    try {
      localStorage.removeItem('guard_ui:guard_access_token')
      localStorage.removeItem('guard_ui:guard_refresh_token')
    } catch {
      // Ignore localStorage errors
    }
  }

  const handleLoginSuccess = useCallback((userData: unknown) => {
    if (continueOAuthFlowIfPresent()) {
      return
    }
    setUser(userData as UserProfile)
  }, [continueOAuthFlowIfPresent])

  const handleLogout = useCallback(async () => {
    try {
      const client = getClient()
      await client.logout()
    } catch {
      // Ignore logout errors
    } finally {
      // Always clear tokens regardless of API success/failure
      try {
        localStorage.removeItem('guard_ui:guard_access_token')
        localStorage.removeItem('guard_ui:guard_refresh_token')
      } catch {
        // Ignore localStorage errors
      }
    }
    setUser(null)
  }, [])

  if (!configured) {
    return (
      <div className="flex min-h-svh flex-col items-center justify-center p-6">
        <div className="w-full max-w-md space-y-4 rounded-xl border p-6">
          <h1 className="text-xl font-semibold">Configure Guard</h1>
          <p className="text-sm text-muted-foreground">
            Enter your Guard API Base URL. We will auto-detect your backend and
            apply the recommended auth mode.
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

              <div className="mt-2 flex gap-2">
                <Button
                  data-testid="save-config"
                  type="submit"
                  disabled={saving || !baseUrl.trim()}
                >
                  {saving ? 'Connecting...' : 'Connect'}
                </Button>
                <Button
                  data-testid="setup-settings-toggle"
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="h-8 px-2 text-xs text-muted-foreground"
                  onClick={() => setShowAdvancedSetup((v) => !v)}
                >
                  {showAdvancedSetup ? 'Hide advanced' : 'Advanced'}
                </Button>
              </div>

              {showAdvancedSetup && baseUrl.trim() && (
                <div className="mt-3 rounded-md border p-3">
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
                    data-testid="discover-button"
                    type="button"
                    variant="outline"
                    size="sm"
                    className="mt-2"
                    onClick={() => void discoverAuthMode()}
                    disabled={discovering || !baseUrl.trim()}
                  >
                    {discovering ? 'Discovering...' : 'Auto-discover now'}
                  </Button>
                </div>
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
                  <h1 className="sr-only">Guard Admin</h1>
                  <div className="text-sm text-muted-foreground">
                    <span data-testid="user-email">{user.email}</span>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <code className="text-xs rounded bg-secondary px-2 py-1">{baseUrl}</code>
                  <Button
                    data-testid="open-settings"
                    variant="ghost"
                    size="sm"
                    className="h-8 px-2 text-xs text-muted-foreground"
                    onClick={openSettings}
                  >
                    Settings
                  </Button>
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
      {showSettingsFlag && (
        <div className="w-full max-w-lg space-y-4 rounded-xl border p-6">
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
              data-testid="open-settings"
              variant="ghost"
              className="h-8 px-2 text-xs text-muted-foreground"
              onClick={openSettings}
            >
              Settings
            </Button>
            <Button
              data-testid="reset-config"
              variant="secondary"
              onClick={onReset}
            >
              Reset config
            </Button>
          </div>
        </div>
      )}
      <div className="mt-4">
        <div className="flex items-center justify-between gap-3">
          {!isOAuthFlow && (
            <Button
              data-testid="open-settings"
              variant="ghost"
              size="sm"
              className="h-8 px-2 text-xs text-muted-foreground"
              onClick={openSettings}
            >
              Settings
            </Button>
          )}
          <div className="flex-1" />
        </div>
        <UniversalLogin onLoginSuccess={handleLoginSuccess} />
      </div>
    </div>
  )
}

export default App
