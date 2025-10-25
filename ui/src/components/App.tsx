import { useEffect, useState } from 'react'
import Login from '@/components/auth/Login'
import { Button } from '@/components/ui/button'
import {
  clearRuntimeConfig,
  ensureRuntimeConfigFromQuery,
  getRuntimeConfig,
  setRuntimeConfig
} from '@/lib/runtime'

function App() {
  const [baseUrl, setBaseUrl] = useState('')
  const [configured, setConfigured] = useState(false)
  const [saving, setSaving] = useState(false)
  const [authMode, setAuthMode] = useState<'bearer' | 'cookie'>('bearer')

  useEffect(() => {
    // Attempt to persist config from query params (redirect flow)
    ensureRuntimeConfigFromQuery()
    const cfg = getRuntimeConfig()
    if (cfg) {
      setBaseUrl(cfg.guard_base_url)
      setAuthMode(cfg.auth_mode || 'bearer')
      setConfigured(true)
    }
  }, [])

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
  }

  if (!configured) {
    return (
      <div className="flex min-h-svh flex-col items-center justify-center p-6">
        <div className="w-full max-w-md space-y-4 rounded-xl border p-6">
          <h1 className="text-xl font-semibold">Configure Guard</h1>
          <p className="text-sm text-muted-foreground">
            Enter your Guard API Base URL to continue.
          </p>
          <form onSubmit={onSave} className="space-y-3">
            <label className="block text-sm font-medium">API Base URL</label>
            <input
              data-testid="base-url-input"
              type="url"
              required
              placeholder="http://localhost:8081"
              className="w-full rounded-md border px-3 py-2 text-sm"
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
            />
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
        <Login />
      </div>
    </div>
  )
}

export default App
