import { useState, useEffect } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Loader2, Save, RefreshCw, Shield } from 'lucide-react'
import { getClient } from '@/lib/sdk'
import { useToast } from '@/lib/toast'

interface RateLimitRow {
  label: string
  limitKey: string
  windowKey: string
  defaultLimit: string
  defaultWindow: string
}

const RATE_LIMIT_ROWS: RateLimitRow[] = [
  { label: 'Login', limitKey: 'rl_login_limit', windowKey: 'rl_login_window', defaultLimit: '10', defaultWindow: '1m' },
  { label: 'Signup', limitKey: 'rl_signup_limit', windowKey: 'rl_signup_window', defaultLimit: '5', defaultWindow: '1m' },
  { label: 'Magic Link', limitKey: 'rl_magic_limit', windowKey: 'rl_magic_window', defaultLimit: '5', defaultWindow: '1m' },
  { label: 'SSO', limitKey: 'rl_sso_limit', windowKey: 'rl_sso_window', defaultLimit: '10', defaultWindow: '1m' },
  { label: 'OAuth Token', limitKey: 'rl_token_limit', windowKey: 'rl_token_window', defaultLimit: '20', defaultWindow: '1m' },
  { label: 'MFA Verify', limitKey: 'rl_mfa_limit', windowKey: 'rl_mfa_window', defaultLimit: '5', defaultWindow: '1m' },
]

interface RateLimitsPanelProps {
  tenantId: string
}

export default function RateLimitsPanel({ tenantId }: RateLimitsPanelProps) {
  const { show: showToast } = useToast()
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [values, setValues] = useState<Record<string, string>>({})
  const [original, setOriginal] = useState<Record<string, string>>({})

  useEffect(() => {
    loadSettings()
  }, [tenantId])

  const loadSettings = async () => {
    setLoading(true)
    setError(null)
    try {
      const client = getClient()
      const res = await client.getTenantSettings(tenantId)
      if (!(res.meta.status >= 200 && res.meta.status < 300)) {
        throw new Error('Failed to load settings')
      }
      const data: Record<string, string> = (res.data as any) ?? {}
      const rlValues: Record<string, string> = {}
      for (const row of RATE_LIMIT_ROWS) {
        rlValues[row.limitKey] = data[row.limitKey] || ''
        rlValues[row.windowKey] = data[row.windowKey] || ''
      }
      setValues(rlValues)
      setOriginal(rlValues)
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to load settings'
      setError(message)
    } finally {
      setLoading(false)
    }
  }

  const saveSettings = async () => {
    setSaving(true)
    setError(null)
    try {
      const client = getClient()
      const changed: Record<string, string> = {}
      for (const key of Object.keys(values)) {
        if (values[key] !== original[key]) {
          changed[key] = values[key]
        }
      }
      if (Object.keys(changed).length === 0) {
        showToast({ description: 'No changes to save', variant: 'info' })
        setSaving(false)
        return
      }
      const res = await client.updateTenantSettings(tenantId, changed as any)
      if (!(res.meta.status >= 200 && res.meta.status < 300)) {
        throw new Error('Failed to save settings')
      }
      setOriginal({ ...values })
      showToast({ description: 'Rate limits saved', variant: 'success' })
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to save settings'
      setError(message)
      showToast({ description: message, variant: 'error' })
    } finally {
      setSaving(false)
    }
  }

  const hasChanges = JSON.stringify(values) !== JSON.stringify(original)

  if (loading) {
    return (
      <div className="flex items-center justify-center py-8" data-testid="ratelimits-loading">
        <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
        <span className="ml-2 text-sm text-muted-foreground">Loading rate limits...</span>
      </div>
    )
  }

  return (
    <div className="space-y-4" data-testid="ratelimits-panel">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Shield className="h-5 w-5 text-muted-foreground" />
          <h3 className="text-sm font-medium">Rate Limits</h3>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={loadSettings}
            disabled={loading}
            data-testid="ratelimits-refresh"
          >
            <RefreshCw className="mr-1 h-3 w-3" />
            Refresh
          </Button>
          <Button
            size="sm"
            onClick={saveSettings}
            disabled={saving || !hasChanges}
            data-testid="ratelimits-save"
          >
            {saving ? <Loader2 className="mr-1 h-3 w-3 animate-spin" /> : <Save className="mr-1 h-3 w-3" />}
            Save
          </Button>
        </div>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <p className="text-xs text-muted-foreground">
        Configure per-endpoint rate limits for this tenant. Leave empty to use global defaults.
        Limits are requests per window. Windows use Go duration format (e.g., 1m, 30s, 5m).
      </p>

      <div className="rounded-md border">
        <div className="grid grid-cols-[1fr_120px_120px] gap-2 border-b bg-muted/50 px-3 py-2 text-xs font-medium text-muted-foreground">
          <span>Endpoint</span>
          <span>Limit (req)</span>
          <span>Window</span>
        </div>
        {RATE_LIMIT_ROWS.map((row) => (
          <div
            key={row.limitKey}
            className="grid grid-cols-[1fr_120px_120px] gap-2 border-b last:border-b-0 px-3 py-2 items-center"
            data-testid={`ratelimit-row-${row.label.toLowerCase().replace(/\s+/g, '-')}`}
          >
            <div>
              <Label className="text-sm font-medium">{row.label}</Label>
              <p className="text-xs text-muted-foreground">
                Default: {row.defaultLimit} req / {row.defaultWindow}
              </p>
            </div>
            <Input
              type="text"
              placeholder={row.defaultLimit}
              value={values[row.limitKey] || ''}
              onChange={(e) => setValues((prev) => ({ ...prev, [row.limitKey]: e.target.value }))}
              className="h-8 text-sm"
              data-testid={`ratelimit-${row.limitKey}`}
            />
            <Input
              type="text"
              placeholder={row.defaultWindow}
              value={values[row.windowKey] || ''}
              onChange={(e) => setValues((prev) => ({ ...prev, [row.windowKey]: e.target.value }))}
              className="h-8 text-sm"
              data-testid={`ratelimit-${row.windowKey}`}
            />
          </div>
        ))}
      </div>

      {hasChanges && (
        <div className="flex items-center justify-between rounded-md border border-yellow-200 bg-yellow-50 px-3 py-2 text-sm">
          <span className="text-yellow-700">You have unsaved changes</span>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setValues({ ...original })}
            data-testid="ratelimits-reset"
          >
            Reset
          </Button>
        </div>
      )}
    </div>
  )
}
