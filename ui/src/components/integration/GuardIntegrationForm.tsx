import { useState, useCallback } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Label } from '@/components/ui/label'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue
} from '@/components/ui/select'

export interface GuardIntegrationConfig {
  enabled: boolean
  baseUrl: string
  tenantId: string
  clientId?: string
  clientSecret?: string
  authMode: 'bearer' | 'cookie'
  redirectUrl: string
  scopes?: string[]
}

export interface GuardIntegrationFormProps {
  initialConfig?: Partial<GuardIntegrationConfig>
  onSave: (config: GuardIntegrationConfig) => Promise<void>
  onTest?: (config: GuardIntegrationConfig) => Promise<{ success: boolean; message?: string }>
  showAdvanced?: boolean
  className?: string
}

function HelpText({ children }: { children: React.ReactNode }) {
  return <p className="text-xs text-muted-foreground mt-1">{children}</p>
}

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch (err) {
      console.error('Failed to copy:', err)
    }
  }, [value])

  return (
    <Button
      type="button"
      variant="outline"
      size="sm"
      className="shrink-0"
      onClick={handleCopy}
      aria-label="Copy to clipboard"
    >
      {copied ? 'Copied!' : 'Copy'}
    </Button>
  )
}

export default function GuardIntegrationForm({
  initialConfig,
  onSave,
  onTest,
  showAdvanced = false,
  className
}: GuardIntegrationFormProps) {
  const [config, setConfig] = useState<GuardIntegrationConfig>({
    enabled: initialConfig?.enabled ?? false,
    baseUrl: initialConfig?.baseUrl ?? '',
    tenantId: initialConfig?.tenantId ?? '',
    clientId: initialConfig?.clientId ?? '',
    clientSecret: initialConfig?.clientSecret ?? '',
    authMode: initialConfig?.authMode ?? 'bearer',
    redirectUrl: initialConfig?.redirectUrl ?? '',
    scopes: initialConfig?.scopes ?? ['openid', 'profile', 'email']
  })

  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState<{ success: boolean; message?: string } | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [showAdvancedOptions, setShowAdvancedOptions] = useState(showAdvanced)
  const [validationErrors, setValidationErrors] = useState<Record<string, string>>({})

  const validateUrl = (url: string, fieldName: string): string | null => {
    if (!url.trim()) return `${fieldName} is required`
    try {
      const parsed = new URL(url)
      if (!['http:', 'https:'].includes(parsed.protocol)) {
        return `${fieldName} must use http or https`
      }
      return null
    } catch {
      return `${fieldName} must be a valid URL`
    }
  }

  const validateUuid = (uuid: string, fieldName: string): string | null => {
    if (!uuid.trim()) return `${fieldName} is required`
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
    if (!uuidRegex.test(uuid)) {
      return `${fieldName} must be a valid UUID`
    }
    return null
  }

  const validate = (): boolean => {
    const errors: Record<string, string> = {}

    if (config.enabled) {
      const baseUrlError = validateUrl(config.baseUrl, 'Guard API URL')
      if (baseUrlError) errors.baseUrl = baseUrlError

      const tenantIdError = validateUuid(config.tenantId, 'Tenant ID')
      if (tenantIdError) errors.tenantId = tenantIdError

      const redirectUrlError = validateUrl(config.redirectUrl, 'Redirect URL')
      if (redirectUrlError) errors.redirectUrl = redirectUrlError
    }

    setValidationErrors(errors)
    return Object.keys(errors).length === 0
  }

  const handleSave = async () => {
    if (!validate()) return

    setSaving(true)
    setError(null)
    try {
      await onSave(config)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to save configuration')
    } finally {
      setSaving(false)
    }
  }

  const handleTest = async () => {
    if (!onTest) return
    if (!validate()) return

    setTesting(true)
    setTestResult(null)
    setError(null)
    try {
      const result = await onTest(config)
      setTestResult(result)
    } catch (e: unknown) {
      const err = e as Error
      setTestResult({ success: false, message: err?.message || 'Connection test failed' })
    } finally {
      setTesting(false)
    }
  }

  const updateConfig = <K extends keyof GuardIntegrationConfig>(
    key: K,
    value: GuardIntegrationConfig[K]
  ) => {
    setConfig((prev) => ({ ...prev, [key]: value }))
    if (validationErrors[key]) {
      setValidationErrors((prev) => {
        const next = { ...prev }
        delete next[key]
        return next
      })
    }
    setTestResult(null)
  }

  const callbackUrl = config.baseUrl
    ? `${config.baseUrl.replace(/\/$/, '')}/api/v1/auth/sso/callback`
    : ''

  return (
    <Card className={className} data-testid="guard-integration-form">
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2">
              <svg
                className="h-5 w-5"
                viewBox="0 0 24 24"
                fill="none"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path
                  d="M12 2L4 6v6c0 5.55 3.84 10.74 8 12 4.16-1.26 8-6.45 8-12V6l-8-4z"
                  fill="currentColor"
                  opacity="0.2"
                />
                <path
                  d="M12 2L4 6v6c0 5.55 3.84 10.74 8 12 4.16-1.26 8-6.45 8-12V6l-8-4z"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
                <path
                  d="M9 12l2 2 4-4"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </svg>
              Guard SSO Integration
            </CardTitle>
            <CardDescription>
              Connect your app to Guard for centralized authentication
            </CardDescription>
          </div>
          <div className="flex items-center gap-2">
            <Label htmlFor="guard-enabled" className="text-sm">
              {config.enabled ? 'Enabled' : 'Disabled'}
            </Label>
            <Switch
              id="guard-enabled"
              checked={config.enabled}
              onCheckedChange={(checked) => updateConfig('enabled', checked)}
              data-testid="guard-enabled-toggle"
            />
          </div>
        </div>
      </CardHeader>

      <CardContent className="space-y-6">
        <div className="space-y-4">
          <h3 className="text-sm font-medium border-b pb-2">Connection Settings</h3>

          <div className="space-y-1">
            <Label htmlFor="base-url">Guard API URL *</Label>
            <Input
              id="base-url"
              type="url"
              placeholder="https://auth.example.com"
              value={config.baseUrl}
              onChange={(e) => updateConfig('baseUrl', e.target.value)}
              disabled={!config.enabled}
              className={validationErrors.baseUrl ? 'border-destructive' : ''}
              data-testid="guard-base-url"
            />
            <HelpText>
              The base URL of your Guard server (e.g., https://auth.yourcompany.com)
            </HelpText>
            {validationErrors.baseUrl && (
              <p className="text-sm text-destructive">{validationErrors.baseUrl}</p>
            )}
          </div>

          <div className="space-y-1">
            <Label htmlFor="tenant-id">Tenant ID *</Label>
            <Input
              id="tenant-id"
              type="text"
              placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
              value={config.tenantId}
              onChange={(e) => updateConfig('tenantId', e.target.value)}
              disabled={!config.enabled}
              className={validationErrors.tenantId ? 'border-destructive' : ''}
              data-testid="guard-tenant-id"
            />
            <HelpText>
              Your unique tenant identifier. Get this from your Guard admin dashboard.
            </HelpText>
            {validationErrors.tenantId && (
              <p className="text-sm text-destructive">{validationErrors.tenantId}</p>
            )}
          </div>

          <div className="space-y-1">
            <Label htmlFor="redirect-url">Redirect URL *</Label>
            <Input
              id="redirect-url"
              type="url"
              placeholder="https://yourapp.com/auth/callback"
              value={config.redirectUrl}
              onChange={(e) => updateConfig('redirectUrl', e.target.value)}
              disabled={!config.enabled}
              className={validationErrors.redirectUrl ? 'border-destructive' : ''}
              data-testid="guard-redirect-url"
            />
            <HelpText>
              Where Guard redirects users after authentication. Must be in the allowlist.
            </HelpText>
            {validationErrors.redirectUrl && (
              <p className="text-sm text-destructive">{validationErrors.redirectUrl}</p>
            )}
          </div>
        </div>

        <div className="space-y-4">
          <h3 className="text-sm font-medium border-b pb-2">Authentication Mode</h3>
          <div className="space-y-1">
            <Label htmlFor="auth-mode">Token Storage</Label>
            <Select
              value={config.authMode}
              onValueChange={(value: 'bearer' | 'cookie') => updateConfig('authMode', value)}
              disabled={!config.enabled}
            >
              <SelectTrigger id="auth-mode" data-testid="guard-auth-mode">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="bearer">Bearer Tokens (localStorage)</SelectItem>
                <SelectItem value="cookie">HTTP-only Cookies</SelectItem>
              </SelectContent>
            </Select>
            <HelpText>
              Bearer mode stores tokens in localStorage. Cookie mode uses HTTP-only cookies.
            </HelpText>
          </div>
        </div>

        <div className="space-y-4">
          <button
            type="button"
            className="flex items-center gap-2 text-sm font-medium text-muted-foreground hover:text-foreground"
            onClick={() => setShowAdvancedOptions(!showAdvancedOptions)}
          >
            <span>{showAdvancedOptions ? '\u25BC' : '\u25B6'}</span>
            Advanced Options
          </button>

          {showAdvancedOptions && (
            <div className="space-y-4 pl-4 border-l-2 border-muted">
              <div className="space-y-1">
                <Label htmlFor="client-id">Client ID (Optional)</Label>
                <Input
                  id="client-id"
                  type="text"
                  placeholder="your-client-id"
                  value={config.clientId}
                  onChange={(e) => updateConfig('clientId', e.target.value)}
                  disabled={!config.enabled}
                  data-testid="guard-client-id"
                />
                <HelpText>
                  Required for OAuth2/OIDC flows. Leave empty for redirect-based auth.
                </HelpText>
              </div>

              <div className="space-y-1">
                <Label htmlFor="client-secret">Client Secret (Optional)</Label>
                <Input
                  id="client-secret"
                  type="password"
                  placeholder="your-client-secret"
                  value={config.clientSecret}
                  onChange={(e) => updateConfig('clientSecret', e.target.value)}
                  disabled={!config.enabled}
                  data-testid="guard-client-secret"
                />
                <HelpText>
                  For server-side apps only. Never expose in frontend code.
                </HelpText>
              </div>

              <div className="space-y-1">
                <Label htmlFor="scopes">Scopes</Label>
                <Input
                  id="scopes"
                  type="text"
                  placeholder="openid profile email"
                  value={config.scopes?.join(' ') ?? ''}
                  onChange={(e) =>
                    updateConfig('scopes', e.target.value.split(/\s+/).filter(Boolean))
                  }
                  disabled={!config.enabled}
                  data-testid="guard-scopes"
                />
                <HelpText>
                  Space-separated OAuth scopes. Default: openid profile email
                </HelpText>
              </div>
            </div>
          )}
        </div>

        {config.baseUrl && config.enabled && (
          <Alert>
            <AlertTitle className="text-sm font-medium">Guard Callback URL</AlertTitle>
            <AlertDescription className="mt-2">
              <p className="text-xs text-muted-foreground mb-2">
                Configure your IdP with this callback URL:
              </p>
              <div className="flex items-center gap-2">
                <code className="flex-1 text-xs bg-muted px-2 py-1.5 rounded border font-mono break-all">
                  {callbackUrl}
                </code>
                <CopyButton value={callbackUrl} />
              </div>
            </AlertDescription>
          </Alert>
        )}

        {testResult && (
          <Alert variant={testResult.success ? 'default' : 'destructive'}>
            <AlertTitle>
              {testResult.success ? 'Connection Successful' : 'Connection Failed'}
            </AlertTitle>
            {testResult.message && (
              <AlertDescription className="mt-1">{testResult.message}</AlertDescription>
            )}
          </Alert>
        )}

        {error && (
          <Alert variant="destructive">
            <AlertTitle>Error</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        <div className="flex items-center justify-between pt-4 border-t">
          <div className="flex items-center gap-2">
            {onTest && (
              <Button
                type="button"
                variant="outline"
                onClick={handleTest}
                disabled={!config.enabled || testing || saving}
                data-testid="guard-test-connection"
              >
                {testing ? 'Testing...' : 'Test Connection'}
              </Button>
            )}
            <a
              href="https://github.com/corvusHold/guard#readme"
              target="_blank"
              rel="noopener noreferrer"
              className="text-sm text-muted-foreground hover:text-foreground"
            >
              Documentation
            </a>
          </div>
          <Button
            type="button"
            onClick={handleSave}
            disabled={saving || testing}
            data-testid="guard-save"
          >
            {saving ? 'Saving...' : 'Save Configuration'}
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}
