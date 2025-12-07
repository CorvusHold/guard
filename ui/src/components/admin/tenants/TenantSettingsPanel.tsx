import { useState, useEffect } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Separator } from '@/components/ui/separator'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Switch } from '@/components/ui/switch'
import { Textarea } from '@/components/ui/textarea'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Badge } from '@/components/ui/badge'
import { AlertCircle, Save, RefreshCw, Eye, EyeOff, Copy } from 'lucide-react'
import { useAuth } from '@/lib/auth'
import { getClient } from '@/lib/sdk'
import { useToast } from '@/lib/toast'

interface TenantSettings {
  // CORS Settings
  app_cors_allowed_origins?: string
  
  // Authentication Settings
  auth_access_token_ttl?: string
  auth_refresh_token_ttl?: string
  auth_magic_link_ttl?: string
  auth_jwt_issuer?: string
  auth_jwt_audience?: string
  
  // Rate Limiting
  auth_ratelimit_login_limit?: string
  auth_ratelimit_login_window?: string
  auth_ratelimit_signup_limit?: string
  auth_ratelimit_signup_window?: string
  auth_ratelimit_mfa_limit?: string
  auth_ratelimit_mfa_window?: string
  auth_ratelimit_token_limit?: string
  auth_ratelimit_token_window?: string
  
  // SSO Settings
  sso_provider?: string
  sso_state_ttl?: string
  sso_redirect_allowlist?: string
  sso_workos_client_id?: string
  sso_workos_client_secret?: string
  sso_workos_api_key?: string
  sso_workos_api_base_url?: string
  sso_workos_default_connection_id?: string
  sso_workos_default_organization_id?: string
  
  // Email Settings
  email_provider?: string
  email_smtp_host?: string
  email_smtp_port?: string
  email_smtp_username?: string
  email_smtp_password?: string
  email_smtp_from?: string
  email_brevo_api_key?: string
  email_brevo_sender?: string
  
  // Application Settings
  app_public_base_url?: string
}

interface TenantSettingsPanelProps {
  tenantId: string
  tenantName: string
  onSettingsUpdated?: () => void
}

export default function TenantSettingsPanel({ tenantId, tenantName, onSettingsUpdated }: TenantSettingsPanelProps) {
  const { user } = useAuth()
  const { show: showToast } = useToast()
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [settings, setSettings] = useState<TenantSettings>({})
  const [originalSettings, setOriginalSettings] = useState<TenantSettings>({})
  const [showSecrets, setShowSecrets] = useState<Record<string, boolean>>({})
  const [hasChanges, setHasChanges] = useState(false)

  useEffect(() => {
    loadSettings()
  }, [tenantId])

  useEffect(() => {
    const changed = JSON.stringify(settings) !== JSON.stringify(originalSettings)
    setHasChanges(changed)
  }, [settings, originalSettings])

  const loadSettings = async () => {
    setLoading(true)
    setError(null)

    try {
      const client = getClient()
      const res = await client.getTenantSettings(tenantId)
      if (!(res.meta.status >= 200 && res.meta.status < 300)) {
        throw new Error('Failed to load settings')
      }
      const data: any = res.data
      const settingsData = data?.settings ?? data ?? {}
      setSettings(settingsData)
      setOriginalSettings(settingsData)
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to load settings'
      setError(message)
      showToast({ description: message, variant: 'error' })
    } finally {
      setLoading(false)
    }
  }

  const saveSettings = async () => {
    setSaving(true)
    setError(null)

    try {
      const client = getClient()
      // Only send changed settings
      const changedSettings: TenantSettings = {}
      Object.keys(settings).forEach(key => {
        if (settings[key as keyof TenantSettings] !== originalSettings[key as keyof TenantSettings]) {
          changedSettings[key as keyof TenantSettings] = settings[key as keyof TenantSettings]
        }
      })
      const res = await client.updateTenantSettings(tenantId, changedSettings as any)
      if (!(res.meta.status >= 200 && res.meta.status < 300)) {
        throw new Error('Failed to save settings')
      }
      setOriginalSettings({ ...settings })
      showToast({ description: 'Settings saved successfully', variant: 'success', testId: 'settings-saved-toast' })
      onSettingsUpdated?.()
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to save settings'
      setError(message)
      showToast({ description: message, variant: 'error', testId: 'settings-error-toast' })
    } finally {
      setSaving(false)
    }
  }

  const resetSettings = () => {
    setSettings({ ...originalSettings })
    setError(null)
  }

  const updateSetting = (key: keyof TenantSettings, value: string) => {
    setSettings(prev => ({ ...prev, [key]: value }))
  }

  const toggleSecretVisibility = (key: string) => {
    setShowSecrets(prev => ({ ...prev, [key]: !prev[key] }))
  }

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text)
    showToast({ description: `${label} copied to clipboard`, variant: 'success' })
  }

  const renderSecretInput = (
    key: keyof TenantSettings,
    label: string,
    placeholder: string,
    required: boolean = false
  ) => {
    const value = settings[key] || ''
    const isVisible = showSecrets[key] || false

    return (
      <div className="space-y-2">
        <Label htmlFor={key}>{label} {required && '*'}</Label>
        <div className="flex space-x-2">
          <div className="relative flex-1">
            <Input
              id={key}
              type={isVisible ? 'text' : 'password'}
              value={value}
              onChange={(e) => updateSetting(key, e.target.value)}
              placeholder={placeholder}
              disabled={loading || saving}
            />
            {value && (
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="absolute right-8 top-0 h-full px-2"
                onClick={() => copyToClipboard(value, label)}
              >
                <Copy className="h-3 w-3" />
              </Button>
            )}
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="absolute right-0 top-0 h-full px-3"
              onClick={() => toggleSecretVisibility(key)}
            >
              {isVisible ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </Button>
          </div>
        </div>
      </div>
    )
  }

  if (loading) {
    return (
      <div data-testid="settings-loading">
        <Card>
          <CardContent className="flex items-center justify-center py-8">
            <RefreshCw className="h-6 w-6 animate-spin mr-2" />
            Loading settings...
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="space-y-6" data-testid="tenant-settings-panel">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Tenant Settings</h2>
          <p className="text-muted-foreground">
            Configure settings for {tenantName} ({tenantId})
          </p>
        </div>
        <div className="flex space-x-2">
          {hasChanges && (
            <Button variant="outline" onClick={resetSettings} disabled={saving}>
              Reset
            </Button>
          )}
          <Button onClick={saveSettings} disabled={!hasChanges || saving} data-testid="save-settings">
            <Save className="h-4 w-4 mr-2" />
            {saving ? 'Saving...' : 'Save Changes'}
          </Button>
        </div>
      </div>

      {hasChanges && (
        <div className="p-3 text-sm text-amber-600 bg-amber-50 border border-amber-200 rounded-md flex items-center" data-testid="unsaved-changes">
          <AlertCircle className="h-4 w-4 mr-2" />
          You have unsaved changes
        </div>
      )}

      {error && (
        <div className="p-3 text-sm text-red-600 bg-red-50 border border-red-200 rounded-md">
          {error}
        </div>
      )}

      <Tabs defaultValue="security" className="w-full">
        <TabsList className="grid w-full grid-cols-5">
          <TabsTrigger value="security" data-testid="settings-tab-security">Security</TabsTrigger>
          <TabsTrigger value="cors" data-testid="settings-tab-cors">CORS</TabsTrigger>
          <TabsTrigger value="sso" data-testid="settings-tab-sso">SSO</TabsTrigger>
          <TabsTrigger value="email">Email</TabsTrigger>
          <TabsTrigger value="advanced">Advanced</TabsTrigger>
        </TabsList>

        <TabsContent value="security" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Authentication Settings</CardTitle>
              <CardDescription>Configure token lifetimes and JWT settings</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="auth_access_token_ttl">Access Token TTL</Label>
                  {/* Test-friendly native select mirror */}
                  <select
                    data-testid="access-token-ttl"
                    value={settings.auth_access_token_ttl || '15m'}
                    onChange={(e) => updateSetting('auth_access_token_ttl', e.target.value)}
                    className="border rounded-md px-2 py-1 text-sm"
                  >
                    <option value="5m">5 minutes</option>
                    <option value="15m">15 minutes</option>
                    <option value="30m">30 minutes</option>
                    <option value="1h">1 hour</option>
                    <option value="2h">2 hours</option>
                  </select>
                  <Select
                    value={settings.auth_access_token_ttl || '15m'}
                    onValueChange={(value) => updateSetting('auth_access_token_ttl', value)}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select TTL" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="5m">5 minutes</SelectItem>
                      <SelectItem value="15m">15 minutes</SelectItem>
                      <SelectItem value="30m">30 minutes</SelectItem>
                      <SelectItem value="1h">1 hour</SelectItem>
                      <SelectItem value="2h">2 hours</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="auth_refresh_token_ttl">Refresh Token TTL</Label>
                  {/* Test-friendly native select mirror */}
                  <select
                    data-testid="refresh-token-ttl"
                    value={settings.auth_refresh_token_ttl || '720h'}
                    onChange={(e) => updateSetting('auth_refresh_token_ttl', e.target.value)}
                    className="border rounded-md px-2 py-1 text-sm"
                  >
                    <option value="168h">7 days</option>
                    <option value="720h">30 days</option>
                    <option value="2160h">90 days</option>
                    <option value="4320h">180 days</option>
                  </select>
                  <Select
                    value={settings.auth_refresh_token_ttl || '720h'}
                    onValueChange={(value) => updateSetting('auth_refresh_token_ttl', value)}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select TTL" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="168h">7 days</SelectItem>
                      <SelectItem value="720h">30 days</SelectItem>
                      <SelectItem value="2160h">90 days</SelectItem>
                      <SelectItem value="4320h">180 days</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="auth_jwt_issuer">JWT Issuer</Label>
                  <Input
                    id="auth_jwt_issuer"
                    value={settings.auth_jwt_issuer || ''}
                    onChange={(e) => updateSetting('auth_jwt_issuer', e.target.value)}
                    placeholder="guard"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="auth_jwt_audience">JWT Audience</Label>
                  <Input
                    id="auth_jwt_audience"
                    value={settings.auth_jwt_audience || ''}
                    onChange={(e) => updateSetting('auth_jwt_audience', e.target.value)}
                    placeholder="guard"
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="auth_magic_link_ttl">Magic Link TTL</Label>
                <Select
                  value={settings.auth_magic_link_ttl || '15m'}
                  onValueChange={(value) => updateSetting('auth_magic_link_ttl', value)}
                >
                  <SelectTrigger className="w-full">
                    <SelectValue placeholder="Select TTL" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="5m">5 minutes</SelectItem>
                    <SelectItem value="10m">10 minutes</SelectItem>
                    <SelectItem value="15m">15 minutes</SelectItem>
                    <SelectItem value="30m">30 minutes</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Rate Limiting</CardTitle>
              <CardDescription>Configure rate limits for authentication endpoints</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-3 gap-4">
                <div className="space-y-2">
                  <Label>Login Rate Limit</Label>
                  <div className="flex space-x-2">
                    <Input
                      value={settings.auth_ratelimit_login_limit || '10'}
                      onChange={(e) => updateSetting('auth_ratelimit_login_limit', e.target.value)}
                      placeholder="10"
                      className="w-20"
                    />
                    {/* Test-friendly select to drive numeric change */}
                    <select
                      data-testid="login-rate-limit"
                      className="border rounded-md px-1 text-sm"
                      value={settings.auth_ratelimit_login_limit || '10'}
                      onChange={(e) => updateSetting('auth_ratelimit_login_limit', e.target.value)}
                    >
                      <option value="5">5</option>
                      <option value="10">10</option>
                      <option value="15">15</option>
                      <option value="20">20</option>
                    </select>
                    <span className="text-sm text-muted-foreground self-center">per</span>
                    <Select
                      value={settings.auth_ratelimit_login_window || '1m'}
                      onValueChange={(value) => updateSetting('auth_ratelimit_login_window', value)}
                    >
                      <SelectTrigger className="w-24">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="1m">1m</SelectItem>
                        <SelectItem value="5m">5m</SelectItem>
                        <SelectItem value="15m">15m</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                <div className="space-y-2">
                  <Label>Signup Rate Limit</Label>
                  <div className="flex space-x-2">
                    <Input
                      value={settings.auth_ratelimit_signup_limit || '5'}
                      onChange={(e) => updateSetting('auth_ratelimit_signup_limit', e.target.value)}
                      placeholder="5"
                      className="w-20"
                    />
                    <span className="text-sm text-muted-foreground self-center">per</span>
                    <Select
                      value={settings.auth_ratelimit_signup_window || '1h'}
                      onValueChange={(value) => updateSetting('auth_ratelimit_signup_window', value)}
                    >
                      <SelectTrigger className="w-24">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="1m">1m</SelectItem>
                        <SelectItem value="5m">5m</SelectItem>
                        <SelectItem value="1h">1h</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                <div className="space-y-2">
                  <Label>MFA Rate Limit</Label>
                  <div className="flex space-x-2">
                    <Input
                      value={settings.auth_ratelimit_mfa_limit || '10'}
                      onChange={(e) => updateSetting('auth_ratelimit_mfa_limit', e.target.value)}
                      placeholder="10"
                      className="w-20"
                    />
                    <span className="text-sm text-muted-foreground self-center">per</span>
                    <Select
                      value={settings.auth_ratelimit_mfa_window || '1m'}
                      onValueChange={(value) => updateSetting('auth_ratelimit_mfa_window', value)}
                    >
                      <SelectTrigger className="w-24">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="1m">1m</SelectItem>
                        <SelectItem value="5m">5m</SelectItem>
                        <SelectItem value="15m">15m</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              </div>
              <div className="space-y-2">
                <Label htmlFor="token-rate-limit">Token Rate Limit (admin/API)</Label>
                <div className="flex space-x-2">
                  <Input
                    id="token-rate-limit"
                    data-testid="token-rate-limit"
                    value={settings.auth_ratelimit_token_limit || '50'}
                    onChange={(e) => updateSetting('auth_ratelimit_token_limit', e.target.value)}
                    placeholder="50"
                    className="w-20"
                  />
                  <span className="text-sm text-muted-foreground self-center">per</span>
                  <Select
                    value={settings.auth_ratelimit_token_window || '1m'}
                    onValueChange={(value) => updateSetting('auth_ratelimit_token_window', value)}
                  >
                    <SelectTrigger className="w-24">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="1m">1m</SelectItem>
                      <SelectItem value="5m">5m</SelectItem>
                      <SelectItem value="15m">15m</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="cors" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>CORS Configuration</CardTitle>
              <CardDescription>Configure Cross-Origin Resource Sharing settings</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="app_cors_allowed_origins">Allowed Origins</Label>
                <Textarea
                  id="app_cors_allowed_origins"
                  data-testid="cors-origins"
                  value={settings.app_cors_allowed_origins || ''}
                  onChange={(e) => updateSetting('app_cors_allowed_origins', e.target.value)}
                  placeholder="https://app.example.com,https://admin.example.com"
                  rows={3}
                />
                <p className="text-xs text-muted-foreground">
                  Comma-separated list of allowed origins. These origins will be able to make requests to the API from browsers.
                </p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="sso" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>SSO Configuration</CardTitle>
              <CardDescription>Configure Single Sign-On settings</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="sso_provider">SSO Provider</Label>
                <Select
                  value={settings.sso_provider || 'none'}
                  onValueChange={(value) => updateSetting('sso_provider', value)}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select provider" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">None</SelectItem>
                    <SelectItem value="dev">Development</SelectItem>
                    <SelectItem value="workos">WorkOS</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {settings.sso_provider && settings.sso_provider !== 'none' && (
                <>
                  <div className="space-y-2">
                    <Label htmlFor="sso_state_ttl">OAuth State TTL</Label>
                    <Select
                      value={settings.sso_state_ttl || '10m'}
                      onValueChange={(value) => updateSetting('sso_state_ttl', value)}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="5m">5 minutes</SelectItem>
                        <SelectItem value="10m">10 minutes</SelectItem>
                        <SelectItem value="15m">15 minutes</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="sso_redirect_allowlist">Redirect Allowlist</Label>
                    <Textarea
                      id="sso_redirect_allowlist"
                      value={settings.sso_redirect_allowlist || ''}
                      onChange={(e) => updateSetting('sso_redirect_allowlist', e.target.value)}
                      placeholder="https://app.example.com/callback,https://admin.example.com/callback"
                      rows={2}
                    />
                    <p className="text-xs text-muted-foreground">
                      Comma-separated list of allowed redirect URLs for SSO callbacks
                    </p>
                  </div>
                </>
              )}

              {settings.sso_provider === 'workos' && (
                <div className="space-y-4 border-t pt-4">
                  <h4 className="font-medium">WorkOS Configuration</h4>
                  
                  {renderSecretInput('sso_workos_client_id', 'Client ID', 'client_01234567890', true)}
                  {renderSecretInput('sso_workos_client_secret', 'Client Secret', 'wk_live_...', true)}
                  {renderSecretInput('sso_workos_api_key', 'API Key', 'sk_live_...')}
                  
                  <div className="space-y-2">
                    <Label htmlFor="sso_workos_api_base_url">API Base URL</Label>
                    <Input
                      id="sso_workos_api_base_url"
                      value={settings.sso_workos_api_base_url || ''}
                      onChange={(e) => updateSetting('sso_workos_api_base_url', e.target.value)}
                      placeholder="https://api.workos.com"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="sso_workos_default_connection_id">Default Connection ID</Label>
                    <Input
                      id="sso_workos_default_connection_id"
                      value={settings.sso_workos_default_connection_id || ''}
                      onChange={(e) => updateSetting('sso_workos_default_connection_id', e.target.value)}
                      placeholder="conn_01234567890"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="sso_workos_default_organization_id">Default Organization ID</Label>
                    <Input
                      id="sso_workos_default_organization_id"
                      value={settings.sso_workos_default_organization_id || ''}
                      onChange={(e) => updateSetting('sso_workos_default_organization_id', e.target.value)}
                      placeholder="org_01234567890"
                    />
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="email" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Email Configuration</CardTitle>
              <CardDescription>Configure email provider settings</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="email_provider">Email Provider</Label>
                <Select
                  value={settings.email_provider || 'smtp'}
                  onValueChange={(value) => updateSetting('email_provider', value)}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select provider" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="smtp">SMTP</SelectItem>
                    <SelectItem value="brevo">Brevo</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {settings.email_provider === 'smtp' && (
                <div className="space-y-4 border-t pt-4">
                  <h4 className="font-medium">SMTP Configuration</h4>
                  
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="email_smtp_host">SMTP Host</Label>
                      <Input
                        id="email_smtp_host"
                        value={settings.email_smtp_host || ''}
                        onChange={(e) => updateSetting('email_smtp_host', e.target.value)}
                        placeholder="smtp.gmail.com"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="email_smtp_port">SMTP Port</Label>
                      <Input
                        id="email_smtp_port"
                        value={settings.email_smtp_port || ''}
                        onChange={(e) => updateSetting('email_smtp_port', e.target.value)}
                        placeholder="587"
                      />
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="email_smtp_username">SMTP Username</Label>
                    <Input
                      id="email_smtp_username"
                      value={settings.email_smtp_username || ''}
                      onChange={(e) => updateSetting('email_smtp_username', e.target.value)}
                      placeholder="user@gmail.com"
                    />
                  </div>

                  {renderSecretInput('email_smtp_password', 'SMTP Password', 'app password')}

                  <div className="space-y-2">
                    <Label htmlFor="email_smtp_from">From Address</Label>
                    <Input
                      id="email_smtp_from"
                      value={settings.email_smtp_from || ''}
                      onChange={(e) => updateSetting('email_smtp_from', e.target.value)}
                      placeholder="MyApp <noreply@example.com>"
                    />
                  </div>
                </div>
              )}

              {settings.email_provider === 'brevo' && (
                <div className="space-y-4 border-t pt-4">
                  <h4 className="font-medium">Brevo Configuration</h4>
                  
                  {renderSecretInput('email_brevo_api_key', 'API Key', 'xkeysib-...', true)}
                  
                  <div className="space-y-2">
                    <Label htmlFor="email_brevo_sender">Sender Email</Label>
                    <Input
                      id="email_brevo_sender"
                      value={settings.email_brevo_sender || ''}
                      onChange={(e) => updateSetting('email_brevo_sender', e.target.value)}
                      placeholder="noreply@example.com"
                    />
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="advanced" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Advanced Settings</CardTitle>
              <CardDescription>Advanced configuration options</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="app_public_base_url">Public Base URL</Label>
                <Input
                  id="app_public_base_url"
                  value={settings.app_public_base_url || ''}
                  onChange={(e) => updateSetting('app_public_base_url', e.target.value)}
                  placeholder="https://api.example.com"
                />
                <p className="text-xs text-muted-foreground">
                  The public base URL for your Guard API instance
                </p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
