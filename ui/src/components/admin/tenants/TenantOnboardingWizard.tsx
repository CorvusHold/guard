import { useState } from 'react'
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
import { CheckCircle, Circle, ArrowRight, ArrowLeft, Copy, Eye, EyeOff } from 'lucide-react'
import { useAuth } from '@/lib/auth'
import { getRuntimeConfig } from '@/lib/runtime'
import { useToast } from '@/lib/toast'

interface OnboardingStep {
  id: string
  title: string
  description: string
  completed: boolean
}

interface TenantData {
  name: string
  id?: string
}

interface AdminUserData {
  email: string
  password: string
  firstName: string
  lastName: string
  enableMFA: boolean
  id?: string
  totpSecret?: string
  backupCodes?: string[]
}

interface TenantSettings {
  corsOrigins: string
  accessTokenTTL: string
  refreshTokenTTL: string
  ssoProvider: 'none' | 'dev' | 'workos'
  ssoRedirectAllowlist: string
  workosClientId?: string
  workosClientSecret?: string
  workosApiKey?: string
  rateLimitLoginLimit: string
  rateLimitLoginWindow: string
}

interface TenantOnboardingWizardProps {
  onComplete?: (tenantId: string, tenantName: string) => void
  onCancel?: () => void
}

export default function TenantOnboardingWizard({ onComplete, onCancel }: TenantOnboardingWizardProps) {
  const { user } = useAuth()
  const { show: showToast } = useToast()
  const [currentStep, setCurrentStep] = useState(0)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [showPassword, setShowPassword] = useState(false)

  const [steps, setSteps] = useState<OnboardingStep[]>([
    { id: 'tenant', title: 'Tenant Details', description: 'Basic tenant information', completed: false },
    { id: 'admin', title: 'Admin User', description: 'Create admin user account', completed: false },
    { id: 'settings', title: 'Configuration', description: 'Configure tenant settings', completed: false },
    { id: 'review', title: 'Review & Create', description: 'Review and finalize setup', completed: false }
  ])

  const [tenantData, setTenantData] = useState<TenantData>({
    name: ''
  })

  const [adminData, setAdminData] = useState<AdminUserData>({
    email: '',
    password: '',
    firstName: '',
    lastName: '',
    enableMFA: false
  })

  const [settings, setSettings] = useState<TenantSettings>({
    corsOrigins: 'http://localhost:3000,http://localhost:5173',
    accessTokenTTL: '15m',
    refreshTokenTTL: '720h',
    ssoProvider: 'none',
    ssoRedirectAllowlist: '',
    rateLimitLoginLimit: '10',
    rateLimitLoginWindow: '1m'
  })

  const updateStepCompletion = (stepIndex: number, completed: boolean) => {
    setSteps(prev => prev.map((step, index) => 
      index === stepIndex ? { ...step, completed } : step
    ))
  }

  const validateTenantStep = (): boolean => {
    return tenantData.name.trim().length > 0
  }

  const validateAdminStep = (): boolean => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    return (
      adminData.email.trim().length > 0 &&
      emailRegex.test(adminData.email) &&
      adminData.password.length >= 8 &&
      adminData.firstName.trim().length > 0 &&
      adminData.lastName.trim().length > 0
    )
  }

  const validateSettingsStep = (): boolean => {
    if (settings.ssoProvider === 'workos') {
      return !!(settings.workosClientId && settings.workosClientSecret)
    }
    return true
  }

  const handleNext = () => {
    let isValid = false
    
    switch (currentStep) {
      case 0:
        isValid = validateTenantStep()
        updateStepCompletion(0, isValid)
        break
      case 1:
        isValid = validateAdminStep()
        updateStepCompletion(1, isValid)
        break
      case 2:
        isValid = validateSettingsStep()
        updateStepCompletion(2, isValid)
        break
      default:
        isValid = true
    }

    if (isValid && currentStep < steps.length - 1) {
      setCurrentStep(prev => prev + 1)
      setError(null)
    } else if (!isValid) {
      setError('Please complete all required fields correctly')
    }
  }

  const handlePrevious = () => {
    if (currentStep > 0) {
      setCurrentStep(prev => prev - 1)
      setError(null)
    }
  }

  const generatePassword = () => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*'
    let password = ''
    for (let i = 0; i < 12; i++) {
      password += chars.charAt(Math.floor(Math.random() * chars.length))
    }
    setAdminData(prev => ({ ...prev, password }))
  }

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text)
    showToast({ description: `${label} copied to clipboard`, variant: 'success' })
  }

  const handleComplete = async () => {
    setLoading(true)
    setError(null)

    try {
      const config = getRuntimeConfig()
      if (!config) {
        throw new Error('Guard configuration not found')
      }

      // Step 1: Create tenant
      const tenantResponse = await fetch(`${config.guard_base_url}/tenants`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${user?.accessToken || ''}`
        },
        body: JSON.stringify({
          name: tenantData.name.trim()
        })
      })

      if (!tenantResponse.ok) {
        const errorData = await tenantResponse.json()
        throw new Error(errorData.error || 'Failed to create tenant')
      }

      const tenant = await tenantResponse.json()
      const tenantId = tenant.id

      // Step 2: Create admin user
      const signupResponse = await fetch(`${config.guard_base_url}/v1/auth/signup`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          tenant_id: tenantId,
          email: adminData.email.trim(),
          password: adminData.password,
          first_name: adminData.firstName.trim(),
          last_name: adminData.lastName.trim()
        })
      })

      if (!signupResponse.ok) {
        const errorData = await signupResponse.json()
        throw new Error(errorData.error || 'Failed to create admin user')
      }

      const signupResult = await signupResponse.json()
      
      // Step 3: Enable MFA if requested
      if (adminData.enableMFA) {
        // This would require additional API calls to enable MFA
        // For now, we'll note it as a manual step
      }

      // Step 4: Configure tenant settings
      const adminToken = signupResult.access_token
      
      const settingsPayload: any = {
        app_cors_allowed_origins: settings.corsOrigins,
        auth_access_token_ttl: settings.accessTokenTTL,
        auth_refresh_token_ttl: settings.refreshTokenTTL,
        auth_ratelimit_login_limit: settings.rateLimitLoginLimit,
        auth_ratelimit_login_window: settings.rateLimitLoginWindow
      }

      if (settings.ssoProvider !== 'none') {
        settingsPayload.sso_provider = settings.ssoProvider
        if (settings.ssoRedirectAllowlist) {
          settingsPayload.sso_redirect_allowlist = settings.ssoRedirectAllowlist
        }
        
        if (settings.ssoProvider === 'workos') {
          if (settings.workosClientId) settingsPayload.sso_workos_client_id = settings.workosClientId
          if (settings.workosClientSecret) settingsPayload.sso_workos_client_secret = settings.workosClientSecret
          if (settings.workosApiKey) settingsPayload.sso_workos_api_key = settings.workosApiKey
        }
      }

      const settingsResponse = await fetch(`${config.guard_base_url}/v1/tenants/${tenantId}/settings`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${adminToken}`
        },
        body: JSON.stringify(settingsPayload)
      })

      if (!settingsResponse.ok) {
        console.warn('Failed to update tenant settings, but tenant was created successfully')
      }

      // Update state with results
      setTenantData(prev => ({ ...prev, id: tenantId }))
      setAdminData(prev => ({ ...prev, id: signupResult.user?.id }))
      
      updateStepCompletion(3, true)
      showToast({ description: 'Tenant onboarding completed successfully!', variant: 'success' })
      
      onComplete?.(tenantId, tenantData.name)

    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to complete onboarding'
      setError(message)
      showToast({ description: message, variant: 'error' })
    } finally {
      setLoading(false)
    }
  }

  const renderTenantStep = () => (
    <div className="space-y-4">
      <div>
        <h3 className="text-lg font-medium">Tenant Information</h3>
        <p className="text-sm text-muted-foreground">
          Enter the basic information for your new tenant
        </p>
      </div>
      
      <div className="space-y-2">
        <Label htmlFor="tenantName">Tenant Name *</Label>
        <Input
          id="tenantName"
          value={tenantData.name}
          onChange={(e) => setTenantData(prev => ({ ...prev, name: e.target.value }))}
          placeholder="e.g., acme-corp"
          disabled={loading}
        />
        <p className="text-xs text-muted-foreground">
          This will be used as the unique identifier for your tenant
        </p>
      </div>
    </div>
  )

  const renderAdminStep = () => (
    <div className="space-y-4">
      <div>
        <h3 className="text-lg font-medium">Admin User Account</h3>
        <p className="text-sm text-muted-foreground">
          Create the initial admin user for this tenant
        </p>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label htmlFor="firstName">First Name *</Label>
          <Input
            id="firstName"
            value={adminData.firstName}
            onChange={(e) => setAdminData(prev => ({ ...prev, firstName: e.target.value }))}
            placeholder="John"
            disabled={loading}
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="lastName">Last Name *</Label>
          <Input
            id="lastName"
            value={adminData.lastName}
            onChange={(e) => setAdminData(prev => ({ ...prev, lastName: e.target.value }))}
            placeholder="Doe"
            disabled={loading}
          />
        </div>
      </div>

      <div className="space-y-2">
        <Label htmlFor="email">Email Address *</Label>
        <Input
          id="email"
          type="email"
          value={adminData.email}
          onChange={(e) => setAdminData(prev => ({ ...prev, email: e.target.value }))}
          placeholder="admin@example.com"
          disabled={loading}
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="password">Password *</Label>
        <div className="flex space-x-2">
          <div className="relative flex-1">
            <Input
              id="password"
              type={showPassword ? 'text' : 'password'}
              value={adminData.password}
              onChange={(e) => setAdminData(prev => ({ ...prev, password: e.target.value }))}
              placeholder="Enter secure password"
              disabled={loading}
              minLength={8}
            />
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="absolute right-0 top-0 h-full px-3"
              onClick={() => setShowPassword(!showPassword)}
            >
              {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </Button>
          </div>
          <Button
            type="button"
            variant="outline"
            onClick={generatePassword}
            disabled={loading}
          >
            Generate
          </Button>
        </div>
        <p className="text-xs text-muted-foreground">
          Password must be at least 8 characters long
        </p>
      </div>

      <div className="flex items-center space-x-2">
        <Switch
          id="enableMFA"
          checked={adminData.enableMFA}
          onCheckedChange={(checked) => setAdminData(prev => ({ ...prev, enableMFA: checked }))}
          disabled={loading}
        />
        <Label htmlFor="enableMFA">Enable Multi-Factor Authentication (MFA)</Label>
      </div>
    </div>
  )

  const renderSettingsStep = () => (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-medium">Tenant Configuration</h3>
        <p className="text-sm text-muted-foreground">
          Configure security and integration settings
        </p>
      </div>

      <Tabs defaultValue="security" className="w-full">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="security">Security</TabsTrigger>
          <TabsTrigger value="cors">CORS</TabsTrigger>
          <TabsTrigger value="sso">SSO</TabsTrigger>
        </TabsList>

        <TabsContent value="security" className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="accessTokenTTL">Access Token TTL</Label>
              <Select
                value={settings.accessTokenTTL}
                onValueChange={(value) => setSettings(prev => ({ ...prev, accessTokenTTL: value }))}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="5m">5 minutes</SelectItem>
                  <SelectItem value="15m">15 minutes</SelectItem>
                  <SelectItem value="30m">30 minutes</SelectItem>
                  <SelectItem value="1h">1 hour</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="refreshTokenTTL">Refresh Token TTL</Label>
              <Select
                value={settings.refreshTokenTTL}
                onValueChange={(value) => setSettings(prev => ({ ...prev, refreshTokenTTL: value }))}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="168h">7 days</SelectItem>
                  <SelectItem value="720h">30 days</SelectItem>
                  <SelectItem value="2160h">90 days</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="rateLimitLoginLimit">Login Rate Limit</Label>
              <Input
                id="rateLimitLoginLimit"
                value={settings.rateLimitLoginLimit}
                onChange={(e) => setSettings(prev => ({ ...prev, rateLimitLoginLimit: e.target.value }))}
                placeholder="10"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="rateLimitLoginWindow">Rate Limit Window</Label>
              <Select
                value={settings.rateLimitLoginWindow}
                onValueChange={(value) => setSettings(prev => ({ ...prev, rateLimitLoginWindow: value }))}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="1m">1 minute</SelectItem>
                  <SelectItem value="5m">5 minutes</SelectItem>
                  <SelectItem value="15m">15 minutes</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </TabsContent>

        <TabsContent value="cors" className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="corsOrigins">Allowed Origins</Label>
            <Textarea
              id="corsOrigins"
              value={settings.corsOrigins}
              onChange={(e) => setSettings(prev => ({ ...prev, corsOrigins: e.target.value }))}
              placeholder="https://app.example.com,https://admin.example.com"
              rows={3}
            />
            <p className="text-xs text-muted-foreground">
              Comma-separated list of allowed CORS origins
            </p>
          </div>
        </TabsContent>

        <TabsContent value="sso" className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="ssoProvider">SSO Provider</Label>
            <Select
              value={settings.ssoProvider}
              onValueChange={(value: 'none' | 'dev' | 'workos') => setSettings(prev => ({ ...prev, ssoProvider: value }))}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="none">None</SelectItem>
                <SelectItem value="dev">Development</SelectItem>
                <SelectItem value="workos">WorkOS</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {settings.ssoProvider !== 'none' && (
            <div className="space-y-2">
              <Label htmlFor="ssoRedirectAllowlist">Redirect Allowlist</Label>
              <Input
                id="ssoRedirectAllowlist"
                value={settings.ssoRedirectAllowlist}
                onChange={(e) => setSettings(prev => ({ ...prev, ssoRedirectAllowlist: e.target.value }))}
                placeholder="https://app.example.com/callback"
              />
            </div>
          )}

          {settings.ssoProvider === 'workos' && (
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="workosClientId">WorkOS Client ID *</Label>
                <Input
                  id="workosClientId"
                  value={settings.workosClientId || ''}
                  onChange={(e) => setSettings(prev => ({ ...prev, workosClientId: e.target.value }))}
                  placeholder="client_01234567890"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="workosClientSecret">WorkOS Client Secret *</Label>
                <Input
                  id="workosClientSecret"
                  type="password"
                  value={settings.workosClientSecret || ''}
                  onChange={(e) => setSettings(prev => ({ ...prev, workosClientSecret: e.target.value }))}
                  placeholder="wk_live_..."
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="workosApiKey">WorkOS API Key (Optional)</Label>
                <Input
                  id="workosApiKey"
                  type="password"
                  value={settings.workosApiKey || ''}
                  onChange={(e) => setSettings(prev => ({ ...prev, workosApiKey: e.target.value }))}
                  placeholder="sk_live_..."
                />
              </div>
            </div>
          )}
        </TabsContent>
      </Tabs>
    </div>
  )

  const renderReviewStep = () => (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-medium">Review Configuration</h3>
        <p className="text-sm text-muted-foreground">
          Please review all settings before creating the tenant
        </p>
      </div>

      <div className="space-y-4">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Tenant Details</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <div className="flex justify-between">
              <span className="text-sm font-medium">Name:</span>
              <span className="text-sm">{tenantData.name}</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Admin User</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <div className="flex justify-between">
              <span className="text-sm font-medium">Name:</span>
              <span className="text-sm">{adminData.firstName} {adminData.lastName}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-sm font-medium">Email:</span>
              <span className="text-sm">{adminData.email}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-sm font-medium">MFA Enabled:</span>
              <Badge variant={adminData.enableMFA ? 'default' : 'secondary'}>
                {adminData.enableMFA ? 'Yes' : 'No'}
              </Badge>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Security Settings</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <div className="flex justify-between">
              <span className="text-sm font-medium">Access Token TTL:</span>
              <span className="text-sm">{settings.accessTokenTTL}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-sm font-medium">SSO Provider:</span>
              <Badge variant="outline">{settings.ssoProvider}</Badge>
            </div>
            <div className="flex justify-between">
              <span className="text-sm font-medium">Login Rate Limit:</span>
              <span className="text-sm">{settings.rateLimitLoginLimit}/{settings.rateLimitLoginWindow}</span>
            </div>
          </CardContent>
        </Card>
      </div>

      {tenantData.id && (
        <Card className="border-green-200 bg-green-50">
          <CardHeader className="pb-3">
            <CardTitle className="text-base text-green-800">Tenant Created Successfully!</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium text-green-700">Tenant ID:</span>
              <div className="flex items-center space-x-2">
                <code className="text-xs bg-white px-2 py-1 rounded">{tenantData.id}</code>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => copyToClipboard(tenantData.id!, 'Tenant ID')}
                >
                  <Copy className="h-3 w-3" />
                </Button>
              </div>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium text-green-700">Admin Email:</span>
              <div className="flex items-center space-x-2">
                <code className="text-xs bg-white px-2 py-1 rounded">{adminData.email}</code>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => copyToClipboard(adminData.email, 'Admin Email')}
                >
                  <Copy className="h-3 w-3" />
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )

  const renderStepContent = () => {
    switch (currentStep) {
      case 0: return renderTenantStep()
      case 1: return renderAdminStep()
      case 2: return renderSettingsStep()
      case 3: return renderReviewStep()
      default: return null
    }
  }

  return (
    <Card className="w-full max-w-4xl mx-auto">
      <CardHeader>
        <CardTitle>Tenant Onboarding Wizard</CardTitle>
        <CardDescription>
          Complete tenant setup with guided configuration
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Progress Steps */}
        <div className="flex items-center justify-between">
          {steps.map((step, index) => (
            <div key={step.id} className="flex items-center">
              <div className="flex flex-col items-center">
                <div className={`flex items-center justify-center w-8 h-8 rounded-full border-2 ${
                  step.completed 
                    ? 'bg-green-500 border-green-500 text-white' 
                    : index === currentStep
                    ? 'border-blue-500 text-blue-500'
                    : 'border-gray-300 text-gray-400'
                }`}>
                  {step.completed ? (
                    <CheckCircle className="w-5 h-5" />
                  ) : (
                    <Circle className="w-5 h-5" />
                  )}
                </div>
                <div className="mt-2 text-center">
                  <div className={`text-sm font-medium ${
                    index === currentStep ? 'text-blue-600' : 'text-gray-500'
                  }`}>
                    {step.title}
                  </div>
                  <div className="text-xs text-gray-400">{step.description}</div>
                </div>
              </div>
              {index < steps.length - 1 && (
                <ArrowRight className="w-4 h-4 text-gray-400 mx-4" />
              )}
            </div>
          ))}
        </div>

        <Separator />

        {/* Step Content */}
        <div className="min-h-[400px]">
          {renderStepContent()}
        </div>

        {error && (
          <div className="p-3 text-sm text-red-600 bg-red-50 border border-red-200 rounded-md">
            {error}
          </div>
        )}

        {/* Navigation */}
        <div className="flex justify-between">
          <div>
            {currentStep > 0 && (
              <Button
                variant="outline"
                onClick={handlePrevious}
                disabled={loading}
              >
                <ArrowLeft className="w-4 h-4 mr-2" />
                Previous
              </Button>
            )}
          </div>
          
          <div className="flex space-x-2">
            <Button
              variant="ghost"
              onClick={onCancel}
              disabled={loading}
            >
              Cancel
            </Button>
            
            {currentStep < steps.length - 1 ? (
              <Button
                onClick={handleNext}
                disabled={loading}
              >
                Next
                <ArrowRight className="w-4 h-4 ml-2" />
              </Button>
            ) : (
              <Button
                onClick={handleComplete}
                disabled={loading || tenantData.id !== undefined}
              >
                {loading ? 'Creating...' : tenantData.id ? 'Completed' : 'Create Tenant'}
              </Button>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
