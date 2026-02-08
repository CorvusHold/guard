import { useState, useEffect, useCallback } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Separator } from '@/components/ui/separator'
import { Eye, EyeOff, ArrowLeft, Loader2, Mail, Key, Building2, X, Wand2, Globe } from 'lucide-react'
import { useToast } from '@/lib/toast'
import { getClient } from '@/lib/sdk'
import type { LoginOptionsResp, SsoProviderOption } from '@/lib/sdk'
import { useTenant } from '@/lib/tenant'

interface UniversalLoginProps {
  onLoginSuccess?: (userData: unknown) => void
  onSignupClick?: () => void
  showSignupLink?: boolean
  className?: string
}

type LoginStep = 'email' | 'options' | 'password' | 'mfa' | 'magic_link_sent'

// Provider logo mapping - using simple SVG icons inline
const providerLogos: Record<string, string> = {
  okta: '🔐',
  azure: '☁️',
  microsoft: '🪟',
  google: '🔍',
  github: '🐙',
  onelogin: '1️⃣',
  auth0: '🔒',
}

function getProviderIcon(name: string): string {
  const nameLower = name.toLowerCase()
  for (const [key, icon] of Object.entries(providerLogos)) {
    if (nameLower.includes(key)) return icon
  }
  return '🔑'
}

export default function UniversalLogin({
  onLoginSuccess,
  onSignupClick,
  showSignupLink = true,
  className
}: UniversalLoginProps) {
  const [step, setStep] = useState<LoginStep>('email')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [loginOptions, setLoginOptions] = useState<LoginOptionsResp | null>(null)
  const [selectedTenantId, setSelectedTenantId] = useState<string | null>(null)
  const [challengeToken, setChallengeToken] = useState<string | null>(null)
  const [challengeMethods, setChallengeMethods] = useState<string[]>([])
  const [challengeMethod, setChallengeMethod] = useState<'totp' | 'backup_code'>('totp')
  const [challengeCode, setChallengeCode] = useState('')
  const { show: showToast } = useToast()
  const { tenantId, tenantName, setTenantId, setTenantName } = useTenant()

  // Hydrate tenant from URL if present
  useEffect(() => {
    try {
      const usp = new URLSearchParams(window.location.search)
      const tid = usp.get('tenant_id')
      if (tid && !tenantId) setTenantId(tid)
    } catch {
      // ignore
    }
  }, [tenantId, setTenantId])

  const validateEmail = (email: string) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    return emailRegex.test(email)
  }

  const fetchLoginOptions = useCallback(async (emailToCheck: string) => {
    if (!validateEmail(emailToCheck)) {
      setError('Please enter a valid email address')
      return
    }

    setLoading(true)
    setError(null)

    try {
      const client = getClient()
      const res = await client.getLoginOptions({
        email: emailToCheck.trim().toLowerCase(),
        tenant_id: tenantId || undefined
      })

      if (res.meta.status >= 200 && res.meta.status < 300 && res.data) {
        setLoginOptions(res.data)

        // Resolve tenant selection
        const tenants = res.data.tenants
        let resolvedTenantId = res.data.tenant_id
        if (!resolvedTenantId && tenants?.length === 1) {
          resolvedTenantId = tenants[0].id
        }
        setSelectedTenantId(resolvedTenantId || null)

        // Update tenant context if discovered
        if (resolvedTenantId && !tenantId) {
          setTenantId(resolvedTenantId)
          const resolvedTenantName =
            tenants?.find((t) => t.id === resolvedTenantId)?.name || res.data.tenant_name || resolvedTenantId
          setTenantName(resolvedTenantName || '')
        }

        // Determine next step based on options
        const hasMultipleTenants = (tenants?.length || 0) > 1 && !resolvedTenantId
        if (res.data.domain_matched_sso) {
          // Domain matches SSO - show SSO option prominently
          setStep('options')
        } else if (res.data.user_exists && res.data.password_enabled && !hasMultipleTenants) {
          // Existing user with password - go to password
          setStep('password')
        } else if (res.data.sso_providers.length > 0 || hasMultipleTenants) {
          // SSO available - show options
          setStep('options')
        } else if (res.data.password_enabled) {
          // Only password available
          setStep('password')
        } else {
          setError('No login methods available for this email')
        }
      } else {
        setError('Failed to check login options')
      }
    } catch (e: unknown) {
      const err = e as Error
      setError(err?.message || 'Failed to check login options')
    } finally {
      setLoading(false)
    }
  }, [tenantId, setTenantId])

  const handleEmailSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    const trimmedEmail = email.trim()
    if (trimmedEmail) {
      fetchLoginOptions(trimmedEmail)
    }
  }

  const handlePasswordLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!password.trim()) return

    setLoading(true)
    setError(null)

    try {
      const client = getClient()
      const tid = loginOptions?.tenant_id || tenantId

      const res = await client.passwordLogin({
        email: email.trim(),
        password: password.trim(),
        tenant_id: tid || undefined
      })

      if (res.meta.status >= 200 && res.meta.status < 300) {
        if (res.data && (res.data as { challenge_token?: string })?.challenge_token) {
          const data = res.data as { challenge_token: string; methods?: string[] }
          setChallengeToken(data.challenge_token)
          setChallengeMethods(data.methods || [])
          if (data.methods?.includes('totp')) {
            setChallengeMethod('totp')
          } else if (data.methods?.includes('backup_code')) {
            setChallengeMethod('backup_code')
          }
          setChallengeCode('')
          setStep('mfa')
          showToast({
            title: 'Verification required',
            description: 'Enter your authentication code to continue.',
            variant: 'info'
          })
        } else {
          const meRes = await client.me()
          if (meRes.meta.status === 200 && onLoginSuccess) {
            onLoginSuccess(meRes.data)
          }
          showToast({
            title: 'Login successful',
            description: 'Welcome back!',
            variant: 'success'
          })
        }
      } else {
        setError('Invalid credentials. Please try again.')
      }
    } catch (e: unknown) {
      const err = e as Error
      setError(err?.message || 'Login failed. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  const handleMfaSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!challengeToken || !challengeCode.trim()) return

    setLoading(true)
    setError(null)

    try {
      const client = getClient()
      const res = await client.mfaVerify({
        challenge_token: challengeToken,
        method: challengeMethod,
        code: challengeCode.trim()
      })

      if (res.meta.status >= 200 && res.meta.status < 300) {
        const meRes = await client.me()
        if (meRes.meta.status === 200 && onLoginSuccess) {
          onLoginSuccess(meRes.data)
        }
        showToast({
          title: 'Verification successful',
          description: 'You are now signed in.',
          variant: 'success'
        })
      } else {
        setError('Verification failed. Please try again.')
      }
    } catch (e: unknown) {
      const err = e as Error
      setError(err?.message || 'Verification failed. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  const handleSSOLogin = (provider: SsoProviderOption) => {
    if (provider.login_url) {
      // Add redirect URL for callback
      const redirectUrl = `${window.location.origin}/auth/callback`
      const url = new URL(provider.login_url)
      url.searchParams.set('redirect_url', redirectUrl)
      window.location.href = url.toString()
    }
  }

  const handleMagicLinkSend = async () => {
    setLoading(true)
    setError(null)
    try {
      const client = getClient()
      const tid = loginOptions?.tenant_id || selectedTenantId || tenantId
      await client.magicSend({
        email: email.trim().toLowerCase(),
        tenant_id: tid || '',
        redirect_url: `${window.location.origin}/auth/callback`
      })
      setStep('magic_link_sent')
      showToast({
        title: 'Magic link sent',
        description: 'Check your email for a sign-in link.',
        variant: 'success'
      })
    } catch (e: unknown) {
      const err = e as Error
      setError(err?.message || 'Failed to send magic link')
    } finally {
      setLoading(false)
    }
  }

  const goBackToEmail = () => {
    setStep('email')
    setPassword('')
    setError(null)
    setLoginOptions(null)
    setSelectedTenantId(null)
    setChallengeToken(null)
    setChallengeCode('')
  }

  const clearTenantSelection = () => {
    setSelectedTenantId(null)
    setTenantId('')
    setTenantName('')
    setLoginOptions(null)
    setError(null)
  }

  return (
    <Card className={`w-full max-w-md ${className || ''}`} data-testid="universal-login">
      <CardHeader className="space-y-1 text-center">
        <CardTitle className="text-2xl font-bold">Welcome</CardTitle>
        <CardDescription>
          {step === 'email' && 'Enter your email to continue'}
          {step === 'options' && 'Choose how to sign in'}
          {step === 'password' && 'Enter your password'}
          {step === 'mfa' && 'Verify your identity'}
          {step === 'magic_link_sent' && 'Check your inbox'}
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-4">
        {error && (
          <Alert variant="destructive" data-testid="login-error">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {/* Email Step */}
        {step === 'email' && (
          <form onSubmit={handleEmailSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  id="email"
                  type="email"
                  placeholder="name@example.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="pl-10"
                  disabled={loading}
                  data-testid="email-input"
                  autoComplete="email"
                  autoFocus
                />
              </div>
            </div>
            {(tenantId || tenantName) && (
              <div className="flex items-center justify-between rounded-md border px-3 py-2 text-sm">
                <div className="flex items-center gap-2">
                  <Building2 className="h-4 w-4 text-muted-foreground" />
                  <div className="flex flex-col">
                    <span className="font-medium">Organization selected</span>
                    <span className="text-muted-foreground text-xs">
                      {tenantName || tenantId}
                    </span>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={clearTenantSelection}
                  className="text-muted-foreground hover:text-foreground"
                  data-testid="clear-tenant-selection"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
            )}
            <Button
              type="submit"
              className="w-full"
              disabled={!email.trim() || loading}
              data-testid="continue-button"
            >
              {loading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Checking...
                </>
              ) : (
                'Continue'
              )}
            </Button>

            {showSignupLink && (
              <div className="text-center text-sm text-muted-foreground">
                Don't have an account?{' '}
                <button
                  type="button"
                  onClick={onSignupClick}
                  className="text-primary hover:underline"
                  data-testid="signup-link"
                >
                  Sign up
                </button>
              </div>
            )}
          </form>
        )}

        {/* Options Step - Show available login methods */}
        {step === 'options' && loginOptions && (
          <div className="space-y-4">
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <span className="truncate">{email}</span>
              <button
                type="button"
                onClick={goBackToEmail}
                className="text-primary hover:underline shrink-0"
              >
                Change
              </button>
            </div>

            {loginOptions.tenant_name && (
              <div className="flex items-center gap-2 text-sm">
                <Building2 className="h-4 w-4 text-muted-foreground" />
                <span>{loginOptions.tenant_name}</span>
              </div>
            )}

            {/* Tenant selection when multiple tenants are returned */}
            {loginOptions.tenants?.length ? (
              <div className="space-y-2">
                <Label>Choose organization</Label>
                <div className="space-y-2">
                  {loginOptions.tenants?.map((t) => (
                    <Button
                      key={t.id}
                      type="button"
                      variant={selectedTenantId === t.id ? 'default' : 'outline'}
                      className="w-full justify-start"
                      onClick={() => {
                        setSelectedTenantId(t.id)
                        setTenantId(t.id)
                        setError(null)
                        setTenantName(t.name || t.id)
                      }}
                      data-testid={`tenant-option-${t.id}`}
                    >
                      <Building2 className="mr-2 h-4 w-4" />
                      {t.name || t.id}
                    </Button>
                  ))}
                </div>
                <Button
                  type="button"
                  variant="ghost"
                  className="w-full justify-start text-sm text-muted-foreground"
                  onClick={clearTenantSelection}
                  data-testid="tenant-clear-button"
                >
                  <X className="mr-2 h-4 w-4" />
                  Choose a different organization
                </Button>
              </div>
            ) : null}

            {/* Domain-matched SSO (recommended) */}
            {loginOptions.domain_matched_sso && (
              <div className="space-y-2">
                <p className="text-sm font-medium text-green-600">
                  ✓ Your organization uses SSO
                </p>
                <Button
                  type="button"
                  className="w-full"
                  onClick={() => handleSSOLogin(loginOptions.domain_matched_sso!)}
                  data-testid="sso-recommended-button"
                >
                  <span className="mr-2">{getProviderIcon(loginOptions.domain_matched_sso.name)}</span>
                  Continue with {loginOptions.domain_matched_sso.name}
                </Button>
              </div>
            )}

            {/* Other SSO providers */}
            {loginOptions.sso_providers.length > 0 && !loginOptions.domain_matched_sso && (
              <div className="space-y-2">
                {loginOptions.sso_providers.map((provider: SsoProviderOption) => (
                  <Button
                    key={provider.slug}
                    type="button"
                    variant="outline"
                    className="w-full justify-start"
                    onClick={() => handleSSOLogin(provider)}
                    data-testid={`sso-button-${provider.slug}`}
                  >
                    <span className="mr-2">{getProviderIcon(provider.name)}</span>
                    Continue with {provider.name}
                  </Button>
                ))}
              </div>
            )}

            {/* SSO required notice */}
            {loginOptions.sso_required && (
              <p className="text-sm text-muted-foreground text-center">
                Your organization requires SSO sign-in.
              </p>
            )}

            {/* Password and magic link options */}
            {(!loginOptions.sso_required && (loginOptions.password_enabled || loginOptions.magic_link_enabled)) && (
              <>
                {(loginOptions.sso_providers.length > 0 || loginOptions.domain_matched_sso) && (
                  <div className="relative">
                    <div className="absolute inset-0 flex items-center">
                      <Separator className="w-full" />
                    </div>
                    <div className="relative flex justify-center text-xs uppercase">
                      <span className="bg-background px-2 text-muted-foreground">
                        Or continue with
                      </span>
                    </div>
                  </div>
                )}
                {loginOptions.password_enabled && (
                  <Button
                    type="button"
                    variant={loginOptions.domain_matched_sso ? 'outline' : 'default'}
                    className="w-full"
                    onClick={() => {
                      const tenantCount = loginOptions?.tenants?.length ?? 0
                      if (!selectedTenantId && tenantCount > 1) {
                        setError('Please choose an organization to continue.')
                        return
                      }
                      setStep('password')
                    }}
                    data-testid="password-option-button"
                  >
                    <Key className="mr-2 h-4 w-4" />
                    Password
                  </Button>
                )}
                {loginOptions.magic_link_enabled && (
                  <Button
                    type="button"
                    variant="outline"
                    className="w-full"
                    onClick={() => {
                      const tenantCount = loginOptions?.tenants?.length ?? 0
                      if (!selectedTenantId && tenantCount > 1) {
                        setError('Please choose an organization to continue.')
                        return
                      }
                      handleMagicLinkSend()
                    }}
                    disabled={loading}
                    data-testid="magic-link-button"
                  >
                    {loading ? (
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    ) : (
                      <Wand2 className="mr-2 h-4 w-4" />
                    )}
                    Email magic link
                  </Button>
                )}
              </>
            )}

            <Button
              type="button"
              variant="ghost"
              className="w-full"
              onClick={goBackToEmail}
            >
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back
            </Button>
          </div>
        )}

        {/* Password Step */}
        {step === 'password' && (
          <form onSubmit={handlePasswordLogin} className="space-y-4">
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <span className="truncate">{email}</span>
              <button
                type="button"
                onClick={goBackToEmail}
                className="text-primary hover:underline shrink-0"
              >
                Change
              </button>
            </div>

            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <div className="relative">
                <Key className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  placeholder="Enter your password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="pl-10 pr-10"
                  disabled={loading}
                  data-testid="password-input"
                  autoComplete="current-password"
                  autoFocus
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                  tabIndex={-1}
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>

            <div className="flex justify-end">
              <a
                href="/forgot-password"
                className="text-sm text-primary hover:underline"
                data-testid="forgot-password-link"
              >
                Forgot password?
              </a>
            </div>

            <Button
              type="submit"
              className="w-full"
              disabled={!password.trim() || loading}
              data-testid="signin-button"
            >
              {loading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Signing in...
                </>
              ) : (
                'Sign in'
              )}
            </Button>

            <Button
              type="button"
              variant="ghost"
              className="w-full"
              onClick={goBackToEmail}
            >
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back
            </Button>
          </form>
        )}

        {/* MFA Step */}
        {step === 'mfa' && challengeToken && (
          <form onSubmit={handleMfaSubmit} className="space-y-4">
            <div className="text-sm text-muted-foreground">
              Enter the verification code from your authenticator app.
            </div>

            {challengeMethods.length > 1 && (
              <div className="flex gap-2">
                {challengeMethods.map((method) => (
                  <Button
                    key={method}
                    type="button"
                    variant={challengeMethod === method ? 'default' : 'outline'}
                    size="sm"
                    onClick={() => setChallengeMethod(method as 'totp' | 'backup_code')}
                    disabled={loading}
                  >
                    {method === 'totp' ? 'Authenticator' : 'Backup code'}
                  </Button>
                ))}
              </div>
            )}

            <div className="space-y-2">
              <Label htmlFor="mfa-code">
                {challengeMethod === 'backup_code' ? 'Backup code' : 'Verification code'}
              </Label>
              <Input
                id="mfa-code"
                type="text"
                placeholder={challengeMethod === 'backup_code' ? 'Enter backup code' : '123456'}
                value={challengeCode}
                onChange={(e) => setChallengeCode(e.target.value)}
                disabled={loading}
                data-testid="mfa-code-input"
                autoComplete="one-time-code"
                autoFocus
              />
            </div>

            <Button
              type="submit"
              className="w-full"
              disabled={!challengeCode.trim() || loading}
              data-testid="mfa-verify-button"
            >
              {loading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Verifying...
                </>
              ) : (
                'Verify'
              )}
            </Button>

            <Button
              type="button"
              variant="ghost"
              className="w-full"
              onClick={() => {
                setChallengeToken(null)
                setChallengeCode('')
                setStep('password')
              }}
            >
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back
            </Button>
          </form>
        )}

        {/* Magic Link Sent Step */}
        {step === 'magic_link_sent' && (
          <div className="space-y-4 text-center">
            <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-primary/10">
              <Mail className="h-6 w-6 text-primary" />
            </div>
            <div className="space-y-2">
              <p className="text-sm font-medium">
                We sent a sign-in link to
              </p>
              <p className="text-sm font-semibold">{email}</p>
              <p className="text-xs text-muted-foreground">
                Click the link in your email to sign in. The link expires in 15 minutes.
              </p>
            </div>
            <div className="space-y-2">
              <Button
                type="button"
                variant="outline"
                className="w-full"
                onClick={handleMagicLinkSend}
                disabled={loading}
                data-testid="resend-magic-link"
              >
                {loading ? (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                ) : (
                  <Wand2 className="mr-2 h-4 w-4" />
                )}
                Resend magic link
              </Button>
              <Button
                type="button"
                variant="ghost"
                className="w-full"
                onClick={goBackToEmail}
              >
                <ArrowLeft className="mr-2 h-4 w-4" />
                Back to sign in
              </Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
