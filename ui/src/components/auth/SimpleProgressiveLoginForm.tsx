import { useState, useEffect, useRef } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Eye, EyeOff, ArrowLeft, Loader2 } from 'lucide-react'
import { useToast } from '@/lib/toast'
import { getClient } from '@/lib/sdk'
import { useTenant } from '@/lib/tenant'

interface EmailDiscoveryResponse {
  found: boolean
  has_tenant: boolean
  tenant_id?: string
  tenant_name?: string
  user_exists: boolean
  suggestions?: string[]
}

interface ProgressiveLoginFormProps {
  onLoginSuccess?: (userData: any) => void
}

export default function SimpleProgressiveLoginForm({
  onLoginSuccess
}: ProgressiveLoginFormProps) {
  const [step, setStep] = useState<'email' | 'password' | 'options' | 'mfa'>('email')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [emailDiscovering, setEmailDiscovering] = useState(false)
  const [discoveryResult, setDiscoveryResult] = useState<EmailDiscoveryResponse | null>(null)
  const [emailError, setEmailError] = useState('')
  const [loginError, setLoginError] = useState('')
  const [loginLoading, setLoginLoading] = useState(false)
  const [challengeToken, setChallengeToken] = useState<string | null>(null)
  const [challengeMethods, setChallengeMethods] = useState<string[]>([])
  const [challengeMethod, setChallengeMethod] = useState<'totp' | 'backup_code'>('totp')
  const [challengeCode, setChallengeCode] = useState('')
  const [challengeLoading, setChallengeLoading] = useState(false)
  const [challengeError, setChallengeError] = useState<string | null>(null)
  const { show: showToast } = useToast()
  const passwordInputRef = useRef<HTMLInputElement>(null)
  const { tenantId, setTenantId, tenantName } = useTenant()

  // Hydrate tenant from URL if present
  useEffect(() => {
    try {
      const usp = new URLSearchParams(window.location.search)
      const tid = usp.get('tenant_id')
      if (tid && !tenantId) setTenantId(tid)
    } catch {}
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Auto-focus password input when step changes to password
  useEffect(() => {
    if (step === 'password' && passwordInputRef.current) {
      passwordInputRef.current.focus()
    }
  }, [step])

  const validateEmail = (email: string) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    return emailRegex.test(email)
  }

  const handleEmailChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const newEmail = e.target.value
    setEmail(newEmail)
    
    // Clear error when user starts typing
    if (emailError) {
      setEmailError('')
    }
  }

  const discoverEmail = async (emailToCheck: string) => {
    if (!validateEmail(emailToCheck)) {
      setEmailError('Please enter a valid email address')
      return
    }

    setEmailError('')
    setEmailDiscovering(true)

    try {
      const client = getClient()
      const res = await client.emailDiscover({ email: emailToCheck, tenant_id: tenantId || undefined })
      if (!(res.meta.status >= 200 && res.meta.status < 300)) {
        throw new Error('Failed to check email')
      }
      const result: EmailDiscoveryResponse = res.data as any
      setDiscoveryResult(result)

      if (result.found && result.user_exists) {
        setStep('password')
      } else {
        setStep('options')
      }
    } catch (error: any) {
      const msg = error?.message || ''
      if (msg.includes('Guard base URL') || msg.toLowerCase().includes('not configured')) {
        setEmailError('Guard configuration not found')
      } else {
        setEmailError('Failed to check email. Please try again.')
      }
      console.error('Email discovery error:', error)
    } finally {
      setEmailDiscovering(false)
    }
  }

  const handleEmailSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    const trimmedEmail = email.trim()
    
    if (!validateEmail(trimmedEmail)) {
      setEmailError('Please enter a valid email address')
      return
    }
    
    if (trimmedEmail) {
      discoverEmail(trimmedEmail)
    }
  }

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!password.trim()) return

    setLoginLoading(true)

    try {
      const client = getClient()
      const tid = discoveryResult?.tenant_id || tenantId

      const res = await client.passwordLogin({
        email: email.trim(),
        password: password.trim(),
        tenant_id: tid || undefined
      })

      if (res.meta.status >= 200 && res.meta.status < 300) {
        if (res.data && (res.data as any)?.challenge_token) {
          const token = (res.data as any).challenge_token as string
          const methods = Array.isArray((res.data as any).methods)
            ? ((res.data as any).methods as string[])
            : []
          setChallengeToken(token)
          setChallengeMethods(methods)
          if (methods.includes('totp')) {
            setChallengeMethod('totp')
          } else if (methods.includes('backup_code')) {
            setChallengeMethod('backup_code')
          }
          setChallengeCode('')
          setChallengeError(null)
          setStep('mfa')
          showToast({
            title: 'Additional verification required',
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
        setLoginError('Invalid credentials. Please try again.')
      }
    } catch (error: any) {
      setLoginError(error?.message || 'Login failed. Please try again.')
      console.error('Login error:', error)
    } finally {
      setLoginLoading(false)
    }
  }

  const handleMfaSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!challengeToken) return
    if (!challengeCode.trim()) {
      setChallengeError('Please enter a verification code')
      return
    }

    setChallengeLoading(true)
    setChallengeError(null)

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
        setChallengeError('Verification failed. Try again.')
      }
    } catch (error: any) {
      const message = error?.message || 'Verification failed. Try again.'
      setChallengeError(message)
      console.error('MFA verify error:', error)
    } finally {
      setChallengeLoading(false)
    }
  }

  const handleSuggestionClick = (suggestion: string) => {
    setEmail(suggestion)
    setEmailError('')
    discoverEmail(suggestion)
  }

  const handleCreateTenant = () => {
    if (typeof window !== 'undefined') {
      const usp = new URLSearchParams()
      if (email) usp.set('email', email)
      // Derive a default org name from email domain (optional)
      try {
        const at = email.indexOf('@')
        if (at > 0) {
          const domain = email.slice(at + 1).split('.')?.[0] || ''
          if (domain) usp.set('name', domain)
        }
      } catch {}
      window.location.href = `/tenant/create?${usp.toString()}`
    }
  }

  const handleJoinOrganization = () => {
    showToast({
      title: 'Contact your organization',
      description: 'Please contact your organization administrator for an invitation',
      variant: 'info'
    })
  }

  const handleCreateAccount = () => {
    if (typeof window !== 'undefined') {
      const usp = new URLSearchParams()
      if (email) usp.set('email', email)
      const tid = discoveryResult?.tenant_id || tenantId
      if (tid) usp.set('tenant_id', tid)
      window.location.href = `/signup?${usp.toString()}`
    }
  }

  const goBackToEmail = () => {
    setStep('email')
    setPassword('')
    setLoginError('')
    setDiscoveryResult(null)
  }

  return (
    <div data-testid="login-form" className="w-full max-w-md space-y-4">
      <div data-testid="status-live-region" aria-live="polite" className="sr-only">
        {step === 'email' && 'Enter your email address'}
        {step === 'password' && 'Email verified. Please enter your password.'}
        {step === 'options' && 'Choose how to proceed'}
      </div>

      {/* Email Step */}
      {step === 'email' && (
        <form onSubmit={handleEmailSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="email">Email Address</Label>
            <Input
              id="email"
              data-testid="email-input"
              type="text"
              value={email}
              onChange={handleEmailChange}
              placeholder="Enter your email"
              aria-label="Email Address"
              disabled={emailDiscovering}
              required
            />
            {emailError && (
              <div data-testid="email-error" className="text-sm text-red-600">
                {emailError}
              </div>
            )}
          </div>
          <div className="space-y-1">
            <Label htmlFor="tenant-id">Tenant ID (optional)</Label>
            <Input
              id="tenant-id"
              data-testid="tenant-id-input"
              type="text"
              value={tenantId || ''}
              onChange={(e) => setTenantId(e.target.value)}
              placeholder="tenant UUID (if you belong to multiple tenants)"
              aria-label="Tenant ID"
              disabled={emailDiscovering}
            />
            <div className="text-xs text-muted-foreground">
              Provide to choose which tenant to sign into. Leave blank if you only have one.
            </div>
          </div>
          <Button
            type="submit"
            data-testid="continue-button"
            disabled={!email.trim() || emailDiscovering}
            className="w-full"
            aria-label="Continue with email"
          >
            {emailDiscovering ? (
              <>
                <Loader2 data-testid="loading-spinner" className="mr-2 h-4 w-4 animate-spin" />
                Checking email...
              </>
            ) : (
              'Continue'
            )}
          </Button>
        </form>
      )}

      {/* Password Step */}
      {step === 'password' && discoveryResult && (
        <div className="space-y-4">
          <div data-testid="email-success" className="text-sm text-green-600">
            ✓ {email}
          </div>
          {discoveryResult.tenant_name && (
            <div data-testid="tenant-info" className="text-sm text-gray-600">
              Signing in to {discoveryResult.tenant_name}
            </div>
          )}
          {discoveryResult.suggestions && discoveryResult.suggestions.length > 0 && (
            <div data-testid="multiple-orgs-info" className="text-sm text-blue-600">
              Your email was found in multiple organizations. You also have access to: {discoveryResult.suggestions.join(', ')}
            </div>
          )}
          
          <form onSubmit={handleLogin} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <div className="relative">
                <Input
                  id="password"
                  ref={passwordInputRef}
                  data-testid="password-input"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your password"
                  aria-label="Password"
                  disabled={loginLoading}
                  required
                />
                <Button
                  type="button"
                  data-testid="toggle-password-button"
                  variant="ghost"
                  size="sm"
                  className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                  onClick={() => setShowPassword(!showPassword)}
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? (
                    <EyeOff className="h-4 w-4" />
                  ) : (
                    <Eye className="h-4 w-4" />
                  )}
                </Button>
              </div>
              {loginError && (
                <div data-testid="login-error" className="text-sm text-red-600">
                  {loginError}
                </div>
              )}
              <a
                href="/forgot-password"
                data-testid="forgot-password-link"
                className="text-sm text-blue-600 hover:underline"
              >
                Forgot password?
              </a>
            </div>
            
            <div className="flex gap-2">
              <Button
                type="button"
                data-testid="change-email-button"
                variant="outline"
                onClick={goBackToEmail}
                disabled={loginLoading}
              >
                <ArrowLeft className="mr-2 h-4 w-4" />
                Change Email
              </Button>
              <Button
                type="submit"
                data-testid="signin-button"
                disabled={!password.trim() || loginLoading}
                className="flex-1"
              >
                {loginLoading ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Signing in...
                  </>
                ) : (
                  'Sign In'
                )}
              </Button>
            </div>
          </form>
        </div>
      )}

      {/* MFA Challenge Step */}
      {step === 'mfa' && challengeToken && (
        <form onSubmit={handleMfaSubmit} className="space-y-4" data-testid="mfa-challenge-form">
          <div className="space-y-2">
            <div className="text-sm text-gray-600">
              Additional verification is required for {email}.
            </div>
            {challengeMethods.length > 1 && (
              <div className="space-y-1" data-testid="mfa-method-selector">
                <div className="text-sm font-medium">Choose a method</div>
                <div className="flex gap-2">
                  {challengeMethods.map((method) => (
                    <Button
                      key={method}
                      type="button"
                      variant={challengeMethod === method ? 'default' : 'outline'}
                      size="sm"
                      disabled={challengeLoading}
                      onClick={() => setChallengeMethod(method as 'totp' | 'backup_code')}
                    >
                      {method === 'totp' ? 'Authenticator app' : 'Backup code'}
                    </Button>
                  ))}
                </div>
              </div>
            )}
            <Label htmlFor="mfa-code">
              {challengeMethod === 'backup_code' ? 'Backup code' : 'Authenticator code'}
            </Label>
            <Input
              id="mfa-code"
              data-testid="mfa-code-input"
              value={challengeCode}
              onChange={(e) => setChallengeCode(e.target.value)}
              placeholder={challengeMethod === 'backup_code' ? 'Enter backup code' : '123456'}
              autoComplete="one-time-code"
              disabled={challengeLoading}
            />
            {challengeError && (
              <div data-testid="mfa-error" className="text-sm text-red-600">
                {challengeError}
              </div>
            )}
          </div>
          <div className="flex gap-2">
            <Button
              type="button"
              variant="outline"
              onClick={() => {
                setChallengeToken(null)
                setChallengeCode('')
                setChallengeError(null)
                setStep('password')
              }}
              disabled={challengeLoading}
            >
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back
            </Button>
            <Button
              type="submit"
              className="flex-1"
              disabled={challengeLoading || !challengeCode.trim()}
            >
              {challengeLoading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Verifying...
                </>
              ) : (
                'Verify'
              )}
            </Button>
          </div>
        </form>
      )}

      {/* Options Step */}
      {step === 'options' && discoveryResult && (
        <div className="space-y-4">
          <div data-testid="email-not-found" className="text-sm text-gray-600">
            We couldn't find an account for {email}
          </div>

          {discoveryResult.suggestions && discoveryResult.suggestions.length > 0 && (
            <div data-testid="email-suggestions" className="space-y-2">
              <div className="text-sm font-medium">Did you mean:</div>
              {discoveryResult.suggestions.map((suggestion) => (
                <Button
                  key={suggestion}
                  data-testid={`suggestion-${suggestion}`}
                  variant="outline"
                  size="sm"
                  onClick={() => handleSuggestionClick(suggestion)}
                  className="mr-2"
                >
                  {suggestion}
                </Button>
              ))}
            </div>
          )}

          <div className="space-y-2">
            {discoveryResult.has_tenant ? (
              <Button
                data-testid="create-account-button"
                onClick={handleCreateAccount}
                className="w-full"
              >
                Create Account in {discoveryResult.tenant_name || tenantName || discoveryResult.tenant_id}
              </Button>
            ) : (
              <>
                <Button
                  data-testid="create-tenant-button"
                  onClick={handleCreateTenant}
                  className="w-full"
                >
                  Create New Organization
                </Button>
                <Button
                  data-testid="join-organization-button"
                  variant="outline"
                  onClick={handleJoinOrganization}
                  className="w-full"
                >
                  Join Existing Organization
                </Button>
              </>
            )}
          </div>

          <Button
            type="button"
            data-testid="change-email-button"
            variant="ghost"
            onClick={goBackToEmail}
            className="w-full"
          >
            <ArrowLeft className="mr-2 h-4 w-4" />
            Try Different Email
          </Button>
        </div>
      )}
    </div>
  )
}
