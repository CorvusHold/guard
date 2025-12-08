import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { getClient } from '@/lib/sdk'
import { useTenant } from '@/lib/tenant'
import { useToast } from '@/lib/toast'
import { isTenantSelectionRequired, type TenantOption } from '../../../../sdk/ts/src/client'
import { isApiError } from '../../../../sdk/ts/src/errors'

export default function ForgotPassword() {
  const [email, setEmail] = useState('')
  const [loading, setLoading] = useState(false)
  const [sent, setSent] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [tenantOptions, setTenantOptions] = useState<TenantOption[] | null>(null)
  const [selectedTenantId, setSelectedTenantId] = useState<string>('')
  const { tenantId, setTenantId } = useTenant()
  const { show } = useToast()

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!email.trim()) return
    setError(null)
    setLoading(true)
    try {
      const client = getClient()
      const res = await client.passwordResetRequest({
        tenant_id: selectedTenantId || tenantId || undefined,
        email: email.trim()
      })
      if (res.meta.status === 202) {
        setSent(true)
        show({ variant: 'success', title: 'Reset email sent', description: 'Check your inbox for the reset link.' })
      } else {
        const errMsg = (res.data as any)?.error || 'Failed to send reset email'
        setError(errMsg)
        show({ variant: 'error', title: 'Failed to send reset email', description: errMsg })
      }
    } catch (err: any) {
      // Check if this is a 409 tenant selection required error
      if (isApiError(err) && err.status === 409 && isTenantSelectionRequired(err.raw)) {
        setTenantOptions(err.raw.tenants)
        setError(null)
      } else {
        setError(err?.message || String(err))
        show({ variant: 'error', title: 'Error', description: err?.message || String(err) })
      }
    } finally {
      setLoading(false)
    }
  }

  async function handleTenantSelect(tenantOption: TenantOption) {
    setSelectedTenantId(tenantOption.tenant_id)
    setTenantId(tenantOption.tenant_id)
    setTenantOptions(null)
    setLoading(true)
    try {
      const client = getClient()
      const res = await client.passwordResetRequest({
        tenant_id: tenantOption.tenant_id,
        email: email.trim()
      })
      if (res.meta.status === 202) {
        setSent(true)
        show({ variant: 'success', title: 'Reset email sent', description: 'Check your inbox for the reset link.' })
      } else {
        const errMsg = (res.data as any)?.error || 'Failed to send reset email'
        setError(errMsg)
        show({ variant: 'error', title: 'Failed to send reset email', description: errMsg })
      }
    } catch (err: any) {
      setError(err?.message || String(err))
      show({ variant: 'error', title: 'Error', description: err?.message || String(err) })
    } finally {
      setLoading(false)
    }
  }

  if (sent) {
    return (
      <div className="flex min-h-svh flex-col items-center justify-center p-6">
        <div className="w-full max-w-md space-y-4 rounded-xl border p-6">
          <h1 className="text-xl font-semibold">Check your email</h1>
          <p className="text-sm text-muted-foreground">
            If an account exists for <strong>{email}</strong>, we've sent a password reset link.
            Please check your inbox and spam folder.
          </p>
          <div className="flex gap-2">
            <Button
              variant="secondary"
              onClick={() => { setSent(false); setEmail(''); setTenantOptions(null); setSelectedTenantId('') }}
            >
              Try another email
            </Button>
            <Button
              variant="secondary"
              onClick={() => { window.location.href = '/' }}
            >
              Back to login
            </Button>
          </div>
        </div>
      </div>
    )
  }

  // Show tenant selection if email exists in multiple tenants
  if (tenantOptions && tenantOptions.length > 0) {
    return (
      <div className="flex min-h-svh flex-col items-center justify-center p-6">
        <div className="w-full max-w-md space-y-4 rounded-xl border p-6">
          <h1 className="text-xl font-semibold">Select your account</h1>
          <p className="text-sm text-muted-foreground">
            The email <strong>{email}</strong> is associated with multiple accounts.
            Please select which account you want to reset the password for.
          </p>
          <div className="space-y-2">
            {tenantOptions.map((tenant) => (
              <Button
                key={tenant.tenant_id}
                variant="outline"
                className="w-full justify-start"
                onClick={() => handleTenantSelect(tenant)}
                disabled={loading}
              >
                {tenant.tenant_name || tenant.tenant_id}
              </Button>
            ))}
          </div>
          <Button
            variant="secondary"
            onClick={() => { setTenantOptions(null); setEmail('') }}
          >
            Use a different email
          </Button>
        </div>
      </div>
    )
  }

  return (
    <div className="flex min-h-svh flex-col items-center justify-center p-6">
      <div className="w-full max-w-md space-y-4 rounded-xl border p-6">
        <h1 className="text-xl font-semibold">Reset your password</h1>
        <p className="text-sm text-muted-foreground">
          Enter your email address and we'll send you a link to reset your password.
        </p>
        {error && (
          <div className="rounded-md border border-red-200 bg-red-50 p-2 text-sm text-red-700" data-testid="forgot-password-error">
            {error}
          </div>
        )}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="email">Email address</Label>
            <Input
              id="email"
              type="email"
              data-testid="forgot-password-email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
              required
              autoFocus
            />
          </div>
          <div className="flex gap-2">
            <Button type="submit" data-testid="forgot-password-submit" disabled={loading || !email.trim()}>
              {loading ? 'Sending...' : 'Send reset link'}
            </Button>
            <Button
              type="button"
              variant="secondary"
              onClick={() => { window.location.href = '/' }}
            >
              Back to login
            </Button>
          </div>
        </form>
      </div>
    </div>
  )
}
